import argparse
import ipaddress
import logging
import os
import platform
import shlex
import shutil
import socket
import subprocess as sp
import sys
import time
from pathlib import Path
from pprint import pformat as pf
from threading import Thread
from typing import List, Tuple

import tomllib

"""
todo:
    - port range (1234-1244, 1555-1600/udp)
    - execute commands instead of opening ports
    - fgsfds
    - make service examples (nssm, systemd --user)
    - open/close ports race condition
"""


class NetshIPRangeBuilder:
    FULL_START = int(ipaddress.IPv4Address("0.0.0.0"))
    FULL_END = int(ipaddress.IPv4Address("255.255.255.255"))

    def __init__(self, allowed_cidrs: List[str]):
        """
        allowed_cidrs: list of CIDR networks, for example [“192.168.0.0/16”, “10.0.0.0/8”]
        """
        self.allowed_cidrs = allowed_cidrs

    @staticmethod
    def _cidr_to_range(cidr: str) -> Tuple[int, int]:
        """converts CIDR (e.g., 192.168.0.0/16) to a range (start_int, end_int)."""
        net = ipaddress.IPv4Network(cidr, strict=False)
        return int(net.network_address), int(net.broadcast_address)

    @staticmethod
    def _merge_ranges(ranges: List[Tuple[int, int]]) -> List[Tuple[int, int]]:
        """merges overlapping or adjacent ranges."""
        if not ranges:
            return []
        ranges_sorted = sorted(ranges, key=lambda x: x[0])
        merged = []
        cur_s, cur_e = ranges_sorted[0]
        for s, e in ranges_sorted[1:]:
            if s <= cur_e + 1:
                cur_e = max(cur_e, e)
            else:
                merged.append((cur_s, cur_e))
                cur_s, cur_e = s, e
        merged.append((cur_s, cur_e))
        return merged

    def _complement_ranges(
        self, allowed: List[Tuple[int, int]]
    ) -> List[Tuple[int, int]]:
        """returns ranges that are not within the allowed CIDR."""
        allowed_merged = self._merge_ranges(allowed)
        res = []
        cur = self.FULL_START
        for s, e in allowed_merged:
            if cur < s:
                res.append((cur, s - 1))
            cur = e + 1
        if cur <= self.FULL_END:
            res.append((cur, self.FULL_END))
        return res

    @staticmethod
    def _format_ranges_for_netsh(ranges: List[Tuple[int, int]]) -> str:
        """formats the list of ranges into a remoteip=... string."""
        if not ranges:
            return ""
        parts = [
            f"{ipaddress.IPv4Address(s)}-{ipaddress.IPv4Address(e)}" for s, e in ranges
        ]
        return "remoteip=" + ",".join(parts)

    def build(self) -> str:
        """main method: returns the string remoteip=... with prohibited ranges."""
        allowed = [self._cidr_to_range(cidr) for cidr in self.allowed_cidrs]
        forbidden = self._complement_ranges(allowed)
        return self._format_ranges_for_netsh(forbidden)


def die(reason=0, code: int = 0):
    if isinstance(reason, int):
        sys.exit(reason)

    reason = str(reason)
    if reason:
        log.error(reason)

    sys.exit(code or int(bool(reason)))


def parse_port(port: str | int):
    """
    3923 => (3923, ['tcp', 'udp'])
    '3923/udp' => (3923, ['udp'])
    """

    protocols = ["tcp", "udp"]

    if isinstance(port, int):
        return port, protocols

    if isinstance(port, str):
        spl = port.split("/")

        if len(spl) != 2:
            die(f"port {port!r} is invalid (len({spl}) != 2)")

        if spl[1].lower() not in protocols:
            die(f"{spl[1]!r} is invalid protocol")

        if not spl[0].isdigit():
            die(f"{spl[0]!r} is not a integer")

        return int(spl[0]), [spl[1]]

    die(f"not string or integer: {port}")


def sp_exec(cmd: str | list, ex_handle: bool = False):
    log.debug(cmd)
    if isinstance(cmd, str):
        cmd = shlex.split(cmd)

    try:
        p = sp.run(
            cmd,
            check=True,
            capture_output=True,
            text=True,
            # shell=True,
            encoding="utf-8",
            errors="replace",
        )
        return p.stdout, p.stderr
    except sp.CalledProcessError as e:
        if ex_handle:
            cmd_fmt = " ".join(cmd)
            log.error(f"failed cmd, are you admin?: {cmd_fmt!r}")
            log.error(e)
            sys.exit(1)
        pass


def netsh(
    port: int,
    protocols: list = ["tcp", "udp"],
    allowed: list = [],
    chain: str = "**NOT USED**",
):
    global SUDO

    block = port < 0
    port = abs(port)

    fw = f"{SUDO} netsh advfirewall firewall"

    for protocol in protocols:
        protocol = protocol.upper()

        allow_name = f'name="!_alw_{protocol}-{port}"'
        block_name = f'name="!_blk_{protocol}-{port}"'

        allow_cmd = f"add rule {allow_name} dir=in action=allow \
            protocol={protocol} localport={port}"

        ip_range = NetshIPRangeBuilder(allowed)
        block_cmd = f"add rule {block_name} dir=in action=block \
            {ip_range.build()} protocol={protocol} localport={port}"

        # recreate allow rule
        sp_exec(f"{fw} delete rule {allow_name}")
        sp_exec(f"{fw} {allow_cmd}", True)

        if block:
            # create block rule
            log.info(f"[block] {protocol} {port}")
            sp_exec(f"{fw} {block_cmd}", True)

        else:
            # remove block rule (allow)
            log.info(f"[allow] {protocol} {port}")
            sp_exec(f"{fw} delete rule {block_name}")


def iptables_rm(comm: str, chain: str = "INPUT"):  # chk: bool = False):
    global SUDO
    fw = f"{SUDO} iptables"
    ipt_list, _ = sp_exec(f"{fw} -L {chain} --line-numbers", True)
    for line in ipt_list.split("\n"):
        rule = line.split()
        if (
            len(rule) >= 3
            and rule[-3] == "/*"
            and rule[-2] == comm
            and rule[-1] == "*/"
        ):
            log.debug(f"[ipt del] {comm}")
            sp_exec(f"{fw} -D {chain} {rule[0]}", True)

            # nums are now dismatched, recursing...
            iptables_rm(comm, chain)
            break


def iptables(
    port: int,
    protocols: list = ["tcp", "udp"],
    allowed: list = [],
    chain: str = "INPUT",
):
    global SUDO

    block = port < 0
    port = abs(port)

    for protocol in protocols:
        protocol = protocol.lower()

        allow_name = f"_alw_{protocol}-{port}"
        block_name = f"_blk_{protocol}-{port}"

        fw = f"{SUDO} iptables -p {protocol} --dport {port}"

        ip_range = " ".join([f"-s {x}" for x in allowed])

        iptables_rm(block_name, chain)
        iptables_rm(allow_name, chain)

        if not block:
            log.info(f"[allow] {protocol} {port}")
            continue

        log.info(f"[block] {protocol} {port}")

        if allowed:
            sp_exec(
                f"{fw} -m comment --comment {allow_name} -I {chain} 1 -j ACCEPT {ip_range}",
                True,
            )
        sp_exec(
            f"{fw} -m comment --comment {block_name} -A {chain} -j DROP",
            True,
        )


def check():
    for svc in CONFIG:
        cs = CONFIG[svc]
        if cs["timeout"] and cs["timeout"] < time.time():
            ports = ", ".join(map(str, cs["ports"]))
            log.warning(f"[expired] {ports!r}")

            for i in cs["ports"]:
                port, protocols = parse_port(i)
                port_set(
                    -port, protocols=protocols, chain=cs["chain"], allowed=cs["allowed"]
                )

            CONFIG[svc]["timeout"] = 0


def server(port):
    global client_timeout

    log.info(f"[lisening] {port}")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("", port))

    while True:
        data, addr = sock.recvfrom(1)
        ip = addr[0]

        log.info(f"[knock] {ip}:{port}")

        knocks = CLIENT_KNOCKS.get(ip, [])
        now = time.time()

        # clean old attempts
        knocks = [k for k in knocks if now - k[1] < (ar.timeout or 999999999)]

        knocks.append((port, now))
        CLIENT_KNOCKS[ip] = knocks

        # seq checking
        seq = [k[0] for k in knocks]

        for svc in CONFIG:
            cs = CONFIG[svc]
            if seq[-len(cs["knocks"]) :] == cs["knocks"]:
                log.info(f"[valid] {ip} => {svc}")
                CLIENT_KNOCKS[ip] = []  # reset after success attempt

                if not cs["timeout"]:
                    ports = ", ".join(map(str, cs["ports"]))
                    log.warning(f"[opening] {ports!r} for {cs['expires']}s")

                    for i in cs["ports"]:
                        _port, protocols = parse_port(i)
                        port_set(
                            _port,
                            protocols=protocols,
                            chain=cs["chain"],
                            allowed=cs["allowed"],
                        )

                CONFIG[svc]["timeout"] = now + cs["expires"]


def remove(ports: list):
    def del_port(action: str, protocol: str, port: int, chain: str = "INPUT"):
        log.info(f"[rm] {action}_{protocol}-{port}")

        match OS:
            case "Windows":
                sp_exec(
                    f'{SUDO} netsh advfirewall firewall delete rule name="!_{action}_{protocol.upper()}-{port}"'
                )

            case "Linux":
                iptables_rm(f"_{action}_{protocol.lower()}-{port}", chain)

    # clean knocks
    for action in ["alw", "blk"]:
        for port in ALL_KNOCKS:
            del_port(action, "udp", port)

    # clean ports
    for svc in CONFIG:
        cs = CONFIG[svc]  # todo: optimise?

        for action in ["alw", "blk"]:
            for i in cs["ports"]:
                port, protocols = parse_port(i)

                for protocol in protocols:
                    del_port(action, protocol, port, cs["chain"])

    log.info("cleaned")


def client(ip: str, services: list = [], timeout: int = 0):
    data = b"\x00"
    gate = time.time() + timeout
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    while True:
        for svc in services:
            cs = CONFIG[svc]

            for port in cs["knocks"]:
                sock.sendto(data, (ip, port))
                log.info(f"[send] {svc} => {ip}:{port} ")
                time.sleep(1)

            time.sleep(5)

        if time.time() > gate:
            break

    sock.close()


if __name__ == "__main__":
    OS = platform.system()
    CLIENT_KNOCKS = {}
    CONFIG = {}
    SUDO = ""

    #########################
    ## args

    ap = argparse.ArgumentParser()
    add = ap.add_argument

    # fmt: off
    add("-c", "--config",             type=Path, default="",   help="config")
    add('-l', '--log',                type=str, default="",    help='write log to file')
    add('-r', '--remove',             action='store_true',     help='remove all blocks / allows')
    add('-v', '--verbose',            action='store_true',     help='verbose output (traces)')   
    add('-b', '--block-at-exit',      action='store_true',     help='block all ports at exit')
    add('-t', '--timeout',            type=int, default=60,    help='server: time for completing the entire sequence, client: time for knocking')

    g = ap.add_argument_group('client options')
    add = g.add_argument

    add('-i', '--ip',      type=str, default='',            help='[toggle] ip to knock')
    add('-s', '--service', nargs='+', type=str, default=[], help='services to knock (default: all)')
    # fmt: on

    ar = ap.parse_args()

    #########################
    ## logger

    log = logging.getLogger()
    log.setLevel(logging.DEBUG if ar.verbose else logging.INFO)

    formatter = logging.Formatter("%(asctime)s | %(levelname)7s | %(message)s")
    formatter_with_colors = logging.Formatter(
        "\033[36m%(asctime)s | \033[33m%(levelname)7s | \033[0m%(message)s"
    )

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter_with_colors if OS == "Linux" else formatter)
    log.addHandler(console_handler)

    if ar.log:
        file_handler = logging.FileHandler(ar.log, mode="a", encoding="utf-8")
        file_handler.setFormatter(formatter)
        log.addHandler(file_handler)

    #########################
    ## config chk

    if ar.config == Path():
        ap.print_help()
        die()

    if not ar.config.is_file():
        die("invalid config path")

    with open(ar.config, "rb") as file:
        CONFIG = tomllib.load(file)

    if not CONFIG:
        die("config file is empty")

    for svc in CONFIG:
        cs = CONFIG[svc]

        for field in ["knocks", "ports"]:
            if not cs.get(field, None):
                die(f"no {field!r} field in {svc!r} service")

        CONFIG[svc]["allowed"] = cs.get("allowed", [])
        CONFIG[svc]["expires"] = cs.get("expires", 120)
        CONFIG[svc]["chain"] = cs.get("chain", "INPUT")
        CONFIG[svc]["timeout"] = 0

    log.debug("config: \n" + pf(CONFIG))

    #########################
    ## client mode

    if ar.ip:
        config_services = [svc for svc, _ in CONFIG.items()]
        if ar.service:
            for svc in ar.service:
                if svc not in config_services:
                    die(f"{svc} not found in config")
        else:
            ar.service = config_services

        client(ar.ip, ar.service, ar.timeout or 9999999999)
        die()

    #########################
    ## os selecting

    match OS:
        case "Windows":
            port_set = netsh

            if not shutil.which("netsh"):
                die("netsh not found (how)")

            import ctypes

            if not ctypes.windll.shell32.IsUserAnAdmin():
                if shutil.which("sudo"):
                    log.warning(
                        "no admin rights, but sudo found (expect slow netsh starts)"
                    )
                    SUDO = "sudo"

                else:
                    s = "rerun as admin, or install gsudo"
                    if shutil.which("choco"):
                        s += " (via choco: choco install gsudo)"
                    die(s)

        case "Linux":
            port_set = iptables

            if not shutil.which("iptables"):
                die("iptables not found")

            if os.getuid() != 0:
                if not shutil.which("sudo"):
                    die("sudo not found")

                try:
                    sp.run(
                        ["sudo", "-n", "true"],
                        check=True,
                        stdout=sp.DEVNULL,
                        stderr=sp.DEVNULL,
                    )

                    log.info("sudo mode on")
                    SUDO = "sudo"

                except sp.CalledProcessError:
                    die("sudo installed, but pass is required")

                except Exception as e:
                    die(f"sudo chk err: {e}")

        case _:
            die(f"platform {OS} is not supported")

    #########################
    ## get all knocks from config

    ALL_KNOCKS = [n for svc in CONFIG.values() for n in svc.get("knocks", [])]
    ALL_KNOCKS = sorted(set(ALL_KNOCKS))  # remove dubs

    #########################
    ## clean ports (-c)

    if ar.remove:
        remove(CONFIG)
        die()

    #########################
    ## check binded knocks

    for port in ALL_KNOCKS:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            try:
                s.bind(("", port))
            except OSError as e:
                die(f"cannot bind {port}/udp: {e}")

    #########################
    ## initial ports blocking

    def block_ports():
        for svc in CONFIG:
            cs = CONFIG[svc]
            for i in cs["ports"]:
                port, protocols = parse_port(i)
                port_set(
                    -port, protocols=protocols, chain=cs["chain"], allowed=cs["allowed"]
                )

    block_ports()

    #########################
    ## starting server

    for port in ALL_KNOCKS:
        port_set(port, ["udp"])

        T = Thread(target=server, args=(port,), daemon=True)
        T.start()

    #########################
    ## main loop (check for expired services)

    try:
        while True:
            check()
            time.sleep(1)

    except KeyboardInterrupt:
        if ar.block_at_exit:
            block_ports()
            for port in ALL_KNOCKS:
                port_set(-port, ["udp"])
        else:
            remove(CONFIG)
