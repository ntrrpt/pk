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
from pprint import pformat
from threading import Thread
from typing import List, Tuple

import tomllib


class NetshIPRangeBuilder:
    FULL_START = int(ipaddress.IPv4Address("0.0.0.0"))
    FULL_END = int(ipaddress.IPv4Address("255.255.255.255"))

    def __init__(self, allowed_cidrs: List[str]):
        # allowed_cidrs: list of CIDR networks, for example [“192.168.0.0/16”, “10.0.0.0/8”]
        self.allowed_cidrs = allowed_cidrs

    @staticmethod
    def _cidr_to_range(cidr: str) -> Tuple[int, int]:
        # converts CIDR (e.g., 192.168.0.0/16) to a range (start_int, end_int).
        net = ipaddress.IPv4Network(cidr, strict=False)
        return int(net.network_address), int(net.broadcast_address)

    @staticmethod
    def _merge_ranges(ranges: List[Tuple[int, int]]) -> List[Tuple[int, int]]:
        # merges overlapping or adjacent ranges.
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
        # returns ranges that are not within the allowed CIDR.
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
        # formats the list of ranges into a remoteip=... string.
        if not ranges:
            return ""
        parts = [
            f"{ipaddress.IPv4Address(s)}-{ipaddress.IPv4Address(e)}" for s, e in ranges
        ]
        return "remoteip=" + ",".join(parts)

    def build(self) -> str:
        # main method: returns the string remoteip=... with prohibited ranges.
        allowed = [self._cidr_to_range(cidr) for cidr in self.allowed_cidrs]
        forbidden = self._complement_ranges(allowed)
        return self._format_ranges_for_netsh(forbidden)


def die(reason: str | int = 0, code: int | None = None):
    if isinstance(reason, int):
        sys.exit(reason)

    reason = str(reason).strip()
    if reason:
        log.error(reason)

    sys.exit(code or int(bool(reason)))


def ports_fmt(ports: list) -> str:
    return ", ".join(
        str(port) if set(protos) == {"tcp", "udp"} else f"{port}/{protos[0]}"
        for port, protos in ports
    )


def ports_expand(ports: str | list) -> List[Tuple[int, list]]:
    if isinstance(ports, str):
        ports = [p.strip() for p in ports.split(",") if p.strip()]

    port_map = {}

    for item in ports:
        if isinstance(item, int):
            item = str(item)

        if "/" in item:
            range_part, proto = item.split("/", 1)
            protos = [proto]
        else:
            range_part = item
            protos = ["tcp", "udp"]

        if "-" in range_part:
            start, end = map(int, range_part.split("-"))
            ports_expanded = range(start, end + 1)
        else:
            ports_expanded = [int(range_part)]

        for p in ports_expanded:
            if p not in port_map:
                port_map[p] = set()
            port_map[p].update(protos)

    return [
        (p, sorted(port_map[p], key=lambda proto: proto != "tcp"))
        for p in sorted(port_map)
    ]


def sp_exec(cmd: str | list, chk: bool = False) -> None | Tuple[str, str]:
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
        if chk:
            cmd_fmt = " ".join(cmd)
            die(f"failed cmd, are you admin?\ncmd: {cmd_fmt!r}\nex: {e}")
        return None


def netsh(
    port: int | str,
    protocols: list = ["tcp", "udp"],
    allowed: list = [],
    chain: str = "**NOT USED**",
):
    global SUDO

    port = int(port)
    block = port < 0
    port = abs(port)

    fw = f"{SUDO} netsh advfirewall firewall"

    for protocol in protocols:
        allow_name = f'name="!_alw_{protocol}-{port}"'
        block_name = f'name="!_blk_{protocol}-{port}"'

        allow_cmd = f"add rule {allow_name} dir=in action=allow \
            protocol={protocol.upper()} localport={port}"

        ip_range = NetshIPRangeBuilder(allowed)
        block_cmd = f"add rule {block_name} dir=in action=block \
            {ip_range.build()} protocol={protocol.upper()} localport={port}"

        # recreate allow rule
        sp_exec(f"{fw} delete rule {allow_name}")
        sp_exec(f"{fw} {allow_cmd}", True)

        if block:
            # create block rule
            log.info(f"[block] {port}/{protocol}")
            sp_exec(f"{fw} {block_cmd}", True)

        else:
            # remove block rule (allow)
            log.info(f"[allow] {port}/{protocol}")
            sp_exec(f"{fw} delete rule {block_name}")


def iptables_rm(comm: str, chain: str = "INPUT"):
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
    port: int | str,
    protocols: list = ["tcp", "udp"],
    allowed: list = [],
    chain: str = "INPUT",
):
    global SUDO

    port = int(port)
    block = port < 0
    port = abs(port)

    for protocol in protocols:
        protocol = protocol.lower()

        allow_name = f"_alw_{protocol}-{port}"
        block_name = f"_blk_{protocol}-{port}"

        fw = f"{SUDO} iptables -p {protocol} --dport {port}"

        iptables_rm(block_name, chain)
        iptables_rm(allow_name, chain)

        if not block:
            log.info(f"[allow] {port}/{protocol}")
            continue

        log.info(f"[block] {port}/{protocol}")

        if allowed:
            ip_range = " ".join([f"-s {x}" for x in allowed])
            sp_exec(
                f"{fw} -m comment --comment {allow_name} -I {chain} 1 -j ACCEPT {ip_range}",
                True,
            )
        sp_exec(
            f"{fw} -m comment --comment {block_name} -A {chain} -j DROP",
            True,
        )


def check():
    for svc, cs in CONFIG.items():
        if cs["timeout"] and cs["timeout"] < time.time():
            if cs["ports"]:
                log.warning(f"[expired] {svc}: {ports_fmt(cs['ports'])!r}")

                for port in cs["ports"]:
                    port_set(
                        -port[0],
                        protocols=port[1],
                        chain=cs["chain"],
                        allowed=cs["allowed"],
                    )

            for cmd in cs["cmd_close"]:
                log.warning(f"[expired] {svc}: {cmd!r}")
                sp_exec(cmd)

            CONFIG[svc]["timeout"] = 0


def server(port):
    global client_timeout

    log.info(f"[lisening] {port}/udp")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("", port))

    while True:
        data, addr = sock.recvfrom(1)
        ip = addr[0]

        log.info(f"[knock] {ip}:{port}")

        knocks = CLIENT_KNOCKS.get(ip, [])
        now = time.time()

        # clean old attempts
        if ar.timeout:
            knocks = [k for k in knocks if now - k[1] < ar.timeout]

        knocks.append((port, now))
        CLIENT_KNOCKS[ip] = knocks

        # seq checking
        seq = [k[0] for k in knocks]

        for svc, cs in CONFIG.items():
            if seq[-len(cs["knocks"]) :] == cs["knocks"]:
                log.info(f"[valid] {ip} => {svc}")
                CLIENT_KNOCKS[ip] = []  # reset after success attempt

                if not cs["timeout"]:
                    if cs["ports"]:
                        log.warning(
                            f"[opening] {ports_fmt(cs['ports'])!r} for {cs['expires']}s"
                        )

                        for _port in cs["ports"]:
                            port_set(
                                _port[0],
                                protocols=_port[1],
                                chain=cs["chain"],
                                allowed=cs["allowed"],
                            )

                    for cmd in cs["cmd_open"]:
                        log.warning(f"[opening] exec: {cmd!r}")
                        sp_exec(cmd)

                CONFIG[svc]["timeout"] = now + cs["expires"]


def remove(ports: list):
    def del_port(port: int, protocol: str, action: str, chain: str = "INPUT"):
        log.info(f"[rm] {action}_{protocol}-{port}")

        match OS:
            case "Windows":
                sp_exec(
                    f'{SUDO} netsh advfirewall firewall delete rule name="!_{action}_{protocol.upper()}-{port}"'
                )

            case "Linux":
                iptables_rm(f"_{action}_{protocol.lower()}-{port}", chain)
                time.sleep(0.1)

    # clean knocks
    for action in ["alw", "blk"]:
        for port in ALL_KNOCKS:
            del_port(port, "udp", action)

    # clean ports
    for svc, cs in CONFIG.items():
        for action in ["alw", "blk"]:
            for port in cs["ports"]:
                for protocol in port[1]:
                    del_port(port[0], protocol, action, cs["chain"])

    log.info("cleaned")


def client(ip: str, services: list = [], timeout: int = 0):
    data = b"\x00"
    gate = time.time() + timeout

    while True:
        seen = []
        for svc, cs in CONFIG.items():
            if services and svc not in services:  # svc chk
                continue
            if cs["knocks"] in seen:  # dubs chk
                continue

            seen.append(cs["knocks"])

            for port in cs["knocks"]:
                log.info(f"[send] {svc} => {ip}:{port} ")

                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    sock.sendto(data, (ip, port))

                time.sleep(ar.knocks_delay)

            time.sleep(ar.services_delay)

        if timeout and time.time() > gate:
            break


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
    add('-v', '--verbose',            action='store_true',     help='verbose output (traces)')   
    add('-t', '--timeout',            type=int, default=0,     help='server: time for completing the entire sequence, client: time for knocking TODO')

    g = ap.add_argument_group('server options')
    add = g.add_argument

    add('-r', '--remove',             action='store_true',     help='remove all blocks / allows')
    add('-b', '--block-at-exit',      action='store_true',     help='block all ports at exit')

    g = ap.add_argument_group('client options')
    add = g.add_argument

    add('-i', '--ip',       type=str, default='',            help='[toggle] ip to knock')
    add('-s', '--service',  nargs='+', type=str, default=[], help='services to knock (default: all)')
    add('--knocks-delay',   type=int, default=1,             help='delay between knocks')
    add('--services-delay', type=int, default=5,             help='delay between services')

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
        die(f"{ar.config!r} doesn't exist")

    with open(ar.config, "rb") as file:
        CONFIG = tomllib.load(file)

    if not CONFIG:
        die("config file is empty")

    for key in ("ip", "knocks_delay", "services_delay"):
        if key in CONFIG:
            if not getattr(ar, key):
                setattr(ar, key, CONFIG[key])
            del CONFIG[key]

    for svc, cs in CONFIG.items():
        CONFIG[svc]["cmd_open"] = cs.get("cmd_open", [])
        CONFIG[svc]["cmd_close"] = cs.get("cmd_close", [])

        CONFIG[svc]["knocks"] = cs.get("knocks", [])
        CONFIG[svc]["ports"] = ports_expand(cs.get("ports", []))
        CONFIG[svc]["allowed"] = cs.get("allowed", [])
        CONFIG[svc]["expires"] = cs.get("expires", 120)
        CONFIG[svc]["chain"] = cs.get("chain", "INPUT")

        CONFIG[svc]["timeout"] = 0

    log.debug("config: \n" + pformat(CONFIG))

    #########################
    ## client mode

    if ar.ip:
        for svc in ar.service:
            if svc not in CONFIG.keys():
                die(f"{svc!r} not found in config")

        client(ar.ip, ar.service, ar.timeout)
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
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            try:
                sock.bind(("", port))
            except OSError as e:
                die(f"cannot bind {port}/udp: {e}")

    #########################
    ## initial ports blocking

    def block_ports():
        for svc, cs in CONFIG.items():
            for port in cs["ports"]:
                port_set(
                    -port[0],
                    protocols=port[1],
                    chain=cs["chain"],
                    allowed=cs["allowed"],
                )
                time.sleep(0.1)

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
