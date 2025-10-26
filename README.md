# usage:
```toml
# example.toml
[cpp] # copyparty
knocks = [1234, 5678, 4444]
ports = [3923, '3921/tcp']
```
```bash
# server:
python3 pk.py -c example.toml

# client:
python3 pk.py -c example.toml -i 127.0.0.1 -s cpp

# bash client:
knock() { 
    nping --udp --count 1 --data-length 1 --dest-port $1 127.0.0.1
}

sq() {
    for num in 1234, 5678, 4444; do knock "$num"; done;
}

sqq() {
    while true; do sq; sleep 10; done;
}
```
# windows install (via nssm):
```cmd
rem user must have administrator rights or installed gsudo.
nssm install pk py pk.py -c example.toml -l pk.log
nssm set pk ObjectName .\<user> <pass>
nssm start pk
```
# linux install (via systemd):
```bash
# as user (need password-less sudo):
git clone https://github.com/ntrrpt/pk.git ~/pk

mkdir -p ~/.config/systemd/user

cat <<EOF > ~/.config/systemd/user/pk.service
[Unit]
Description=pk
After=default.target

[Service]
Type=simple
WorkingDirectory=%h/pk
ExecStart=/usr/bin/python3 pk.py -c example.toml -l pk.log
Restart=always
RestartSec=10

[Install]
WantedBy=default.target
EOF

systemctl --user daemon-reload
systemctl --user enable pk
systemctl --user restart pk
```
```bash
# as root:
git clone https://github.com/ntrrpt/pk.git ~/pk

cat <<EOF > /etc/systemd/system/pk.service
[Unit]
Description=pk
After=default.target

[Service]
Type=simple
User=root
WorkingDirectory=%h/pk
ExecStart=/usr/bin/python3 pk.py -c example.toml -l pk.log
Restart=always
RestartSec=10

[Install]
WantedBy=default.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable pk
sudo systemctl restart pk
```
