# knocking example:
```toml
# config.toml
[cpp]
knocks = [1234, 5678, 4444]
ports = [3923, '3921/tcp']
```
```bash
server:
    python3 pk.py -c config.toml

client:
    python3 pk.py -c config.toml -i 127.0.0.1 -s cpp

bash client:
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