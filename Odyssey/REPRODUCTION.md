# Odyssey reproduction bundle

Run every local command from this `Odyssey` directory. The repository contains the custom source helpers and payloads used by the writeup. Runtime output belongs in `responses/`, `scans/`, `smb-share/`, and `tools/`; those directories are retained with `.gitkeep`, while their generated contents are ignored by Git.

Downloaded target assemblies, generated executables, cookies, password responses, registry hives, recovered keys, Kerberos caches, and flags are intentionally not bundled.

## Clone the repository

```bash
git clone https://github.com/Zendeni/HTB-Writeups.git
cd HTB-Writeups/Odyssey
```

## Python environment

Kali marks its system Python as externally managed under PEP 668. Use a virtual environment instead of `pip --break-system-packages`:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

If the `venv` module is absent, install the Kali package first:

```bash
apt update
apt install -y python3-venv
```

## External tools

The complete chain also uses:

- `curl`, `jq`, `rg`, Nmap, SecLists, and ProxyChains;
- Chromium, ChromeDriver, and Selenium;
- Chisel;
- Impacket's MSSQL client, SMB server, and `secretsdump`;
- Responder and Hashcat;
- BloodyAD, NetExec, Evil-WinRM, and Kerberos `klist`;
- Mono's `mcs`, OpenSSL, and ILSpyCmd.

Tool packaging varies by Kali release. Confirm the command names used by the helpers before starting:

```bash
command -v chromium chromedriver chisel proxychains4
command -v impacket-mssqlclient impacket-smbserver impacket-secretsdump
command -v responder hashcat bloodyAD nxc evil-winrm
command -v mcs openssl ilspycmd
```

ILSpyCmd is commonly installed as a .NET global tool, whose directory is not always in root's `PATH`. Version `8.2.0.7535` works with the .NET 6 SDK used during this assessment:

```bash
export PATH="$PATH:/root/.dotnet/tools"
command -v ilspycmd || dotnet tool install --global ilspycmd --version 8.2.0.7535
TERM=xterm ilspycmd --version
```

Use `TERM=xterm` for the later decompilation commands as well. This limits the workaround to ILSpyCmd and avoids `.NET 6` failures such as `The terminfo database is invalid` when the interactive shell advertises a newer or incompatible terminal definition.

Kali's `/usr/bin/impacket-*` launchers call `python3` through `PATH`. An active virtual environment can therefore make them use `.venv/bin/python`, which does not contain Kali's system Impacket package. The included launcher avoids that conflict by explicitly using `/usr/bin/python3` on Kali:

```bash
./scripts/impacket-example.sh mssqlclient -h
./scripts/impacket-example.sh smbserver -h
./scripts/impacket-example.sh secretsdump -h
```

## Network values

Set the current public target and derive the VPN address from `tun0`:

```bash
export TARGET_IP=10.129.104.203
export ATTACKER_IP=$(ip -4 -o addr show tun0 | awk '{split($4,a,"/"); print a[1]; exit}')
test -n "$ATTACKER_IP"
```

The recorded run used `10.10.15.156`. Two source SQL files retain that address as a template. The writeup creates per-run copies under `responses/` with the current `ATTACKER_IP`; do not execute those templates unchanged after a VPN reconnect.

The internal tools require a working SOCKS listener at `127.0.0.1:1080`. The reverse Chisel server on TCP/8001 is not sufficient by itself: the web-host Chisel client must also be connected. Verify all listeners with:

```bash
ss -ltnp '( sport = :8000 or sport = :8001 or sport = :1080 )'
```

The ProxyChains configuration must end with:

```text
[ProxyList]
socks5 127.0.0.1 1080
```

## Runtime values

Where possible, wrappers recover values from files created by the preceding step. They can also be supplied explicitly:

```bash
export AEGIS_COOKIE='connect.sid=...'
export MDS_DIAG_TOKEN='...'
export AEGIS_RENDER_DB_USER='aegis_audit_publisher'
export AEGIS_RENDER_DB_PASS='...'
export AEGIS_RENDER_DB_HOST='172.16.0.11'
export AEGIS_RENDER_DB_DB='aegis_audit'
export AEGIS_RENDER_DB_PORT='1433'
export SVC_MSSQL_PASSWORD='...'
export ODYSSEY_DB_NT_HASH='...'
export DEPLOY_NT_HASH='...'
```

`build-token-helper.sh` pins GodPotato to commit `59f66583474fb0297b7447551460e1072de324c0` before compiling its executable and SQL CLR forms.
It also runs Mono's compiler with `TERM=dumb` to avoid failures on terminfo entries larger than Mono 6's 4 KB parser limit.

## Fresh-instance warning

Invitations, cookies, diagnostic tokens, Chisel sessions, captured authentication data, Kerberos tickets, and recovered account keys are per-run state. After a box reset, repeat the preceding discovery steps instead of copying values from an earlier run.
