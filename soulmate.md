---

# Hack The Box – Soulmate

---

# 1. Initial Enumeration

## 1.1 Nmap

```bash
nmap -sC -sV -p- -oN full_scan.txt target
```

Relevant services discovered:

* SSH (OpenSSH)
* HTTP (nginx)

The HTTP service redirected to a domain-based virtual host, indicating name-based virtual hosting.

---

# 2. Web Enumeration

After adding the discovered domain to `/etc/hosts`, the main application loaded correctly.

The front-end functionality did not expose direct injection points, file upload features, or obvious logic flaws.

Given the minimal attack surface, virtual host enumeration was performed.

## 2.1 Virtual Host Fuzzing

```bash
ffuf -w /usr/share/wordlists/dirb/big.txt \
-u http://target \
-H "Host: FUZZ.target" -fs <size>
```

Discovered subdomain:

```
ftp.target
```

This host exposed a **CrushFTP login interface**, significantly expanding the attack surface.

---

# 3. CrushFTP Authentication Bypass

Inspection of the web interface indicated:

* CrushFTP version 11
* Early 2025 build

Research identified:

```
CVE-2025-31161
```

### 3.1 Vulnerability Overview

CVE-2025-31161 is an authentication bypass in CrushFTP’s AWS4-HMAC authorization handling.

The application incorrectly validates the `Authorization` header when parsing AWS-style signed requests. Due to flawed header parsing and trust assumptions, crafted requests can:

* Bypass authentication checks
* Directly access administrative API endpoints

Specifically, the endpoint:

```
/WebInterface/function/
```

accepts administrative commands such as `setUserItem` when the header validation logic is improperly triggered.

This effectively allows unauthenticated creation of administrative users.

---

## 3.2 Exploit Execution

A public proof-of-concept was used to create a new administrative account:

```bash
python3 cve_2025_31161.py \
--target ftp.target \
--port 80 \
--exploit \
--new-user admin_user \
--password admin_pass \
--custom-headers '{"Host":"ftp.target"}'
```

The exploit crafted a `setUserItem` request containing an XML user object with:

* `<admin>true</admin>`
* Full filesystem permissions

Administrative access to the CrushFTP panel was obtained.

---

# 4. Web Root Access

Within the administrative interface:

* An existing user’s password was reset.
* Login was performed using that account.

The user had access to FTP share:

```
webProd
```

This directory mapped directly to the production web root.

### 4.1 Architectural Weakness

CrushFTP allowed:

* File upload capability
* Direct write access to web root
* No extension filtering or execution restrictions

This combination enabled arbitrary PHP file upload.

---

# 5. Remote Code Execution

## 5.1 Web Shell Upload

A PHP reverse shell was uploaded to `webProd`.

Because this directory mapped to the nginx-served document root, uploaded files were immediately executable.

## 5.2 Shell Access

Listener:

```bash
nc -lvnp 9090
```

Triggering the uploaded file resulted in a shell as:

```
www-data
```

### 5.3 Root Cause

The compromise was possible due to:

* Lack of file type validation
* No separation between file storage and executable web root
* Over-privileged FTP user configuration

---

# 6. Local Enumeration

From the www-data shell:

```bash
ss -tlnp
```

Discovered:

```
127.0.0.1:2222
```

This indicated a locally bound service not externally accessible.

Internal-only services frequently assume trust based on localhost binding, making them ideal post-exploitation targets.

---

# 7. Erlang SSH Service

Inspection of local scripts revealed:

* Custom Erlang SSH daemon
* Version 5.2.9
* Hardcoded credentials within startup scripts

Banner identification:

```
SSH-2.0-Erlang/5.2.9
```

This version was vulnerable to:

```
CVE-2025-32433
```

---

# 8. SSH Port Forwarding

Because the Erlang SSH service was bound to localhost, direct access from the attacker machine was not possible.

Port forwarding was used:

```bash
ssh -L 2222:127.0.0.1:2222 user@target
```

This exposed the internal service locally on the attacker machine.

Verification:

```bash
nmap -p 2222 -sV 127.0.0.1
```

Confirmed Erlang SSH was reachable through the tunnel.

---

# 9. Erlang Pre-Authentication RCE

## 9.1 Vulnerability Overview

```
CVE-2025-32433
```

The Erlang SSH daemon improperly handles `SSH_MSG_CHANNEL_REQUEST` packets.

Specifically:

* Channel requests are processed before authentication is completed.
* The `exec` request handler invokes Erlang expressions directly.
* No authentication state validation is performed prior to command execution.

This allows arbitrary Erlang code to be evaluated pre-authentication.

Because the daemon runs as root, exploitation results in immediate root command execution.

---

## 9.2 Exploit Execution

A packet-level proof-of-concept was used to:

1. Send SSH banner
2. Send `SSH_MSG_KEXINIT`
3. Send `SSH_MSG_CHANNEL_OPEN`
4. Send crafted `SSH_MSG_CHANNEL_REQUEST` with malicious Erlang expression

The payload invoked:

```
os:cmd(...)
```

Resulting in execution of arbitrary system commands.

Reverse shell was obtained as root.

---

# 10. Vulnerability Analysis

## 10.1 CVE-2025-31161 – CrushFTP Auth Bypass

Root cause:

* Improper validation of AWS4-HMAC authorization headers
* Trusting header structure without strict verification

Impact:

* Administrative user creation
* Full application takeover

---

## 10.2 Web Root File Upload

Root cause:

* Direct mapping of FTP write access to executable web directory
* No upload restrictions
* No extension filtering

Impact:

* Arbitrary PHP execution
* Remote code execution as web server user

---

## 10.3 Local Service Trust Assumption

Root cause:

* Internal service bound to localhost assumed secure
* No layered authentication controls
* Hardcoded credentials in service configuration

Impact:

* Privilege escalation via pivoting

---

## 10.4 CVE-2025-32433 – Erlang SSH Pre-Auth Execution

Root cause:

* Execution of channel request logic prior to authentication
* Direct evaluation of Erlang expressions
* Service running with root privileges

Impact:

* Arbitrary command execution as root
* Full system compromise

---

# 11. Complete Attack Chain

1. Port enumeration
2. Virtual host discovery
3. Identification of CrushFTP instance
4. Exploitation of CVE-2025-31161
5. Administrative access obtained
6. Password reset of existing user
7. Upload of PHP web shell
8. Shell as www-data
9. Discovery of internal Erlang SSH service
10. SSH port forwarding
11. Exploitation of CVE-2025-32433
12. Root compromise

---
