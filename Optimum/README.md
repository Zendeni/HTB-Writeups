# HTB – Optimum
---
## Overview
---
Optimum is a classic Hack The Box Windows machine vulnerable to **Rejetto HTTP File Server (HFS) 2.3**.  
The machine allows unauthenticated remote code execution via an input handling flaw in the HFS search functionality.  
Initial access is gained as a low-privileged user, followed by local privilege escalation to `NT AUTHORITY\SYSTEM`.
---
## Initial Enumeration

A full TCP port scan reveals a single exposed service:

- **TCP/80** – Rejetto HTTP File Server 2.3

The HFS version is known to be vulnerable to macro injection leading to command execution.
---
## Initial Access – HFS Macro RCE

The vulnerability allows execution of server-side commands via crafted `search` parameters using HFS macro syntax.

The exploit workflow implemented in `optimum_hfs_rce.py` is:

1. Host a temporary HTTP server on the attacker machine.
2. Use the HFS `.save` macro to write a VBScript stager to `%TEMP%` on the target.
3. Use the HFS `.exec` macro to execute the stager.
4. The stager downloads and executes a second-stage VBScript.
5. The second stage launches a PowerShell reverse shell.

This results in an interactive shell as the user **`kostas`**.

> The exploit randomizes filenames and endpoints to mirror real-world tooling behavior.

---

## Post-Exploitation

After gaining a shell, standard Windows enumeration is performed to identify the operating system version, installed patches, and privilege escalation opportunities.

Key observations:

- Legacy Windows build
- Missing modern security mitigations
- Known vulnerable local privilege escalation paths available

---

## Privilege Escalation

Privilege escalation is achieved using a **Windows token/handle impersonation vulnerability** affecting older Windows versions.

At a high level, the escalation works by:

- Abusing the way Windows handles privileged thread/process tokens
- Leaking or duplicating a SYSTEM-level token during specific logon or process creation operations
- Spawning a new process that inherits the SYSTEM token

This results in execution as:

```

NT AUTHORITY\SYSTEM

```
