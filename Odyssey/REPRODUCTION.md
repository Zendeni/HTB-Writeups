# Odyssey reproduction bundle

Run commands from this directory. The tracked `scripts/` and `artifacts/`
directories contain source helpers and payloads; the empty `responses/`,
`scans/`, `smb-share/`, and `tools/` directories hold runtime output.

Generated executables, downloaded target assemblies, cookies, password hashes,
registry hives, recovered keys, and flags are intentionally not bundled. Create
them during your own authorized lab run.

The helpers require the usual HTB toolchain plus `curl`, `jq`, Chromium,
ChromeDriver, Selenium, ProxyChains, Impacket, NetExec, BloodyAD, Mono, OpenSSL,
Hashcat, Chisel, and ILSpyCmd. Install the Python modules with:

```bash
python3 -m pip install -r requirements.txt
```

Values recovered during the chain can be supplied without editing scripts:

```bash
export AEGIS_COOKIE='connect.sid=...'
export MDS_DIAG_TOKEN='...'
export AEGIS_RENDER_DB_USER='aegis_audit_publisher'
export AEGIS_RENDER_DB_PASS='...'
export AEGIS_RENDER_DB_HOST='172.16.0.11'
export AEGIS_RENDER_DB_DB='aegis_audit'
export AEGIS_RENDER_DB_PORT='1433'
export SVC_MSSQL_PASSWORD='...'
export ODYSSEY_DB_NT_HASH='...'
export DEPLOY_NT_HASH='...'
```

Where possible, the wrappers also recover these values from the response files
created by preceding steps. `build-token-helper.sh` pins GodPotato to commit
`59f66583474fb0297b7447551460e1072de324c0` before building the CLR payload.
