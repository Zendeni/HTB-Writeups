#!/usr/bin/env bash
set -euo pipefail

source "$(dirname -- "${BASH_SOURCE[0]}")/common.sh"

assembly="$odyssey_root/artifacts/AuditWorkerSql.dll"
assembly_hex=$(xxd -p "$assembly" | tr -d '\n')
assembly_sha=$(sha512sum "$assembly" | awk '{print $1}')

"$script_dir/mssql-svc.sh" -command \
  "EXEC sp_configure 'clr enabled', 1; RECONFIGURE" \
  "DROP PROCEDURE IF EXISTS dbo.audit_token_exec" \
  "IF EXISTS (SELECT 1 FROM sys.assemblies WHERE name='AuditWorkerSql') DROP ASSEMBLY AuditWorkerSql" \
  "IF EXISTS (SELECT 1 FROM sys.trusted_assemblies WHERE hash=0x$assembly_sha) EXEC sys.sp_drop_trusted_assembly 0x$assembly_sha" \
  "EXEC sys.sp_add_trusted_assembly 0x$assembly_sha, N'AuditWorkerSql'" \
  "CREATE ASSEMBLY AuditWorkerSql AUTHORIZATION dbo FROM 0x$assembly_hex WITH PERMISSION_SET=UNSAFE" \
  "CREATE PROCEDURE dbo.audit_token_exec @command nvarchar(4000) AS EXTERNAL NAME AuditWorkerSql.[AuditWorker.SqlEntry].[Execute]"
