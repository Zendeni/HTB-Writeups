SELECT SYSTEM_USER AS login_name, USER_NAME() AS database_user, DB_NAME() AS database_name, @@SERVERNAME AS server_name, @@VERSION AS version
SELECT IS_SRVROLEMEMBER('sysadmin') AS sysadmin, IS_SRVROLEMEMBER('securityadmin') AS securityadmin, IS_SRVROLEMEMBER('serveradmin') AS serveradmin, IS_SRVROLEMEMBER('setupadmin') AS setupadmin, IS_SRVROLEMEMBER('processadmin') AS processadmin, IS_SRVROLEMEMBER('diskadmin') AS diskadmin, IS_SRVROLEMEMBER('dbcreator') AS dbcreator, IS_SRVROLEMEMBER('bulkadmin') AS bulkadmin
SELECT name, state_desc, user_access_desc, is_trustworthy_on FROM sys.databases ORDER BY database_id
SELECT name, type_desc, is_disabled FROM sys.server_principals WHERE type IN ('S','U','G') ORDER BY type_desc,name
SELECT name, value_in_use FROM sys.configurations WHERE name IN ('show advanced options','xp_cmdshell','Ole Automation Procedures','clr enabled') ORDER BY name
SELECT permission_name, state_desc FROM sys.server_permissions WHERE grantee_principal_id = SUSER_ID() ORDER BY permission_name
SELECT roles.name AS database_role FROM sys.database_role_members drm JOIN sys.database_principals roles ON roles.principal_id=drm.role_principal_id JOIN sys.database_principals members ON members.principal_id=drm.member_principal_id WHERE members.name=USER_NAME() ORDER BY roles.name
