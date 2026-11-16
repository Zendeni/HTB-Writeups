SELECT SYSTEM_USER AS login_name, USER_NAME() AS database_user, IS_SRVROLEMEMBER('sysadmin') AS sysadmin, IS_SRVROLEMEMBER('securityadmin') AS securityadmin, IS_SRVROLEMEMBER('serveradmin') AS serveradmin, IS_SRVROLEMEMBER('bulkadmin') AS bulkadmin
SELECT permission_name, state_desc FROM sys.server_permissions WHERE grantee_principal_id=SUSER_ID() ORDER BY permission_name
