SELECT BulkColumn AS win_ini FROM OPENROWSET(BULK 'C:\Windows\win.ini', SINGLE_CLOB) AS file_data
SELECT BulkColumn AS sql_error_log FROM OPENROWSET(BULK 'C:\Program Files\Microsoft SQL Server\MSSQL16.MSSQLSERVER\MSSQL\Log\ERRORLOG', SINGLE_CLOB) AS file_data
