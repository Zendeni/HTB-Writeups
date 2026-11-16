SELECT BulkColumn AS sql_error_log_1 FROM OPENROWSET(BULK 'C:\Program Files\Microsoft SQL Server\MSSQL16.MSSQLSERVER\MSSQL\Log\ERRORLOG.1', SINGLE_NCLOB) AS file_data
SELECT BulkColumn AS sql_error_log_2 FROM OPENROWSET(BULK 'C:\Program Files\Microsoft SQL Server\MSSQL16.MSSQLSERVER\MSSQL\Log\ERRORLOG.2', SINGLE_NCLOB) AS file_data
