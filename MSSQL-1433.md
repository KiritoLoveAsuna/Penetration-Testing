### Show all databases
proxychains4 -f /etc/proxychains4.conf crackmapexec mssql 10.10.124.142 -u web_svc -p Diamond1 -q 'SELECT name FROM master.sys.databases;'

### Show all tables from msdb database
proxychains4 -f /etc/proxychains4.conf crackmapexec mssql 10.10.124.142 -u web_svc -p Diamond1 -q 'SELECT name FROM msdb.sys.tables'

### show all values of table spt_monitor from master database
SELECT * FROM msdb.dbo.monitor;

### Mssql Connection
```
impacket-mssqlclient user:pass@IP
impacket-mssqlclient user:pass@IP -windows-auth
```

### Sql authentication vs Windows authentication
>SQL Server Authentication:

>User Credentials: Requires a username and password specific to the SQL Server database.
Authentication Process: The SQL Server validates the username and password provided by the user.
Security Implications: Typically involves storing a username and password in the application's connection string. This method is more vulnerable to security threats if credentials are not adequately protected.
Example connection string using SQL Server Authentication:

>Windows Authentication:

>User Credentials: Relies on the user's Windows credentials (username and password) without requiring a separate SQL Server username and password.
Authentication Process: The SQL Server trusts the Windows authentication process, and the user is authenticated based on their Windows login credentials.
Security Implications: Generally considered more secure as it leverages the security features of the Windows operating system. Credentials are not typically stored in connection strings.
