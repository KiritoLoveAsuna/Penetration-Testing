### Show all databases
proxychains4 -f /etc/proxychains4.conf crackmapexec mssql 10.10.124.142 -u web_svc -p Diamond1 -q 'SELECT name FROM master.sys.databases;'

### Show all tables from msdb database
proxychains4 -f /etc/proxychains4.conf crackmapexec mssql 10.10.124.142 -u web_svc -p Diamond1 -q 'SELECT name FROM msdb.sys.tables'

### show all values of table spt_monitor from master database
SELECT * FROM msdb.dbo.monitor;

### Mssql Connection
```
impacket-mssqlclient user:pass@IP
```
