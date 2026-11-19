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

