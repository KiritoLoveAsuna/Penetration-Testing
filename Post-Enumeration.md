### git folder
```
directory name = .git
python3 git_extract.py gitfilename
```
### Private key
```
.ssh/id_rsa||id_dsa||id_ecdsa||id_ed25519||id_ecdsa-sk||id_ed25519-sk
```
### Sensitive files
```
find *.log, passwd, username, credential
C:\Users\username\Documents
C:\Users\username\Downloads
*.gpg
*.pgp
*config*.php
elasticsearch.y*ml
kibana.y*ml
*.p12
*.der
*.csr
*.cer
known_hosts
id_rsa
id_dsa
*.ovpn
anaconda-ks.cfg
hostapd.conf
rsyncd.conf
cesi.conf
supervisord.conf
tomcat-users.xml
*.kdbx
KeePass.config
Ntds.dit
SAM
SYSTEM
FreeSSHDservice.ini
access.log
error.log
server.xml
ConsoleHost_history.txt
.github folder
setupinfo
setupinfo.bak
*.bak, *.db
*.pdf
```
### Linux Web Service
```
Check all the folders and files under var/www/html
```
### tcpdump to capture packets 
```
tcpdump -i any udp -vvv
```
### History
```
Linux:
check all user's .bash_history
/home/user/.bash_history
```
### Password Hash
Mimikatz - sekurlsa::logonpasswords
>Extracting passwords in memory

Pwdump
>dump the password hashes of local user accounts on a Windows system
