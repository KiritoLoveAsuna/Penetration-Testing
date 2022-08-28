# Domain-PenetrationTesting
### Check if there is domain
* net time /domain
* ipconfig /all
* net config workstation

### Check live hosts within Domain
* nbtscan.exe 192.168.1.0/24
* for /L %l in (1,1,254) DO @ping -w 1 -n 1 192.168.1.%l | findstr "TTL="
* arp-scan

### PortScan within Domain
* telnet port 

### Check members within Domain
* net group "domain computers" /domain

### Check domain forests
* nltest /domain_trusts

### Locate DC
* net time /domain

### Locate Domain user and admins
* net user /domain
* dsquery user

### Remote connect domain user
* rdesktop -u username -p passwd -d domain ip:port

### Retrieve domain user full info
* Get-ADUser -Identity Susan -Properties "*"

### Retrieve domain computer full info
* Get-AdComputer -Identity APPSRV01 -Properties *
