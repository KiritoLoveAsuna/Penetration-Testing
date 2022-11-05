### Get installed software
Get-WmiObject -Class Win32_Product

### Get Antivirus Product Status
Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct

### In table format, display processes and include the CommandLine, ProcessName, and SessionID. Filter to show SessionID of 2 and ProcessName of "svchost.exe" only. Sort the results alphabetically by CommandLine.
gps | Select-Object -Property ProcessName,SessionID | Sort-Object -Property ProcessName -Descending | Where-Object SessionID -EQ 2 | Where-Object ProcessName -EQ svchost.exe | Format-Table

### Services with unquoted executable paths that start automatically can lead to escalating privileges. How many services fit that description on this machine?
Get-WmiObject -class Win32_Service -Property StartMode,PathName | Where {$_.StartMode -EQ "Auto" -and $_.PathName -notlike '"*'} | select StartMode,PathName

### Get current logged in user
query user /server:$server
Get-WmiObject -Class win32_computersystem
(Get-CimInstance -ClassName Win32_ComputerSystem).Username
(Get-WMIObject -ClassName Win32_ComputerSystem).Username


### Get file under path using hash value
Get-FileHash -Path C:\Windows\System32\* -Algorithm MD5 | findstr /i "6CECC33A62E935F5E8665B9597479A36"

### Find string in txt files under path by "password" string
Select-String -Path C:\Windows\System32\*.txt -Pattern 'password'

### Powershell to get shell from 192.168.79.79 to 192.168.79.80(username:offensive)
192.168.79.79:Enable-PSRemoting,Set-Item wsman:\localhost\client\trustedhosts 192.168.79.80,Enter-PSSession -ComputerName 192.168.79.80 -Credential offensive

### Domain
###### Domain Users and Groups
Get-ADUser Jim  
Get-ADUSer -filter *  
Get-ADUser Morgan -Properties *(get full info of aduser)  
Get-ADComputer APPSRV01  
Get-ADGroup -filter 'GroupScope -eq Global/Domain Local/Universal'  
Get-ADGroup -filter * -properties * |select SAMAccountName, Description|Export-Csv adGroupList.csv  

###### Enumerate Domain group member
Get-ADGroupMember ThirdGroup -recursive 

### Get windows firewall rules
Get-NetFirewallRule
