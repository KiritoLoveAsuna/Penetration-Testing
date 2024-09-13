### Check installed apps on windows
cmd.exe->wmic->product get name

### Find file with txt extension starts from C:\Users\Freddy recursively, output the path of the file to our terminal
forfiles /P C:\Users\Freddy /S /M *.txt /c "cmd /c echo @PATH" 

### runas to execute cmd in another user's permission
runas /user:username "cmd" ("notepad "path to file"")

### runas to carry out the command specified but remains
runas /user:username "cmd /K file"

### check parent process id of windows process
wmic process where (processid=PROCID_HERE) get parentprocessid

### find files with txt extension recursively under drive 
where /R S:\ *.txt

### find how many drives/drivetype(CD-ROM or fixed drive) 
futil fsinfo drives/drivetype
 
### Check dir or file permission
icacls file/directory

### Domain information
nslookup www.offensive-security.com 8.8.8.8(using google dns server to search)  

### Psexec with shell
psexec \\ip -u username -p password -i cmd(interactive shell)  
psexec -s \\ip -u username -p password -i cmd(with system priviledges)  

### Firewall
netsh advfirewall reset(state to on)  
netsh advfirewall set allprofiles state off  
netsh advfirewall show allprofiles  
netsh advfirewall firewall add rule name="Deny Ping OffSec" dir=in action=block protocol=icmpv4 remoteip=192.124.249.5  
netsh advfirewall firewall show rule name="Deny Ping OffSec"  
netsh advfirewall firewall delete rule name="Deny Ping OffSec"  
netsh advfirewall firewall add rule name="Block OffSec" remoteip=192.124.249.5 dir=out enable=yes action=block  
netsh advfirewall firewall add rule name="Block OffSec" remoteip=192.124.249.5 dir=out enable=yes action=block remoteport=443 protocol=tcp  
netsh advfirewall firewall add rule name="Allow SSH" dir=in enable=yes action=allow localport=22 protocol=tcp  
netsh advfirewall export C:\firewallPolicy.wfw

### Services
sc start servicename  
sc stop servicename  
sc query dhcp  
PsService.exe query WSearch  
PsService.exe config WSearch  
tasklist /svc /FI "services eq dhcp"  
wmic service list brief  
sc qc servicename
### Find System Process
tasklist /v /fi "username eq system"
### Find Process owned by current user
```
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize
```
### Zipping
tar -xf zipfilename

### hidden stream
echo fileTwo uses the 'offsec' stream > offsecStream.txt:offsec  
dir /R  
more < offsecStream.txt:offsec
