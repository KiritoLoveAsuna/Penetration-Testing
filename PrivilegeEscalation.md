### Windows
#### Processes(Windows can't list processes run by privileged users)
tasklist /svc
#### Firewall
netsh advfirewall show currentprofile  
netsh advfirewall show allprofile  
netsh advfirewall firewall show rule name=all
#### Scheduled Tasks
schtasks /query /fo LIST /v
#### Enumerating Unmounted Disks
mountvol
#### Enumerating Device Drivers and Kernel Modules
1. driverquery /v /FO CSV  
2. Get-WmiObject Win32_PnPSignedDriver | Select-Object DeviceName, DriverVersion, Manufacturer | Where-Object {$_.DeviceName -like "*VMware*"}

### Linux
#### Kernel exploits
```
OS version:
cat /etc/issue  
cat /etc/*-release  
Kernel Version and Architecture: 
uname -a
```
#### Processes(Linux can list processes run by privileged users)
ps aux
#### Enumerating Readable/Writable Files and Directories
find / -writable(-readable,-executable) -type d(f) 2>/dev/null  
#### Enumerating Unmounted Disks
mount  
lsblk
#### Enumerating Device Drivers and Kernel Modules
1. lsmod  
2. /sbin/modinfo libata
