### Windows
##### Processes(Windows can't list processes run by privileged users)
tasklist /svc
##### Firewall
netsh advfirewall show currentprofile  
netsh advfirewall show allprofile  
netsh advfirewall firewall show rule name=all
##### Scheduled Tasks
schtasks /query /fo LIST /v
##### Enumerating Unmounted Disks
mountvol
##### Enumerating Device Drivers and Kernel Modules
1. driverquery /v /FO CSV  
2. Get-WmiObject Win32_PnPSignedDriver | Select-Object DeviceName, DriverVersion, Manufacturer | Where-Object {$_.DeviceName -like "*VMware*"}
##### Enumerating Binaries That AutoElevate
reg query HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer  
reg query HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer

### Linux
##### Kernel exploits
```
OS version:
cat /etc/issue  
cat /etc/*-release  
Kernel Version and Architecture: 
uname -a
```
##### Processes(Linux can list processes run by privileged users)
ps aux
##### Enumerating Readable/Writable Files and Directories
find / -writable(-readable,-executable) -type d(f) 2>/dev/null  
##### Enumerating Unmounted Disks
mount  
lsblk
##### Enumerating Device Drivers and Kernel Modules
1. lsmod  
2. /sbin/modinfo libata
##### Enumerating Binaries That AutoElevate
>Normally, when running an executable, it inherits the permissions of the user that runs it. However, if the SUID permissions are set, the binary will run with the permissions of the file owner. This means that if a binary has the SUID bit set and the file is owned by root, any local user will be able to execute that binary with elevated privileges
 ```
 find / -perm -u=s -type f 2>/dev/null
 ```
