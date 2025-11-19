### Domain Trust Types
* Parent-child: Two or more domains within the same forest. The child domain has a two-way transitive trust with the parent domain, meaning that users in the child domain corp.inlanefreight.local could authenticate into the parent domain inlanefreight.local, and vice-versa.
* Cross-link: A trust between child domains to speed up authentication.
* External: A non-transitive trust between two separate domains in separate forests which are not already joined by a forest trust. This type of trust utilizes SID filtering or filters out authentication requests (by SID) not from the trusted domain.
* Tree-root: A two-way transitive trust between a forest root domain and a new tree root domain. They are created by design when you set up a new tree root domain within a forest.
* Forest: A transitive trust between two forest root domains.
* ESAE: A bastion forest used to manage Active Directory.

### ExtraSID Attack
Requires
* The KRBTGT hash for the child domain (mimikatz # lsadump::dcsync /user:LOGISTICS\krbtgt)
* The SID for the child domain (Powerview,Get-DomainSID)
* The name of a target user in the child domain (does not need to exist!)
* The FQDN of the child domain.
* The SID of the Enterprise Admins group of the root domain.(Powerview, Get-ADGroup -Identity "Enterprise Admins" -Server "INLANEFREIGHT.LOCAL")
