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
