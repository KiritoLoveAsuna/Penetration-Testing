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
