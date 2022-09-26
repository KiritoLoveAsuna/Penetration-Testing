### Get installed software
Get-WmiObject -Class Win32_Product

### Get Antivirus Product Status
Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct
