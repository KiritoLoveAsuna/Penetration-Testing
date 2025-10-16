### Windows Defender Status
```
PS C:\htb> Get-MpComputerStatus

RealTimeProtectionEnabled       : True
```
### App Locker Enumeration
```
 Get-AppLockerPolicy -Effective 
```
