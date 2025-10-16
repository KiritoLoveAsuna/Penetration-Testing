### Windows Defender Status
```
PS C:\htb> Get-MpComputerStatus

RealTimeProtectionEnabled       : True
```
### App Locker Enumeration
>An application whitelist is a list of approved software applications or executables that are allowed to be present and run on a system. The goal is to protect the environment from harmful malware and unapproved software that does not align with the specific business needs of an organization. AppLocker is Microsoft's application whitelisting solution and gives system administrators control over which applications and files users can run. It provides granular control over executables, scripts, Windows installer files, DLLs, packaged apps, and packed app installers.
```
 Get-AppLockerPolicy -Effective 
```
### PowerShell Constrained Language Mode
>PowerShell Constrained Language Mode locks down many of the features needed to use PowerShell effectively, such as blocking COM objects, only allowing approved .NET types, XAML-based workflows, PowerShell classes, and more. We can quickly enumerate whether we are in Full Language Mode or Constrained Language Mode.
```
$ExecutionContext.SessionState.LanguageMode
```
