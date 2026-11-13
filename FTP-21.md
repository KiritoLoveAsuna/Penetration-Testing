### Introduction
The ftp command-line utility is a standard tool available on many Unix-like operating systems, including Linux, and it is used to connect to FTP servers. While ftp is primarily designed for connecting to FTP servers, it may not be directly compatible with FileZilla Server because FileZilla Server often uses an extended version of FTP called FTP over TLS (FTPS) for secure connections. The standard ftp utility does not support FTPS by default.
### Get directory to local folder
```
wget -m --user=ftp_jp --password="~be<3@6fe1Z:2e8" ftp://192.168.197.226:24621/umbraco
```
### ftp possible username
![image](https://github.com/KiritoLoveAsuna/Penetration-Testing/assets/38044499/0b7f8ae2-2f84-4149-8ecb-a985ae23bbfc)

### SSL
![image](https://github.com/user-attachments/assets/9160d945-9e8b-4984-bf31-08a948ce2c47)
```
ftp-ssl -z secure -z verify=0 192.168.221.61
ftp-ssl -z secure -z verify=0 -z cipher="$(openssl ciphers -tls1)" 192.168.221.61
```
### Solving timeout listing directory 
use ftp active mode
### Active vs Passive
>A distinction is made between active and passive FTP. In the active variant, the client establishes the connection as described via TCP port 21 and thus informs the server via which client-side port the server can transmit its responses. However, if a firewall protects the client, the server cannot reply because all external connections are blocked. For this purpose, the passive mode has been developed. Here, the server announces a port through which the client can establish the data channel. Since the client initiates the connection in this method, the firewall does not block the transfer.
### vsFTPd
Config File: /etc/vsftpd.conf
### /etc/ftpusers
this file is used to deny certain users access to the FTP service
