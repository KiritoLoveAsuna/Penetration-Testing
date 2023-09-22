### Introduction
The ftp command-line utility is a standard tool available on many Unix-like operating systems, including Linux, and it is used to connect to FTP servers. While ftp is primarily designed for connecting to FTP servers, it may not be directly compatible with FileZilla Server because FileZilla Server often uses an extended version of FTP called FTP over TLS (FTPS) for secure connections. The standard ftp utility does not support FTPS by default.
### Get directory to local folder
```
wget -m --user=ftp_jp --password="~be<3@6fe1Z:2e8" ftp://192.168.197.226:24621/umbraco
```
