### Overview
-sS cant detect udp ports status  
-sU cant detect tcp ports status
### UDP
sudo nmap -sUV -T4 --top-ports=100 -v 192.168.221.222  
nmap -p- -sU --min-rate 5000 ip
### tftp enum
sudo nmap -sU -p 69 --script=tftp-enum -T4 192.168.197.222

### nmap script args
>sudo nmap -sSV -p 20000 --script=http-brute --script-args http-brute.path="https://oscp:20000/session_login.cgi" 192.168.189.157

### nmap scripts
```
auth: 负责处理鉴权证书（绕开鉴权）的脚本  
broadcast: 在局域网内探查更多服务开启状况，如dhcp/dns/sqlserver等服务  
brute: 提供暴力破解方式，针对常见的应用如http/snmp等  
default: 使用-sC或-A选项扫描时候默认的脚本，提供基本脚本扫描能力  
discovery: 对网络进行更多的信息，如SMB枚举、SNMP查询等  
dos: 用于进行拒绝服务攻击  
exploit: 利用已知的漏洞入侵系统  
external: 利用第三方的数据库或资源，例如进行whois解析  
fuzzer: 模糊测试的脚本，发送异常的包到目标机，探测出潜在漏洞 intrusive: 入侵性的脚本，此类脚本可能引发对方的IDS/IPS的记录或屏蔽  
malware: 探测目标机是否感染了病毒、开启了后门等信息  
safe: 此类与intrusive相反，属于安全性脚本  
version: 负责增强服务与版本扫描（Version Detection）功能的脚本  
vuln: 负责检查目标机是否有常见的漏洞（Vulnerability），如是否有MS08_067
All: Use all the nse scipts to scan
```
### nmap use downloaded nse script
```
download nse script to /usr/share/nmap/scripts
sudo nmap --script-updatedb
```
