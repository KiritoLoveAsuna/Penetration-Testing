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
### Evade Defense Mechanism
1. 改用 TCP Connect 扫描 (-sT)  
SYN 扫描 (-sS) 发送 SYN 包，若被防火墙丢弃则返回 filtered。TCP Connect 扫描完成完整的三次握手，某些防火墙策略可能允许此行为（尤其是出站连接）。尝试：  
```
sudo nmap -sT -sV -Pn -p 389,3268,445,139 10.10.110.0/24
```
2. 使用常见源端口伪装 (--source-port)  
许多防火墙允许 DNS（53）、HTTP（80）、HTTPS（443）等常用端口的入站流量。将源端口伪装成这些端口可能绕过过滤：  
```
sudo nmap -sS -sV -Pn -p 389,3268,445,139 --source-port 53 10.10.110.0/24
也可尝试 --source-port 80 或 --source-port 443。
```
3. 启用分片 (-f) 或修改 MTU  
将探测包分片可绕过某些简单的包过滤设备：  
```
sudo nmap -sS -sV -Pn -p 389,3268,445,139 -f 10.10.110.0/24
或指定更小的 MTU（如 16）：

sudo nmap -sS -sV -Pn -p 389,3268,445,139 --mtu 16 10.10.110.0/24
```
4. 增加重试次数与延长超时  
防火墙可能对某些包丢弃，但偶尔响应，增加重试和等待时间可提高命中率：  
```
sudo nmap -sS -sV -Pn -p 389,3268,445,139 --max-retries 5 --host-timeout 10m 10.10.110.0/24
```
5. 降低扫描速率（避免触发阈值）  
快速扫描可能触发 IDS/IPS 阻断，使用 --scan-delay 放缓扫描：  
```
sudo nmap -sS -sV -Pn -p 389,3268,445,139 --scan-delay 2s 10.10.110.0/24
```
6. 组合参数（综合推荐）  
将最可能有效的组合起来，例如 TCP Connect + 源端口伪装 + 分片：  
```
sudo nmap -sT -sV -Pn -p 389,3268,445,139 --source-port 53 -f --max-retries 3 10.10.110.0/24
```
7. 若以上均无效，考虑全端口扫描  
有时域服务可能运行在非标准端口上，可先扫描所有 TCP 端口（耗时较长）：  
```
sudo nmap -sS -sV -Pn -p- --min-rate 1000 10.10.110.0/24
```
### ACK Scan
>ACK扫描的结果只有两种状态：
>unfiltered (未被过滤)：表示端口可访问。Nmap收到了目标主机返回的 RST 数据包。这说明ACK数据包可以到达目标主机，但无法确定该端口是开放还是关闭。
>filtered (被过滤)：表示端口被防火墙保护。Nmap没有收到任何响应（数据包被丢弃），或者收到了 ICMP不可达错误 等消息。这说明有防火墙或过滤设备阻止了数据包到达目标端口。
