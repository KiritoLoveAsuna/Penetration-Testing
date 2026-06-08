### How DNS Works
Once it retrieves the request from us, the recursive resolver starts making queries. It holds a list of root name servers3 (as of 2022, there are 13 of them scattered around the world4). Its first task is to send a DNS query to one of these root name servers. Because example.com has the ".com" suffix, the root name server will respond with the address of a DNS name server that's responsible for the .com top-level domain (TLD).5 This is known as the TLD name server.

The recursive resolver then queries the .com TLD name server, asking which DNS server is responsible for example.com. The TLD name server will respond with the authoritative name server6 for the example.com domain.

The recursive resolver then asks the example.com authoritative name server for the IPv4 address of www.example.com. The example.com authoritative name server replies with the A record for that.
### Brute-force subdomains
```
for ip in $(cat list.txt); do host $ip.megacorpone.com; done
```

### domains resolving to the ip
dig -x ip @<DNS_IP>  
host ip dns-server-address  
https://ip:443/, find domain from certifications

### host command
>-l This  option  tells  named to list the zone, meaning the host command performs a zone transfer of zone name and prints  out the NS, PTR, and address records (A/AAAA).Together, the -l -a options print all records in the zone.

### dig
```
dig ANY @<DNS_IP> <DOMAIN>     #Any information
dig A @<DNS_IP> <DOMAIN>       #Regular DNS request
dig AAAA @<DNS_IP> <DOMAIN>    #IPv6 DNS request
dig TXT @<DNS_IP> <DOMAIN>     #Information
dig MX @<DNS_IP> <DOMAIN>      #Emails related
dig NS @<DNS_IP> <DOMAIN>      #DNS that resolves that domain_name(NS记录 域名服务器记录 ,记录该域名由哪台域名服务器解析)
dig SOA @dns_ip lvl_1_domain   #best source of name server for that dns zone(SOA 资源记录表明此 DNS 名称服务器是为该 DNS 域中的数据的信息的最佳来源)
dig -x 192.168.0.2 @<DNS_IP>   #Reverse lookup
dig -x 2a00:1450:400c:c06::93 @<DNS_IP> #reverse IPv6 lookup
```

### DNS query
To perform Reverse Lookup: host target-ip-address(host target-ip dns-server-address), dig @dns-server-address -x ip_address, nslookup ip_address dns-server-address  
To find Domain Name servers: host -t ns target-domain  
To query certain domain nameserver: host target-domain [name-server]  
To find domain MX records: host -t MX target-domain  
To find domain TXT records: host -t txt target-domain  
To find domain SOA record: host -t soa target-domain  
To find domain CNAME records: host -t cname target-domain  
To find domain TTL information: host -v -t a target-domain

### DNS zone transfer
```
dig axfr @dns_server lvl_1_domain name
dig axfr @name_servers_of_dns_server lvl_1_domain_name

```
>SOA，是起始授权机构记录，说明了在众多 NS 记录里哪一台才是主要的服务器。在任何DNS记录文件中，都是以SOA ( Startof Authority )记录开始。SOA资源记录表明此DNS名称服务器是该DNS域中数据信息的最佳来源。
>
>SOA记录与NS记录的区别：NS记录表示域名服务器记录，用来指定该域名由哪个DNS服务器来进行解析；SOA记录设置一些数据版本和更新以及过期时间等信息。
```
$ dig axfr friendzone.red @10.129.35.124

; <<>> DiG 9.18.21 <<>> axfr friendzone.red @10.129.35.124
;; global options: +cmd
friendzone.red.         604800  IN      SOA     localhost. root.localhost. 2 604800 86400 2419200 604800
friendzone.red.         604800  IN      AAAA    ::1
friendzone.red.         604800  IN      NS      localhost.
friendzone.red.         604800  IN      A       127.0.0.1
administrator1.friendzone.red. 604800 IN A      127.0.0.1
hr.friendzone.red.      604800  IN      A       127.0.0.1
uploads.friendzone.red. 604800  IN      A       127.0.0.1
friendzone.red.         604800  IN      SOA     localhost. root.localhost. 2 604800 86400 2419200 604800
;; Query time: 483 msec
;; SERVER: 10.129.35.124#53(10.129.35.124) (TCP)
;; WHEN: Thu Jan 18 17:07:52 UTC 2024
;; XFR size: 8 records (messages 1, bytes 289)

echo "10.129.35.124 friendzone.red administrator1.friendzone.red hr.friendzone.red uploads.friendzone.red >> /etc/hosts
```

### DNS Recursion DDoS
>If DNS recursion is enabled, an attacker could spoof the origin on the UDP packet in order to make the DNS send the response to the victim server. An attacker could abuse ANY or DNSSEC record types as they use to have the bigger responses. The way to check if a DNS supports recursion is to query a domain name and check if the flag "ra" (recursion available) is in the response.
![image](https://user-images.githubusercontent.com/38044499/211767388-00cc00d3-394f-4344-a53d-bce3c2d5fd44.png)
![image](https://user-images.githubusercontent.com/38044499/211767512-e07f20d8-2221-4354-9b6e-615eeb91396c.png)
```
dig google.com A @<DNS-IP>
```
### Bypass SPF DKIM DMARC
>SPF 通过 DNS TXT 记录 声明"哪些 IP 地址被允许代表本域名发送邮件" 
```
v=spf1 [ qualifier] [ mechanism] ... [ qualifier] all

qualifier:
  +  → Pass（通过，默认）
  -  → Fail（拒绝）
  ~  → SoftFail（软失败，标记但不拒绝）
  ?  → Neutral（中立，不判断）

mechanism:
  ip4:<ip>/<mask>     → 允许指定 IP 或网段
  ip6:<ip>/<mask>     → 允许指定 IPv6 地址
  a:<domain>           → 允许指定域名的 A 记录 IP
  mx:<domain>          → 允许指定域名的 MX 记录 IP
  include:<domain>     → 引入其他域名的 SPF 记录（如第三方邮件服务）
  redirect=<domain>    → 重定向到另一个域名的 SPF 记录
  exists:<domain>      → DNS 存在性检查（高级用法）
```
错误 1：~all 而非 -all  

错误 2：SPF 记录超过 10 次 DNS 查询限制SPF 标准（RFC 7208）规定，验证过程中 DNS 查询次数不得超过 10 次，否则结果为 PermError（永久错误），大多数服务器会跳过 SPF 验证。存在问题的 SPF 记录（嵌套 include 过多）  

错误 3：redirect= 与 include: 混淆# redirect= 会替换整个 SPF 记录（只在最后生效）  

|手法|原理|
|  ----  | ----  |
|冒充子域名（无 SPF 记录）|大多数管理员只为 @company.com 配置 SPF，忽略 hr.company.com、mail.company.com 等子域名|
|CVE-2026-3187|2026 年 4 月新披露的 0day（CVE-2026-3187）：Exim 邮件服务器在解析 SPF 记录中的 exists: 机制时存在整数溢出漏洞，攻击者可以构造特殊 SPF 记录使验证结果恒为 Pass。该漏洞目前已有在野利用，官方已发布补丁|
|利用被入侵的合法域名代发|攻击者入侵一个 SPF 配置正确的域名，利用其邮件服务器发送钓鱼邮件|
|DNS 劫持 / DNS 缓存投毒|篡改目标域名的 SPF DNS 记录（需要控制 DNS 服务器）|
