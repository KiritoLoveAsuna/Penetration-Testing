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
bind port 445 on our local machine (0.0.0.0:445) from ssh protocol to port 445 on the Windows Server (192.168.1.110:445) and do this through a session to our original Linux target, logging in as student (student@10.11.0.128)
```
sudo ssh -N -L 0.0.0.0(src 127.0.0.1):445:192.168.1.110(dst):445 student@10.11.0.128(relay)
```
###### ssh remote port forwarding
```
ssh -N -R 192.168.163.52(src):5555(established listening state on this port):127.0.0.1(dst):12345 student@192.168.163.52(src credential) -p 2222
```
###### SSH Dynamic Port Forwarding
After bind proxychains to local 8080 port, through proxychains all traffic can be forwarded to all ports of remote machine, accessing 127.0.0.1 is like accessing remote machine
```
sudo ssh -N -D 127.0.0.1:8080 student@10.11.0.128
cat /etc/proxychains.conf
[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
socks4 	127.0.0.1 8080 
sudo proxychains nmap --top-ports=20 -sT -Pn 192.168.1.110(another internal network of 10.11.0.128)
```
###### httptunnel
```
sudo apt install httptunnel
hts --forward-port localhost:8888 1234(listening on)
htc --forward-port 8080(listening on) 10.11.0.128:1234
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
```
