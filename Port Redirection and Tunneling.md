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
