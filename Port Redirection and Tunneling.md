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
###### SSH Tunneling
bind port 445 on our local machine (0.0.0.0:445) from ssh protocol to port 445 on the Windows Server (192.168.1.110:445) and do this through a session to our original Linux target, logging in as student (student@10.11.0.128)
```
sudo ssh -N -L 0.0.0.0:445:192.168.1.110:445 student@10.11.0.128
```
