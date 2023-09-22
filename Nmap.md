### Overview
-sS cant detect udp ports status
-sU cant detect tcp ports status
### UDP
sudo nmap -sUV -T4 --top-ports=100 -v 192.168.221.222
### tftp enum
sudo nmap -sU -p 69 --script=tftp-enum -T4 192.168.197.222
