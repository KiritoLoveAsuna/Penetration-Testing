### Certification

###### Installation on iphone
```
1. create a 1.txt file in desktop
2. import/export CA certificate
3. Certificate in Der format
4. select 1.txt to export ca certificate
5. change 1.txt to  1.der
6. close windows public network firewall
7. start python http server
8. make sure iphone and windows are in the same wifi
9. if windows pc ip is 192.168.2.4, burp add 192.168.2.4 to proxy listen address list,
iphone wifi proxy mannually add 192.168.2.4 8080 as proxy, turn off proxy dns
10. iphone access windows python http server and download 1.der then install from the setting
```
###### Benefit for iphone installing burp CA certificate
>Burp Suite is a popular tool used for web application security testing. It can be used to intercept and analyze network traffic between a client and a server. When you install Burp Suite’s CA certificate on your iPhone, it allows Burp Suite to intercept HTTPS traffic between your iPhone and the server1. This is because the CA certificate is used to establish a secure connection between the client and the server. By installing the CA certificate, you are essentially telling your iPhone to trust Burp Suite as a trusted certificate authority. This allows Burp Suite to decrypt the HTTPS traffic and analyze it for security vulnerabilities2
