### Version < 7.7
```
python sshUsernameEnumExploit.py <IP> -w <wordlist>
```

### Login via kerberos
```
/etc/hosts(顺序必须一摸一样):
10.10.11.60     frizzdc.frizz.htb frizz.htb


/etc/krb5.conf:
[domain_realm]
    .frizz.htb = FRIZZ.HTB
    frizz.htb = FRIZZ.HTB
 
[libdefaults]
    default_realm = FRIZZ.HTB
    dns_lookup_realm = false
    dns_lookup_kdc = true
    ticket_lifetime = 24h
    forwardable = true
 
[realms]
    FRIZZ.HTB = {
        kdc = FRIZZDC.FRIZZ.HTB
        admin_server = FRIZZDC.FRIZZ.HTB
        default_domain = FRIZZ.HTB
    }

kinit f.frizzle@FRIZZ.HTB; klist or impacket-getTGT export KRB5CCNAME=f.frizzle.ccache klist

ssh f.frizzle@frizz.htb -K 
```
Solving Permission denied (gssapi-with-mic,keyboard-interactive).
```
sudo timedatectl set-ntp off
sudo rdate -n 10.10.10.100
Open a new terminal
```
### Change ssh port from 22 to 80
```
sudo vim /etc/ssh/sshd_config
Change the port from 22 to 80:
sudo service ssh restart
```
