### Version < 7.7
```
python sshUsernameEnumExploit.py <IP> -w <wordlist>
```

### Login via kerberos
ssh username@ip -K 
```
impacket-getTGT frizz.htb/'f.frizzle':'xxxxxxxxxxxxx' -dc-ip frizzdc.frizz.htb
export KRB5CCNAME=f.frizzle.ccache

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

kinit f.frizzle@FRIZZ.HTB
```
