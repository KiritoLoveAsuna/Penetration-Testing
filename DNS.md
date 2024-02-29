### domains resolving to the ip
dig -x ip @<DNS_IP>  
host ip dns-server-address  
https://ip:443/, find domain from certifications

### host command
>-l This  option  tells  named to list the zone, meaning the host command performs a zone transfer of zone name and prints  out the NS, PTR, and address records (A/AAAA).Together, the -l -a options print all records in the zone.

### dig
```
dig ANY @<DNS_IP> <DOMAIN>     #Any information
dig A @<DNS_IP> <DOMAIN>       #Regular DNS request
dig AAAA @<DNS_IP> <DOMAIN>    #IPv6 DNS request
dig TXT @<DNS_IP> <DOMAIN>     #Information
dig MX @<DNS_IP> <DOMAIN>      #Emails related
dig NS @<DNS_IP> <DOMAIN>      #DNS that resolves that name
dig -x 192.168.0.2 @<DNS_IP>   #Reverse lookup
dig -x 2a00:1450:400c:c06::93 @<DNS_IP> #reverse IPv6 lookup
```

### check dmarc and spf records of domain
dig txt _dmarc.stryker.com  
dig @8.8.8.8 stryker.com txt

### DNS query
To perform Reverse Lookup: host target-ip-address(host target-ip dns-server-address), dig @dns-server-address -x ip_address, nslookup ip_address dns-server-address  
To find Domain Name servers: host -t ns target-domain  
To query certain domain nameserver: host target-domain [name-server]  
To find domain MX records: host -t MX target-domain  
To find domain TXT records: host -t txt target-domain  
To find domain SOA record: host -t soa target-domain  
To find domain CNAME records: host -t cname target-domain  
To find domain TTL information: host -v -t a target-domain

### Why zone transfer
>Zone transfers are typically used to replicate DNS data across a number of DNS servers or to back up DNS files. A user or server will perform a specific zone transfer request from a name server. If the name server allows zone transfers to occur, all the DNS names and IP addresses hosted by the name server will be returned in human-readable ASCII text. Clearly, this mechanism suits our purposes at this point admirably. If the name server for a given domain allows zone transfers, we can simply request and collect all of the DNS entries for a given domain.

### DNS zone transfer
```
host -t ns megacorpone.com | cut -d " " -f 4(list all of domain's dns servers)  
host -l megacorpone.com ns2.megacorpone.com  
host -l MAILMAN.com 192.168.182.149(internal ip address of dc.mailman.com)  

dig axfr @192.168.185.149 _msdcs.mailman.com(host -l -a _msdcs.MAILMAN.com 192.168.182.149)
```   

### Interpret name servers from domain
>MAILMAN.com name server dc.MAILMAN.com.  
_msdcs.MAILMAN.com name server dc.MAILMAN.com.

<strong>The name server of both MAILMAN.com and _msdcs.MAILMAN.com is dc.MAILMAN.com</strong>

### DNS Recursion DDoS
>If DNS recursion is enabled, an attacker could spoof the origin on the UDP packet in order to make the DNS send the response to the victim server. An attacker could abuse ANY or DNSSEC record types as they use to have the bigger responses. The way to check if a DNS supports recursion is to query a domain name and check if the flag "ra" (recursion available) is in the response.
![image](https://user-images.githubusercontent.com/38044499/211767388-00cc00d3-394f-4344-a53d-bce3c2d5fd44.png)
![image](https://user-images.githubusercontent.com/38044499/211767512-e07f20d8-2221-4354-9b6e-615eeb91396c.png)
```
dig google.com A @<DNS-IP>
```
