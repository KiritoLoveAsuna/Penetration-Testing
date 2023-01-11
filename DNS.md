### host command
>-l This  option  tells  named to list the zone, meaning the host command performs a zone transfer of zone name and prints  out the NS, PTR, and address records (A/AAAA).Together, the -l -a options print all records in the zone.

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
host -t ns megacorpone.com | cut -d " " -f 4(list all of domain's dns servers)  
host -l megacorpone.com ns2.megacorpone.com  
host -l MAILMAN.com 192.168.182.149(internal ip address of dc.mailman.com)  
dig axfr @192.168.185.149 _msdcs.mailman.com(host -l -a _msdcs.MAILMAN.com 192.168.182.149)   

### Interpret name servers from domain
>MAILMAN.com name server dc.MAILMAN.com.  
_msdcs.MAILMAN.com name server dc.MAILMAN.com.  
<strong>The name server of both MAILMAN.com and _msdcs.MAILMAN.com is dc.MAILMAN.com</strong>

