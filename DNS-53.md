### How DNS Works
Once it retrieves the request from us, the recursive resolver starts making queries. It holds a list of root name servers3 (as of 2022, there are 13 of them scattered around the world4). Its first task is to send a DNS query to one of these root name servers. Because example.com has the ".com" suffix, the root name server will respond with the address of a DNS name server that's responsible for the .com top-level domain (TLD).5 This is known as the TLD name server.

The recursive resolver then queries the .com TLD name server, asking which DNS server is responsible for example.com. The TLD name server will respond with the authoritative name server6 for the example.com domain.

The recursive resolver then asks the example.com authoritative name server for the IPv4 address of www.example.com. The example.com authoritative name server replies with the A record for that.
### Brute-force subdomains
```
for ip in $(cat list.txt); do host $ip.megacorpone.com; done
```

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

### DNS zone transfer
```
dig axfr @dns_server domain name
dig axfr @name_servers_of_dns_server domain_name

```

### DNS Recursion DDoS
>If DNS recursion is enabled, an attacker could spoof the origin on the UDP packet in order to make the DNS send the response to the victim server. An attacker could abuse ANY or DNSSEC record types as they use to have the bigger responses. The way to check if a DNS supports recursion is to query a domain name and check if the flag "ra" (recursion available) is in the response.
![image](https://user-images.githubusercontent.com/38044499/211767388-00cc00d3-394f-4344-a53d-bce3c2d5fd44.png)
![image](https://user-images.githubusercontent.com/38044499/211767512-e07f20d8-2221-4354-9b6e-615eeb91396c.png)
```
dig google.com A @<DNS-IP>
```
