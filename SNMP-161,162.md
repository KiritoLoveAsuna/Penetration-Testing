### SNMP enumeration(161,community string most cases is "public")
onesixtyone -c community -i ip_list  
snmpwalk -c public -v1 -t 10 10.11.1.14(Enumerating the Entire MIB Tree)  
snmpwalk -c public -v1 10.11.1.14 1.3.6.1.4.1.77.1.2.25(Enumerating Windows Users)
