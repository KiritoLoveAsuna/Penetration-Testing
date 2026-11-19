# Port
ports 110 and 995 are used for POP3, ports 143 and 993 are used for IMAP
# Initiate Connect
openssl s_client -connect 10.129.14.128:pop3s  
openssl s_client -connect 10.129.14.128:imaps  
