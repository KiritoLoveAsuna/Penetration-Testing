###### linux ssh private key
```
Under linux file system, if one user account has private key(id_rsa) under its .ssh directory, usually there is user authenticated with this machine

Username:
look for public key(id_rsa.pub)

connect: 
ssh -i private_key username@ip
```
