### Responder
##### Attack 1: LLMNR/NBT-NS Poisoning through SMB
>Essentially when a system tries to access an SMB share, it sends a request to the DNS server which then resolves the share name to the respective IP address and the requesting system can access it. However, when the provided share name doesn’t exist, the system sends out an LLMNR query to the entire network. This way, if any user(IP address) has access to that share, it can reply and provide the communication to the requestor.

>Let’s see a share “wow” which doesn’t exist currently. If the share exists on the same network, wow can be accessed by typing “\\\\wow” in the address bar of file explorer. It doesn’t exist and so, Windows throws an error.

![image](https://github.com/KiritoLoveAsuna/Penetration-Testing/assets/38044499/9dbcb69f-3468-4a23-869f-57f49bcf4ec8)

>In comes responder. Now at this point, the requesting machine (windows 10) sends out an LLMNR request. We set up responder to poison that request. We need to tell responder the NIC on which we want to listen for LLMNR requests. Here, eth0. The default responder run shall start LLMNR and NBT-NS poisoning by default.

![image](https://github.com/KiritoLoveAsuna/Penetration-Testing/assets/38044499/715de23d-fb7c-4794-92ec-28663d168154)

>Now, when the victim tries to access shared drive “wow” he sees this! Wow has suddenly been made available and the poisoner asking for user credentials.

![image](https://github.com/KiritoLoveAsuna/Penetration-Testing/assets/38044499/7b811a5b-998f-4456-8972-589602aa57ea)

>Wow isn’t available at all! That’s just our poisoned answer in order to obtain NTLM hashes. Even if the user doesn’t input credentials, the hashes will be obtained.

![image](https://github.com/KiritoLoveAsuna/Penetration-Testing/assets/38044499/e7d16cb4-e0ce-4032-8aa4-2b03ccd661b0)

>We can now save these hashes in a file hash.txt and use hashcat to crack it. Please note that module number 5600 is the one suited to crack NTLMv2. If you obtained some other version of NTLM, please follow the hashcat modules here to specify the correct one.

##### Responder
>OSCP exam only allow Analyze mode by -Av
```
sudo responder -I tun0 -v
```
##### LLMNR
```
\\IPv4 address\test || //ip/test
```
##### HTTP
```
http://ip/
```
