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
```
