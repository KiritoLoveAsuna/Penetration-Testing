### Darkarmour
https://github.com/bats3c/darkarmour  
python3 darkarmour.py -f /usr/share/windows-resources/mimikatz/x64/mimikatz.exe -e xor -j -k darkbyte -l 500 -u -o /home/kali/Desktop/b_m.exe
```
 -f FILE, --file FILE  file to crypt, assumed as binary if not told otherwise
  -e ENCRYPT, --encrypt ENCRYPT
                        encryption algorithm to use (xor)
  -S SHELLCODE, --shellcode SHELLCODE
                        file contating the shellcode, needs to be in the
                        'msfvenom -f raw' style format
  -b, --binary          provide if file is a binary exe
  -d, --dll             use reflective dll injection to execute the binary
                        inside another process
  -u, --upx             pack the executable with upx
  -j, --jmp             use jmp based pe loader
  -r, --runpe           use runpe to load pe
  -s, --source          provide if the file is c source code
  -k KEY, --key KEY     key to encrypt with, randomly generated if not
                        supplied
  -l LOOP, --loop LOOP  number of levels of encryption
  -o OUTFILE, --outfile OUTFILE
                        name of outfile, if not provided then random filename
                        is assigned
```
