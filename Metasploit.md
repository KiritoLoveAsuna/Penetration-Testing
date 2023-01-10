### Testing buffer size
msf-pattern_create -l 800  
msf-pattern_create -l 2000 -s ABCDEF,def,1234(custom chars set,it can remove some specific bad chars)  
msf-pattern_offset -l 800 -q 42306142

### To find the opcode equivalent of JMP ESP
```
msf-nasm_shell  
nasm > jmp esp  
00000000  FFE4              jmp esp  
```
