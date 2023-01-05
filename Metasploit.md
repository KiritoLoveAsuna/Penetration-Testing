### Testing buffer size
msf-pattern_create -l 800  
msf-pattern_offset -l 800 -q 42306142

### To find the opcode equivalent of JMP ESP
```
msf-nasm_shell  
nasm > jmp esp  
00000000  FFE4              jmp esp  
```
