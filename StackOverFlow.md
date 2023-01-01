![image](https://user-images.githubusercontent.com/38044499/206827307-3175d02e-bf93-4689-9917-29e706a49388.png)
![image](https://user-images.githubusercontent.com/38044499/206829029-c8ca291b-1614-4f33-88db-69501d6bbf53.png)
![e565981a4dd076ed16b46ed458a3d5a](https://user-images.githubusercontent.com/38044499/209507662-9322663f-ca9a-434f-bd72-321fddc7191f.jpg)

### testing buffer size
msf-pattern_create -l 800  
msf-pattern_offset -l 800 -q 42306142

### To find the opcode equivalent of JMP ESP
```
msf-nasm_shell  
nasm > jmp esp  
00000000  FFE4              jmp esp  
```
