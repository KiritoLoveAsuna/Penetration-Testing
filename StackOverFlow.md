### Common Bad Characters
```
0x00    NULL (\0)
0x09     Tab (\t)
0x0a     Line Feed (\n)
0x0d    Carriage Return (\r)
0xff      Form Feed (\f)
```
### Nop instruction
```
\x90
```

### shellcode Length
```
standard reverse shell requires 350-400 bytes
```

### The ways to make jmp esp work
```
1. the compiled libraries must not have ASLR support
2. jmp esp address must not have bad chars
```
