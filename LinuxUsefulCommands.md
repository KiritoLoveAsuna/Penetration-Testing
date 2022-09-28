### show connections
netstat -natup  
ss -natup

### copy file from remote machine to local tmp
scp john@localhost:/var/tmp/CopyMe.txt /tmp  
scp [OPTION] [user@]SRC_HOST:]file1 [user@]DEST_HOST:]file2

### echo current shell
echo $SHELL

### echo environmental variable
env
