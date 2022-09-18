### Check installed apps on windows
cmd.exe->wmic->product get name

### Find file with txt extension starts from C:\Users\Freddy recursively, output the path of the file to our terminal
forfiles /P C:\Users\Freddy /S /M *.txt /c "cmd /c echo @PATH"

### Retrieve local group information on our system
net localgroup

### Add "Tristan" to the Administrators group with net localgroup
net localgroup Administrators Tristan /add
-------net localgroup Administrators Tristan /del

### Add local user
net user /add Tristan greatpassword
-------net user /del Tristan

### runas to execute cmd in another user's permission
runas /user:username "cmd" ("notepad "path to file"")
