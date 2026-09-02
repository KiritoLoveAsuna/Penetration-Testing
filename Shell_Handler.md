# Penelop
### Install
```
pipx install git+https://github.com/brightio/penelope
```
### Usage
```
penelope -p port
```
### Features
Run nano, vim inside revershell  

### Modules
after receiving shell
```
 peass_ng               │ Run the latest version of PEASS-ng in the background               
  lse                    │ Run the latest version of linux-smart-enumeration in the background
  linuxexploitsuggester  │ Run the latest version of linux-exploit-suggester in the background
```
run peass_ng | lse | linuxexploitsuggester
# Python
```
python -c 'import pty; pty.spawn("/bin/bash")'
C:\python27\python.exe -c "import os; os.system('cmd.exe')"
```
