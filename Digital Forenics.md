### Shredding files
shred(kali) -f -n 3 filepath  

### clear bash history
1. history -c(clear the history on the current BASH shell)
2. export HISTSIZE=0
3. history -w(only clears the history of the current shell)
4. cat /dev/null > ~.bash_history && history -c && exit
5. shred ~/.bash_history
6. shred ~/.bash_history && cat /dev/null > .bash_history && history -c && exit  
