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
