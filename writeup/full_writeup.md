### **Penetration Test Report: Cuppa CMS LFI to Root Compromise**

**Report Date:** [Current Date]
**Target:** 192.168.56.101 (Internal Lab Environment)
**Author:** [Your Name/Handle]

---

### **1. Executive Summary**

A penetration test was conducted on an internal server located at `192.168.56.101`. The engagement revealed a chain of critical vulnerabilities that allowed an unauthenticated attacker to gain complete control over the system.

The attack path began with the discovery of a **Local File Inclusion (LFI)** vulnerability in the web application, which was identified as Cuppa CMS. This flaw was exploited to read sensitive system files, including `/etc/shadow`, exposing user password hashes. A weak password for the user `w1r3s` was subsequently cracked, granting initial access to the server via SSH.

Post-exploitation analysis revealed a severe **sudo misconfiguration**, allowing the compromised user to escalate privileges to `root` without a password. This combination of vulnerabilities demonstrates a critical failure in multiple layers of security, leading to a full system compromise. Immediate remediation is required to address these findings.

---

### **2. Technical Walkthrough: Attack Narrative**

#### **2.1. Phase 1: Reconnaissance & Service Enumeration**

Initial reconnaissance was performed on the `192.168.56.0/24` subnet to identify active hosts. The target `192.168.56.101` was identified, and a detailed port scan was executed using Nmap to enumerate running services.

**Command:**
```bash
nmap -A -sV -p- 192.168.56.101
```

**Key Services Identified:**
*   **Port 22/TCP (SSH):** OpenSSH 7.6p1
*   **Port 80/TCP (HTTP):** Apache httpd 2.4.29
*   **Port 21/TCP (FTP):** vsftpd 3.0.3
*   **Port 3306/TCP (MySQL):** MySQL 5.7.24

The web service on port 80 was selected as the primary vector for further investigation.

#### **2.2. Phase 2: Web Application Enumeration**

The web application was identified as a standard installation of Cuppa CMS. Directory brute-forcing using `gobuster` revealed the administrator login panel at `/administrator/`. While manual browsing was conducted, a reference to a PHP file, `alertConfigField.php`, was observed in the page source, marking it as a point of interest for further testing.

#### **2.3. Phase 3: LFI Vulnerability Discovery & Exploitation**

Direct navigation to `http://192.168.56.101/alertConfigField.php` resulted in an error indicating a missing parameter. Analysis suggested a `urlConfig` parameter was expected.

The vulnerability was confirmed by supplying a path traversal payload to read the `/etc/passwd` file:
```bash
curl 'http://192.168.56.101/alertConfigField.php?urlConfig=../../../../../../etc/passwd'
```
The server responded with the contents of the file, confirming a classic LFI vulnerability. The vulnerability was further exploited to read the `/etc/shadow` file, which was successful due to improper file permissions on the system.

#### **2.4. Phase 4: Password Cracking & Initial Access**

The shadow file contained a password hash for the user `w1r3s`. The hash was extracted and cracked offline using John the Ripper with the `rockyou.txt` wordlist.

**Commands:**
```bash
# Prepare the hash file for John
unshadow passwd shadow > unshadow.txt

# Crack the hash
john --wordlist=/usr/share/wordlists/rockyou.txt unshadow.txt
```
The password was cracked in approximately 20 minutes, revealed to be `computer`. These credentials were used to successfully authenticate to the server via SSH.

**Command:**
```bash
ssh w1r3s@192.168.56.101
```

#### **2.5. Phase 5: Privilege Escalation**

Post-access, a check of the user's sudo privileges was performed using `sudo -l`. The output revealed a critical misconfiguration:

```
User w1r3s may run the following commands on this host:
    (ALL : ALL) NOPASSWD: ALL
```

This configuration allowed the `w1r3s` user to execute any command as any user, including `root`, without requiring a password. Full root access was obtained immediately.

**Command:**
```bash
sudo su -
```

---

### **3. Vulnerability Findings & Recommendations**

#### **Finding 1: Local File Inclusion (LFI) in Web Application**
*   **Risk:** `CRITICAL`
*   **Description:** The `urlConfig` parameter in `/alertConfigField.php` is vulnerable to path traversal. It fails to sanitize user-provided input, allowing an unauthenticated attacker to read arbitrary files from the server's file system, limited only by the web server's permissions.
*   **Impact:** Disclosure of sensitive information, including source code, configuration files, and system credentials, which can serve as a direct entry point into the system.
*   **Recommendation:**
    1.  **Immediate:** Apply a patch to the `alertConfigField.php` script to properly validate and sanitize the `urlConfig` parameter. Implement a whitelist of allowed files/directories if file inclusion is a required feature.
    2.  **Long-Term:** Conduct a full source code review of the CMS to identify and remediate any other input validation flaws.

#### **Finding 2: Weak User Password Policy**
*   **Risk:** `HIGH`
*   **Description:** The password for user `w1r3s` was found to be "computer", a common and easily guessable password. This indicates a lack of an enforced password complexity policy.
*   **Impact:** Weak passwords significantly reduce the time and effort required for an attacker to compromise user accounts once a hash is obtained.
*   **Recommendation:**
    1.  **Immediate:** Change all user passwords on the system, starting with `w1r3s`.
    2.  **Short-Term:** Implement and enforce a strong password policy (e.g., using `pam_pwquality`) that requires a minimum length, character complexity (uppercase, lowercase, numbers, symbols), and history.

#### **Finding 3: Sudo Privilege Escalation Misconfiguration**
*   **Risk:** `CRITICAL`
*   **Description:** The user `w1r3s` is configured in the `/etc/sudoers` file to run all commands as `root` without providing a password (`NOPASSWD`).
*   **Impact:** Any compromise of this user account leads to an immediate and trivial full compromise of the entire system, as it negates the security boundary between user and administrator.
*   **Recommendation:**
    1.  **Immediate:** Modify the sudoers configuration for the `w1r3s` user. Adhere to the **Principle of Least Privilege** by only granting access to the specific commands the user needs to perform their duties.
    2.  **Short-Term:** Remove the `NOPASSWD` directive for all users unless absolutely necessary for specific, non-interactive scripts. Audit all sudoer configurations regularly.

---

### **4. Conclusion**

The complete compromise of the target server was made possible by a chain of distinct but related security failures. A web application vulnerability provided the initial foothold, weak credentials allowed for account takeover, and improper system configuration enabled privilege escalation. This scenario underscores the importance of a defense-in-depth strategy, where security controls are applied at the application, system, and policy levels to prevent a single point of failure from resulting in a catastrophic breach.
