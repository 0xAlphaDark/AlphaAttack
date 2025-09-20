# 🛠️ Tools Reference

This document lists the main tools used during the penetration testing project, along with their purpose and typical usage.

---

## 🔍 Enumeration & Scanning
- **Nmap** – Network scanning and service enumeration  
  Example: `nmap -sC -sV -oN scans/initial.txt <target-ip>`

- **Gobuster** – Directory and file brute-forcing  
  Example: `gobuster dir -u http://<target-ip>/ -w wordlists/common.txt`

- **Nikto** – Web vulnerability scanner  
  Example: `nikto -h http://<target-ip>/`

---

## 💻 Exploitation
- **Metasploit Framework** – Automated exploitation and post-exploitation modules  
  Example: `msfconsole`

- **Manual Exploits / Custom Scripts** – Custom Python, Bash, or PHP scripts for tailored exploitation.

---

## 📂 Privilege Escalation
- **LinPEAS** – Linux privilege escalation auditing script  
  Example: `./linpeas.sh`

- **pspy** – Process monitoring without root privileges  
  Example: `./pspy64`

---

## 📑 Post-Exploitation & Reporting
- **Netcat** – Reverse/bind shells & file transfer  
  Example: `nc -lvnp 4444`

- **Chisel / SSH Tunneling** – Port forwarding and pivoting.

- **KeePass / Notes** – Storing credentials and session notes securely.

---

## 🧰 Utilities
- **Burp Suite (Community)** – Intercepting and manipulating HTTP requests.  
- **Hydra** – Brute force tool for various services.  
- **John the Ripper / Hashcat** – Password cracking utilities.

---

📌 **Note:** Tools are chosen based on legality and lab scope. Always ensure they are used only in authorized environments.

