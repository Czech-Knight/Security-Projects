# 🔐 Security Projects

This repository contains hands-on cybersecurity projects focused on practical security testing, automation, and reconnaissance.  
Each project is built to strengthen real-world security skills using scripting and open-source tools.

---

## 📂 Projects Included

### 🔎 Subdomain Enumerator
A Python-based subdomain enumeration tool that checks the availability of discovered subdomains over HTTP and HTTPS.

**Features:**
- Reads subdomains from a wordlist
- Checks both HTTP and HTTPS connectivity
- Displays progress using a live progress bar
- Saves working and failed domains to an output file

**Tech Stack:**
- Python
- Requests
- tqdm

**Usage:**
```bash
python3 subdomain_enumerator.py example.com
```
### 🛡 ARP Spoof

A Python-based ARP spoofing detection tool that monitors ARP traffic on a local network and detects suspicious MAC address changes for the same IP address.  
Built to strengthen practical network security monitoring skills using packet inspection and scripting.

---

A Python-based ARP spoofing detection tool that monitors ARP traffic and alerts when an IP address is associated with multiple MAC addresses.

**Features:**
- Monitors ARP reply packets  
- Detects IP-to-MAC address changes  
- Includes simulation mode for safe testing  
- Supports live monitoring mode  
- Displays colored terminal alerts  

**Tech Stack:**
- Python  
- Scapy  
- PyFiglet  
- Colorama  

**Usage:**
```bash
python main.py simulate
```

**Live Monitoring:**
```bash
python main.py live
```

