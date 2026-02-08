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
