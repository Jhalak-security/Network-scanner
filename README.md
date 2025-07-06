# 🔐 Network Vulnerability Scanner

A simple yet effective Python-based network vulnerability scanner that performs port scanning on a target IPv4 address, identifies open services, and fetches real-world CVEs using the CIRCL CVE Search API. Built for educational and ethical hacking purposes.

---

## 🚀 Features

- ✅ Scans common TCP ports (FTP, SSH, HTTP, etc.)
- ✅ Detects open ports and identifies common services
- ✅ Fetches top CVEs from CIRCL's public vulnerability database
- ✅ Displays CVSS scores and summaries
- ✅ Saves a full report to a timestamped `.txt` file
- ✅ Easy to use — runs from the terminal

---

## 🛠️ Requirements

- Python 3.6+
- Internet connection (for CVE lookup)
- Dependencies:
  - `requests`

Install using:

```bash
pip install -r requirements.txt
