This tool is for **educational purposes only**.

# 🔍 Vulnerability Scanner

A Python-based CLI tool that automates vulnerability assessment by combining port scanning, CVE lookup, and PDF report generation.

---

## ⚙️ Features

- 🔎 **Port Scanning** — Detects open ports and running services using Nmap
- 🛡️ **CVE Lookup** — Searches NIST NVD API for known vulnerabilities
- 📄 **PDF Report** — Generates a professional report with all findings
- 🎨 **Colored Output** — Clear and readable terminal output

---

## 🛠️ Technologies Used

- Python 3.13
- python-nmap
- NIST NVD API
- ReportLab
- Colorama

---

## 🚀 Usage

```bash
# Basic scan
sudo python3 scanner.py -t <target> -p 1-1024

# Custom port range
sudo python3 scanner.py -t <target> -p 1-65535

# Custom output
sudo python3 scanner.py -t <target> -p 1-1024 -o report.pdf
```

---

## 📁 Project Structure

vuln-scanner/

├── scanner.py

├── modules/

│   ├── port_scanner.py

│   ├── cve_lookup.py

│   └── report.py

├── requirements.txt

└── README.md


---

## 📸 Demo

> Screenshot or video coming soon

---

## ⚠️ Disclaimer

Again this tool is for **educational purposes only**.
Only use it on systems you own or have explicit permission to test.

---

## 👤 Author

**Laith Hatem**  
