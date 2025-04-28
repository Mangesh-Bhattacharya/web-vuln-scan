# 🔒 Web Vulnerability Scanner | Cybersecurity Project

**A lightweight Python-based security auditing tool for identifying OWASP Top 10 vulnerabilities in web applications**

![Python](https://img.shields.io/badge/Python-3.10%2B-blue) 
![License](https://img.shields.io/badge/License-MIT-red) 
![OWASP](https://img.shields.io/badge/OWASP-Aligned-yellowgreen)
![Build](https://img.shields.io/badge/CI/CD-GitHub%20Actions-blueviolet)

## 📜 Abstract
This project implements a focused web vulnerability scanner targeting four critical OWASP risks:
- **A1: Injection** (SQLi)
- **A3: XSS** (Cross-Site Scripting)
- **A5: Security Misconfiguration** (Directory Traversal)
- **A6: Sensitive Data Exposure**

Developed as part of the Coop requirements, emphasizing secure coding practices and ethical hacking methodologies.

## 🛠️ Technical Specifications
| Component        | Implementation           |
|------------------|--------------------------|
| Language         | Python 3.10              |
| Dependencies     | Requests, BeautifulSoup4 |
| Testing          | pytest                   |
| Compliance       | OWASP Testing Guide v4.2 |
| Code Quality     | Bandit, Pylint           |

## 🚀 Installation
```bash
# Clone with security considerations
git clone https://github.com/Mangesh-Bhattacharya/web-vuln-scan
cd web-vuln-scanner
```
# Create an isolated environment
```
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate    # Windows
```
# Secure installation
```
pip install -r requirements.txt
```
## 🔍 Usage
# Basic scan (ethical use only)
python scanner.py -u https://target.com or http://target.com

# Full parameter list
python scanner.py \
  -u https://target.com \
  --timeout 15 \
  --user-agent "SecurityScan/1.0 (Academic)" \
  --output report.json

## 📊 Test Coverage

| Vulnerability Type       | Test Cases | Detection Rate | Visual Indicator       |
|--------------------------|------------|----------------|------------------------|
| **SQL Injection**        | 27/30      | 90%            | ██████████▊ (90%)      |
| **XSS**                  | 25/30      | 83.3%          | █████████▋ (83%)       |
| **Directory Traversal**  | 22/30      | 73.3%          | ███████▌ (73%)         |
| **Sensitive Files**      | 28/30      | 93.3%          | ██████████▉ (93%)      |
| **False Positive Rate**  | 2.8%       | -              | █▌ (2.8%)              |

*Tested against OWASP Juice Shop (v15.1.0) and DVWA (v1.10)*

# ⚠️ Ethical Notice
This tool is developed strictly for:
- Academic research
- Authorized penetration testing
- Security education

Unauthorized scanning of systems is illegal. Always obtain written permission before testing any web application.

# 📚 References
  1. OWASP Testing Guide (v4.2)
  2. NIST SP 800-115 (Technical Security Testing)
  3. MITRE ATT&CK Framework (Web TTPs)
