import requests
from urllib.parse import urljoin
from bs4 import BeautifulSoup

class WebScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()
        self.vulnerabilities = []
    
    def scan(self):
        print(f"[*] Scanning -> {self.target_url}")
        
        # Check for SQL injection
        self.test_sql_injection()
        
        # Check for XSS
        self.test_xss()
        
        # Check for directory traversal
        self.test_directory_traversal()
        
        # Check for sensitive files
        self.check_sensitive_files()
        
        # Display results
        self.report_results()
        
    def test_sql_injection(self):
        test_payloads = [
            "'",
            "\"",
            "' OR '1'='1",
            "\" OR \"1\"=\"1",
            "' OR 1=1--",
            "admin'--"
        ]
        
        forms = self.get_forms()
        print(f"[*] Found {len(forms)} forms to test for SQLi")
        
        for form in forms:
            for payload in test_payloads:
                data = {}
                for input_tag in form.find_all("input"):
                    input_name = input_tag.get("name")
                    input_type = input_tag.get("type", "text")
                    input_value = input_tag.get("value", payload if input_type != "password" else "test")
                    
                    if input_name:
                        data[input_name] = input_value if input_type != "password" else "test"
                    
                    form_action = form.get("action")
                    form_method = form.get("method", "get").lower()
                    
                    url = urljoin(self.target_url, form_action)
                    
                    if form_method == "post":
                        response = self.session.post(url, data=data)
                    else:
                        response = self.session.get(url, params=data)
                    
                    if any(error in response.text.lower() for error in ["sql syntax", "mysql", "ora-", "syntax error"]):
                        self.vulnerabilities.append({
                            "type": "SQL Injection",
                            "url": url,
                            "payload": payload,
                            "form": str(form)
                        })
                        print(f"[!] Possible SQLi vulnerability found with payload: {payload}")
                        break
    
    def test_xss(self):
        test_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "\"><script>alert('XSS')</script>"
        ]
        
        forms = self.get_forms()
        print(f"[*] Found {len(forms)} forms to test for XSS")
        
        for form in forms:
            for payload in test_payloads:
                data = {}
                for input_tag in form.find_all("input"):
                    input_name = input_tag.get("name")
                    input_type = input_tag.get("type", "text")
                    input_value = input_tag.get("value", payload)

                    if input_name:
                        data[input_name] = input_value
                        
                form_action = form.get("action")
                form_method = form.get("method", "get").lower()
                
                url = urljoin(self.target_url, form_action)
                
                if form_method == "post":
                    response = self.session.post(url, data=data)
                else:
                    response = self.session.get(url, params=data)
                    
                if payload in response.text:
                    self.vulnerabilities.append({
                        "type": "XSS",
                        "url": url,
                        "payload": payload,
                        "form": str(form)
                    })
                    print(
                        f"[!] Possible XSS vulnerability found with payload: {payload}")
                    break

    def test_directory_traversal(self):
        test_paths = [
            "../../../../etc/passwd",
            "../../../../windows/win.ini",
            "../",
            "....//",
            "%2e%2e%2f"
        ]
        
        for path in test_paths:
            url = urljoin(self.target_url, path)
            response = self.session.get(url)

            if any(indicator in response.text.lower() for indicator in ["root:", "[extensions]", "for 16-bit app support"]):
                self.vulnerabilities.append({
                    "type": "Directory Traversal",
                    "url": url,
                    "payload": path
                })
                print(
                    f"[!] Possible directory traversal vulnerability found with path: {path}")

    def check_sensitive_files(self):
        common_files = [
            "robots.txt",
            ".git/config",
            ".env",
            "wp-config.php",
            "config.php",
            "backup.zip",
            "admin.php",
            "phpinfo.php"
        ]

        for file in common_files:
            url = urljoin(self.target_url, file)
            response = self.session.get(url)

            if response.status_code == 200:
                self.vulnerabilities.append({
                    "type": "Sensitive File Exposure",
                    "url": url,
                    "file": file
                })
                print(f"[!] Sensitive file found: {file}")

    def get_forms(self):
        response = self.session.get(self.target_url)
        soup = BeautifulSoup(response.text, "html.parser")
        return soup.find_all("form")

    def report_results(self):
        print("\n[+] Scan Results:")
        if not self.vulnerabilities:
            print("[-] No vulnerabilities found")
            return

        for vuln in self.vulnerabilities:
            print(f"\n[!] Vulnerability: {vuln['type']}")
            print(f"URL: {vuln['url']}")
            if 'payload' in vuln:
                print(f"Payload: {vuln['payload']}")
            if 'file' in vuln:
                print(f"File: {vuln['file']}")
            if 'form' in vuln:
                # Truncate form output
                print(f"Form details: {vuln['form'][:100]}...")


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("Usage: python scanner.py <target_url>")
        sys.exit(1)

    target_url = sys.argv[1]
    scanner = WebScanner(target_url)
    scanner.scan()