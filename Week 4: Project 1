import requests
import time
import socket
import json
import re

NVD_API_KEY = ""
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
HEADER = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 3306, 3389]

def scan_ports(target, ports):
    open_ports = []
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((target, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        except:
            pass
    return open_ports

def grab_banner(target, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((target, port))
        if port in [80, 443]:
            if port == 443:
                import ssl
                context = ssl.create_default_context()
                sock = context.wrap_socket(sock, server_hostname=target)
            sock.send(b"GET / HTTP/1.1\r\nHost: " + target.encode() + b"\r\n\r\n")
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
        elif port == 22:
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
        else:
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
        sock.close()
        return banner
    except:
        return ""

def parse_service_version(banner, port):
    service = ""
    version = ""
    if port == 80 or port == 443:
        match = re.search(r'Server:\s*([^\\r\\n]+)', banner, re.IGNORECASE)
        if match:
            server = match.group(1)
            parts = server.split('/')
            if len(parts) > 1:
                service = parts[0]
                version = parts[1].split(' ')[0]
    elif port == 22:
        lines = banner.split('\\n')
        if lines:
            first_line = lines[0].strip()
            parts = first_line.split()
            if len(parts) > 1:
                service = "SSH"
                version = parts[1]
    elif port == 21:
        if "FTP" in banner.upper():
            service = "FTP"
            match = re.search(r'FTP[^\d]*([\d.]+)', banner, re.IGNORECASE)
            if match:
                version = match.group(1)
    elif port == 25:
        if "SMTP" in banner.upper():
            service = "SMTP"
    elif port == 110:
        if "POP3" in banner.upper():
            service = "POP3"
    elif port == 143:
        if "IMAP" in banner.upper():
            service = "IMAP"
    elif port == 3306:
        if "MySQL" in banner.upper():
            service = "MySQL"
    return service, version

def search_cve(product, version):
    query = f"{product}:{version}"
    params = {
        "keywordSearch": query,
        "resultsPerPage": 10
    }
    try:
        response = requests.get(NVD_API_URL, headers=HEADER, params=params, timeout=10)
        if response.status_code == 200:
            return response.json()
        else:
            return {}
    except:
        return {}
    
def parse_cve_results(data):
    results = []
    for item in data.get("vulnerabilities", []):
        cve = item["cve"]
        cve_id = cve["id"]
        desc = cve["description"][0]["value"]
        severity = "N/A"
        metrics = cve.get("metrics", {})
        if "cvssMetricV31" in metrics:
            severity = metrics["cvssMetricV31"][0]["cvssData"]["baseSeverity"]
        elif "cvssMetricV30" in metrics:
            severity = metrics["cvssMetricV30"][0]["cvssData"]["baseSeverity"]

        results.append((cve_id, desc, severity))
    return results

def generate_report(target, findings, filename="vulnerability_report.txt"):
    with open(filename, 'w') as f:
        f.write(f"Vulnerability Scan Report for {target}\\n")
        f.write("=" * 50 + "\\n\\n")
        for port, service, version, cves in findings:
            f.write(f"Port: {port}\\n")
            f.write(f"Service: {service}\\n")
            f.write(f"Version: {version}\\n")
            if cves:
                f.write("CVEs:\\n")
                for cve_id, desc, severity in cves:
                    f.write(f"  {cve_id} - Severity: {severity}\\n")
                    f.write(f"  {desc}\\n\\n")
            else:
                f.write("No CVEs found.\\n\\n")
        f.write("\\nResponsible Disclosure and Triage Basics:\\n")
        f.write("- Do not exploit vulnerabilities without permission.\\n")
        f.write("- Report findings to the vendor or appropriate authorities.\\n")
        f.write("- Use triage to prioritize based on severity and exploitability.\\n")
        f.write("- Follow ethical hacking guidelines.\\n")

def main():
    print("=== Lightweight CVE Vulnerability Scanner ===")
    target = input("Enter target IP address: ").strip()

    print(f"\\n[+] Scanning {target} for open ports...\\n")
    open_ports = scan_ports(target, COMMON_PORTS)

    findings = []
    for port in open_ports:
        print(f"[+] Checking port {port}...")
        banner = grab_banner(target, port)
        service, version = parse_service_version(banner, port)
        if service:
            print(f"  Detected: {service} {version}")
            data = search_cve(service, version)
            cves = parse_cve_results(data)
            findings.append((port, service, version, cves))
        time.sleep(0.5)

    if findings:
        generate_report(target, findings)
        print("\\n[+] Report generated: vulnerability_report.txt")
        print("\\nResponsible Disclosure and Triage Basics:")
        print("=== Do not exploit vulnerabilities without permission ===")
        print("=== Report findings to the vendor or appropriate authorities ===")
        print("=== Use triage to prioritize based on severity and exploitability ===")
        print("=== Follow ethical hacking guidelines ===")
    else:
        print("No services detected or no CVEs found.")

if __name__ == "__main__":
    main()
