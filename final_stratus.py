import threading
import requests
import time
import json
import whois
import ssl
import socket
from urllib.parse import urlparse
import os
from concurrent.futures import ThreadPoolExecutor

def print_ascii_art():
    art = """
   _____ _______ _____         _______ _    _  _____ 
  / ____|__   __|  __ \     /\|__   __| |  | |/ ____|
 | (___    | |  | |__) |   /  \  | |  | |  | | (___  
  \___ \   | |  |  _  /   / /\ \ | |  | |  | |\___ \ 
  ____) |  | |  | | \ \  / ____ \| |  | |__| |____) |
 |_____/   |_|  |_|  \_\/_/    \_\_|   \____/|_____/ 
                                                     
                                                     
    """
    print(art)

def load_payloads(file):
    try:
        with open(file, "r") as f:
            return [line.strip() for line in f.readlines()]
    except FileNotFoundError:
        print(f"[-] Payload file {file} not found. Using empty payload list.")
        return []

def validate_url(target):
    try:
        parsed = urlparse(target)
        if not parsed.scheme:
            target = "http://" + target
        requests.get(target, timeout=5)
        return target
    except requests.exceptions.RequestException:
        print("[-] Invalid URL. Exiting.")
        exit()

def find_subdomains(target, payload_file, report):
    subdomains = load_payloads(payload_file)
    with ThreadPoolExecutor() as executor:
        executor.map(lambda sub: check_subdomain(sub, target, report), subdomains)

def check_subdomain(sub, target, report):
    url = f"http://{sub}.{target}"
    try:
        res = requests.get(url, timeout=3)
        if res.status_code < 400:
            result = f"[+] Subdomain Found: {url}\n"
            print(result, end='')
            report.append(result)
    except requests.exceptions.RequestException:
        pass

def find_directories(target, payload_file, report):
    directories = load_payloads(payload_file)
    with ThreadPoolExecutor() as executor:
        executor.map(lambda directory: check_directory(target, directory, report), directories)

def check_directory(target, directory, report):
    url = f"{target}/{directory}"
    try:
        res = requests.get(url, timeout=3)
        if res.status_code < 400:
            result = f"[+] Directory Found: {url}\n"
            print(result, end='')
            report.append(result)
    except requests.exceptions.RequestException:
        pass

def check_sqli(target, payload_file, report):
    payloads = load_payloads(payload_file)
    with ThreadPoolExecutor() as executor:
        executor.map(lambda payload: test_sqli(target, payload, report), payloads)

def test_sqli(target, payload, report):
    url = f"{target}?id={payload}"
    try:
        res = requests.get(url, timeout=3)
        if "sql" in res.text.lower():
            result = f"[+] Possible SQLi Vulnerability: {url}\n"
            print(result, end='')
            report.append(result)
    except requests.exceptions.RequestException:
        pass

def check_xss(target, payload_file, report):
    payloads = load_payloads(payload_file)
    with ThreadPoolExecutor() as executor:
        executor.map(lambda payload: test_xss(target, payload, report), payloads)

def test_xss(target, payload, report):
    url = f"{target}?q={payload}"
    try:
        res = requests.get(url, timeout=3)
        if payload in res.text:
            result = f"[+] Possible XSS Vulnerability: {url}\n"
            print(result, end='')
            report.append(result)
    except requests.exceptions.RequestException:
        pass

def find_vhosts(target, payload_file, report):
    vhosts = load_payloads(payload_file)
    with ThreadPoolExecutor() as executor:
        executor.map(lambda vhost: check_vhost(vhost, target, report), vhosts)

def check_vhost(vhost, target, report):
    headers = {"Host": vhost}
    try:
        res = requests.get(target, headers=headers, timeout=3)
        if res.status_code < 400:
            result = f"[+] Vhost Found: {vhost}\n"
            print(result, end='')
            report.append(result)
    except requests.exceptions.RequestException:
        pass

def check_http_methods(target, report):
    methods = ["GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "TRACE", "CONNECT"]
    with ThreadPoolExecutor() as executor:
        executor.map(lambda method: test_http_method(method, target, report), methods)

def test_http_method(method, target, report):
    try:
        res = requests.request(method, target, timeout=3)
        result = f"[+] {method} supported: {res.status_code}\n"
        print(result, end='')
        report.append(result)
    except requests.exceptions.RequestException:
        pass

def get_ssl_info(domain, report):
    try:
        ctx = ssl.create_default_context()
        conn = ctx.wrap_socket(socket.socket(), server_hostname=domain)
        conn.connect((domain, 443))
        cert = conn.getpeercert()
        result = f"[+] SSL Certificate: {cert}\n"
        print(result, end='')
        report.append(result)
    except Exception:
        print("[-] SSL Info retrieval failed")

def get_whois_info(domain, report):
    try:
        details = whois.whois(domain)
        result = f"[+] WHOIS Information:\n{details}\n"
        print(result, end='')
        report.append(result)
    except Exception:
        print("[-] WHOIS lookup failed")

if __name__ == "__main__":
    print_ascii_art()
    target = validate_url(input("Enter target URL: "))
    domain = urlparse(target).netloc
    report = []
    
    features = {
        "subdomains": "Subdomain Enumeration",
        "directories": "Directory Traversal",
        "sqli": "SQL Injection Testing",
        "xss": "Cross-Site Scripting (XSS)",
        "vhosts": "Virtual Host Discovery",
        "http_methods": "HTTP Method Enumeration",
        "ssl": "SSL Certificate Info",
        "whois": "WHOIS Lookup"
    }
    
    selected_features = {}
    for key, desc in features.items():
        choice = input(f"Do you want to perform {desc}? (yes/no): ").strip().lower()
        if choice == "yes":
            selected_features[key] = True
    
    payload_files = {}
    for key in ["subdomains", "directories", "sqli", "xss", "vhosts"]:
        if selected_features.get(key):
            custom = input(f"Do you want to use a custom payload file for {features[key]}? (yes/no): ").strip().lower()
            if custom == "yes":
                file_path = input("Enter full path to your payload file: ")
            else:
                file_path = f"/home/kali/file/{key}.txt"
            payload_files[key] = file_path
    
    threads = []
    for key in payload_files.keys():
        func = globals().get(f"find_{key}" if key != "sqli" and key != "xss" else f"check_{key}")
        if func:
            t = threading.Thread(target=func, args=(target, payload_files[key], report))
            threads.append(t)
            t.start()
            time.sleep(1)
    
    if selected_features.get("http_methods"):
        check_http_methods(target, report)
    if selected_features.get("ssl"):
        get_ssl_info(domain, report)
    if selected_features.get("whois"):
        get_whois_info(domain, report)
    
    for t in threads:
        t.join()
    
    with open("scan_report.txt", "w") as f:
        f.writelines(report)
    
    print("[+] Scan complete! Report saved as scan_report.txt")
