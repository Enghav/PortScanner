#!/usr/bin/env python3
import socket
import threading
from queue import Queue
import argparse
import subprocess
import sys
import time
import requests
import re
import os

# Global lists to keep track of open ports and services found
open_ports_services = []

def ping_check(target):
    try:
        param = "-n" if sys.platform.lower().startswith("win") else "-c"
        result = subprocess.run(
            ["ping", param, "1", "-w", "1000", target],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return result.returncode == 0
    except Exception:
        return False

def query_vulners(service_name, version=None):
    query = service_name
    if version:
        query += f" {version}"
    url = f"https://vulners.com/api/v3/search/lucene/"
    params = {"query": query, "size": 5}

    try:
        response = requests.get(url, params=params, timeout=5)
        if response.status_code == 200:
            data = response.json()
            cve_list = []
            if data.get("data") and data["data"].get("search"):
                for item in data["data"]["search"]:
                    title = item.get("title", "")
                    cves = re.findall(r"CVE-\d{4}-\d{4,7}", title)
                    cve_list.extend(cves)
            return list(set(cve_list))
        else:
            print(f"[!] Vulners API error: HTTP {response.status_code}")
    except Exception as e:
        print(f"[!] Vulners API request failed: {e}")
    return []

def extract_service_version(banner):
    if not banner:
        return None, None
    m = re.search(r"(Apache)/([\d\.]+)", banner, re.IGNORECASE)
    if m:
        return m.group(1), m.group(2)
    m = re.search(r"(OpenSSH)[_\s]?([\d\.p]+)", banner, re.IGNORECASE)
    if m:
        return m.group(1), m.group(2)
    m = re.search(r"(nginx)/([\d\.]+)", banner, re.IGNORECASE)
    if m:
        return m.group(1), m.group(2)
    m = re.search(r"(Microsoft-IIS)/([\d\.]+)", banner, re.IGNORECASE)
    if m:
        return m.group(1), m.group(2)
    m = re.search(r"([a-zA-Z\-]+)[/ _]?([\d\.]+)", banner)
    if m:
        return m.group(1), m.group(2)
    return None, None

def scan_port_connect(target, port, timeout=1, vuln_alert=False):
    global open_ports_services
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((target, port))
        
        if result == 0:
            banner = ""
            try:
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                banner = sock.recv(1024).decode(errors='ignore').strip()
                banner_line = banner.splitlines()[0] if banner else ""
            except:
                banner_line = ""

            print(f"[+] Port {port}/tcp OPEN", end="")
            if banner_line:
                print(f" - Banner: {banner_line[:70]}")
            else:
                print("")

            service, version = (None, None)
            if banner_line:
                service, version = extract_service_version(banner_line)
            open_ports_services.append({
                "port": port,
                "service": service if service else "unknown",
                "version": version,
                "banner": banner_line,
            })

            if vuln_alert and banner_line and service:
                print(f"    [*] Detected service: {service} {version if version else ''}")
                cves = query_vulners(service, version)
                if cves:
                    print(f"    [!] CVE(s) found: {', '.join(cves)}")
                    open_ports_services[-1]["cves"] = cves
                else:
                    open_ports_services[-1]["cves"] = []
        sock.close()
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        exit()
    except:
        pass

def scan_port_stealth(target, port, timeout=1, vuln_alert=False):
    time.sleep(0.1)
    scan_port_connect(target, port, timeout, vuln_alert)

def worker(target, queue, scan_type, vuln_alert):
    while not queue.empty():
        port = queue.get()
        if scan_type == "t1":
            scan_port_connect(target, port, timeout=1, vuln_alert=vuln_alert)
        elif scan_type == "t2":
            scan_port_stealth(target, port, timeout=2, vuln_alert=vuln_alert)
        elif scan_type == "t3":
            scan_port_connect(target, port, timeout=3, vuln_alert=True)
        elif scan_type == "t4":
            scan_port_stealth(target, port, timeout=3, vuln_alert=True)
        elif scan_type == "t5":
            scan_port_connect(target, port, timeout=5, vuln_alert=True)
        queue.task_done()

def suggest_next_steps(target):
    print("\n[+] Suggestions based on scan results:")
    ports = [item["port"] for item in open_ports_services]

    if 80 in ports or 443 in ports:
        print("  - HTTP(S) service detected: consider running 'gobuster' or 'dirb' for directory/file enumeration.")
    if 22 in ports:
        print("  - SSH service detected: consider running 'ssh-audit' or checking for weak credentials.")
    if 21 in ports:
        print("  - FTP service detected: check for anonymous login or use 'nmap --script ftp-anon'.")
    if 3306 in ports:
        print("  - MySQL detected: consider checking for weak passwords or use 'mysql' client for further enumeration.")
    if 1433 in ports:
        print("  - MS SQL Server detected: consider testing for SQL Server vulnerabilities or bruteforce.")
    cve_found = any("cves" in item and item["cves"] for item in open_ports_services)
    if cve_found:
        print("  - Vulnerabilities detected: consider researching CVEs and using Metasploit or manual exploit development.")
    if not ports:
        print("  - No open ports detected or no services identified; consider other network reconnaissance methods.")

    # Build list of recommended scripts to run
    nmap_suggestions = []
    for i, item in enumerate(open_ports_services, start=1):
        port = item["port"]
        service = item["service"].lower()
        script = None
        if "ftp" in service:
            script = "ftp-anon"
        elif "ssh" in service:
            script = "ssh2-enum-algos"
        elif "http" in service:
            script = "http-enum"
        elif "mysql" in service:
            script = "mysql-info"
        elif "microsoft-ds" in service or port == 445:
            script = "smb-enum-shares"

        if script:
            nmap_suggestions.append((i, port, script, service))

    if not nmap_suggestions:
        print("\nNo recommended Nmap scripts found based on detected services.")
    else:
        print("\nRecommended Nmap scripts:")
        for i, port, script, service in nmap_suggestions:
            print(f"  {i}. Port {port} - Service '{service}': script '{script}'")

        choices = input("\nEnter the numbers of the scripts you want to run, separated by commas (or press Enter to skip): ").strip()
        if choices:
            selected_nums = set()
            for choice in choices.split(","):
                if choice.strip().isdigit():
                    selected_nums.add(int(choice.strip()))
            for i, port, script, service in nmap_suggestions:
                if i in selected_nums:
                    print(f"\nRunning: nmap -p {port} --script={script} {target}")
                    os.system(f"nmap -p {port} --script={script} {target}")

    # Custom command option
    custom_choice = input("\nWould you like to run a custom Nmap command? (y/n): ").strip().lower()
    if custom_choice == "y":
        custom_cmd = input("Enter your custom Nmap command: ").strip()
        if custom_cmd:
            print(f"Running custom command: {custom_cmd}")
            os.system(custom_cmd)
    else:
        print("Skipping custom Nmap command.")


def main(target, ports, threads=100, scan_type="t1"):
    print(f"\n[+] Checking if {target} is reachable via ping...")
    reachable = ping_check(target)
    if reachable:
        print(f"[+] Host {target} is reachable by ping.")
    else:
        print(f"[-] Host {target} is NOT reachable by ping, continuing with port scan anyway.")

    print(f"[+] Starting {scan_type.upper()} scan on {target} with {threads} threads")
    queue = Queue()
    
    for port in ports:
        queue.put(port)
    
    vuln_alert = scan_type in ["t3", "t4", "t5"]
    
    thread_list = []
    for _ in range(threads):
        thread = threading.Thread(target=worker, args=(target, queue, scan_type, vuln_alert))
        thread.daemon = True
        thread_list.append(thread)
        thread.start()
    
    queue.join()

    print("\n[+] Scan completed")
    suggest_next_steps(target)

if __name__ == "__main__":
    import sys

    # If no args given, ask interactively
    if len(sys.argv) == 1:
        target = input("Enter target IP or domain: ").strip()
        ports_input = input("Enter ports or port range (default 1-1024): ").strip()
        if not ports_input:
            ports_input = "1-1024"
        scan_type = input("Choose scan type (t1-t5) (default t1): ").strip().lower()
        if scan_type not in ["t1", "t2", "t3", "t4", "t5"]:
            scan_type = "t1"
        threads_input = input("Enter number of threads (default 100): ").strip()
        threads = int(threads_input) if threads_input.isdigit() else 100

        # parse ports
        if "-" in ports_input:
            start, end = map(int, ports_input.split("-"))
            ports = range(start, end + 1)
        else:
            ports = [int(p) for p in ports_input.split(",") if p.isdigit()]

        main(target, ports, threads, scan_type)

    else:
        # If args provided, use argparse as before
        import argparse

        parser = argparse.ArgumentParser(description="Python Auto Port Scanner with dynamic CVE lookup and suggestions")
        parser.add_argument("target", help="Target IP address or hostname")
        parser.add_argument("-p", "--ports", help="Port range (e.g., 1-1000 or 22,80,443)", default="1-1024")
        parser.add_argument("-t", "--threads", help="Number of threads", type=int, default=100)
        parser.add_argument(
            "-s",
            "--scan-type",
            help="Scan type: t1=basic, t2=stealth, t3=banner+vuln, t4=stealth+vuln, t5=aggressive+vuln",
            choices=["t1", "t2", "t3", "t4", "t5"],
            default="t1"
        )

        args = parser.parse_args()

        if "-" in args.ports:
            start, end = map(int, args.ports.split("-"))
            ports = range(start, end + 1)
        else:
            ports = [int(p) for p in args.ports.split(",") if p.isdigit()]

        main(args.target, ports, args.threads, args.scan_type)
