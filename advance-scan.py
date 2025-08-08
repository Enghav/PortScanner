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
import json
from bs4 import BeautifulSoup
import random
from datetime import datetime
import ipaddress
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
import platform
import logging
from typing import List, Dict, Any, Optional, Tuple
import csv

# === CONFIGURATION ===
VULN_API_SOURCES = {
    'vulners': 'https://vulners.com/api/v3/search/lucene/',
    'cve_search': 'https://cve.circl.lu/api/search/',
    'nvd': 'https://services.nvd.nist.gov/rest/json/cves/1.0'
}

EXPLOIT_SOURCES = {
    'exploit_db': 'https://www.exploit-db.com/search',
    'github': 'https://api.github.com/search/repositories',
    'packetstorm': 'https://packetstormsecurity.com/search'
}

TOOL_SUGGESTIONS = {
    'web': ['nikto', 'gobuster', 'nuclei', 'wpscan', 'sqlmap', 'dirb', 'ffuf'],
    'ssh': ['hydra', 'ssh-audit', 'crowbar', 'patator'],
    'ftp': ['hydra', 'metasploit', 'ftp-brute'],
    'database': ['sqlmap', 'metasploit', 'mysql', 'psql'],
    'smb': ['enum4linux', 'smbclient', 'crackmapexec', 'rpcclient'],
    'dns': ['dig', 'nslookup', 'dnsrecon', 'fierce'],
    'ldap': ['ldapsearch', 'ldapenum'],
    'snmp': ['snmpwalk', 'snmp-check', 'onesixtyone']
}

# Common ports for different scan types
COMMON_PORTS = {
    'top_100': [7,9,13,21,22,23,25,26,37,53,79,80,81,88,106,110,111,113,119,135,139,143,144,179,199,389,427,443,444,445,465,513,514,515,543,544,548,554,587,631,646,873,990,993,995,1025,1026,1027,1028,1029,1110,1433,1720,1723,1755,1900,2000,2001,2049,2121,2717,3000,3128,3306,3389,3986,4899,5000,5009,5051,5060,5101,5190,5357,5432,5631,5666,5800,5900,6000,6001,6646,7070,8000,8008,8009,8080,8081,8443,8888,9100,9999,10000,32768,49152,49153,49154,49155,49156,49157],
    'top_1000': list(range(1, 1001)),
    'all': list(range(1, 65536))
}

NMAP_SCRIPTS = {
    'http': ['http-enum', 'http-headers', 'http-methods', 'http-title', 'http-robots.txt'],
    'https': ['ssl-cert', 'ssl-enum-ciphers', 'ssl-heartbleed'],
    'ssh': ['ssh-hostkey', 'ssh-auth-methods', 'ssh2-enum-algos'],
    'ftp': ['ftp-anon', 'ftp-bounce', 'ftp-proftpd-backdoor'],
    'smtp': ['smtp-commands', 'smtp-enum-users', 'smtp-open-relay'],
    'dns': ['dns-zone-transfer', 'dns-recursion'],
    'smb': ['smb-enum-shares', 'smb-os-discovery', 'smb-security-mode', 'smb-vuln-*'],
    'mysql': ['mysql-info', 'mysql-empty-password', 'mysql-users'],
    'mssql': ['ms-sql-info', 'ms-sql-empty-password'],
    'oracle': ['oracle-sid-brute', 'oracle-enum-users'],
    'ldap': ['ldap-rootdse', 'ldap-search'],
    'snmp': ['snmp-sysdescr', 'snmp-processes', 'snmp-netstat']
}

# === GLOBALS ===
scan_results = []
vuln_cache = {}
service_signatures = {}
current_scan_id = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(f'{current_scan_id}.log'),
        logging.StreamHandler()
    ]
)

# === ENHANCED UTILITIES ===

def expand_ip_range(ip_range_str: str) -> List[str]:
    """Enhanced IP range expansion with better CIDR support"""
    ip_list = []
    try:
        if "-" in ip_range_str:
            start_ip, end_ip = ip_range_str.split("-")
            start = int(ipaddress.IPv4Address(start_ip.strip()))
            end = int(ipaddress.IPv4Address(end_ip.strip()))
            for ip_int in range(start, end+1):
                ip_list.append(str(ipaddress.IPv4Address(ip_int)))
        elif "/" in ip_range_str:
            net = ipaddress.ip_network(ip_range_str.strip(), strict=False)
            for ip in net.hosts():
                ip_list.append(str(ip))
        else:
            # Single IP
            ipaddress.IPv4Address(ip_range_str.strip())  # Validate
            ip_list.append(ip_range_str.strip())
    except ipaddress.AddressValueError as e:
        logging.error(f"Invalid IP address format: {ip_range_str}")
        sys.exit(1)
    return ip_list

def load_service_signatures():
    """Load Nmap service fingerprints if available"""
    global service_signatures
    try:
        with open('nmap-service-probes.txt', 'r') as f:
            current_probe = None
            for line in f:
                if line.startswith('Probe '):
                    current_probe = line.split()[1]
                    service_signatures[current_probe] = []
                elif line.startswith('match ') and current_probe:
                    service_signatures[current_probe].append(line[6:].strip())
        logging.info("Loaded Nmap service signatures")
    except FileNotFoundError:
        logging.warning("nmap-service-probes.txt not found, using basic detection")

def get_banner(sock: socket.socket, port: int, timeout: int = 3) -> Optional[str]:
    """Enhanced banner grabbing with better protocol support"""
    try:
        sock.settimeout(timeout)
        
        if port in [80, 8080, 8000, 8443]:
            sock.send(b"GET / HTTP/1.1\r\nHost: target\r\nUser-Agent: Mozilla/5.0\r\n\r\n")
            return sock.recv(4096).decode('utf-8', 'ignore')
        elif port == 443:
            # For HTTPS, we'd need SSL context, but basic socket won't work
            return None
        elif port == 22:
            # SSH banner is sent immediately
            return sock.recv(1024).decode('utf-8', 'ignore')
        elif port == 21:
            # FTP sends banner immediately, then we can try commands
            banner = sock.recv(1024).decode('utf-8', 'ignore')
            try:
                sock.send(b"USER anonymous\r\n")
                banner += sock.recv(1024).decode('utf-8', 'ignore')
            except:
                pass
            return banner
        elif port == 25:
            # SMTP
            banner = sock.recv(1024).decode('utf-8', 'ignore')
            try:
                sock.send(b"EHLO test\r\n")
                banner += sock.recv(1024).decode('utf-8', 'ignore')
            except:
                pass
            return banner
        elif port == 110:
            # POP3
            return sock.recv(1024).decode('utf-8', 'ignore')
        elif port == 143:
            # IMAP
            return sock.recv(1024).decode('utf-8', 'ignore')
        elif port in [139, 445]:
            # SMB - needs special handling, return None for now
            return None
        elif port == 53:
            # DNS - UDP typically
            return None
        else:
            # Generic probe
            sock.send(b"\r\n")
            return sock.recv(1024).decode('utf-8', 'ignore')
    except Exception as e:
        logging.debug(f"Banner grab failed for port {port}: {e}")
        return None

def detect_service(banner: Optional[str], port: int) -> Tuple[str, Optional[str]]:
    """Enhanced service detection with better pattern matching"""
    if not banner:
        # Fallback to common port mapping
        fallback = {
            21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
            80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn",
            143: "imap", 389: "ldap", 443: "https", 445: "microsoft-ds", 993: "imaps",
            995: "pop3s", 1433: "mssql", 3306: "mysql", 3389: "rdp", 5432: "postgresql",
            5900: "vnc", 6379: "redis", 27017: "mongodb"
        }
        service = fallback.get(port, "unknown")
        return service, None
    
    service = None
    version = None

    # Enhanced patterns with version extraction
    patterns = {
        "ssh": (r"SSH[-_]?([\d\.]+)", r"OpenSSH[_\s]+([\d\.]+)"),
        "ftp": (r"FTP.*?([\d\.]+)", r"vsftpd ([\d\.]+)", r"ProFTPD ([\d\.]+)"),
        "http": (r"Server:\s*Apache/([\d\.]+)", r"Server:\s*nginx/([\d\.]+)", r"Server:\s*IIS/([\d\.]+)"),
        "smtp": (r"SMTP.*?([\d\.]+)", r"Postfix", r"Exchange"),
        "mysql": (r"mysql.*?([\d\.]+)", r"MariaDB.*?([\d\.]+)"),
        "postgresql": (r"PostgreSQL.*?([\d\.]+)",),
        "rdp": (r"RDP", r"Terminal\s+Services"),
        "microsoft-ds": (r"Microsoft.*?Windows", r"Samba.*?([\d\.]+)"),
        "telnet": (r"Telnet",),
        "pop3": (r"POP3.*?([\d\.]+)",),
        "imap": (r"IMAP.*?([\d\.]+)", r"Dovecot.*?([\d\.]+)"),
        "ldap": (r"LDAP",),
        "dns": (r"BIND.*?([\d\.]+)",)
    }

    banner_lower = banner.lower()
    
    for svc, pattern_list in patterns.items():
        for pattern in pattern_list:
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                service = svc
                if match.groups():
                    version = match.group(1)
                break
        if service:
            break
    
    if not service:
        # Fallback based on port
        fallback = {
            21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
            80: "http", 110: "pop3", 143: "imap", 443: "https", 445: "microsoft-ds",
            3306: "mysql", 3389: "rdp", 5900: "vnc"
        }
        service = fallback.get(port, "unknown")

    return service, version

def perform_os_detection(target: str) -> Optional[str]:
    """Simple OS detection using TTL and other indicators"""
    try:
        # Use ping to get TTL
        system = platform.system().lower()
        if system == "windows":
            result = subprocess.run(['ping', '-n', '1', target], 
                                  capture_output=True, text=True, timeout=5)
        else:
            result = subprocess.run(['ping', '-c', '1', target], 
                                  capture_output=True, text=True, timeout=5)
        
        if result.returncode == 0:
            ttl_match = re.search(r'ttl=(\d+)', result.stdout, re.IGNORECASE)
            if ttl_match:
                ttl = int(ttl_match.group(1))
                if ttl <= 64:
                    return "Linux/Unix"
                elif ttl <= 128:
                    return "Windows"
                else:
                    return "Network Device"
    except Exception as e:
        logging.debug(f"OS detection failed: {e}")
    
    return "Unknown"

def scan_port(target: str, port: int, scan_type: str) -> Optional[Dict[str, Any]]:
    """Enhanced port scanning with different techniques"""
    try:
        start_time = time.time()
        
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            timeout = {"t1": 1, "t2": 2, "t3": 3, "t4": 5, "t5": 10}[scan_type]
            sock.settimeout(timeout)

            # Stealth options for certain scan types
            if scan_type in ["t2", "t4"]:
                time.sleep(random.uniform(0.1, 1.0))
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

            result = sock.connect_ex((target, port))
            if result == 0:
                banner = get_banner(sock, port, timeout)
                service, version = detect_service(banner, port)
                response_time = round((time.time() - start_time) * 1000, 2)

                data = {
                    "port": port,
                    "state": "open",
                    "service": service,
                    "version": version,
                    "banner": (banner[:500] if banner else None),
                    "response_time": response_time,
                    "scan_time": datetime.now().isoformat()
                }

                # Add vulnerability data for deeper scans
                if scan_type in ["t3", "t4", "t5"]:
                    vuln_data = get_vulnerabilities(service, version)
                    data.update(vuln_data)

                return data
            else:
                # Port is closed or filtered
                return {
                    "port": port,
                    "state": "closed",
                    "service": "unknown",
                    "scan_time": datetime.now().isoformat()
                }
                
    except Exception as e:
        logging.debug(f"Error scanning {target}:{port}: {str(e)}")
        return {
            "port": port,
            "state": "filtered",
            "service": "unknown",
            "error": str(e)[:100],
            "scan_time": datetime.now().isoformat()
        }

def get_vulnerabilities(service: str, version: Optional[str] = None) -> Dict[str, List[str]]:
    """Enhanced vulnerability lookup with caching and multiple sources"""
    cache_key = f"{service}_{version}" if version else service
    if cache_key in vuln_cache:
        return vuln_cache[cache_key]

    vulnerabilities = {"cves": [], "exploits": [], "risk_level": "Unknown"}

    try:
        # Mock vulnerability data - in real implementation, you'd query APIs
        known_vulns = {
            "ssh": {
                "2.3": ["CVE-2016-0777", "CVE-2016-0778"],
                "default": ["SSH-WEAK-CIPHER", "SSH-WEAK-HMAC"]
            },
            "ftp": {
                "default": ["FTP-ANON-LOGIN", "FTP-WEAK-AUTH"]
            },
            "http": {
                "default": ["HTTP-METHODS", "HTTP-TRACE-ENABLED"]
            },
            "mysql": {
                "5.5": ["CVE-2012-2122", "CVE-2012-5612"],
                "default": ["MYSQL-EMPTY-PASSWORD"]
            }
        }
        
        if service in known_vulns:
            service_vulns = known_vulns[service]
            if version and version in service_vulns:
                vulnerabilities["cves"] = service_vulns[version]
                vulnerabilities["risk_level"] = "High"
            elif "default" in service_vulns:
                vulnerabilities["cves"] = service_vulns["default"]
                vulnerabilities["risk_level"] = "Medium"

        # Add some exploit suggestions
        if vulnerabilities["cves"]:
            vulnerabilities["exploits"] = [f"searchsploit {service}", f"msfconsole -q -x 'search {service}'"]

    except Exception as e:
        logging.debug(f"Vulnerability lookup failed: {e}")

    vuln_cache[cache_key] = vulnerabilities
    return vulnerabilities

def run_nmap_integration(target: str, ports: List[int], scan_type: str) -> Optional[Dict]:
    """Integration with actual Nmap for advanced features"""
    try:
        port_range = f"{min(ports)}-{max(ports)}" if len(ports) > 10 else ",".join(map(str, ports))
        
        # Build nmap command based on scan type
        nmap_options = {
            "t1": "-T1 -sS",
            "t2": "-T2 -sS --randomize-hosts",
            "t3": "-T3 -sV -sC",
            "t4": "-T4 -sV -sC -A",
            "t5": "-T5 -sV -sC -A --script=vuln"
        }
        
        cmd = f"nmap {nmap_options.get(scan_type, '-sS')} -p {port_range} -oX {current_scan_id}_nmap.xml {target}"
        logging.info(f"Running Nmap: {cmd}")
        
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=300)
        
        if result.returncode == 0:
            # Parse XML output
            return parse_nmap_xml(f"{current_scan_id}_nmap.xml")
        else:
            logging.error(f"Nmap failed: {result.stderr}")
            
    except subprocess.TimeoutExpired:
        logging.error("Nmap scan timed out")
    except Exception as e:
        logging.error(f"Nmap integration failed: {e}")
    
    return None

def parse_nmap_xml(xml_file: str) -> Dict:
    """Parse Nmap XML output"""
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
        
        results = {"hosts": [], "scan_info": {}}
        
        for host in root.findall('host'):
            host_data = {
                "ip": host.find('address').get('addr'),
                "status": host.find('status').get('state'),
                "ports": [],
                "os": None
            }
            
            # Extract port information
            ports_elem = host.find('ports')
            if ports_elem is not None:
                for port in ports_elem.findall('port'):
                    port_data = {
                        "port": int(port.get('portid')),
                        "protocol": port.get('protocol'),
                        "state": port.find('state').get('state'),
                        "service": None,
                        "version": None,
                        "scripts": []
                    }
                    
                    # Service detection
                    service_elem = port.find('service')
                    if service_elem is not None:
                        port_data["service"] = service_elem.get('name')
                        port_data["version"] = service_elem.get('version')
                        port_data["product"] = service_elem.get('product')
                    
                    # Script results
                    for script in port.findall('script'):
                        port_data["scripts"].append({
                            "id": script.get('id'),
                            "output": script.get('output')
                        })
                    
                    host_data["ports"].append(port_data)
            
            # OS detection
            os_elem = host.find('os')
            if os_elem is not None:
                osmatch = os_elem.find('osmatch')
                if osmatch is not None:
                    host_data["os"] = osmatch.get('name')
            
            results["hosts"].append(host_data)
        
        return results
        
    except Exception as e:
        logging.error(f"Failed to parse Nmap XML: {e}")
        return {}

def generate_report(target: str, results: List[Dict], format: str = 'cli', output_file: str = None):
    """Enhanced reporting with multiple formats"""
    timestamp = datetime.now().isoformat()
    
    if format == 'cli':
        print(f"\n{'='*80}")
        print(f"SCAN REPORT FOR {target}")
        print(f"Scan ID: {current_scan_id}")
        print(f"Timestamp: {timestamp}")
        print(f"{'='*80}")
        
        # Summary
        open_ports = [r for r in results if r.get('state') == 'open']
        closed_ports = [r for r in results if r.get('state') == 'closed']
        filtered_ports = [r for r in results if r.get('state') == 'filtered']
        
        print(f"\nSUMMARY:")
        print(f"  Open ports: {len(open_ports)}")
        print(f"  Closed ports: {len(closed_ports)}")
        print(f"  Filtered ports: {len(filtered_ports)}")
        
        if open_ports:
            print(f"\nOPEN PORTS:")
            print("-" * 80)
            
            for result in open_ports:
                port = result['port']
                service = result.get('service', 'unknown')
                version = result.get('version', '')
                
                print(f"\n[PORT {port:>5}] {service.upper()}")
                
                if version:
                    print(f"         Version: {version}")
                
                if result.get('response_time'):
                    print(f"         Response Time: {result['response_time']}ms")
                
                if result.get('banner'):
                    banner_preview = result['banner'].replace('\n', ' ').replace('\r', '')[:100]
                    print(f"         Banner: {banner_preview}...")
                
                # Vulnerabilities
                if result.get('cves'):
                    print(f"         CVEs: {', '.join(result['cves'][:3])}")
                    if len(result['cves']) > 3:
                        print(f"               (+{len(result['cves'])-3} more)")
                
                if result.get('risk_level'):
                    print(f"         Risk Level: {result['risk_level']}")
                
                # Tool suggestions
                tools = TOOL_SUGGESTIONS.get(service, [])
                if tools:
                    print(f"         Suggested Tools: {', '.join(tools[:3])}")
    
    elif format == 'json':
        filename = output_file or f"{current_scan_id}.json"
        report_data = {
            "scan_id": current_scan_id,
            "target": target,
            "timestamp": timestamp,
            "results": results,
            "summary": {
                "total_ports": len(results),
                "open_ports": len([r for r in results if r.get('state') == 'open']),
                "closed_ports": len([r for r in results if r.get('state') == 'closed']),
                "filtered_ports": len([r for r in results if r.get('state') == 'filtered'])
            }
        }
        
        with open(filename, 'w') as f:
            json.dump(report_data, f, indent=2)
        print(f"\n[+] JSON report saved to {filename}")
    
    elif format == 'csv':
        filename = output_file or f"{current_scan_id}.csv"
        with open(filename, 'w', newline='') as csvfile:
            fieldnames = ['port', 'state', 'service', 'version', 'banner', 'response_time', 'cves', 'risk_level']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            
            writer.writeheader()
            for result in results:
                row = {k: result.get(k, '') for k in fieldnames}
                if isinstance(row.get('cves'), list):
                    row['cves'] = ','.join(row['cves'])
                writer.writerow(row)
        
        print(f"\n[+] CSV report saved to {filename}")
    
    elif format == 'xml':
        filename = output_file or f"{current_scan_id}.xml"
        # Create simple XML report (you could make this more sophisticated)
        xml_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<scan_report>
    <scan_id>{current_scan_id}</scan_id>
    <target>{target}</target>
    <timestamp>{timestamp}</timestamp>
    <results>
"""
        for result in results:
            xml_content += f"""        <port>
            <number>{result['port']}</number>
            <state>{result.get('state', 'unknown')}</state>
            <service>{result.get('service', 'unknown')}</service>
            <version>{result.get('version', '')}</version>
        </port>
"""
        xml_content += """    </results>
</scan_report>"""
        
        with open(filename, 'w') as f:
            f.write(xml_content)
        print(f"\n[+] XML report saved to {filename}")

def run_recommended_nmap_scripts(target: str, scan_results: List[Dict]):
    """Enhanced Nmap script recommendations"""
    recommendations = []
    
    for result in scan_results:
        if result.get('state') != 'open':
            continue
            
        port = result["port"]
        service = result["service"].lower()
        
        # Get scripts for this service
        scripts = NMAP_SCRIPTS.get(service, [])
        for script in scripts:
            recommendations.append((port, script))
        
        # Special cases
        if service == 'http' and port == 443:
            recommendations.extend([(port, script) for script in NMAP_SCRIPTS['https']])
        elif service in ['smb', 'microsoft-ds'] or port in [139, 445]:
            recommendations.extend([(port, script) for script in NMAP_SCRIPTS['smb']])

    if not recommendations:
        print("\n[!] No recommended Nmap scripts for detected services.")
        return

    print(f"\n[+] RECOMMENDED NMAP SCRIPTS:")
    print("-" * 50)
    
    # Group by service
    script_groups = {}
    for port, script in recommendations:
        service = next((r['service'] for r in scan_results if r['port'] == port), 'unknown')
        if service not in script_groups:
            script_groups[service] = []
        script_groups[service].append((port, script))
    
    for service, scripts in script_groups.items():
        print(f"\n{service.upper()} ({len(scripts)} scripts):")
        for port, script in scripts[:5]:  # Limit display
            print(f"  nmap -p {port} --script={script} {target}")

    choice = input("\nRun scripts? (y/n/custom/select): ").strip().lower()
    
    if choice == "y":
        for port, script in recommendations:
            cmd = f"nmap -p {port} --script={script} {target}"
            print(f"\n[+] Running: {cmd}")
            try:
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
                if result.stdout:
                    print(result.stdout)
            except subprocess.TimeoutExpired:
                print(f"[!] Script {script} timed out")
                
    elif choice == "select":
        print("\nAvailable scripts:")
        for i, (port, script) in enumerate(recommendations, 1):
            print(f"{i:2d}. Port {port} - {script}")
        
        selection = input("Enter script numbers (comma-separated): ").strip()
        try:
            indices = [int(x.strip()) - 1 for x in selection.split(",")]
            for i in indices:
                if 0 <= i < len(recommendations):
                    port, script = recommendations[i]
                    cmd = f"nmap -p {port} --script={script} {target}"
                    print(f"\n[+] Running: {cmd}")
                    os.system(cmd)
        except ValueError:
            print("[!] Invalid selection")
            
    elif choice == "custom":
        cmd = input("Enter custom Nmap command: ").strip()
        if cmd:
            print(f"\n[+] Running: {cmd}")
            os.system(cmd)

def interactive_mode(target: str):
    """Enhanced interactive mode with more options"""
    global scan_results
    
    while True:
        print(f"\n{'='*60}")
        print("INTERACTIVE MODE")
        print(f"Target: {target} | Results: {len(scan_results)} ports")
        print("="*60)
        
        options = [
            "1. Rescan specific port(s)",
            "2. Deep vulnerability scan",
            "3. Run Nmap scripts",
            "4. Launch recommended tool",
            "5. Export results (JSON/CSV/XML)",
            "6. Show detailed port info",
            "7. Scan new port range",
            "8. OS detection",
            "9. Generate custom report",
            "10. Exit"
        ]
        
        for option in options:
            print(option)
        
        choice = input("\nSelect option: ").strip()
        
        if choice == '1':
            ports_input = input("Enter port(s) to rescan (e.g., 80 or 80,443,22): ").strip()
            try:
                if ',' in ports_input:
                    ports = [int(p.strip()) for p in ports_input.split(',')]
                else:
                    ports = [int(ports_input)]
                
                print(f"[+] Rescanning ports: {ports}")
                for port in ports:
                    result = scan_port(target, port, "t5")  # Deep scan
                    if result:
                        # Update existing result or add new one
                        for i, r in enumerate(scan_results):
                            if r["port"] == port:
                                scan_results[i] = result
                                break
                        else:
                            scan_results.append(result)
                        
                        if result.get('state') == 'open':
                            print(f"[+] Port {port}: {result.get('service', 'unknown')} - {result.get('state')}")
                        else:
                            print(f"[-] Port {port}: {result.get('state')}")
                    else:
                        print(f"[!] Failed to scan port {port}")
                        
            except ValueError:
                print("[!] Invalid port format")
                
        elif choice == '2':
            print("[+] Running deep vulnerability scan...")
            vuln_count = 0
            for i, result in enumerate(scan_results):
                if result.get('state') == 'open':
                    service = result.get('service')
                    version = result.get('version')
                    vuln_data = get_vulnerabilities(service, version)
                    scan_results[i].update(vuln_data)
                    if vuln_data.get('cves'):
                        vuln_count += len(vuln_data['cves'])
            
            print(f"[+] Found {vuln_count} potential vulnerabilities")
            generate_report(target, [r for r in scan_results if r.get('state') == 'open'])
            
        elif choice == '3':
            open_results = [r for r in scan_results if r.get('state') == 'open']
            if open_results:
                run_recommended_nmap_scripts(target, open_results)
            else:
                print("[!] No open ports found for script scanning")
                
        elif choice == '4':
            # Launch recommended tools
            tools = set()
            for result in scan_results:
                if result.get('state') == 'open':
                    service_tools = TOOL_SUGGESTIONS.get(result.get('service'), [])
                    tools.update(service_tools)
            
            if not tools:
                print("[!] No tools available for detected services")
                continue
                
            tools_list = sorted(list(tools))
            print(f"\nAvailable tools:")
            for i, tool in enumerate(tools_list, 1):
                print(f"{i:2d}. {tool}")
            
            try:
                selection = input("Select tool number (or 'back'): ").strip()
                if selection.lower() == 'back':
                    continue
                    
                tool_idx = int(selection) - 1
                if 0 <= tool_idx < len(tools_list):
                    tool = tools_list[tool_idx]
                    
                    # Get target ports for this tool
                    relevant_ports = []
                    for result in scan_results:
                        if result.get('state') == 'open':
                            service = result.get('service')
                            if tool in TOOL_SUGGESTIONS.get(service, []):
                                relevant_ports.append(result['port'])
                    
                    if relevant_ports:
                        port_list = ','.join(map(str, relevant_ports))
                        cmd = f"{tool} -p {port_list} {target}"
                    else:
                        cmd = f"{tool} {target}"
                    
                    print(f"[+] Running: {cmd}")
                    custom_cmd = input(f"Modify command? (Enter for default, or type new command): ").strip()
                    if custom_cmd:
                        cmd = custom_cmd
                    
                    os.system(cmd)
                else:
                    print("[!] Invalid selection")
                    
            except ValueError:
                print("[!] Invalid input")
                
        elif choice == '5':
            # Export results
            formats = ['json', 'csv', 'xml', 'cli']
            print(f"\nAvailable formats:")
            for i, fmt in enumerate(formats, 1):
                print(f"{i}. {fmt.upper()}")
            
            try:
                fmt_choice = input("Select format: ").strip()
                if fmt_choice.isdigit():
                    fmt_idx = int(fmt_choice) - 1
                    if 0 <= fmt_idx < len(formats):
                        selected_format = formats[fmt_idx]
                        filename = input(f"Enter filename (or press Enter for default): ").strip()
                        generate_report(target, scan_results, selected_format, filename or None)
                    else:
                        print("[!] Invalid format selection")
                else:
                    print("[!] Invalid input")
            except ValueError:
                print("[!] Invalid input")
                
        elif choice == '6':
            # Show detailed port info
            open_ports = [r for r in scan_results if r.get('state') == 'open']
            if not open_ports:
                print("[!] No open ports to display")
                continue
                
            print(f"\nOpen ports:")
            for i, result in enumerate(open_ports, 1):
                print(f"{i:2d}. Port {result['port']} - {result.get('service', 'unknown')}")
            
            try:
                selection = input("Select port for details: ").strip()
                if selection.isdigit():
                    port_idx = int(selection) - 1
                    if 0 <= port_idx < len(open_ports):
                        result = open_ports[port_idx]
                        print(f"\n{'='*50}")
                        print(f"PORT {result['port']} DETAILS")
                        print("="*50)
                        
                        for key, value in result.items():
                            if key == 'banner' and value:
                                print(f"{key.title()}: {value[:200]}...")
                            elif key == 'cves' and value:
                                print(f"{key.upper()}: {', '.join(value)}")
                            elif value and key != 'scan_time':
                                print(f"{key.title()}: {value}")
                    else:
                        print("[!] Invalid port selection")
                        
            except ValueError:
                print("[!] Invalid input")
                
        elif choice == '7':
            # Scan new port range
            new_ports = input("Enter new port range (e.g., 8000-8100 or 8080,9090): ").strip()
            try:
                if '-' in new_ports:
                    start, end = map(int, new_ports.split('-'))
                    ports_to_scan = list(range(start, end + 1))
                elif ',' in new_ports:
                    ports_to_scan = [int(p.strip()) for p in new_ports.split(',')]
                else:
                    ports_to_scan = [int(new_ports)]
                
                print(f"[+] Scanning {len(ports_to_scan)} new ports...")
                
                new_results = []
                for port in ports_to_scan:
                    result = scan_port(target, port, "t3")
                    if result:
                        new_results.append(result)
                        if result.get('state') == 'open':
                            print(f"[+] Found: {port}/{result.get('service', 'unknown')}")
                
                scan_results.extend(new_results)
                print(f"[+] Added {len(new_results)} new results")
                
            except ValueError:
                print("[!] Invalid port range format")
                
        elif choice == '8':
            # OS detection
            print("[+] Performing OS detection...")
            os_info = perform_os_detection(target)
            if os_info:
                print(f"[+] Detected OS: {os_info}")
            else:
                print("[!] Could not determine OS")
                
            # Try with nmap if available
            try:
                cmd = f"nmap -O --osscan-guess {target}"
                print(f"[+] Running: {cmd}")
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
                if result.stdout:
                    print(result.stdout)
            except Exception as e:
                print(f"[!] Nmap OS detection failed: {e}")
                
        elif choice == '9':
            # Custom report generation
            print("\nCustom Report Options:")
            print("1. Only open ports")
            print("2. Only vulnerable services")
            print("3. Only high-risk findings")
            print("4. Full detailed report")
            
            report_choice = input("Select report type: ").strip()
            
            filtered_results = scan_results
            if report_choice == '1':
                filtered_results = [r for r in scan_results if r.get('state') == 'open']
            elif report_choice == '2':
                filtered_results = [r for r in scan_results if r.get('cves')]
            elif report_choice == '3':
                filtered_results = [r for r in scan_results if r.get('risk_level') == 'High']
            elif report_choice == '4':
                filtered_results = scan_results
            else:
                print("[!] Invalid choice, using all results")
            
            generate_report(target, filtered_results, 'cli')
            
        elif choice == '10':
            print("[+] Exiting interactive mode...")
            break
            
        else:
            print("[!] Invalid choice")

# === MAIN FUNCTION ===
def main():
    """Enhanced main function with better argument handling"""
    global scan_results
    
    print(f"""
    ╔══════════════════════════════════════════════════════════════╗
    ║                       Advanced Scan                          ║
    ╚══════════════════════════════════════════════════════════════╝
    """)
    
    load_service_signatures()
    
    parser = argparse.ArgumentParser(
        description="Enhanced Network Scanner with Advanced Features",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    parser.add_argument("-t", "--target", 
                       help="Target IP, hostname, or IP range (e.g., 192.168.1.1-10 or 192.168.1.0/24)")
    parser.add_argument("-p", "--ports", 
                       help="Port specification:\n"
                            "  - Range: 1-1000\n"
                            "  - List: 22,80,443\n"
                            "  - Preset: top100, top1000, all")
    parser.add_argument("-th", "--threads", type=int, default=50,
                       help="Number of concurrent threads (default: 50)")
    parser.add_argument("-s", "--scan-type", choices=["t1","t2","t3","t4","t5"],
                       help="Scan types:\n"
                            "  t1: Fast connect scan (1s timeout)\n"
                            "  t2: Stealth scan with delays (2s timeout)\n"
                            "  t3: Standard scan with service detection (3s)\n"
                            "  t4: Comprehensive scan with OS detection (5s)\n"
                            "  t5: Deep scan with vulnerability assessment (10s)")
    parser.add_argument("-o", "--output", choices=["cli","json","csv","xml","all"], 
                       default="cli", help="Output format")
    parser.add_argument("-f", "--file", help="Output filename (optional)")
    parser.add_argument("--nmap", action="store_true", 
                       help="Use integrated Nmap for advanced features")
    parser.add_argument("--no-ping", action="store_true",
                       help="Skip host discovery (assume host is up)")
    parser.add_argument("-v", "--verbose", action="store_true",
                       help="Verbose output")
    
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Get target
    if not args.target:
        target_input = input("Enter target (IP, range, or CIDR): ").strip()
        if not target_input:
            print("[!] Target is required")
            sys.exit(1)
        target = target_input
    else:
        target = args.target

    # Expand target range if needed
    try:
        targets = expand_ip_range(target)
        if len(targets) > 1:
            print(f"[+] Scanning {len(targets)} targets")
    except Exception as e:
        print(f"[!] Invalid target format: {e}")
        sys.exit(1)

    # Get scan type
    if not args.scan_type:
        print("\nScan Types:")
        print("  t1: Fast (1s timeout)")
        print("  t2: Stealth (2s timeout, delays)")
        print("  t3: Standard (3s timeout, service detection)")
        print("  t4: Comprehensive (5s timeout, OS detection)")
        print("  t5: Deep (10s timeout, vulnerability assessment)")
        
        scan_type = input("Select scan type [t3]: ").strip().lower()
        if scan_type not in ["t1","t2","t3","t4","t5"]:
            scan_type = "t3"
    else:
        scan_type = args.scan_type

    # Get ports
    if not args.ports:
        print("\nPort Options:")
        print("  1. Top 100 ports")
        print("  2. Top 1000 ports")
        print("  3. All ports (1-65535)")
        print("  4. Custom range")
        
        port_choice = input("Select option [1]: ").strip()
        
        if port_choice == '2':
            ports = COMMON_PORTS['top_1000']
        elif port_choice == '3':
            confirm = input("Scan all 65535 ports? This will take a long time (y/n): ")
            if confirm.lower() == 'y':
                ports = COMMON_PORTS['all']
            else:
                ports = COMMON_PORTS['top_100']
        elif port_choice == '4':
            custom_ports = input("Enter ports (e.g., 1-1000 or 22,80,443): ").strip()
            if '-' in custom_ports:
                start, end = map(int, custom_ports.split('-'))
                ports = list(range(start, end + 1))
            else:
                ports = [int(p.strip()) for p in custom_ports.split(',')]
        else:
            ports = COMMON_PORTS['top_100']
    else:
        if args.ports.lower() in COMMON_PORTS:
            ports = COMMON_PORTS[args.ports.lower()]
        elif '-' in args.ports:
            start, end = map(int, args.ports.split('-'))
            ports = list(range(start, end + 1))
        else:
            ports = [int(p.strip()) for p in args.ports.split(',')]

    print(f"\n[+] Starting {scan_type.upper()} scan")
    print(f"[+] Targets: {len(targets)}")
    print(f"[+] Ports: {len(ports)}")
    print(f"[+] Threads: {args.threads}")
    print(f"[+] Scan ID: {current_scan_id}")

    # Use Nmap integration if requested and available
    if args.nmap:
        for target_ip in targets:
            nmap_results = run_nmap_integration(target_ip, ports, scan_type)
            if nmap_results:
                print(f"[+] Nmap integration completed for {target_ip}")
                # Convert Nmap results to our format
                for host in nmap_results.get('hosts', []):
                    for port_info in host.get('ports', []):
                        if port_info.get('state') == 'open':
                            scan_results.append({
                                'port': port_info['port'],
                                'state': port_info['state'],
                                'service': port_info.get('service', 'unknown'),
                                'version': port_info.get('version'),
                                'product': port_info.get('product'),
                                'scripts': port_info.get('scripts', []),
                                'scan_time': datetime.now().isoformat()
                            })

    # Custom scanner
    start_time = time.time()
    
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = []
        
        for target_ip in targets:
            for port in ports:
                future = executor.submit(scan_port, target_ip, port, scan_type)
                futures.append(future)
        
        try:
            completed = 0
            total = len(futures)
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    scan_results.append(result)
                    if result.get('state') == 'open':
                        service = result.get('service', 'unknown')
                        port = result.get('port')
                        print(f"[+] {port:>5}/tcp {service:<15} open")
                
                completed += 1
                if completed % 100 == 0 or completed == total:
                    progress = (completed / total) * 100
                    print(f"[+] Progress: {progress:.1f}% ({completed}/{total})")
                    
        except KeyboardInterrupt:
            print("\n[!] Scan interrupted by user")
            print(f"[+] Partial results: {len(scan_results)} ports scanned")

    scan_time = time.time() - start_time
    print(f"\n[+] Scan completed in {scan_time:.2f} seconds")

    # Filter and sort results
    scan_results = [r for r in scan_results if r is not None]
    scan_results.sort(key=lambda x: x.get('port', 0))

    # Generate output
    if args.output in ["cli", "all"]:
        generate_report(targets[0] if len(targets) == 1 else f"{len(targets)}_hosts", 
                       scan_results, 'cli', args.file)
        
        # Suggest Nmap scripts
        open_results = [r for r in scan_results if r.get('state') == 'open']
        if open_results:
            run_recommended_nmap_scripts(targets[0] if len(targets) == 1 else "targets", 
                                       open_results)

    if args.output in ["json", "all"]:
        generate_report(targets[0] if len(targets) == 1 else f"{len(targets)}_hosts", 
                       scan_results, 'json', args.file)

    if args.output in ["csv", "all"]:
        generate_report(targets[0] if len(targets) == 1 else f"{len(targets)}_hosts", 
                       scan_results, 'csv', args.file)

    if args.output in ["xml", "all"]:
        generate_report(targets[0] if len(targets) == 1 else f"{len(targets)}_hosts", 
                       scan_results, 'xml', args.file)

    # Enter interactive mode
    if scan_results:
        enter_interactive = input("\nEnter interactive mode? (y/n): ").strip().lower()
        if enter_interactive == 'y':
            interactive_mode(targets[0] if len(targets) == 1 else "multiple_targets")

    print(f"\n[+] Scan complete. Results saved with ID: {current_scan_id}")

if __name__ == "__main__":
    main()