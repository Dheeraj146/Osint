from flask import Flask, render_template, request, Response
import dns.resolver
import socket
import requests
from bs4 import BeautifulSoup
import re
from wafw00f.main import WAFW00F
import io
from urllib.parse import quote

# Import all API keys from the config file
from config import (
    IPINFO_TOKEN, ABUSEIPDB_API_KEY, OTX_API_KEY,
    VIRUSTOTAL_API_KEY, SHODAN_API_KEY
)

# ============================================
# 1. Flask App Initialization
# ============================================
app = Flask(__name__)


# ============================================
# 2. Pure-Python Port Scanner (Render Compatible)
# ============================================

import threading
import queue

def scan_port(target, port, results):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.4)
        sock.connect((target, port))
        results.put(port)
    except:
        pass
    finally:
        sock.close()

def run_fast_scan(target, ports=None):
    if ports is None:
        ports = [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
            143, 443, 445, 587, 993, 995, 1723, 3306,
            3389, 5900, 8080, 8443
        ]

    results = queue.Queue()
    threads = []

    for port in ports:
        t = threading.Thread(target=scan_port, args=(target, port, results))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    open_ports = sorted(list(results.queue))
    return open_ports


# ============================================
# 3. Helper Functions (Your Code)
# ============================================

def find_emails(domain):
    emails = set()
    try:
        url = f"http://{domain}"
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')
        email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        found_emails = re.findall(email_pattern, soup.get_text())
        for email in found_emails:
            if not email.endswith(('.png', '.jpg', '.gif', '.css', '.js')):
                emails.add(email)
    except Exception:
        return ["Could not scrape emails."]
    return list(emails) if emails else ["No public emails found on homepage."]


def find_subdomains(domain):
    subdomains = []
    wordlist = ['www', 'mail', 'ftp', 'admin', 'blog', 'dev', 'api', 'shop', 'test']
    for sub in wordlist:
        try:
            full_domain = f"{sub}.{domain}"
            dns.resolver.resolve(full_domain, 'A')
            subdomains.append(full_domain)
        except:
            continue
    return subdomains if subdomains else ["No common subdomains found."]


def find_directories(domain):
    directories = []
    wordlist = ['admin', 'login', 'dashboard', 'wp-admin', 'test']
    for directory in wordlist:
        try:
            url = f"http://{domain}/{directory}"
            response = requests.get(url, timeout=3)
            if response.status_code in [200, 301, 302]:
                directories.append(f"/{directory} (Status: {response.status_code})")
        except:
            continue
    return directories if directories else ["No common directories found."]


def find_waf(domain):
    try:
        waf_check = WAFW00F(f"http://{domain}")
        waf_results = waf_check.identwaf()
        return waf_results if waf_results else ["No WAF detected."]
    except:
        return ["Could not perform WAF check."]


# ============================================
# 4. API Helper Functions
# ============================================

def query_abuseipdb(ip):
    try:
        headers = {'Key': ABUSEIPDB_API_KEY, 'Accept': 'application/json'}
        params = {'ipAddress': ip, 'maxAgeInDays': '90'}
        response = requests.get('https://api.abuseipdb.com/api/v2/check', headers=headers, params=params)
        return response.json().get('data', {})
    except Exception as e:
        return {'error': str(e)}

def query_virustotal(value, type='ip'):
    try:
        endpoint = 'ip_addresses' if type == 'ip' else 'domains'
        headers = {'x-apikey': VIRUSTOTAL_API_KEY}
        response = requests.get(f'https://www.virustotal.com/api/v3/{endpoint}/{value}', headers=headers)
        return response.json().get('data', {}).get('attributes', {})
    except Exception as e:
        return {'error': str(e)}

def query_otx(value, type='ip'):
    try:
        endpoint = 'ip' if type == 'ip' else 'domain'
        headers = {'X-OTX-API-KEY': OTX_API_KEY}
        response = requests.get(f'https://otx.alienvault.com/api/v1/indicators/{endpoint}/{value}/general',
                                headers=headers)
        return response.json()
    except Exception as e:
        return {'error': str(e)}

def query_shodan(ip):
    try:
        response = requests.get(f'https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}')
        return response.json()
    except Exception as e:
        return {'error': str(e)}


# ============================================
# 5. IP and Domain Lookup (Nmap Removed)
# ============================================

def perform_ip_lookup(ip_address):
    results = {}

    # IPINFO
    results['ipinfo'] = requests.get(f'https://ipinfo.io/{ip_address}?token={IPINFO_TOKEN}').json()

    if results['ipinfo'].get('bogon'):
        return {'Error': 'Private or reserved IP address.'}

    # Hostname
    try:
        results['hostname'] = socket.gethostbyaddr(ip_address)[0]
    except:
        results['hostname'] = "No hostname found."

    # 🚀 New Port Scan using pure Python
    results['open_ports'] = run_fast_scan(ip_address)

    # Threat Intel
    results['abuseipdb'] = query_abuseipdb(ip_address)
    results['virustotal'] = query_virustotal(ip_address, type='ip')
    results['otx'] = query_otx(ip_address, type='ip')
    results['shodan'] = query_shodan(ip_address)

    return results


def perform_dns_lookup(domain):
    results = {}
    results['dns_records'] = {}

    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT']
    for r_type in record_types:
        try:
            answers = dns.resolver.resolve(domain, r_type)
            results['dns_records'][r_type] = [r.to_text() for r in answers]
        except:
            results['dns_records'][r_type] = []

    primary_ip = results['dns_records'].get('A', [None])[0]
    if primary_ip:
        results['ip_intelligence'] = perform_ip_lookup(primary_ip)

    results['waf'] = find_waf(domain)
    results['emails'] = find_emails(domain)
    results['subdomains'] = find_subdomains(domain)
    results['directories'] = find_directories(domain)
    results['domain_virustotal'] = query_virustotal(domain, type='domain')
    results['domain_otx'] = query_otx(domain, type='domain')

    return results


# ============================================
# 6. Routes
# ============================================

@app.route('/')
def dashboard():
    return render_template('dashboard.html')

@app.route('/dns', methods=['GET', 'POST'])
def dns_lookup():
    results, domain = {}, ""
    if request.method == 'POST':
        domain = request.form.get('domain')
        try:
            results = perform_dns_lookup(domain)
        except Exception as e:
            results = {"Error": str(e)}
    return render_template('dns_lookup.html', results=results, domain=domain)

@app.route('/ip', methods=['GET', 'POST'])
def ip_lookup():
    results, ip_address = {}, ""
    if request.method == 'POST':
        ip_address = request.form.get('ip_address')
        try:
            results = perform_ip_lookup(ip_address)
        except Exception as e:
            results = {"Error": str(e)}
    return render_template('ip_lookup.html', results=results, ip_address=ip_address)

@app.route('/download_report')
def download_report():
    report_type = request.args.get('type')
    query = request.args.get('query')
    results = {}
    try:
        if report_type == 'dns':
            results = perform_dns_lookup(query)
        elif report_type == 'ip':
            results = perform_ip_lookup(query)
    except Exception as e:
        results = {"Error": str(e)}

    report_content = f"--- OSINT Report for: {query} ---\n\n{results}"
    return Response(
        report_content,
        mimetype="text/plain",
        headers={"Content-disposition": f"attachment; filename={query}_report.txt"}
    )


# ============================================
# 7. Run App
# ============================================
if __name__ == '__main__':
    app.run(debug=True)
