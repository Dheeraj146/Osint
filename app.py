from flask import Flask, render_template, request, Response
import dns.resolver
import socket
import nmap
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

# --- 1. App Initialization ---
app = Flask(__name__)


# --- 2. Helper Functions ---

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
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
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
        except requests.exceptions.RequestException:
            continue
    return directories if directories else ["No common directories found."]


def find_waf(domain):
    try:
        waf_check = WAFW00F(f"http://{domain}")
        waf_results = waf_check.identwaf()
        return waf_results if waf_results else ["No WAF detected."]
    except Exception:
        return ["Could not perform WAF check."]


# --- API Helper Functions ---
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


# --- Reporting Function ---
def format_report(title, data):
    report = f"--- OSINT-Nexus Report for: {title} ---\n\n"
    if data.get('Error'):
        return report + f"An error occurred: {data['Error']}"

    # IP Report Formatting
    if 'ipinfo' in data:
        report += "[+] Core Intelligence (IPinfo)\n"
        report += f"  - Hostname: {data.get('hostname', 'N/A')}\n"
        report += f"  - Location: {data['ipinfo'].get('city', 'N/A')}, {data['ipinfo'].get('country', 'N/A')}\n"
        report += f"  - Organization: {data['ipinfo'].get('org', 'N/A')}\n\n"

        report += "[+] Nmap Scan Results\n"
        if data.get('nmap') and not data['nmap'].get('error'):
            report += f"  - OS Guess: {data['nmap']['osmatch'][0]['name'] if data['nmap'].get('osmatch') else 'N/A'}\n"
        #     if data['nmap'].get('tcp'):
        #         for port, info in data['nmap']['tcp'].items():
        #             report += f"    - Port {port}: {info.get('name', '')} ({info.get('product', '')} {info.get('version', '')})\n"
        else:
            report += "  - Nmap scan failed or host was down.\n"
        report += "\n"

        report += "[+] AbuseIPDB Reputation\n"
        if data.get('abuseipdb') and not data['abuseipdb'].get('error'):
            report += f"  - Confidence Score of Abuse: {data['abuseipdb'].get('abuseConfidenceScore', 0)}%\n"
            report += f"  - Total Reports: {data['abuseipdb'].get('totalReports', 0)}\n\n"
        else:
            report += "  - No data found.\n\n"

        report += "[+] VirusTotal Analysis\n"
        if data.get('virustotal') and data['virustotal'].get('last_analysis_stats'):
            stats = data['virustotal']['last_analysis_stats']
            report += f"  - Malicious Detections: {stats.get('malicious', 0)}\n"
            report += f"  - Suspicious Detections: {stats.get('suspicious', 0)}\n\n"
        else:
            report += "  - No data found.\n\n"

        report += "[+] Shodan Device Information\n"
        if data.get('shodan') and not data['shodan'].get('error'):
            report += f"  - ISP: {data['shodan'].get('isp', 'N/A')}\n"
            report += f"  - Open Ports: {', '.join(map(str, data['shodan'].get('ports', [])))}\n"
            report += f"  - Known CVEs: {', '.join(data['shodan'].get('vulns', [])) or 'None'}\n\n"
        else:
            report += "  - No data found.\n\n"

    # DNS Report Formatting
    if 'dns_records' in data:
        report += "[+] DNS Records\n"
        for r_type, records in data['dns_records'].items():
            if records:
                report += f"  - {r_type} Records:\n"
                for record in records:
                    report += f"    - {record}\n"
        report += "\n"

        if data.get('ip_intelligence'):
            report += format_report(f"Primary IP ({data['ip_intelligence']['ipinfo']['ip']})", data['ip_intelligence'])

    return report


# --- MASTER LOOKUP FUNCTIONS ---
def perform_ip_lookup(ip_address):
    """Gathers all intelligence for a single IP and returns a results dict."""
    results = {}
    results['ipinfo'] = requests.get(f'https://ipinfo.io/{ip_address}?token={IPINFO_TOKEN}').json()
    if results['ipinfo'].get('bogon'):
        return {'Error': 'Private or reserved IP address.'}
    try:
        results['hostname'] = socket.gethostbyaddr(ip_address)[0]
    except socket.herror:
        results['hostname'] = "No hostname found."
    nm = nmap.PortScanner()
    nm.scan(ip_address, arguments='-sV --top-ports 20')
    results['nmap'] = nm[ip_address] if ip_address in nm.all_hosts() else {
        'error': "Host seems down or firewall is blocking scan."}
    results['abuseipdb'] = query_abuseipdb(ip_address)
    results['virustotal'] = query_virustotal(ip_address, type='ip')
    results['otx'] = query_otx(ip_address, type='ip')
    results['shodan'] = query_shodan(ip_address)
    return results


def perform_dns_lookup(domain):
    """Gathers all intelligence for a domain and returns a results dict."""
    results = {}
    results['dns_records'] = {}
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT']
    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            results['dns_records'][record_type] = [r.to_text() for r in answers]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            results['dns_records'][record_type] = []

    primary_ip = results.get('dns_records', {}).get('A', [None])[0]
    if primary_ip:
        results['ip_intelligence'] = perform_ip_lookup(primary_ip)

    results['waf'] = find_waf(domain)
    results['emails'] = find_emails(domain)
    results['subdomains'] = find_subdomains(domain)
    results['directories'] = find_directories(domain)
    results['domain_virustotal'] = query_virustotal(domain, type='domain')
    results['domain_otx'] = query_otx(domain, type='domain')
    return results


# --- 4. Routes ---

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

    report_content = format_report(query, results)
    return Response(
        report_content,
        mimetype="text/plain",
        headers={"Content-disposition": f"attachment; filename={query}_report.txt"}
    )


# --- 5. Run the App ---
if __name__ == '__main__':
    app.run(debug=True)

