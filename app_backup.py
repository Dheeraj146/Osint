from flask import Flask, render_template, request, Response
import dns.resolver
import socket
import nmap
import requests
from bs4 import BeautifulSoup
import re
from wafw00f.main import WAFW00F
import io

# --- 1. App Initialization ---
app = Flask(__name__)


# --- 2. Helper Functions ---

# NEW HELPER FUNCTION for finding associated accounts
def find_associated_accounts(email):
    """Performs a web search to find potential associated accounts."""
    accounts = []
    try:
        # We'll use DuckDuckGo as it's often less restrictive for scraping
        search_url = f"https://duckduckgo.com/html/?q=%22{email}%22"
        headers = {'User-Agent': 'Mozilla/5.0'}
        response = requests.get(search_url, headers=headers)
        soup = BeautifulSoup(response.text, 'html.parser')

        # Extract links from search results
        links = soup.find_all('a', class_='result__a')
        for link in links:
            url = link.get('href')
            # Filter common unhelpful links
            if url and not any(domain in url for domain in ['duckduckgo.com', 'google.com']):
                accounts.append(url)
    except Exception as e:
        print(f"Error scraping for accounts: {e}")  # Log error for debugging
        return ["Could not perform account search."]
    return accounts if accounts else ["No public accounts found in web search."]


# (Keep other helper functions: find_emails, find_subdomains, etc.)
# ...

# UPDATED format_report function
def format_report(title, data):
    """Formats the results dictionary into a text string for download."""
    # (Code for IP and DNS reports remains the same)
    # ...
    elif 'breaches' in data or 'accounts' in data:  # Persona Report
    report_string += "[Data Breach Exposure (Have I Been Pwned)]\n"
    if data.get('breaches'):
        for breach in data['breaches']:
            report_string += f"  - {breach['Name']} ({breach['BreachDate']})\n"
    else:
        report_string += "  No pwnage found in any public data breaches.\n"

    report_string += "\n[Potential Associated Accounts (from Web Search)]\n"
    if data.get('accounts'):
        for account in data['accounts']:
            report_string += f"  - {account}\n"
    else:
        report_string += "  No public accounts found.\n"


# (Rest of the function is the same)
# ...
return report_string


# --- 3. All Routes ---

# (Keep routes for dashboard, dns, ip)
# ...

# UPDATED Persona Lookup route
@app.route('/persona', methods=['GET', 'POST'])
def persona_lookup():
    results = {}
    email = ""
    if request.method == 'POST':
        email = request.form.get('email')
        if email:
            try:
                # 1. HIBP API check (existing)
                headers = {'user-agent': 'OSINT-Nexus-App'}
                response = requests.get(f'https://haveibeenpwned.com/api/v3/breachedaccount/{email}', headers=headers)

                if response.status_code == 200:
                    results['breaches'] = response.json()
                elif response.status_code == 404:
                    results['breaches'] = []
                else:
                    results['Error'] = f"HIBP API returned an error: {response.status_code}"

                # 2. NEW: Find associated accounts
                if 'Error' not in results:
                    results['accounts'] = find_associated_accounts(email)

            except Exception as e:
                results = {"Error": str(e)}
    return render_template('persona_lookup.html', results=results, email=email)

# (Keep the download_report route and the final app.run() call)
# ...