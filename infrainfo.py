import requests
import socket
import sys
import os
import csv
import re

def print_usage():
    print("""
Usage:
  python ipinfo_lookup.py <IPINFO_API_KEY> <domain(s)|file> [--csv output.csv]

Examples:
  python ipinfo_lookup.py YOUR_API_KEY tesla.com
  python ipinfo_lookup.py YOUR_API_KEY tesla.com,ford.com
  python ipinfo_lookup.py YOUR_API_KEY domains.txt --csv output.csv

Note:
  - The second argument can be a single domain, comma-separated domains, or a filename.
  - To get a free API key, register at: https://ipinfo.io/signup
""")
    sys.exit(1)

def sanitize_domain(domain):
    """Remove protocols and trailing slashes."""
    domain = re.sub(r'^https?://', '', domain)
    domain = domain.strip().rstrip('/')
    return domain

def parse_domains(source):
    if os.path.isfile(source):
        with open(source, 'r') as f:
            return [sanitize_domain(line.strip()) for line in f if line.strip()]
    else:
        return [sanitize_domain(d) for d in source.split(',') if d.strip()]

def resolve_domain(domain):
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror as e:
        print(f"[!] Could not resolve {domain}: {e}")
        return None

def get_ip_info(api_key, ip):
    url = f"https://ipinfo.io/{ip}/json"
    headers = {"Authorization": f"Bearer {api_key}"}
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            return response.json()
        else:
            print(f"[!] IPInfo error for {ip}: {response.status_code}")
            return {}
    except requests.RequestException as e:
        print(f"[!] Request failed for {ip}: {e}")
        return {}

def write_to_csv(data, output_file):
    keys = ['domain', 'ip', 'city', 'region', 'country', 'loc', 'org']
    with open(output_file, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        for entry in data:
            writer.writerow(entry)
    print(f"\n[+] Results written to: {output_file}")

def main():
    if len(sys.argv) < 3:
        print_usage()

    ipinfo_key = sys.argv[1]
    domain_input = sys.argv[2]
    csv_output = None

    if '--csv' in sys.argv:
        csv_index = sys.argv.index('--csv')
        if csv_index + 1 < len(sys.argv):
            csv_output = sys.argv[csv_index + 1]
        else:
            print("[!] CSV file name not provided after --csv")
            sys.exit(1)

    domains = parse_domains(domain_input)
    results = []

    print(f"\n[+] Processing the following domains: {domains}\n")

    for domain in domains:
        ip = resolve_domain(domain)
        if ip:
            info = get_ip_info(ipinfo_key, ip)
            record = {
                'domain': domain,
                'ip': ip,
                'city': info.get('city', 'N/A'),
                'region': info.get('region', 'N/A'),
                'country': info.get('country', 'N/A'),
                'loc': info.get('loc', 'N/A'),
                'org': info.get('org', 'N/A')
            }
            results.append(record)
            if not csv_output:
                print(f"{domain} : {ip} | City: {record['city']} | Region: {record['region']} | "
                      f"Country: {record['country']} | Location: {record['loc']} | Hosting: {record['org']}")
                print("-----------")

    if csv_output:
        write_to_csv(results, csv_output)

if __name__ == "__main__":
    main()
