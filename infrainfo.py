import requests
import socket
import sys
import os

def print_usage():
    print("Usage:")
    print("  python ipinfo_lookup.py <IPINFO_API_KEY> <domains.txt>")
    print("\nExample:")
    print("  python ipinfo_lookup.py YOUR_API_KEY domains.txt")
    print("\nNOTE:")
    print("- To get a free API key, register at: https://ipinfo.io/signup")
    sys.exit(1)

def read_domains(file_path):
    if not os.path.isfile(file_path):
        print(f"[!] File not found: {file_path}")
        sys.exit(1)
    with open(file_path, 'r') as f:
        return [line.strip() for line in f if line.strip()]

def resolve_domain(domain):
    try:
        ip = socket.gethostbyname(domain)
        return ip
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

def main():
    if len(sys.argv) != 3:
        print_usage()

    api_key = sys.argv[1]
    domain_file = sys.argv[2]
    domains = read_domains(domain_file)

    print(f"\n[+] Processing {len(domains)} domain(s)...\n")

    for domain in domains:
        print(f"[Domain] {domain}")
        ip = resolve_domain(domain)
        if ip:
            ip_info = get_ip_info(api_key, ip)
            output = (
                f"{domain} : {ip} | "
                f"City: {ip_info.get('city', 'N/A')} | "
                f"Region: {ip_info.get('region', 'N/A')} | "
                f"Country: {ip_info.get('country', 'N/A')} | "
                f"Location: {ip_info.get('loc', 'N/A')} | "
                f"Hosting: {ip_info.get('org', 'N/A')}"
            )
            print(output)
        print("-----------")

if __name__ == "__main__":
    main()
