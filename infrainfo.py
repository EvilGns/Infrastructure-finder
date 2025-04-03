import requests
import socket
import sys

def print_usage():
    """
    Prints the usage instructions for running the script.
    """
    print("Usage: python script.py <IP_API_KEY> <domain_or_file>")
    print("Example 1: python script.py <YOUR_IP_API_KEY> example.com")
    print("Example 2: python script.py <YOUR_IP_API_KEY> domains.txt")
    print("Note: Replace <YOUR_IP_API_KEY> with your actual IpInfo API key.")
    print("If you use a file (domains.txt), make sure it contains one domain name per line.")
    print("To enter multiple domains, separate them with commas (e.g., domain1.com, domain2.com).")
    sys.exit(1)

def get_ip_info(ip_api_key, ip_address):
    """Get IP Info using IpInfo API"""
    url = f"https://ipinfo.io/{ip_address}/json"
    headers = {"Authorization": f"Bearer {ip_api_key}"}
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            return response.json()
        else:
            print(f"Error: {response.status_code} - {response.text}")
            return None
    except requests.exceptions.RequestException as e:
        print(f"Request Error: {e}")
        return None

def fetch_subdomains(domain_name):
    """Fetch subdomains (Example function)"""
    # Replace with actual subdomain fetching logic (e.g., from crt.sh, SecurityTrails, etc.)
    return [f"www.{domain_name}", f"mail.{domain_name}", f"api.{domain_name}"]

def process_domains(domain_names, ip_api_key):
    """Process domains to fetch IP and location info"""
    ip_addresses = []
    combined = []
    
    for domain_name in domain_names:
        print(f"Processing domain: {domain_name}")
        subdomains = fetch_subdomains(domain_name)

        # Resolving IP addresses of respective subdomains
        for subdomain in subdomains:
            print(subdomain)  # DEBUG
            try:
                ip_address = socket.gethostbyname(subdomain)
                print(f"Resolved {subdomain} to {ip_address}")  # DEBUG
                ip_addresses.append(ip_address)

                # Get IP info from IpInfo API
                ip_info = get_ip_info(ip_api_key, ip_address)
                if ip_info:
                    # Use .get() to safely access 'asn_name' and 'org' fields
                    asn_name = ip_info.get('asn_name', 'N/A')  # Default to 'N/A' if not available
                    org = ip_info.get('org', 'N/A')  # Default to 'N/A' if not available
                    
                    # Include 'org' as part of the output
                    list_info = f"{subdomain} : {ip_address} | City: {ip_info.get('city', 'N/A')} | Region: {ip_info.get('region', 'N/A')} | Country: {ip_info.get('country', 'N/A')} | Location: {ip_info.get('loc', 'N/A')} | Hosting: {org} | ASN: {asn_name}"
                    combined.append(list_info)
            except socket.gaierror as error:
                print(f"Error resolving {subdomain}: {error}")
                
    return combined

def read_domains_from_file(file_path):
    """Read domain names from a text file"""
    with open(file_path, 'r') as file:
        return [line.strip() for line in file.readlines()]

def main():
    # Check if proper arguments are passed
    if len(sys.argv) < 3:
        print_usage()

    ip_api_key = sys.argv[1]
    input_source = sys.argv[2]

    if input_source.endswith(".txt"):
        # If a file is provided, read the domains from the file
        domain_names = read_domains_from_file(input_source)
    else:
        # If a single domain or multiple domains separated by commas are provided
        domain_names = input_source.split(",")

    print(f"Processing the following domains: {domain_names}")
    results = process_domains(domain_names, ip_api_key)

    # Output the combined results, separated by "-----------"
    if results:
        print("\nInfrastructure Info:\n")
        for result in results:
            print(result)
            print("-----------")  # Separate results by "-----------"
    else:
        print("No infrastructure information found.")

if __name__ == "__main__":
    main()
