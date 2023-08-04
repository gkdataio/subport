import subprocess
import argparse
import nmap
import re
from tabulate import tabulate

def find_subdomains(domain):
    command = f'curl -s "https://crt.sh/?q=%25.{domain}&output=json" | jq -r ".[].name_value" | sed "s/*.//g" | sort -u'
    result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, text=True)
    return result.stdout.strip().splitlines()

def scan_ports(subdomain):
    nm = nmap.PortScanner()
    try:
        nm.scan(subdomain, arguments="-p- -sV")
        return nm.csv()
    except nmap.PortScannerError:
        return ""

def print_colored(text, color_code):
    print(f"\033[{color_code}m{text}\033[0m")

def color_ip_addresses(text):
    ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    return re.sub(ip_pattern, lambda match: f"\033[32m{match.group(0)}\033[0m", text)

def color_services(text):
    service_pattern = r"\b\w+(?=:)"
    return re.sub(service_pattern, lambda match: f"\033[35m{match.group(0)}\033[0m", text)

def create_table(scan_info):
    lines = scan_info.splitlines()
    headers = lines[0].split(';')
    data = [line.split(';') for line in lines[1:]]
    return tabulate(data, headers=headers, tablefmt="grid")

if __name__ == "__main__":
    BANNER = r'''
┌─┐┬ ┬┌┐ ┌─┐┌─┐┬─┐┌┬┐
└─┐│ │├┴┐├─┘│ │├┬┘ │ 
└─┘└─┘└─┘┴  └─┘┴└─ ┴ @gkdata.io
'''

    description = "Find subdomains and scan open ports/services/versions."
    parser = argparse.ArgumentParser(description=description, formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("target", help="Domain name or IP address to scan")
    parser.add_argument("-u", "--url", action="store_true", help="Use if target is a domain name")
    args = parser.parse_args()

    print_colored(BANNER, "34")
    print_colored(description, "34")

    # Find subdomains
    subdomains = find_subdomains(args.target)

    print_colored(f"\nSubdomains found for {args.target}:", "33")
    for subdomain in subdomains:
        print_colored(f" - {subdomain}", "33")

    # Scan ports for each subdomain
    print_colored(f"\nScanning open ports for each subdomain:", "36")
    for subdomain in subdomains:
        print_colored(f"\nScanning {subdomain}...", "35")
        result = scan_ports(subdomain)
        if result:
            table = create_table(color_ip_addresses(color_services(result)))
            print(table)
        else:
            print_colored("No open ports found.", "31")
