# Subport - Subdomain and Port Scanner

![Banner](https://i.imgur.com/n7eVrbg.png)
![Banner](https://i.imgur.com/hm2SZfW.png)

## Overview

Subport is a Python tool designed to find subdomains and scan open ports, services, and versions for a given domain or IP address. Utilizing crt.sh for subdomain enumeration and nmap for port scanning, it provides detailed insights into the target's network configuration.

## Dependencies

- Python 3
- nmap
- jq
- curl
- tabulate

To install these dependencies, you can run:

```bash
pip install python-nmap tabulate
```

## Usage
```
python subport.py <target> [-u]
```

## Parameters
```
target: (Required) Domain name or IP address to scan.
-u, --url: Use if the target is a domain name.
```

## Example

To scan the domain name:
```
python subport.py example.com -u
```

To scan an IP address:
```
python subport.py 192.168.1.1
```

## Output

The script prints the subdomains found and a detailed table of open ports, services, and versions for each subdomain.

## Disclaimer

Ensure that you have the necessary permissions to scan the target. Usage of this tool should comply with all applicable laws.
