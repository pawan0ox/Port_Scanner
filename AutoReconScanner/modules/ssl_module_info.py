import json
import argparse
from modules.ssl_info import get_ssl_certificate_info

def main():
    parser = argparse.ArgumentParser(description="SSL Certificate Info Module")
    parser.add_argument("subdomains_file", help="JSON file with subdomains")
    parser.add_argument("-o", "--output", help="Output file for SSL info", default="reports/ssl_info.json")
    args = parser.parse_args()

    with open(args.subdomains_file, "r") as f:
        subdomains = json.load(f)

    ssl_results = {}

    for domain in subdomains.keys():
        print(f"[*] Fetching SSL info for {domain}")
        ssl_results[domain] = get_ssl_certificate_info(domain)

    with open(args.output, "w") as f:
        json.dump(ssl_results, f, indent=4)

    print(f"[+] SSL info saved to {args.output}")

if __name__ == "__main__":
    main()