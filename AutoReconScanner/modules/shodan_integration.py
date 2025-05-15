import argparse
import json
import shodan

# Replace this with your actual API key
SHODAN_API_KEY = "arQ3VaCMk4z6p5exV8Ra7Nm39O7K8Nd8"

def get_shodan_data(ip):
    api = shodan.Shodan(SHODAN_API_KEY)
    try:
        host = api.host(ip)
        return {
            "ip": host.get("ip_str"),
            "org": host.get("org"),
            "os": host.get("os"),
            "ports": host.get("ports"),
            "hostnames": host.get("hostnames"),
            "vulns": host.get("vulns"),
            "data": host.get("data", [])
        }
    except shodan.APIError as e:
        return {"error": str(e)}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("subdomains_file", help="Path to subdomains JSON")
    parser.add_argument("-o", "--output", default="reports/shodan_results.json", help="Output file path")
    args = parser.parse_args()

    with open(args.subdomains_file, "r") as f:
        subdomains = json.load(f)

    results = {}
    for domain, ip in subdomains.items():
        print(f"[+] Fetching Shodan info for {ip} ({domain})...")
        results[domain] = get_shodan_data(ip)

    with open(args.output, "w") as f:
        json.dump(results, f, indent=2)

    print(f"[+] Shodan results saved to {args.output}")

if __name__ == "__main__":
    main()
