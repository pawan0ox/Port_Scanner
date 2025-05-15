import argparse
import json
import os

# Module imports
from modules import subdomain_enum
from modules import port_scanner
from modules import banner_grabber
from modules import whois_lookup
from modules import geoip_lookup
from modules import cve_checker
from modules import shodan_integration
from modules import ssl_module_info


def main():
    parser = argparse.ArgumentParser(description="Automated Recon and Vulnerability Scanner")
    parser.add_argument("target", help="Domain or JSON file with subdomains")
    parser.add_argument("-o", "--output", help="Output directory for reports", default="reports")
    args = parser.parse_args()

    target = args.target.strip()
    output_dir = args.output

    os.makedirs(output_dir, exist_ok=True)
    recon_data = {}

    # 1. Subdomain Enumeration
    print("[*] Running Subdomain Enumeration...")
    if target.endswith(".json"):
        with open(target) as f:
            subdomains = json.load(f)
    else:
        subdomains = subdomain_enum.brute_force_subdomains(target, subdomain_enum.load_wordlist("subdomains.txt"))
        output_path = os.path.join(output_dir, f"{target.replace('.', '_')}_subdomains.json")
        with open(output_path, "w") as f:
            json.dump(subdomains, f, indent=4)
        print(f"[+] Subdomains saved to {output_path}")
    recon_data['subdomains'] = subdomains

    # 2. Port Scanning
    print("[*] Running Port Scanning...")
    port_scan_results = {}
    for sub, ip in subdomains.items():
        ports = port_scanner.scan_ports(ip, range(20,25))
        port_scan_results[sub] = {
            "ip": ip,
            "open_ports": ports
        }
    recon_data["ports"] = port_scan_results

    # 3. Banner Grabbing
    print("[*] Running Banner Grabbing...")
    banner_results = {}
    for sub, info in port_scan_results.items():
        ip = info["ip"]
        ports = info["open_ports"]
        banner_results[sub] = {}
        for port in ports:
            banner = banner_grabber.grab_banner(ip, port)
            if banner:
                banner_results[sub][port] = banner
    recon_data["banners"] = banner_results

    # 4. WHOIS Lookup
    print("[*] Running WHOIS Lookup...")
    try:
        whois_data = whois_lookup.lookup(subdomains, output_dir)
        recon_data['whois'] = whois_data
    except Exception as e:
        print(f"[!] WHOIS Lookup failed: {e}")
        recon_data['whois'] = {"error": str(e)}

    # 5. GeoIP Lookup
    print("[*] Running GeoIP Lookup...")
    try:
        geoip_data = geoip_lookup.lookup(subdomains)
        recon_data['geoip'] = geoip_data
    except Exception as e:
        print(f"[!] GeoIP Lookup failed: {e}")
        recon_data['geoip'] = {"error": str(e)}

    # 6. CVE Checker
    print("[*] Running CVE Checker...")
    cve_data = {}
    for sub, info in port_scan_results.items():
        cve_data[sub] = {}
        for port in info["open_ports"]:
            vulns = cve_checker.check_vulnerabilities(port)
            if vulns:
                cve_data[sub][port] = vulns
    recon_data["cve"] = cve_data

    # 7. Shodan Integration
    print("[*] Running Shodan Integration...")
    try:
        shodan_data = shodan_integration.search_subdomains(subdomains)
        recon_data['shodan'] = shodan_data
    except Exception as e:
        print(f"[!] Shodan integration failed: {e}")
        recon_data['shodan'] = {"error": str(e)}

    # 8. SSL Info Extraction
    print("[*] Running SSL Info Extraction...")
    try:
        ssl_data = ssl_module_info.get_ssl_info(subdomains)
        recon_data['ssl'] = ssl_data
    except Exception as e:
        print(f"[!] SSL Info extraction failed: {e}")
        recon_data['ssl'] = {"error": str(e)}

    # Save final JSON report
    output_file = os.path.join(output_dir, f"{target.replace('.', '_')}_full_report.json")
    with open(output_file, "w") as f:
        json.dump(recon_data, f, indent=4)

    print(f"[✓] Full recon report saved to {output_file}")


if __name__ == "__main__":
    main()