import whois
import json
import os

def extract_domain(subdomain):
    parts = subdomain.split('.')
    if len(parts) >= 2:
        return '.'.join(parts[-2:])
    return subdomain

def lookup(subdomains: dict, output_dir: str):
    seen_domains = set()
    results = {}

    for subdomain in subdomains:
        root_domain = extract_domain(subdomain)
        if root_domain in seen_domains:
            continue
        print(f"[*] Performing WHOIS lookup for {root_domain}...")
        try:
            w = whois.whois(root_domain)
            results[root_domain] = {
                "domain_name": w.domain_name,
                "registrar": w.registrar,
                "creation_date": str(w.creation_date),
                "expiration_date": str(w.expiration_date),
                "name_servers": w.name_servers,
                "emails": w.emails
            }
            seen_domains.add(root_domain)
        except Exception as e:
            print(f"[!] Error fetching WHOIS for {root_domain}: {e}")
            results[root_domain] = {"error": str(e)}

    os.makedirs(output_dir, exist_ok=True)
    out_file = os.path.join(output_dir, "whois_info.json")
    with open(out_file, 'w') as f:
        json.dump(results, f, indent=4)
    print(f"[✓] WHOIS info saved to {out_file}")
    return results