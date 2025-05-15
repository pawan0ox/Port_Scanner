import socket
import json
import os
import re

def load_wordlist(filepath):
    try:
        with open(filepath, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"[!] Wordlist file not found: {filepath}")
        return []

def brute_force_subdomains(domain, wordlist):
    found = {}
    for sub in wordlist:
        subdomain = f"{sub}.{domain}"
        print(f"[*] Checking {subdomain}")
        try:
            ip = socket.gethostbyname(subdomain)
            print(f"[+] Found: {subdomain} -> {ip}")
            found[subdomain] = ip
        except socket.gaierror:
            pass
    return found

def clean_filename(domain):
    return re.sub(r'[^a-zA-Z0-9_-]', '_', domain)

def enumerate_subdomains(domain, wordlist_path="subdomains.txt", output_folder="reports"):
    wordlist = load_wordlist(wordlist_path)
    if not wordlist:
        print("[-] Wordlist is empty or not found.")
        return {}

    results = brute_force_subdomains(domain, wordlist)
    if results:
        os.makedirs(output_folder, exist_ok=True)
        filename = f"{output_folder}/{clean_filename(domain)}_subdomains.json"
        with open(filename, 'w') as f:
            json.dump(results, f, indent=4)
        print(f"[✓] Results saved to: {filename}")
    else:
        print("[-] No subdomains found.")
    return results

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Subdomain Brute Forcer")
    parser.add_argument("domain", help="Target domain (e.g. example.com)")
    parser.add_argument("-w", "--wordlist", default="subdomains.txt", help="Path to subdomain wordlist")
    parser.add_argument("-o", "--output", default="reports", help="Output folder for results")

    args = parser.parse_args()

    enumerate_subdomains(args.domain, args.wordlist, args.output)