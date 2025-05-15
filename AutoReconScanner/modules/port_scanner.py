import socket
import json
import os
import argparse
from tqdm import tqdm

def load_subdomains(filepath):
    try:
        with open(filepath, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"[!] Error loading subdomain file: {e}")
        return {}

def scan_ports(ip, ports):
    open_ports = []
    for port in tqdm(ports, desc=f"Scanning {ip}", leave=False):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                if s.connect_ex((ip, port)) == 0:
                    open_ports.append(port)
        except Exception:
            pass
    return open_ports

def main(json_file, output_dir):
    subdomains = load_subdomains(json_file)
    results = {}

    for subdomain, ip in subdomains.items():
        ports = scan_ports(ip, range(20, 1025))
        results[subdomain] = {
            "ip": ip,
            "open_ports": ports
        }

    os.makedirs(output_dir, exist_ok=True)
    out_file = os.path.join(output_dir, os.path.basename(json_file).replace("_subdomains", "_ports"))
    with open(out_file, 'w') as f:
        json.dump(results, f, indent=4)

    print(f"[✓] Port scan results saved to {out_file}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Port Scanner")
    parser.add_argument("json_file", help="Path to subdomains JSON file")
    parser.add_argument("-o", "--output", default="reports", help="Directory to save output JSON")
    args = parser.parse_args()

    main(args.json_file, args.output)
