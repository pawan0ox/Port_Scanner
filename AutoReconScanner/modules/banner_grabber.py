import socket
import json
import os
import argparse

def load_ports_data(filepath):
    try:
        with open(filepath, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"[!] Failed to load port file: {e}")
        return {}

def grab_banner(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2)
            s.connect((ip, port))
            banner = s.recv(1024)
            return banner.decode(errors="ignore").strip()
    except Exception:
        return None

def main(port_file, output_dir):
    targets = load_ports_data(port_file)
    results = {}

    for subdomain, data in targets.items():
        ip = data.get("ip")
        ports = data.get("open_ports", [])
        banners = {}
        print(f"[*] Grabbing banners from {subdomain} ({ip})")
        for port in ports:
            banner = grab_banner(ip, port)
            if banner:
                print(f"[+] {subdomain}:{port} -> {banner}")
                banners[port] = banner
        if banners:
            results[subdomain] = {
                "ip": ip,
                "banners": banners
            }

    os.makedirs(output_dir, exist_ok=True)
    out_file = os.path.join(output_dir, os.path.basename(port_file).replace("_ports", "_banners"))
    with open(out_file, 'w') as f:
        json.dump(results, f, indent=4)
    print(f"[✓] Banners saved to {out_file}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Banner Grabber")
    parser.add_argument("port_file", help="Path to *_ports.json file")
    parser.add_argument("-o", "--output", default="reports", help="Directory to save output")
    args = parser.parse_args()

    main(args.port_file, args.output)
