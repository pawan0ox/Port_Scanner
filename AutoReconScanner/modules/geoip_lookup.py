import json
import requests
import os
import argparse

def get_geoip_info(ip):
    try:
        # You can replace the below URL with your own IP geolocation provider.
        url = f"https://ipinfo.io/{ip}/json"
        response = requests.get(url)
        if response.status_code == 200:
            return response.json()
        else:
            print(f"[!] Failed to fetch GeoIP info for {ip}")
            return None
    except Exception as e:
        print(f"[!] Error fetching GeoIP info for {ip}: {e}")
        return None

def main(banners_file, output_dir):
    with open(banners_file, 'r') as f:
        banners = json.load(f)

    geoip_data = {}

    for subdomain, details in banners.items():
        ip = details.get("ip")
        if ip:
            print(f"[*] Performing GeoIP lookup for {subdomain} ({ip})...")
            geo_info = get_geoip_info(ip)
            if geo_info:
                geoip_data[subdomain] = geo_info

    os.makedirs(output_dir, exist_ok=True)
    out_file = os.path.join(output_dir, os.path.basename(banners_file).replace("_banners", "_geoip"))
    with open(out_file, 'w') as f:
        json.dump(geoip_data, f, indent=4)
    print(f"[✓] GeoIP info saved to {out_file}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="GeoIP Lookup")
    parser.add_argument("banners_file", help="Path to banner JSON file")
    parser.add_argument("-o", "--output", default="reports", help="Output directory")
    args = parser.parse_args()

    main(args.banners_file, args.output)
