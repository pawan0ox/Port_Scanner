import argparse
import json
import requests
import re

def extract_software_info(banner):
    match = re.search(r"Server:\s*([a-zA-Z]+(?:/[0-9\.]+)?)", banner)
    return match.group(1) if match else None

def search_cve(software):
    print(f"[+] Searching CVEs for: {software}")
    try:
        response = requests.get(f"https://vulners.com/api/v3/search/lucene/?query={software}")
        data = response.json()
        cves = []

        if data.get("data") and data["data"].get("search"):
            for item in data["data"]["search"]:
                if item.get("id", "").startswith("CVE-"):
                    cves.append({
                        "cve": item["id"],
                        "title": item["title"],
                        "cvss": item.get("cvss", "N/A"),
                        "published": item.get("published"),
                        "href": item.get("href")
                    })
        return cves
    except Exception as e:
        print(f"Error: {e}")
        return []

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("banner_file", help="Path to banner JSON file")
    parser.add_argument("-o", "--output", default="reports/cve_results.json", help="Output file path")
    args = parser.parse_args()

    with open(args.banner_file, "r") as f:
        banners = json.load(f)

    results = {}
    for target, info in banners.items():
        banner = info.get("banner", "")
        software = extract_software_info(banner)
        if software:
            cves = search_cve(software)
            results[target] = {
                "software": software,
                "cves": cves
            }
        else:
            results[target] = {"error": "No software identified"}

    with open(args.output, "w") as f:
        json.dump(results, f, indent=2)

    print(f"[+] CVE results saved to {args.output}")

if __name__ == "__main__":
    main()