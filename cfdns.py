import requests
import os
import json
import traceback

CF_API_TOKEN = os.environ["CF_API_TOKEN"]
CF_ZONE_ID = os.environ["CF_ZONE_ID"]
CF_DNS_NAME = os.environ["CF_DNS_NAME"]
PUSHPLUS_TOKEN = os.environ.get("PUSHPLUS_TOKEN", "")

HEADERS = {
    "Authorization": f"Bearer {CF_API_TOKEN}",
    "Content-Type": "application/json"
}

def get_ips_via_google_dns(domain):
    url = f"https://dns.google/resolve?name={domain}&type=A"
    try:
        resp = requests.get(url, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        if "Answer" in data:
            ips = [answer["data"] for answer in data["Answer"] if answer["type"] == 1]
            return list(dict.fromkeys(ips))  # 去重且保证顺序
        else:
            print(f"No A record found for {domain} in Google DNS response.")
    except Exception as e:
        print(f"Exception during Google DNS query: {e}")
        traceback.print_exc()
    return []

def get_ips_from_github_raw(url):
    try:
        resp = requests.get(url, timeout=10)
        resp.raise_for_status()
        ips = []
        for line in resp.text.splitlines():
            parts = line.strip().split()
            for part in parts:
                if validate_ip(part):
                    ips.append(part)
        return list(dict.fromkeys(ips))
    except Exception as e:
        print(f"Exception fetching IPs from GitHub raw: {e}")
        traceback.print_exc()
    return []

def validate_ip(ip_str):
    parts = ip_str.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(part) <= 255 for part in parts)
    except:
        return False

def list_a_records(name):
    url = f"https://api.cloudflare.com/client/v4/zones/{CF_ZONE_ID}/dns_records"
    params = {"type": "A", "name": name, "per_page": 100}
    try:
        resp = requests.get(url, headers=HEADERS, params=params, timeout=10)
        resp.raise_for_status()
        return resp.json().get("result", [])
    except Exception as e:
        print(f"Exception listing A records: {e}")
        traceback.print_exc()
        return []

def delete_dns_record(record_id):
    url = f"https://api.cloudflare.com/client/v4/zones/{CF_ZONE_ID}/dns_records/{record_id}"
    try:
        resp = requests.delete(url, headers=HEADERS, timeout=10)
        resp.raise_for_status()
        print(f"Deleted DNS record {record_id}")
        return True
    except Exception as e:
        print(f"Exception deleting DNS record {record_id}: {e}")
        traceback.print_exc()
        return False

def delete_all_a_records(name):
    records = list_a_records(name)
    success = True
    for rec in records:
        rid = rec.get("id")
        if rid:
            success = delete_dns_record(rid) and success
    return success

def create_dns_record(name, ip):
    url = f"https://api.cloudflare.com/client/v4/zones/{CF_ZONE_ID}/dns_records"
    data = {"type": "A", "name": name, "content": ip}
    try:
        resp = requests.post(url, headers=HEADERS, json=data, timeout=10)
        resp.raise_for_status()
        print(f"Created DNS A record {ip}")
        return f"ip:{ip} added successfully"
    except Exception as e:
        print(f"Exception creating DNS record {ip}: {e}")
        traceback.print_exc()
        return f"ip:{ip} add failed"

def push_plus(content):
    if not PUSHPLUS_TOKEN:
        print("PushPlus token empty, skipping push")
        return
    url = "http://www.pushplus.plus/send"
    data = {
        "token": PUSHPLUS_TOKEN,
        "title": "IP优选DNSCF推送",
        "content": content,
        "template": "markdown",
        "channel": "wechat",
    }
    try:
        requests.post(url, json=data, timeout=10)
    except Exception as e:
        print(f"Exception pushing notifications: {e}")
        traceback.print_exc()

def main():
    domain = "cm.cf.cname.vvhan.com"
    github_ips_url = "https://raw.githubusercontent.com/gslege/CloudflareIP/main/Cfxyz.txt"

    print(f"Getting IPs for domain {domain} via Google DNS")
    domain_ips = get_ips_via_google_dns(domain)
    print(f"Got domain IPs: {domain_ips}")

    print(f"Fetching IPs from GitHub raw {github_ips_url}")
    github_ips = get_ips_from_github_raw(github_ips_url)
    print(f"Got GitHub IPs: {github_ips}")

    all_ips = list(dict.fromkeys(domain_ips + github_ips))

    if not all_ips:
        print("No IPs found to update.")
        return

    max_records_env = os.getenv("CF_MAX_RECORDS")
    if max_records_env and max_records_env.isdigit():
        max_records = int(max_records_env)
        all_ips = all_ips[:max_records]

    if not delete_all_a_records(CF_DNS_NAME):
        print("Warning: Failed to delete all existing A records; continuing.")

    results = [create_dns_record(CF_DNS_NAME, ip) for ip in all_ips]

    push_plus("\n".join(results))


if __name__ == "__main__":
    main()
