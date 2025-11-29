import requests
import traceback
import time
import os
import json
import re

CF_API_TOKEN = os.environ["CF_API_TOKEN"]
CF_ZONE_ID = os.environ["CF_ZONE_ID"]
CF_DNS_NAME = os.environ["CF_DNS_NAME"]
PUSHPLUS_TOKEN = os.environ.get("PUSHPLUS_TOKEN", "")

headers = {
    'Authorization': f'Bearer {CF_API_TOKEN}',
    'Content-Type': 'application/json'
}

def extract_ipv4s(text: str):
    candidates = re.findall(r'(?:\d{1,3}\.){3}\d{1,3}', text)
    def valid(ip):
        try:
            parts = list(map(int, ip.split('.')))
            return len(parts) == 4 and all(0 <= p <= 255 for p in parts)
        except Exception:
            return False
    seen = set()
    result = []
    for ip in candidates:
        if valid(ip) and ip not in seen:
            seen.add(ip)
            result.append(ip)
    return result

def get_ips_from_urls(urls, timeout=10, max_retries=5):
    seen = set()
    result = []
    for url in urls:
        for attempt in range(max_retries):
            try:
                resp = requests.get(url, timeout=timeout)
                if resp.status_code == 200 and resp.text:
                    ips = extract_ipv4s(resp.text)
                    for ip in ips:
                        if ip not in seen:
                            seen.add(ip)
                            result.append(ip)
                    break
            except Exception as e:
                traceback.print_exc()
                print(f"Failed to get IPs from {url} ({attempt+1}/{max_retries}): {e}")
    return result

def list_a_records(name):
    url = f'https://api.cloudflare.com/client/v4/zones/{CF_ZONE_ID}/dns_records'
    params = {'type': 'A', 'name': name, 'per_page': 100}
    try:
        r = requests.get(url, headers=headers, params=params, timeout=10)
        if r.status_code == 200:
            return r.json().get('result', [])
        print('Failed fetching DNS records:', r.text)
    except Exception as e:
        print(f"Exception in list_a_records: {e}")
    return []

def delete_dns_record(record_id):
    url = f'https://api.cloudflare.com/client/v4/zones/{CF_ZONE_ID}/dns_records/{record_id}'
    try:
        r = requests.delete(url, headers=headers, timeout=10)
        if r.status_code == 200:
            print(f"Deleted DNS record id={record_id} at {time.strftime('%Y-%m-%d %H:%M:%S')}")
            return True
        print(f"Failed to delete DNS record id={record_id}: {r.status_code} {r.text}")
    except Exception as e:
        traceback.print_exc()
        print(f"Exception deleting DNS record id={record_id}: {e}")
    return False

def delete_all_a_records(name):
    records = list_a_records(name)
    success = True
    for rec in records:
        rid = rec.get('id')
        if rid:
            success = delete_dns_record(rid) and success
    return success

def create_dns_record(name, ip):
    url = f'https://api.cloudflare.com/client/v4/zones/{CF_ZONE_ID}/dns_records'
    data = {
        'type': 'A',
        'name': name,
        'content': ip
    }
    try:
        resp = requests.post(url, headers=headers, json=data, timeout=10)
        if resp.status_code == 200:
            print(f"Created DNS A record {ip} for {name} at {time.strftime('%Y-%m-%d %H:%M:%S')}")
            return f"ip:{ip} added to {name} successfully"
        print(f"Failed to create DNS record {ip}: {resp.status_code} {resp.text}")
        return f"ip:{ip} failed to add to {name}"
    except Exception as e:
        traceback.print_exc()
        print(f"Exception creating DNS record for {ip}: {e}")
        return f"ip:{ip} failed to add to {name}"

def push_plus(content):
    if not PUSHPLUS_TOKEN:
        print("PushPlus skipped: token empty")
        return
    url = "http://www.pushplus.plus/send"
    data = {
        "token": PUSHPLUS_TOKEN,
        "title": "IP优选DNSCF推送",
        "content": content,
        "template": "markdown",
        "channel": "wechat"
    }
    try:
        requests.post(url, json=data, timeout=10)
    except Exception as e:
        print(f"PushPlus error: {e}")

def main():
    urls = [
        "https://ip.164746.xyz/ipTop10.html",
        "https://raw.githubusercontent.com/gslege/CloudflareIP/refs/heads/main/cfxyz.txt"
    ]
    ips = get_ips_from_urls(urls)
    if not ips:
        print("No IPs fetched from sources.")
        return

    max_records = os.getenv("CF_MAX_RECORDS")
    if max_records and max_records.isdigit():
        ips = ips[:int(max_records)]

    if not delete_all_a_records(CF_DNS_NAME):
        print("Error deleting existing A records, continuing...")

    results = [create_dns_record(CF_DNS_NAME, ip) for ip in ips]

    if results:
        push_plus("\n".join(results))

if __name__ == "__main__":
    main()
