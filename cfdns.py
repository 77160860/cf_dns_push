import requests
import traceback
import time
import os
import json
import re
import dns.resolver

CF_API_TOKEN = os.environ["CF_API_TOKEN"]
CF_ZONE_ID = os.environ["CF_ZONE_ID"]
CF_DNS_NAME = os.environ["CF_DNS_NAME"]
PUSHPLUS_TOKEN = os.environ.get("PUSHPLUS_TOKEN", "")

HEADERS = {
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

def get_ips_from_urls(urls, timeout=10, max_retries=3):
    UA_HEADERS = {
        'User-Agent': 'Mozilla/5.0 (compatible; IPFetcher/1.0)'
    }
    seen = set()
    result = []
    for url in urls:
        for attempt in range(max_retries):
            try:
                resp = requests.get(url, timeout=timeout, headers=UA_HEADERS)
                if resp.status_code == 200 and resp.text:
                    ips = extract_ipv4s(resp.text)
                    for ip in ips:
                        if ip not in seen:
                            seen.add(ip)
                            result.append(ip)
                    break
                else:
                    print(f"Failed to get IPs from {url}, status code: {resp.status_code}")
            except Exception as e:
                traceback.print_exc()
                print(f"Attempt {attempt + 1} failed for {url}: {e}")
    return result

def get_ips_from_domain(domain):
    try:
        answers = dns.resolver.resolve(domain, 'A')
        ips = [answer.to_text() for answer in answers]
        return ips
    except Exception as e:
        print(f"Failed to resolve {domain}: {e}")
        return []

def list_a_records(name):
    url = f'https://api.cloudflare.com/client/v4/zones/{CF_ZONE_ID}/dns_records'
    params = {'type': 'A', 'name': name, 'per_page': 100}
    try:
        resp = requests.get(url, headers=HEADERS, params=params, timeout=10)
        if resp.status_code == 200:
            return resp.json().get('result', [])
        else:
            print(f"List A records failed: {resp.status_code} {resp.text}")
    except Exception as e:
        print(f"Exception list_a_records: {e}")
    return []

def delete_dns_record(record_id):
    url = f'https://api.cloudflare.com/client/v4/zones/{CF_ZONE_ID}/dns_records/{record_id}'
    try:
        resp = requests.delete(url, headers=HEADERS, timeout=10)
        if resp.status_code == 200:
            print(f"Deleted DNS record {record_id}")
            return True
        else:
            print(f"Delete DNS record failed {record_id}: {resp.status_code} {resp.text}")
    except Exception as e:
        print(f"Exception delete_dns_record {record_id}: {e}")
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
        'content': ip,
    }
    try:
        resp = requests.post(url, headers=HEADERS, json=data, timeout=10)
        if resp.status_code == 200:
            print(f"Created DNS A record {ip}")
            return f"ip:{ip} added successfully"
        else:
            print(f"Create DNS record failed {ip}: {resp.status_code} {resp.text}")
            return f"ip:{ip} add failed"
    except Exception as e:
        print(f"Exception create_dns_record {ip}: {e}")
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
        "channel": "wechat"
    }
    try:
        requests.post(url, json=data, timeout=10)
    except Exception as e:
        print(f"PushPlus error: {e}")

def main():
    domain = "cm.cf.cname.vvhan.com"
    domain_ips = get_ips_from_domain(domain)

    github_url = "https://raw.githubusercontent.com/gslege/CloudflareIP/main/Cfxyz.txt"
    github_ips = get_ips_from_urls([github_url])

    # 合并去重
    all_ips_set = set(domain_ips + github_ips)
    all_ips = list(all_ips_set)

    if not all_ips:
        print("No IPs fetched from domain or github.")
        return

    max_records = os.getenv("CF_MAX_RECORDS")
    if max_records and max_records.isdigit():
        all_ips = all_ips[:int(max_records)]

    if not delete_all_a_records(CF_DNS_NAME):
        print("Error deleting existing DNS A records, continuing...")

    results = [create_dns_record(CF_DNS_NAME, ip) for ip in all_ips]

    push_plus("\n".join(results))

if __name__ == "__main__":
    main()
