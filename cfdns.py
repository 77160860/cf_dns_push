import dns.resolver
import requests
import traceback
import re
import os
import json

CF_API_TOKEN = os.environ["CF_API_TOKEN"]
CF_ZONE_ID = os.environ["CF_ZONE_ID"]
CF_DNS_NAME = os.environ["CF_DNS_NAME"]
PUSHPLUS_TOKEN = os.environ.get("PUSHPLUS_TOKEN", "")

HEADERS = {
    'Authorization': f'Bearer {CF_API_TOKEN}',
    'Content-Type': 'application/json'
}

DNS_SERVERS = ['8.8.8.8']

def resolve_domain_ips_multi_dns(domain, depth=5):
    if depth == 0:
        return []

    ips = set()
    for server in DNS_SERVERS:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [server]
        try:
            answers = resolver.resolve(domain, 'A')
            ips.update(rdata.to_text() for rdata in answers)
        except dns.resolver.NoAnswer:
            try:
                cnames = resolver.resolve(domain, 'CNAME')
                for cname in cnames:
                    cname_target = cname.target.to_text().rstrip('.')
                    ips.update(resolve_domain_ips_multi_dns(cname_target, depth - 1))
            except Exception as e:
                print(f"CNAME query failed on server {server} for {domain}: {e}")
        except Exception as e:
            print(f"A record query failed on server {server} for {domain}: {e}")
    return list(ips)

def extract_ipv4s(text):
    pattern = r'(?:\d{1,3}\.){3}\d{1,3}'
    candidates = re.findall(pattern, text)
    def valid(ip):
        try:
            parts = [int(p) for p in ip.split('.')]
            return len(parts) == 4 and all(0 <= p <= 255 for p in parts)
        except:
            return False
    seen = set()
    result = []
    for ip in candidates:
        if valid(ip) and ip not in seen:
            seen.add(ip)
            result.append(ip)
    return result

def get_ips_from_github_raw(url):
    try:
        resp = requests.get(url, timeout=15)
        resp.raise_for_status()
        text = resp.text
        print(f"GitHub raw content preview:\n{text[:500]}")
        ips = extract_ipv4s(text)
        print(f"Extracted {len(ips)} IPs from GitHub raw")
        return ips
    except Exception as e:
        print(f"Error fetching GitHub IPs: {e}")
        traceback.print_exc()
        return []

def list_a_records(name):
    url = f"https://api.cloudflare.com/client/v4/zones/{CF_ZONE_ID}/dns_records"
    params = {'type': 'A', 'name': name, 'per_page': 100}
    try:
        resp = requests.get(url, headers=HEADERS, params=params, timeout=10)
        resp.raise_for_status()
        return resp.json().get('result', [])
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
        rid = rec.get('id')
        if rid:
            success = delete_dns_record(rid) and success
    return success

def create_dns_record(name, ip):
    url = f"https://api.cloudflare.com/client/v4/zones/{CF_ZONE_ID}/dns_records"
    data = {'type':'A', 'name':name, 'content':ip}
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
        print("PUSHPLUS_TOKEN empty, skipping push")
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
        print(f"PushPlus push error: {e}")

def main():
    domain = "cm.cf.cname.vvhan.com"
    github_url = "https://raw.githubusercontent.com/gslege/CloudflareIP/main/Cfxyz.txt"

    print(f"Resolving domain {domain} using DNS servers {DNS_SERVERS}")
    domain_ips = resolve_domain_ips_multi_dns(domain)
    print(f"Domain IPs resolved: {domain_ips}")

    print(f"Fetching IPs from GitHub raw {github_url}")
    github_ips = get_ips_from_github_raw(github_url)
    print(f"GitHub IPs obtained: {github_ips}")

    all_ips = list(dict.fromkeys(domain_ips + github_ips))
    if not all_ips:
        print("No IPs obtained from any source, exiting.")
        return

    max_records = os.getenv("CF_MAX_RECORDS")
    if max_records and max_records.isdigit():
        all_ips = all_ips[:int(max_records)]

    if not delete_all_a_records(CF_DNS_NAME):
        print("Failed to delete old A records, continuing.")

    results = [create_dns_record(CF_DNS_NAME, ip) for ip in all_ips]

    push_plus("\n".join(results))


if __name__ == "__main__":
    main()
