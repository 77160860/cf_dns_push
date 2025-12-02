import requests
import traceback
import os

CF_API_TOKEN = os.environ["CF_API_TOKEN"]
CF_ZONE_ID = os.environ["CF_ZONE_ID"]
CF_DNS_NAME = os.environ["CF_DNS_NAME"]

HEADERS = {
    'Authorization': f'Bearer {CF_API_TOKEN}',
    'Content-Type': 'application/json'
}

def get_ips_from_url(url):
    try:
        r = requests.get(url, timeout=15)
        r.raise_for_status()
        data = r.json()
        ips = []
        if isinstance(data, list):
            for item in data:
                ip = item.get('ip')
                if isinstance(ip, str):
                    ips.append(ip)
        else:
            print("Unexpected JSON structure: expected list")
        return ips
    except Exception:
        traceback.print_exc()
        return []

def list_a_records(name):
    url = f'https://api.cloudflare.com/client/v4/zones/{CF_ZONE_ID}/dns_records'
    params = {'type':'A','name':name,'per_page':100}
    try:
        r = requests.get(url, headers=HEADERS, params=params, timeout=10)
        r.raise_for_status()
        return r.json().get("result", [])
    except Exception:
        traceback.print_exc()
        return []

def delete_dns_record(record_id):
    url = f'https://api.cloudflare.com/client/v4/zones/{CF_ZONE_ID}/dns_records/{record_id}'
    try:
        r = requests.delete(url, headers=HEADERS, timeout=10)
        r.raise_for_status()
        print(f"Deleted DNS record {record_id}")
        return True
    except Exception:
        traceback.print_exc()
        return False

def delete_all_a_records(name):
    records = list_a_records(name)
    ok = True
    for rec in records:
        rid = rec.get('id')
        if rid:
            ok = delete_dns_record(rid) and ok
    return ok

def create_dns_record(name, ip):
    url = f'https://api.cloudflare.com/client/v4/zones/{CF_ZONE_ID}/dns_records'
    data = {'type':'A', 'name':name, 'content':ip}
    try:
        r = requests.post(url, headers=HEADERS, json=data, timeout=10)
        r.raise_for_status()
        print(f"Created DNS A record {ip}")
        return f"ip:{ip} added successfully"
    except Exception:
        traceback.print_exc()
        return f"ip:{ip} add failed"

def main():
    github_url = 'https://raw.githubusercontent.com/NiREvil/vless/refs/heads/main/sub/Cf-ipv4.json'
    github_ips = get_ips_from_url(github_url)
    print(f"IPs from JSON: {github_ips}")

    if not github_ips:
        print("No IPs found; exiting")
        return

    # 去重IP，避免重复添加导致的400错误
    github_ips = list(dict.fromkeys(github_ips))

    max_records = os.getenv('CF_MAX_RECORDS')
    if max_records and max_records.isdigit():
        github_ips = github_ips[:int(max_records)]

    if not delete_all_a_records(CF_DNS_NAME):
        print("Warning: delete old records failed; continue")

    results = [create_dns_record(CF_DNS_NAME, ip) for ip in github_ips]
    for res in results:
        print(res)

if __name__ == '__main__':
    main()
