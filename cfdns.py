import dns.resolver
import requests
import traceback
import re
import os
import ipaddress

CF_API_TOKEN = os.environ["CF_API_TOKEN"]
CF_ZONE_ID = os.environ["CF_ZONE_ID"]
CF_DNS_NAME = os.environ["CF_DNS_NAME"]
HEADERS = {
    'Authorization': f'Bearer {CF_API_TOKEN}',
    'Content-Type': 'application/json'
}
DNS_SERVERS = ['8.8.8.8', '114.114.114.114']

def resolve_domain_ips(domain, depth=5):
    if depth == 0:
        return []
    ips = set()
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = DNS_SERVERS
    try:
        answers = resolver.resolve(domain, 'A')
        ips.update(rdata.to_text() for rdata in answers)
        print(f"A records for {domain}: {ips}")
    except dns.resolver.NoAnswer:
        # try CNAME
        try:
            cnames = resolver.resolve(domain, 'CNAME')
            for cname in cnames:
                target = cname.target.to_text().rstrip('.')
                print(f"CNAME found for {domain}: {target}")
                ips.update(resolve_domain_ips(target, depth -1))
        except Exception as e:
            print(f"CNAME query failed for {domain}: {e}")
    except Exception as e:
        print(f"A record query failed for {domain}: {e}")
    return list(ips)

def extract_ipv4s(text):
    pattern = r'(?:\d{1,3}\.){3}\d{1,3}'
    candidates = re.findall(pattern, text)
    result = []
    for ip in candidates:
        try:
            if isinstance(ipaddress.ip_address(ip), ipaddress.IPv4Address):
                if ip not in result:
                    result.append(ip)
        except ValueError:
            continue
    return result

def get_ips_from_url(url):
    headers = {"User-Agent": "Mozilla/5.0"}
    try:
        r = requests.get(url, headers=headers, timeout=15)
        r.raise_for_status()
        ips = extract_ipv4s(r.text)
        print(f"Extracted IPs from {url}: {ips}")
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
    domain = 'cm.cf.cname.vvhan.com'
    github_url = 'https://ip.164746.xyz/ipTop.html'

    domain_ips = resolve_domain_ips(domain)
    github_ips = get_ips_from_url(github_url)
    all_ips = list(dict.fromkeys(domain_ips + github_ips))

    print(f"All IPs to add: {all_ips}")

    if not all_ips:
        print("No IPs found; exiting")
        return

    max_records = os.getenv('CF_MAX_RECORDS')
    if max_records and max_records.isdigit():
        all_ips = all_ips[:int(max_records)]

    if not delete_all_a_records(CF_DNS_NAME):
        print("Warning: delete old records failed; continue")

    results = [create_dns_record(CF_DNS_NAME, ip) for ip in all_ips]
    for res in results:
        print(res)

if __name__ == '__main__':
    main()
