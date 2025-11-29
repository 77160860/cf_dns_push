import dns.resolver
import os
import requests
import traceback
import re
import json
import time

CF_API_TOKEN = os.environ.get("CF_API_TOKEN", "")
CF_ZONE_ID = os.environ.get("CF_ZONE_ID", "")
CF_DNS_NAME = os.environ.get("CF_DNS_NAME", "")
PUSHPLUS_TOKEN = os.environ.get("PUSHPLUS_TOKEN", "")

HEADERS = {
    "Authorization": f"Bearer {CF_API_TOKEN}",
    "Content-Type": "application/json"
}


def extract_ipv4s(text):
    candidates = re.findall(r"(?:\d{1,3}\.){3}\d{1,3}", text)
    def valid(ip):
        try:
            parts = list(map(int, ip.split(".")))
            return len(parts) == 4 and all(0 <= p <= 255 for p in parts)
        except:
            return False
    seen = set()
    ips = []
    for ip in candidates:
        if valid(ip) and ip not in seen:
            seen.add(ip)
            ips.append(ip)
    return ips


def get_ips_from_urls(urls):
    seen = set()
    ips = []
    headers = {"User-Agent": "Mozilla/5.0 (compatible; IPFetcher/1.0)"}
    for url in urls:
        try:
            resp = requests.get(url, headers=headers, timeout=10)
            if resp.status_code == 200 and resp.text:
                extracted = extract_ipv4s(resp.text)
                for ip in extracted:
                    if ip not in seen:
                        seen.add(ip)
                        ips.append(ip)
        except Exception as e:
            print(f"Error fetching {url}: {e}")
    return ips


def resolve_cname_recursive(domain, max_depth=5):
    # 递归解析CNAME直到拿到A记录或达到最大递归深度
    if max_depth == 0:
        return []
    try:
        answers = dns.resolver.resolve(domain, "A")
        return [rdata.to_text() for rdata in answers]
    except dns.resolver.NoAnswer:
        try:
            cnames = dns.resolver.resolve(domain, "CNAME")
            for cname in cnames:
                target = cname.target.to_text().rstrip(".")
                return resolve_cname_recursive(target, max_depth - 1)
        except Exception as e:
            print(f"Failed to resolve CNAME for {domain}: {e}")
    except Exception as e:
        print(f"Error resolving {domain}: {e}")
    return []


def list_a_records(name):
    url = f"https://api.cloudflare.com/client/v4/zones/{CF_ZONE_ID}/dns_records"
    params = {"type": "A", "name": name, "per_page": 100}
    try:
        resp = requests.get(url, headers=HEADERS, params=params, timeout=10)
        if resp.status_code == 200:
            return resp.json().get("result", [])
        else:
            print(f"Error listing a-records {resp.status_code}: {resp.text}")
    except Exception as e:
        print(f"Exception listing A records: {e}")
    return []


def delete_dns_record(record_id):
    url = f"https://api.cloudflare.com/client/v4/zones/{CF_ZONE_ID}/dns_records/{record_id}"
    try:
        resp = requests.delete(url, headers=HEADERS, timeout=10)
        if resp.status_code == 200:
            print(f"Deleted DNS record {record_id}")
            return True
        else:
            print(f"Error deleting record {record_id}: {resp.status_code} {resp.text}")
    except Exception as e:
        print(f"Exception deleting record {record_id}: {e}")
    return False


def delete_all_a_records(name):
    records = list_a_records(name)
    ok = True
    for rec in records:
        rid = rec.get("id")
        if rid:
            ok = delete_dns_record(rid) and ok
    return ok


def create_dns_record(name, ip):
    url = f"https://api.cloudflare.com/client/v4/zones/{CF_ZONE_ID}/dns_records"
    data = {
        "type": "A",
        "name": name,
        "content": ip,
        # "ttl": 120,
        # "proxied": False
    }
    try:
        resp = requests.post(url, headers=HEADERS, json=data, timeout=10)
        if resp.status_code == 200:
            print(f"Created DNS record {ip}")
            return f"ip:{ip} added successfully"
        else:
            print(f"Error creating DNS record {ip}: {resp.status_code} {resp.text}")
            return f"ip:{ip} add failed"
    except Exception as e:
        print(f"Exception creating DNS record {ip}: {e}")
        return f"ip:{ip} add failed"


def push_plus(content):
    if not PUSHPLUS_TOKEN:
        print("PushPlus token empty, skipped push")
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
    domain_ips = resolve_cname_recursive(domain)

    github_ips = get_ips_from_urls(
        ["https://raw.githubusercontent.com/gslege/CloudflareIP/main/Cfxyz.txt"]
    )

    all_ips = list(dict.fromkeys(domain_ips + github_ips))  # 去重且保持顺序

    if not all_ips:
        print("No IPs fetched from domain or github.")
        return

    max_records = os.getenv("CF_MAX_RECORDS")
    if max_records and max_records.isdigit():
        all_ips = all_ips[: int(max_records)]

    if not delete_all_a_records(CF_DNS_NAME):
        print("Warning: Failed to delete all existing A records. Continuing...")

    results = [create_dns_record(CF_DNS_NAME, ip) for ip in all_ips]

    push_plus("\n".join(results))


if __name__ == "__main__":
    main()
