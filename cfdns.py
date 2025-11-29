import dns.resolver
import requests
import traceback
import re
import os
import json
import time

CF_API_TOKEN = os.environ["CF_API_TOKEN"]
CF_ZONE_ID = os.environ["CF_ZONE_ID"]
CF_DNS_NAME = os.environ["CF_DNS_NAME"]
PUSHPLUS_TOKEN = os.environ.get("PUSHPLUS_TOKEN", "")

HEADERS = {
    'Authorization': f'Bearer {CF_API_TOKEN}',
    'Content-Type': 'application/json'
}

ALIYUN_DNS_SERVERS = ['223.5.5.5', '223.6.6.6']

def resolve_domain_ips_aliyun(domain, depth=5):
    """通过阿里云DNS递归解析域名IPv4地址"""
    if depth == 0:
        return []
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = ALIYUN_DNS_SERVERS
    try:
        answers = resolver.resolve(domain, 'A')
        return [rdata.to_text() for rdata in answers]
    except dns.resolver.NoAnswer:
        try:
            cnames = resolver.resolve(domain, 'CNAME')
            for cname in cnames:
                cname_target = cname.target.to_text().rstrip('.')
                return resolve_domain_ips_aliyun(cname_target, depth - 1)
        except Exception as e:
            print(f"阿里DNS查询 CNAME 失败: {e}")
            return []
    except Exception as e:
        print(f"阿里DNS查询 A 记录失败: {e}")
        return []

def extract_ipv4s(text: str):
    pattern = r'(?:\d{1,3}\.){3}\d{1,3}'
    candidates = re.findall(pattern, text)
    def valid(ip):
        try:
            parts = [int(p) for p in ip.split('.')]
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
        print(f"获取 GitHub IP列表异常: {e}")
        traceback.print_exc()
        return []

def list_a_records(name):
    url = f"https://api.cloudflare.com/client/v4/zones/{CF_ZONE_ID}/dns_records"
    params = {'type':'A', 'name':name, 'per_page':100}
    try:
        resp = requests.get(url, headers=HEADERS, params=params, timeout=10)
        resp.raise_for_status()
        return resp.json().get('result', [])
    except Exception as e:
        print(f"列出 A 记录异常: {e}")
        traceback.print_exc()
        return []

def delete_dns_record(record_id):
    url = f"https://api.cloudflare.com/client/v4/zones/{CF_ZONE_ID}/dns_records/{record_id}"
    try:
        resp = requests.delete(url, headers=HEADERS, timeout=10)
        resp.raise_for_status()
        print(f"删除 DNS 记录 {record_id} 成功")
        return True
    except Exception as e:
        print(f"删除 DNS 记录 {record_id} 失败: {e}")
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
    data = {
        'type':'A',
        'name': name,
        'content': ip,
    }
    try:
        resp = requests.post(url, headers=HEADERS, json=data, timeout=10)
        resp.raise_for_status()
        print(f"添加 DNS A 记录 {ip} 成功")
        return f"ip:{ip} 添加成功"
    except Exception as e:
        print(f"添加 DNS A 记录 {ip} 失败: {e}")
        traceback.print_exc()
        return f"ip:{ip} 添加失败"

def push_plus(content):
    if not PUSHPLUS_TOKEN:
        print("PUSHPLUS_TOKEN 为空，跳过推送")
        return
    url = "http://www.pushplus.plus/send"
    data = {
        "token": PUSHPLUS_TOKEN,
        "title": "IP优选DNS CF推送",
        "content": content,
        "template": "markdown",
        "channel": "wechat"
    }
    try:
        requests.post(url, json=data, timeout=10)
    except Exception as e:
        print(f"PushPlus 推送异常: {e}")

def main():
    domain = "cm.cf.cname.vvhan.com"
    github_url = "https://raw.githubusercontent.com/gslege/CloudflareIP/main/Cfxyz.txt"

    print(f"使用阿里云 DNS 解析 {domain}")
    domain_ips = resolve_domain_ips_aliyun(domain)
    print(f"阿里云 DNS 解析到的IP: {domain_ips}")

    print(f"从 GitHub 获取 IP 列表: {github_url}")
    github_ips = get_ips_from_github_raw(github_url)
    print(f"GitHub 获得 IP 列表: {github_ips}")

    all_ips = list(dict.fromkeys(domain_ips + github_ips))
    if not all_ips:
        print("未从任一渠道获取到IP，退出。")
        return

    max_records = os.getenv("CF_MAX_RECORDS")
    if max_records and max_records.isdigit():
        all_ips = all_ips[:int(max_records)]

    if not delete_all_a_records(CF_DNS_NAME):
        print("删除旧 A 记录失败，继续执行。")

    results = [create_dns_record(CF_DNS_NAME, ip) for ip in all_ips]

    push_plus("\n".join(results))

if __name__ == "__main__":
    main()
