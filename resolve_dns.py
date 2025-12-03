import dns.resolver
import ipaddress

DNS_SERVERS = ['223.5.5.5']

def is_valid_ipv4(ip):
    try:
        return isinstance(ipaddress.ip_address(ip), ipaddress.IPv4Address)
    except:
        return False

def resolve_all_ips(domain, depth=5):
    if depth == 0:
        return []

    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = DNS_SERVERS
    ips = set()
    try:
        # 查询A记录
        answers = resolver.resolve(domain, 'A')
        for rdata in answers:
            ip = rdata.to_text()
            if is_valid_ipv4(ip):
                ips.add(ip)
        if ips:
            print(f"[A] {domain} -> {ips}")
            return list(ips)
    except dns.resolver.NoAnswer:
        try:
            # 查询CNAME
            cnames = resolver.resolve(domain, 'CNAME')
            for cname in cnames:
                target = cname.target.to_text().rstrip('.')
                print(f"[CNAME] {domain} -> {target}")
                ips.update(resolve_all_ips(target, depth-1))
        except Exception as e:
            print(f"CNAME查询失败: {e}")
    except Exception as e:
        print(f"A记录查询失败: {e}")
    return list(ips)

if __name__ == "__main__":
    domains = [
        "cm.cf.cname.vvhan.com",
        "ct.cf.cname.vvhan.com",
        "cu.cf.cname.vvhan.com",
    ]

    all_ips = {}

    for dom in domains:
        ips = resolve_all_ips(dom)
        all_ips[dom] = ips

    print("\n所有域名解析结果：")
    for dom, ips in all_ips.items():
        print(f"{dom} : {ips}")
