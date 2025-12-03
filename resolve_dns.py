import dns.resolver
import ipaddress

DNS_SERVERS = ['1.1.1.1', '8.8.8.8', '114.114.114.114']

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
        # 先尝试查A记录
        answers = resolver.resolve(domain, 'A')
        for rdata in answers:
            ip = rdata.to_text()
            if is_valid_ipv4(ip):
                ips.add(ip)
        if ips:
            print(f"[A] {domain} -> {ips}")
            return list(ips)
    except dns.resolver.NoAnswer:
        # 没有A记录，试着查CNAME
        try:
            cnames = resolver.resolve(domain, 'CNAME')
            for cname in cnames:
                target = cname.target.to_text()
                print(f"[CNAME] {domain} -> {target}")
                # 递归解析CNAME目标域名
                ips.update(resolve_all_ips(target.rstrip('.'), depth - 1))
        except dns.resolver.NoAnswer:
            print(f"No A or CNAME record found for {domain}")
        except Exception as e:
            print(f"CNAME lookup error for {domain}: {e}")
    except Exception as e:
        print(f"A record lookup error for {domain}: {e}")

    return list(ips)

if __name__ == "__main__":
    domain = "cm.cf.cname.vvhan.com"
    ips = resolve_all_ips(domain)
    print(f"\n{domain} 解析得到的所有A记录IP：")
    for ip in ips:
        print(ip)
