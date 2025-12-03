import dns.resolver

DNS_SERVERS = ['8.8.8.8', '114.114.114.114']

def resolve_domain_ips(domain, depth=5):
    """
    解析域名所有关联的A记录IP，如果存在CNAME则递归处理

    :param domain: 要解析的域名
    :param depth: CNAME递归深度防止无限循环
    :return: 所有A记录IP列表
    """
    if depth == 0:
        return []

    ips = set()
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = DNS_SERVERS

    try:
        # 先查询A记录
        answers = resolver.resolve(domain, 'A')
        for rdata in answers:
            ips.add(rdata.to_text())
    except dns.resolver.NoAnswer:
        # 没有A记录，尝试查询CNAME
        try:
            cnames = resolver.resolve(domain, 'CNAME')
            for cname in cnames:
                target = cname.target.to_text().rstrip('.')
                # 递归解析CNAME对应的域名A记录
                resolved_ips = resolve_domain_ips(target, depth - 1)
                ips.update(resolved_ips)
        except Exception as e:
            print(f"CNAME查询失败: {e}")
    except Exception as e:
        print(f"A记录查询失败: {e}")

    return list(ips)

if __name__ == "__main__":
    domain_name = "cm.cf.cname.vvhan.com"
    all_ips = resolve_domain_ips(domain_name)
    print(f"{domain_name} 解析到的所有IP：")
    for ip in all_ips:
        print(ip)
