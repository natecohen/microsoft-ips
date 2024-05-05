import ipaddress
import re
import urllib.error
import urllib.request


def write_list(directory, filename, items):
    if items:
        with open(directory / filename, "w") as f:
            for item in items:
                f.write(f"{item}\n")


def natsort_fqdn(s):
    split_text = re.split(r"(\d+|\*|\.)", s)
    sort_key = []
    for text in split_text:
        if text.isdigit():
            sort_key.append((int(text), text))
        else:
            sort_key.append((0, text))
    return sort_key


# Sorts IPV6 before IVP4
# Also sorts IPV6 with :: notation first since the addresses are expanded
def natsort_ip(ip_list):
    def ip_sort_key(ip):
        addr = ipaddress.ip_network(ip)
        if isinstance(addr, ipaddress.IPv6Network):
            return 0, addr.network_address.packed
        else:
            return 1, addr.network_address.packed

    return sorted(ip_list, key=ip_sort_key)


def get_response_data(url):
    try:
        with urllib.request.urlopen(url) as response:
            data = response.read().decode()
            return data
    except urllib.error.URLError as e:
        raise Exception(f"Error: {e} while fetching data from {url}")


def return_fqdn_no_wildcard(url_set):
    re_wildcard_start_only = re.compile(r"^\*[^*]*$")

    urls_no_wildcard = set()
    for url in url_set:
        if re.match(re_wildcard_start_only, url):
            non_wildcard_url = url[2:]
            urls_no_wildcard.add(non_wildcard_url)
        elif "*" in url:
            # Discard URL with wildcard in the middle or end
            pass
        else:
            # No wildcard
            urls_no_wildcard.add(url)

    return urls_no_wildcard


def process_ips(ip_input, return_ipv6=False):
    ip_with_cidr = {"ipv6": set(), "ipv4": set()}

    for ip_addr_s in ip_input:
        try:
            addr = ipaddress.ip_network(ip_addr_s)
            ip_type = "ipv6" if isinstance(addr, ipaddress.IPv6Network) else "ipv4"
            if not addr.is_private:
                ip_with_cidr[ip_type].add(ip_addr_s)
        except ValueError:
            # Ignore invalid IP ranges
            pass

    return ip_with_cidr["ipv6"] if return_ipv6 else ip_with_cidr["ipv4"]
