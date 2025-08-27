import ipaddress
import json
import os
import re
import urllib.error
import urllib.request

from patterns import RE_IPV4, RE_IPV6, RE_MDTABLE


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
            return 0, addr.network_address.packed, addr.prefixlen
        return 1, addr.network_address.packed, addr.prefixlen

    return sorted(remove_redundant_ranges(ip_list), key=ip_sort_key)


def remove_redundant_ranges(ip_list):
    if not ip_list:
        return []

    networks = [(ip_str, ipaddress.ip_network(ip_str)) for ip_str in ip_list]

    result = []

    for i, (ip_str_i, network_i) in enumerate(networks):
        is_redundant = False

        # Check if this network is contained within any other network of the same version
        for j, (ip_str_j, network_j) in enumerate(networks):
            if i != j and network_i.version == network_j.version and network_i.subnet_of(network_j):
                is_redundant = True
                break

        if not is_redundant:
            result.append(ip_str_i)

    return result


def get_response_data(url, headers=None):
    req = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(req) as response:
        return response.read().decode()


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


def extract_tables(input_data):
    return re.findall(RE_MDTABLE, input_data)


def md_table_to_dict(table_string):
    lines = table_string.split("\n")
    if len(lines) < 3:
        return []

    keys = [k.strip() for k in lines[0].split("|")]
    return [
        {keys[i]: v.strip() for i, v in enumerate(line.split("|")) if 0 < i < len(keys) - 1}
        for line in lines[2:]  # Skip header and separator
    ]


def extract_network_item(source_list, pattern):
    result_list = []
    for item in source_list:
        # Split multiline strings into separate lines
        lines = re.split(r"\r?\n|<br\s*/?>", item)
        for line in lines:
            # Extract potential matches
            matches = re.findall(pattern, line)
            for match in matches:
                if pattern in (RE_IPV4, RE_IPV6):
                    # Normalize the IPs so single IP gets /32 or /128 appended
                    result_list.append(str(ipaddress.ip_network(match)))
                else:
                    # Edge case to avoid italicized markdown
                    if not re.search(rf"`\S*{re.escape(match)}\S*`", line) and match.count("*") > 1:
                        match = match.replace("*", "")

                    result_list.append(match.lower())
    return result_list


def get_last_commit_date(repo, path):
    url = f"https://api.github.com/repos/{repo}/commits?path={path}"
    headers = {}

    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"token {token}"

    data = json.loads(get_response_data(url, headers))

    return data[0]["commit"]["committer"]["date"]
