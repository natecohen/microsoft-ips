import ipaddress
import json
import re
import urllib.error
import urllib.request
from urllib.parse import urlparse

import uuid
from pathlib import Path


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
    ipv6_with_cidr = set()
    ipv4_with_cidr = set()

    for ip_addr_s in ip_input:
        try:
            addr = ipaddress.ip_network(ip_addr_s)
            if isinstance(addr, ipaddress.IPv6Network):
                ipv6_with_cidr.add(ip_addr_s)
            elif isinstance(addr, ipaddress.IPv4Network):
                ipv4_with_cidr.add(ip_addr_s)
        except ValueError:
            # Ignore invalid IP ranges
            pass

    if return_ipv6 is True:
        return ipv6_with_cidr
    else:
        return ipv4_with_cidr


def process_m365():
    client_request_id = str(uuid.uuid4())

    endpoints = ["Worldwide", "China", "USGOVDoD", "USGOVGCCHigh"]
    mem_endpoints = ["Worldwide", "USGOVDoD"]

    for endpoint in endpoints:
        service_areas = {"All": {"urls": set(), "ips": set()}}

        json_url = f"https://endpoints.office.com/endpoints/{endpoint}?ClientRequestId={client_request_id}"
        try:
            data = json.loads(get_response_data(json_url))

            # For whatever reason, the MEM serviceArea is not included by default
            if endpoint in mem_endpoints:
                try:
                    mem_json_url = f"https://endpoints.office.com/endpoints/{endpoint}?ServiceAreas=MEM&ClientRequestId={client_request_id}"
                    mem_json_data = json.loads(get_response_data(mem_json_url))

                    for obj in mem_json_data:
                        if obj.get("serviceArea") == "MEM":
                            data.append(obj)
                except:
                    pass

            for obj in data:
                service_area = obj["serviceArea"]
                urls = obj.get("urls")
                ips = obj.get("ips")

                if service_area not in service_areas:
                    service_areas[service_area] = {"urls": set(), "ips": set()}

                if urls is not None:
                    service_areas[service_area]["urls"].update(urls)
                    service_areas["All"]["urls"].update(urls)
                if ips is not None:
                    service_areas[service_area]["ips"].update(ips)
                    service_areas["All"]["ips"].update(ips)
        except:
            pass

        for service_area in service_areas:
            outdir = Path(__file__).parent / "microsoft-365" / endpoint / service_area
            outdir.mkdir(parents=True, exist_ok=True)

            service_urls = service_areas[service_area]["urls"]
            service_ips = service_areas[service_area]["ips"]

            sorted_fqdn = sorted(service_urls, key=natsort_fqdn)
            write_list(outdir, "fqdn_wildcard.txt", sorted_fqdn)

            fqdn_no_wildcard = return_fqdn_no_wildcard(service_urls)
            sorted_fqdn_no_wildcard = sorted(fqdn_no_wildcard, key=natsort_fqdn)
            write_list(outdir, "fqdn_no_wildcard.txt", sorted_fqdn_no_wildcard)

            sorted_ips = natsort_ip(service_ips)
            write_list(outdir, "ip_cidr.txt", sorted_ips)

            sorted_ipv6 = natsort_ip(process_ips(service_ips, return_ipv6=True))
            write_list(outdir, "ipv6_cidr.txt", sorted_ipv6)

            sorted_ipv4 = natsort_ip(process_ips(service_ips, return_ipv6=False))
            write_list(outdir, "ipv4_cidr.txt", sorted_ipv4)


def process_office_for_mac():
    md_url = "https://raw.githubusercontent.com/MicrosoftDocs/microsoft-365-docs/public/microsoft-365/enterprise/network-requests-in-office-2016-for-mac.md"

    office_mac_fqdns = set()

    try:
        md_data = get_response_data(md_url).splitlines()

        in_table = False

        for line in md_data:
            stripped_line = line.strip()

            # Start of a new table
            if stripped_line.startswith("|") and "---" in stripped_line:
                in_table = True
                continue

            # End of a table
            if not stripped_line.startswith("|"):
                in_table = False
                continue

            if in_table:
                first_column_value = stripped_line.split("|")[1].strip()
                raw_url = re.findall(r"`(.*?)`", first_column_value)[1]
                parsed_uri = urlparse(raw_url)
                fqdn = f"{parsed_uri.netloc}"
                office_mac_fqdns.add(fqdn)

    except:
        pass

    outdir = Path(__file__).parent / "office-mac"
    outdir.mkdir(parents=True, exist_ok=True)

    sorted_fqdn = sorted(office_mac_fqdns, key=natsort_fqdn)
    write_list(outdir, "fqdn_wildcard.txt", sorted_fqdn)

    fqdn_no_wildcard = return_fqdn_no_wildcard(office_mac_fqdns)
    sorted_fqdn_no_wildcard = sorted(fqdn_no_wildcard, key=natsort_fqdn)
    write_list(outdir, "fqdn_no_wildcard.txt", sorted_fqdn_no_wildcard)


if __name__ == "__main__":
    process_m365()
    process_office_for_mac()
