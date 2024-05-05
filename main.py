import json
import re
import uuid
from pathlib import Path
from urllib.parse import urlparse

import util


def process_m365():
    client_request_id = str(uuid.uuid4())

    endpoints = ["Worldwide", "China", "USGOVDoD", "USGOVGCCHigh"]
    mem_endpoints = ["Worldwide", "USGOVDoD"]

    for endpoint in endpoints:
        service_areas = {"All": {"urls": set(), "ips": set()}}

        json_url = f"https://endpoints.office.com/endpoints/{endpoint}?ClientRequestId={client_request_id}"
        try:
            data = json.loads(util.get_response_data(json_url))

            # For whatever reason, the MEM serviceArea is not included by default
            if endpoint in mem_endpoints:
                try:
                    mem_json_url = f"https://endpoints.office.com/endpoints/{endpoint}?ServiceAreas=MEM&ClientRequestId={client_request_id}"
                    mem_json_data = json.loads(util.get_response_data(mem_json_url))

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

            sorted_fqdn = sorted(service_urls, key=util.natsort_fqdn)
            util.write_list(outdir, "fqdn_wildcard.txt", sorted_fqdn)

            fqdn_no_wildcard = util.return_fqdn_no_wildcard(service_urls)
            sorted_fqdn_no_wildcard = sorted(fqdn_no_wildcard, key=util.natsort_fqdn)
            util.write_list(outdir, "fqdn_no_wildcard.txt", sorted_fqdn_no_wildcard)

            sorted_ips = util.natsort_ip(service_ips)
            util.write_list(outdir, "ip_cidr.txt", sorted_ips)

            sorted_ipv6 = util.natsort_ip(util.process_ips(service_ips, return_ipv6=True))
            util.write_list(outdir, "ipv6_cidr.txt", sorted_ipv6)

            sorted_ipv4 = util.natsort_ip(util.process_ips(service_ips, return_ipv6=False))
            util.write_list(outdir, "ipv4_cidr.txt", sorted_ipv4)


def process_office_for_mac():
    md_url = "https://raw.githubusercontent.com/MicrosoftDocs/microsoft-365-docs/public/microsoft-365/enterprise/network-requests-in-office-2016-for-mac.md"

    office_mac_fqdns = set()

    try:
        md_data = util.get_response_data(md_url)

        extracted_tables = util.extract_tables(md_data)

        for table in extracted_tables:
            table_data = util.md_table_to_dict(table)

            table_urls = [x["**URL**"] for x in table_data]

            extracted_fqdn_list = util.extract_network_item(table_urls, util.re_url)

            office_mac_fqdns.update(extracted_fqdn_list)

    except:
        pass

    outdir = Path(__file__).parent / "office-mac"
    outdir.mkdir(parents=True, exist_ok=True)

    sorted_fqdn = sorted(office_mac_fqdns, key=util.natsort_fqdn)
    util.write_list(outdir, "fqdn_wildcard.txt", sorted_fqdn)

    fqdn_no_wildcard = util.return_fqdn_no_wildcard(office_mac_fqdns)
    sorted_fqdn_no_wildcard = sorted(fqdn_no_wildcard, key=util.natsort_fqdn)
    util.write_list(outdir, "fqdn_no_wildcard.txt", sorted_fqdn_no_wildcard)


def process_azure():
    endpoints = ["Public", "AzureGermany", "AzureGovernment", "China"]

    for endpoint in endpoints:
        json_url = f"https://azureipranges.azurewebsites.net/Data/{endpoint}.json"

        try:
            data = json.loads(util.get_response_data(json_url))

            region_service_list = {}

            for item in data["values"]:

                # Skip generic AzureCloud
                if item["id"].startswith("AzureCloud"):
                    continue

                region = item["properties"].get("region") or "_noregion"
                system_service = item["properties"].get("systemService") or item.get("id")
                address_prefixes = set(item["properties"]["addressPrefixes"])

                if region not in region_service_list:
                    region_service_list[region] = {}

                if system_service not in region_service_list[region]:
                    region_service_list[region][system_service] = set()

                region_service_list[region][system_service].update(address_prefixes)

            for region, services in region_service_list.items():
                for service, address_prefixes in services.items():
                    outdir = Path(__file__).parent / "azure" / endpoint / region / service
                    outdir.mkdir(parents=True, exist_ok=True)

                    sorted_ips = util.natsort_ip(address_prefixes)
                    util.write_list(outdir, "ip_cidr.txt", sorted_ips)

                    sorted_ipv6 = util.natsort_ip(util.process_ips(address_prefixes, return_ipv6=True))
                    util.write_list(outdir, "ipv6_cidr.txt", sorted_ipv6)

                    sorted_ipv4 = util.natsort_ip(util.process_ips(address_prefixes, return_ipv6=False))
                    util.write_list(outdir, "ipv4_cidr.txt", sorted_ipv4)

        except:
            pass


if __name__ == "__main__":
    process_m365()
    process_office_for_mac()
    process_azure()
