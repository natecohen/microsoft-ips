import json
import re
import urllib.request
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import urlparse

import util


def process_m365():
    client_request_id = str(uuid.uuid4())

    endpoints = ["Worldwide", "China", "USGOVDoD", "USGOVGCCHigh"]
    mem_endpoints = ["Worldwide", "USGOVDoD"]

    for endpoint in endpoints:

        change_url = f"https://endpoints.office.com/version/{endpoint}?allversions=true&format=rss&clientrequestid={client_request_id}"

        try:
            change_data_root = ET.fromstring(util.get_response_data(change_url))
            last_build_date = change_data_root.find(".//lastBuildDate").text

            if last_build_date == last_update_data[f"microsoft-365-{endpoint}"]:
                print(f"No update: microsoft-365-{endpoint}")
                continue
            else:
                last_update_data[f"microsoft-365-{endpoint}"] = last_build_date

        except:
            pass

        service_areas = {"All": {"urls": set(), "ips": set()}}

        json_url = f"https://endpoints.office.com/endpoints/{endpoint}?ClientRequestId={client_request_id}"
        try:
            data = json.loads(util.get_response_data(json_url))

            # MEM serviceArea is not included by default
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
            continue

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

        with open("last_update.json", "w") as f:
            json.dump(last_update_data, f, indent=2)


def process_markdown_common(md_url, url_key, outdir):
    fqdns = set()

    try:
        md_data = util.get_response_data(md_url)

        extracted_tables = util.extract_tables(md_data)

        for table in extracted_tables:
            table_data = util.md_table_to_dict(table)
            table_urls = [x.get(url_key) for x in table_data if url_key in x]
            extracted_fqdn_list = util.extract_network_item(table_urls, util.re_url)
            fqdns.update(extracted_fqdn_list)
    except:
        pass

    outdir = Path(__file__).parent / outdir
    outdir.mkdir(parents=True, exist_ok=True)

    sorted_fqdn = sorted(fqdns, key=util.natsort_fqdn)
    util.write_list(outdir, "fqdn_wildcard.txt", sorted_fqdn)

    fqdn_no_wildcard = util.return_fqdn_no_wildcard(fqdns)
    sorted_fqdn_no_wildcard = sorted(fqdn_no_wildcard, key=util.natsort_fqdn)
    util.write_list(outdir, "fqdn_no_wildcard.txt", sorted_fqdn_no_wildcard)


def process_office_for_mac():
    endpoint = "office-mac"
    repo = "MicrosoftDocs/microsoft-365-docs"
    path = "microsoft-365/enterprise/network-requests-in-office-2016-for-mac.md"

    last_commit_date = util.get_last_commit_date(repo, path)

    if last_commit_date == last_update_data[endpoint]:
        print(f"No update: {endpoint}")
        return
    else:
        last_update_data[endpoint] = last_commit_date

    md_url = f"https://raw.githubusercontent.com/{repo}/public/{path}"

    process_markdown_common(md_url, "Destination", endpoint)

    with open("last_update.json", "w") as f:
        json.dump(last_update_data, f, indent=2)


def process_windows_11():
    endpoint = "windows-11"
    repo = "MicrosoftDocs/windows-itpro-docs"
    path = "windows/privacy/manage-windows-11-endpoints.md"

    last_commit_date = util.get_last_commit_date(repo, path)

    if last_commit_date == last_update_data[endpoint]:
        print(f"No update: {endpoint}")
        return
    else:
        last_update_data[endpoint] = last_commit_date

    md_url = f"https://raw.githubusercontent.com/{repo}/public/{path}"

    process_markdown_common(md_url, "Destination", endpoint)

    with open("last_update.json", "w") as f:
        json.dump(last_update_data, f, indent=2)


def process_entra_connect():
    endpoint = "entra-connect"
    repo = "MicrosoftDocs/entra-docs"
    path = "docs/identity/hybrid/connect/tshoot-connect-connectivity.md"

    last_commit_date = util.get_last_commit_date(repo, path)

    if last_commit_date == last_update_data[endpoint]:
        print(f"No update: {endpoint}")
        return
    else:
        last_update_data[endpoint] = last_commit_date

    md_url = f"https://raw.githubusercontent.com/{repo}/main/{path}"

    process_markdown_common(md_url, "Destination", f"{endpoint}/Worldwide")

    with open("last_update.json", "w") as f:
        json.dump(last_update_data, f, indent=2)


def process_entra_connect_health():
    endpoint = "entra-connect-health"
    repo = "MicrosoftDocs/entra-docs"
    path = "docs/identity/hybrid/connect/how-to-connect-health-agent-install.md"

    last_commit_date = util.get_last_commit_date(repo, path)

    if last_commit_date == last_update_data[endpoint]:
        print(f"No update: {endpoint}")
        return
    else:
        last_update_data[endpoint] = last_commit_date

    md_url = f"https://raw.githubusercontent.com/{repo}/main/{path}"

    health_fqdns = {"Public": set(), "AzureGovernment": set()}

    try:
        md_data = util.get_response_data(md_url)

        extracted_tables = util.extract_tables(md_data)

        for table in extracted_tables:
            table_data = util.md_table_to_dict(table)

            for d in table_data:
                if d.get("Domain environment") == "General public":
                    table_urls = [d.get("Required Azure service endpoints")]
                    extracted_fqdn_list = util.extract_network_item(table_urls, util.re_url)
                    health_fqdns["Public"].update(extracted_fqdn_list)

                elif d.get("Domain environment") == "Azure Government":
                    table_urls = [d.get("Required Azure service endpoints")]
                    extracted_fqdn_list = util.extract_network_item(table_urls, util.re_url)
                    health_fqdns["AzureGovernment"].update(extracted_fqdn_list)

                else:
                    break

    except:
        pass

    for endpoint, urls in health_fqdns.items():

        outdir = Path(__file__).parent / "entra-connect-health" / endpoint
        outdir.mkdir(parents=True, exist_ok=True)

        sorted_fqdn = sorted(urls, key=util.natsort_fqdn)
        util.write_list(outdir, "fqdn_wildcard.txt", sorted_fqdn)

        fqdn_no_wildcard = util.return_fqdn_no_wildcard(urls)
        sorted_fqdn_no_wildcard = sorted(fqdn_no_wildcard, key=util.natsort_fqdn)
        util.write_list(outdir, "fqdn_no_wildcard.txt", sorted_fqdn_no_wildcard)

    with open("last_update.json", "w") as f:
        json.dump(last_update_data, f, indent=2)


def process_azure():
    endpoints = ["Public", "AzureGermany", "AzureGovernment", "China"]

    for endpoint in endpoints:
        json_url = f"https://azureipranges.azurewebsites.net/Data/{endpoint}.json"

        head_request = urllib.request.Request(json_url, method="HEAD")
        head_request.add_header("If-Modified-Since", "Thu, 01 Jan 1970 00:00:00 GMT")
        response = urllib.request.urlopen(head_request)

        last_modified = response.getheader("last-modified")

        if last_modified == last_update_data[f"azure-{endpoint}"]:
            print(f"No update: azure-{endpoint}")
            continue
        else:
            last_update_data[f"azure-{endpoint}"] = last_modified

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

            with open("last_update.json", "w") as f:
                json.dump(last_update_data, f, indent=2)

        except:
            continue


if __name__ == "__main__":
    global last_update_data

    with open("last_update.json", "r") as f:
        last_update_data = json.load(f)

    process_m365()
    process_office_for_mac()
    process_windows_11()
    process_entra_connect()
    process_entra_connect_health()
    process_azure()
