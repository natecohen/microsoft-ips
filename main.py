import json
import os
import urllib.error
import urllib.request
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path

from patterns import RE_URL
from util import (
    extract_network_item,
    extract_tables,
    get_last_commit_date,
    get_response_data,
    md_table_to_dict,
    natsort_fqdn,
    natsort_ip,
    process_ips,
    return_fqdn_no_wildcard,
    write_list,
)

from urlextract import URLExtract


def process_markdown_common(md_url, url_key, outdir, urlextract=False, ignore_list=None):
    fqdns = set()
    md_data = get_response_data(md_url)

    if urlextract:
        extractor = URLExtract()
        if ignore_list:
            extractor.ignore_list = ignore_list
        fqdns.update(extractor.find_urls(md_data))

    else:
        extracted_tables = extract_tables(md_data)

        for table in extracted_tables:
            table_data = md_table_to_dict(table)
            table_urls = [x.get(url_key) for x in table_data if url_key in x]
            extracted_fqdn_list = extract_network_item(table_urls, RE_URL)
            fqdns.update(extracted_fqdn_list)

    outdir = Path(__file__).parent / outdir
    outdir.mkdir(parents=True, exist_ok=True)

    sorted_fqdn = sorted(fqdns, key=natsort_fqdn)
    write_list(outdir, "fqdn_wildcard.txt", sorted_fqdn)

    fqdn_no_wildcard = return_fqdn_no_wildcard(fqdns)
    sorted_fqdn_no_wildcard = sorted(fqdn_no_wildcard, key=natsort_fqdn)
    write_list(outdir, "fqdn_no_wildcard.txt", sorted_fqdn_no_wildcard)


def _write_fqdn_files(outdir, urls):
    outdir.mkdir(parents=True, exist_ok=True)

    sorted_fqdn = sorted(urls, key=natsort_fqdn)
    write_list(outdir, "fqdn_wildcard.txt", sorted_fqdn)

    fqdn_no_wildcard = return_fqdn_no_wildcard(urls)
    sorted_fqdn_no_wildcard = sorted(fqdn_no_wildcard, key=natsort_fqdn)
    write_list(outdir, "fqdn_no_wildcard.txt", sorted_fqdn_no_wildcard)


def _write_ip_files(outdir, ips):
    outdir.mkdir(parents=True, exist_ok=True)

    sorted_ips = natsort_ip(ips)
    write_list(outdir, "ip_cidr.txt", sorted_ips)

    sorted_ipv6 = natsort_ip(process_ips(ips, return_ipv6=True))
    write_list(outdir, "ipv6_cidr.txt", sorted_ipv6)

    sorted_ipv4 = natsort_ip(process_ips(ips, return_ipv6=False))
    write_list(outdir, "ipv4_cidr.txt", sorted_ipv4)


class MicrosoftUpdateProcessor:
    def __init__(self, update_file):
        self.update_file = update_file
        self.last_update_data = {}
        self.updated_categories = []

        try:
            with open(self.update_file) as f:
                self.last_update_data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            pass

    def _check_and_update(self, category, new_version):
        if new_version != self.last_update_data.get(category):
            self.last_update_data[category] = new_version
            self.updated_categories.append(category)
            print(f"Processing: {category}")
            return True

        print(f"No update: {category}")
        return False

    def has_updates(self):
        return bool(self.updated_categories)

    def save_updates(self):
        with open(self.update_file, "w") as f:
            json.dump(self.last_update_data, f, indent=2)

    def get_updated_categories(self):
        return self.updated_categories

    def process_azure(self):
        endpoints = ["Public", "AzureGermany", "AzureGovernment", "China"]

        for endpoint in endpoints:
            category = f"azure-{endpoint}"
            json_url = f"https://azureipranges.azurewebsites.net/Data/{endpoint}.json"

            try:
                request = urllib.request.Request(json_url, method="HEAD")
                request.add_header("If-Modified-Since", "Thu, 01 Jan 1970 00:00:00 GMT")
                last_modified = urllib.request.urlopen(request).getheader("last-modified")

                if not self._check_and_update(category, last_modified):
                    continue

                data = json.loads(get_response_data(json_url))
                region_service_list = {}

                for item in data["values"]:
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
                        _write_ip_files(outdir, address_prefixes)

            except (json.JSONDecodeError, urllib.error.URLError, KeyError) as e:
                print(f"Error processing {category}: {type(e).__name__}")
                continue

    def process_m365(self):
        client_request_id = str(uuid.uuid4())

        endpoints = ["Worldwide", "China", "USGOVDoD", "USGOVGCCHigh"]
        mem_endpoints = ["Worldwide", "USGOVDoD"]

        for endpoint in endpoints:
            category = f"microsoft-365-{endpoint}"
            change_url = f"https://endpoints.office.com/version/{endpoint}?allversions=true&format=rss&clientrequestid={client_request_id}"

            try:
                change_data_root = ET.fromstring(get_response_data(change_url))
                last_build_date = change_data_root.find(".//lastBuildDate").text

                if not self._check_and_update(category, last_build_date):
                    continue

            except (ET.ParseError, urllib.error.URLError):
                print(f"Error getting version for {category}")
                continue

            service_areas = {"All": {"urls": set(), "ips": set()}}

            json_url = f"https://endpoints.office.com/endpoints/{endpoint}?ClientRequestId={client_request_id}"
            try:
                data = json.loads(get_response_data(json_url))

                # MEM serviceArea is not included by default
                if endpoint in mem_endpoints:
                    try:
                        mem_data = json.loads(
                            get_response_data(
                                f"https://endpoints.office.com/endpoints/{endpoint}?ServiceAreas=MEM&ClientRequestId={client_request_id}"
                            )
                        )
                        data.extend(obj for obj in mem_data if obj.get("serviceArea") == "MEM")
                    except (json.JSONDecodeError, urllib.error.URLError):
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
            except (json.JSONDecodeError, urllib.error.URLError, KeyError) as e:
                print(f"Error processing {category}: {type(e).__name__}")
                continue

            for service_area in service_areas:
                outdir = Path(__file__).parent / "microsoft-365" / endpoint / service_area
                _write_fqdn_files(outdir, service_areas[service_area]["urls"])
                _write_ip_files(outdir, service_areas[service_area]["ips"])

    def process_office_for_mac(self):
        endpoint = "office-mac"
        repo = "MicrosoftDocs/microsoft-365-docs"
        path = "microsoft-365/enterprise/network-requests-in-office-2016-for-mac.md"

        try:
            last_commit_date = get_last_commit_date(repo, path)
            if not self._check_and_update(endpoint, last_commit_date):
                return

            md_url = f"https://raw.githubusercontent.com/{repo}/public/{path}"
            process_markdown_common(md_url, "**URL**", endpoint)

        except (urllib.error.URLError, KeyError, json.JSONDecodeError) as e:
            print(f"Error processing {endpoint}: {type(e).__name__}")

    def process_windows_11(self):
        endpoint = "windows-11"
        repo = "MicrosoftDocs/windows-itpro-docs"
        path = "windows/privacy/manage-windows-11-endpoints.md"

        try:
            last_commit_date = get_last_commit_date(repo, path)
            if not self._check_and_update(endpoint, last_commit_date):
                return

            md_url = f"https://raw.githubusercontent.com/{repo}/public/{path}"
            process_markdown_common(md_url, "Destination", endpoint)

        except (urllib.error.URLError, KeyError, json.JSONDecodeError) as e:
            print(f"Error processing {endpoint}: {type(e).__name__}")

    def process_entra_connect(self):
        endpoint = "entra-connect"
        repo = "MicrosoftDocs/entra-docs"
        path = "docs/identity/hybrid/connect/tshoot-connect-connectivity.md"

        try:
            last_commit_date = get_last_commit_date(repo, path)
            if not self._check_and_update(endpoint, last_commit_date):
                return

            md_url = f"https://raw.githubusercontent.com/{repo}/main/{path}"
            process_markdown_common(md_url, "Destination", f"{endpoint}/Worldwide")

        except (urllib.error.URLError, KeyError, json.JSONDecodeError) as e:
            print(f"Error processing {endpoint}: {type(e).__name__}")

    def process_entra_connect_health(self):
        endpoint = "entra-connect-health"
        repo = "MicrosoftDocs/entra-docs"
        path = "docs/identity/hybrid/connect/how-to-connect-health-agent-install.md"

        try:
            last_commit_date = get_last_commit_date(repo, path)
            if not self._check_and_update(endpoint, last_commit_date):
                return

            md_url = f"https://raw.githubusercontent.com/{repo}/main/{path}"
            health_fqdns = {"Public": set(), "AzureGovernment": set()}

            md_data = get_response_data(md_url)
            extracted_tables = extract_tables(md_data)

            for table in extracted_tables:
                table_data = md_table_to_dict(table)
                for d in table_data:
                    if d.get("Domain environment") == "General public":
                        table_urls = [d.get("Required Azure service endpoints")]
                        extracted_fqdn_list = extract_network_item(table_urls, RE_URL)
                        health_fqdns["Public"].update(extracted_fqdn_list)
                    elif d.get("Domain environment") == "Azure Government":
                        table_urls = [d.get("Required Azure service endpoints")]
                        extracted_fqdn_list = extract_network_item(table_urls, RE_URL)
                        health_fqdns["AzureGovernment"].update(extracted_fqdn_list)
                    else:
                        break

            for endpoint_name, urls in health_fqdns.items():
                outdir = Path(__file__).parent / "entra-connect-health" / endpoint_name
                _write_fqdn_files(outdir, urls)

        except (urllib.error.URLError, KeyError, json.JSONDecodeError) as e:
            print(f"Error processing {endpoint}: {type(e).__name__}")

    def process_power_bi(self):
        endpoint = "power-bi"
        repo = "MicrosoftDocs/fabric-docs"
        path = "docs/security/power-bi-allow-list-urls.md"

        try:
            last_commit_date = get_last_commit_date(repo, path)
            if not self._check_and_update(endpoint, last_commit_date):
                return

            md_url = f"https://raw.githubusercontent.com/{repo}/main/{path}"
            process_markdown_common(md_url, "Destination", endpoint)

        except (urllib.error.URLError, KeyError, json.JSONDecodeError) as e:
            print(f"Error processing {endpoint}: {type(e).__name__}")

    def process_autopilot(self):
        endpoint = "windows-autopilot"
        repo = "MicrosoftDocs/memdocs"
        path = "autopilot/requirements.md"
        ignore_list = {
            "learn.microsoft.com",
            "www.microsoft.com",
            "support.microsoft.com",
            "techcommunity.microsoft.com",
            "youtube.com",
        }

        try:
            last_commit_date = get_last_commit_date(repo, path)
            if not self._check_and_update(endpoint, last_commit_date):
                return

            md_url = f"https://raw.githubusercontent.com/{repo}/main/{path}"
            process_markdown_common(md_url, "Destination", endpoint, True, ignore_list)

        except (urllib.error.URLError, KeyError, json.JSONDecodeError) as e:
            print(f"Error processing {endpoint}: {type(e).__name__}")


def main():
    processor = MicrosoftUpdateProcessor("last_update.json")

    processor.process_m365()
    processor.process_office_for_mac()
    processor.process_windows_11()
    processor.process_entra_connect()
    processor.process_entra_connect_health()
    processor.process_azure()
    processor.process_power_bi()
    processor.process_autopilot()

    updates_found = False
    updated_categories = ""

    if processor.has_updates():
        processor.save_updates()
        updated_categories = ", ".join(processor.get_updated_categories())
        print(f"Updates found: {updated_categories}")
        updates_found = True
    else:
        print("No updates found")

    # Set environment variables for GitHub Action
    env_path = os.getenv("GITHUB_ENV")
    if env_path:
        with open(env_path, "a") as f:
            f.write(f"UPDATES_FOUND={str(updates_found).lower()}\n")
            if updates_found:
                f.write(f"UPDATED_CATEGORIES={updated_categories}\n")


if __name__ == "__main__":
    main()
