import hashlib
import json
import os
import urllib.error
import urllib.request
import uuid
from pathlib import Path

from patterns import RE_URL
from urlextract import URLExtract
from util import (
    extract_network_item,
    extract_tables,
    get_response_data,
    md_table_to_dict,
    natsort_fqdn,
    natsort_ip,
    process_ips,
    return_fqdn_no_wildcard,
)


def process_markdown_common(md_data, url_key, urlextract=False, ignore_list=None):
    fqdns = set()
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
    return fqdns


def write_if_changed(filepath, new_content_list):
    filepath.parent.mkdir(parents=True, exist_ok=True)
    new_content_str = "\n".join(new_content_list)
    if new_content_list:
        new_content_str += "\n"

    try:
        old_content_str = filepath.read_text(encoding="utf-8")
        if old_content_str == new_content_str:
            return False  # No changes
    except FileNotFoundError:
        pass  # File doesn't exist, so it's a change

    filepath.write_text(new_content_str, encoding="utf-8")
    return True  # Changes were made


def _write_fqdn_files(outdir, urls):
    sorted_fqdn = sorted(urls, key=natsort_fqdn)
    changed_fqdn = write_if_changed(outdir / "fqdn_wildcard.txt", sorted_fqdn)

    fqdn_no_wildcard = return_fqdn_no_wildcard(urls)
    sorted_fqdn_no_wildcard = sorted(fqdn_no_wildcard, key=natsort_fqdn)
    changed_wildcard = write_if_changed(outdir / "fqdn_no_wildcard.txt", sorted_fqdn_no_wildcard)

    return changed_fqdn or changed_wildcard


def _write_ip_files(outdir, ips):
    changed_ip = write_if_changed(outdir / "ip_cidr.txt", natsort_ip(ips))
    changed_ipv4 = write_if_changed(outdir / "ipv6_cidr.txt", natsort_ip(process_ips(ips, return_ipv6=True)))
    changed_ipv6 = write_if_changed(outdir / "ipv4_cidr.txt", natsort_ip(process_ips(ips, return_ipv6=False)))
    return changed_ip or changed_ipv4 or changed_ipv6


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

    def has_updates(self):
        return bool(self.updated_categories)

    def save_updates(self):
        with open(self.update_file, "w") as f:
            json.dump(self.last_update_data, f, indent=2)

    def get_updated_categories(self):
        return self.updated_categories

    def _process_generic_markdown(self, endpoint, repo, path, url_key, urlextract=False, ignore_list=None, subdir=None):
        try:
            md_url = f"https://raw.githubusercontent.com/{repo}/main/{path}"
            if endpoint in ["windows-11", "office-mac"]:
                md_url = f"https://raw.githubusercontent.com/{repo}/public/{path}"

            md_data = get_response_data(md_url)
            content_hash = hashlib.sha256(md_data.encode()).hexdigest()

            if content_hash == self.last_update_data.get(endpoint):
                print(f"No update: {endpoint}")
                return

            urls = process_markdown_common(md_data, url_key, urlextract, ignore_list)

            outdir = Path(__file__).parent / endpoint
            if subdir:
                outdir = outdir / subdir

            if _write_fqdn_files(outdir, urls):
                print(f"Update found for: {endpoint}")
                self.updated_categories.append(endpoint)
                self.last_update_data[endpoint] = content_hash
            else:
                print(f"No meaningful update: {endpoint}")

        except (urllib.error.URLError, KeyError, json.JSONDecodeError) as e:
            print(f"Error processing {endpoint}: {type(e).__name__}")

    def process_azure(self):
        endpoints = ["Public", "AzureGermany", "AzureGovernment", "China"]

        for endpoint in endpoints:
            category = f"azure-{endpoint}"
            json_url = f"https://azureipranges.azurewebsites.net/Data/{endpoint}.json"

            try:
                json_string = get_response_data(json_url)
                content_hash = hashlib.sha256(json_string.encode()).hexdigest()

                if content_hash == self.last_update_data.get(category):
                    print(f"No update: {category}")
                    continue

                data = json.loads(json_string)
                any_change_in_category = False

                # Process data into a structured map first
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

                # Now, iterate and write if changed
                for region, services in region_service_list.items():
                    for service, address_prefixes in services.items():
                        outdir = Path(__file__).parent / "azure" / endpoint / region / service
                        if _write_ip_files(outdir, address_prefixes):
                            any_change_in_category = True

                if any_change_in_category:
                    print(f"Update found for: {category}")
                    self.updated_categories.append(category)
                    self.last_update_data[category] = content_hash
                else:
                    print(f"No meaningful update: {category}")

            except (json.JSONDecodeError, urllib.error.URLError, KeyError) as e:
                print(f"Error processing {category}: {type(e).__name__}")
                continue

    def process_m365(self):
        client_request_id = str(uuid.uuid4())

        endpoints = ["Worldwide", "China", "USGOVDoD", "USGOVGCCHigh"]
        mem_endpoints = ["Worldwide", "USGOVDoD"]

        for endpoint in endpoints:
            category = f"microsoft-365-{endpoint}"

            try:
                json_url = f"https://endpoints.office.com/endpoints/{endpoint}?ClientRequestId={client_request_id}"
                data_list = json.loads(get_response_data(json_url))
                if endpoint in mem_endpoints:
                    try:
                        mem_data = json.loads(
                            get_response_data(
                                f"https://endpoints.office.com/endpoints/{endpoint}?ServiceAreas=MEM&ClientRequestId={client_request_id}"
                            )
                        )
                        data_list.extend(obj for obj in mem_data if obj.get("serviceArea") == "MEM")
                    except (json.JSONDecodeError, urllib.error.URLError):
                        pass

                data_list.sort(key=lambda x: x["id"])
                canonical_json = json.dumps(data_list)
                content_hash = hashlib.sha256(canonical_json.encode()).hexdigest()

                if content_hash == self.last_update_data.get(category):
                    print(f"No update: {category}")
                    continue

                service_areas = {"All": {"urls": set(), "ips": set()}}
                for obj in data_list:
                    service_area = obj["serviceArea"]
                    urls, ips = obj.get("urls"), obj.get("ips")
                    if service_area not in service_areas:
                        service_areas[service_area] = {"urls": set(), "ips": set()}
                    if urls:
                        service_areas[service_area]["urls"].update(urls)
                        service_areas["All"]["urls"].update(urls)
                    if ips:
                        service_areas[service_area]["ips"].update(ips)
                        service_areas["All"]["ips"].update(ips)

                any_change_in_category = False
                for service_area, data in service_areas.items():
                    outdir = Path(__file__).parent / "microsoft-365" / endpoint / service_area
                    urls_changed = _write_fqdn_files(outdir, data["urls"])
                    ips_changed = _write_ip_files(outdir, data["ips"])
                    if urls_changed or ips_changed:
                        any_change_in_category = True

                if any_change_in_category:
                    print(f"Update found for: {category}")
                    self.updated_categories.append(category)
                    self.last_update_data[category] = content_hash
                else:
                    print(f"No meaningful update: {category}")

            except (json.JSONDecodeError, urllib.error.URLError, KeyError) as e:
                print(f"Error processing {category}: {type(e).__name__}")

    def process_entra_connect_health(self):
        endpoint = "entra-connect-health"
        repo = "MicrosoftDocs/entra-docs"
        path = "docs/identity/hybrid/connect/how-to-connect-health-agent-install.md"
        try:
            md_url = f"https://raw.githubusercontent.com/{repo}/main/{path}"
            md_data = get_response_data(md_url)
            content_hash = hashlib.sha256(md_data.encode()).hexdigest()

            if content_hash == self.last_update_data.get(endpoint):
                print(f"No update: {endpoint}")
                return

            health_fqdns = {"Public": set(), "AzureGovernment": set()}
            extracted_tables = extract_tables(md_data)
            for table in extracted_tables:
                table_data = md_table_to_dict(table)
                for d in table_data:
                    if d.get("Domain environment") == "General public":
                        urls = extract_network_item([d.get("Required Azure service endpoints")], RE_URL)
                        health_fqdns["Public"].update(urls)
                    elif d.get("Domain environment") == "Azure Government":
                        urls = extract_network_item([d.get("Required Azure service endpoints")], RE_URL)
                        health_fqdns["AzureGovernment"].update(urls)

            any_change_in_category = False
            for endpoint_name, urls in health_fqdns.items():
                outdir = Path(__file__).parent / "entra-connect-health" / endpoint_name
                if _write_fqdn_files(outdir, urls):
                    any_change_in_category = True

            if any_change_in_category:
                print(f"Update found for: {endpoint}")
                self.updated_categories.append(endpoint)
                self.last_update_data[endpoint] = content_hash
            else:
                print(f"No meaningful update: {endpoint}")

        except (urllib.error.URLError, KeyError, json.JSONDecodeError) as e:
            print(f"Error processing {endpoint}: {type(e).__name__}")

    def process_office_for_mac(self):
        self._process_generic_markdown(
            "office-mac",
            "MicrosoftDocs/microsoft-365-docs",
            "microsoft-365/enterprise/network-requests-in-office-2016-for-mac.md",
            "**URL**",
        )

    def process_windows_11(self):
        self._process_generic_markdown(
            "windows-11",
            "MicrosoftDocs/windows-itpro-docs",
            "windows/privacy/manage-windows-11-endpoints.md",
            "Destination",
        )

    def process_entra_connect(self):
        self._process_generic_markdown(
            "entra-connect",
            "MicrosoftDocs/entra-docs",
            "docs/identity/hybrid/connect/tshoot-connect-connectivity.md",
            "URL",
            subdir="Worldwide",
        )

    def process_power_bi(self):
        self._process_generic_markdown(
            "power-bi",
            "MicrosoftDocs/fabric-docs",
            "docs/security/power-bi-allow-list-urls.md",
            "Destination",
        )

    def process_autopilot(self):
        ignore_list = {
            "learn.microsoft.com",
            "www.microsoft.com",
            "support.microsoft.com",
            "techcommunity.microsoft.com",
            "youtube.com",
            "www.youtube.com",
        }
        self._process_generic_markdown(
            "windows-autopilot",
            "MicrosoftDocs/memdocs",
            "autopilot/requirements.md",
            "Destination",
            urlextract=True,
            ignore_list=ignore_list,
        )


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
