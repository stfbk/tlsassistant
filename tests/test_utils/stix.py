import json


def load_stix_from_file(file_path):
    with open(file_path, 'r') as file:
        stix_data = json.load(file)
    return stix_data


def get_vulnerabilities_per_ip(stix_data):
    if isinstance(stix_data, str):
        stix_data = load_stix_from_file(stix_data)
    vulnerabilities_per_ip = {}
    items_categories = {}
    ips_mapping = {}
    vulns_mapping = {}
    for item in stix_data.get('objects', []):
        if item.get('type') == 'sighting':
            items_categories[item['id']] = {
                "vuln_id": item.get('sighting_of_ref'),
                "hosts": item.get('observed_data_refs', [])
            }
        elif item.get('type') == 'vulnerability':
            # items_categories[item['id']] = {
            #     "name": item.get('name'),
            #     "id": item.get('id')
            # }
            vulns_mapping[item['id']] = item.get('name')
        elif item.get("type") == "observed-data":
            if len(item.get('objects', {})) == 1:
                # items_categories[item['id']] = {
                #     "ip": item["objects"]["0"].get('value')
                # }
                ips_mapping[item['id']] = item["objects"]["0"].get('value')

    
    for k in filter(lambda x: x.startswith("sighting"), items_categories.keys()):
        hosts = items_categories[k]["hosts"]
        items_categories[k]["vuln_id"] = vulns_mapping.get(items_categories[k]["vuln_id"], items_categories[k]["vuln_id"])
        for i, host in enumerate(hosts):
            hosts[i] = ips_mapping.get(host)

        for host in hosts:
            if host not in vulnerabilities_per_ip:
                vulnerabilities_per_ip[host] = []
            vulnerabilities_per_ip[host].append(items_categories[k]["vuln_id"])

    return vulnerabilities_per_ip
