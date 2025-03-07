import os
import json
import time
import logging
from jinja2 import Environment, FileSystemLoader
import requests
from main import get_domain
from database import Database

def read_json_dir(directory):
    results = []
    for file in os.listdir(directory):
        filepath = os.path.join(directory, file)
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
            results.append(data)
    return results

def request_cve_score(cve_id):
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    NVD_API_KEY = "b3cd1e5b-825b-4822-85e0-28663a21d775"
    headers = { "apiKey": NVD_API_KEY }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        cve_items = data.get("vulnerabilities", [])
        if cve_items:
            cve_item = cve_items[0].get("cve", {})
            metrics = cve_item.get("metrics", {})
            cvss_v3_data = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {})
            cvss_v2_data = metrics.get("cvssMetricV2", [{}])[0].get("cvssData", {})
            cvss_v3 = cvss_v3_data.get("baseScore")
            cvss_v2 = cvss_v2_data.get("baseScore")
            return cvss_v3 or cvss_v2
    return None  

def get_cve_score(cve_id, cve_db):
    if cve_db.contains("cve", "cve", cve_id):
        cve_score = cve_db.get("cve", "score", "cve", cve_id)
    else:
        cve_score = request_cve_score(cve_id)
        cve_db.add("cve", **{ "cve":cve_id, "score":cve_score })
    return cve_score

def write_out_html(results):
    env = Environment(loader=FileSystemLoader('templates'))
    template = env.get_template('template.html')
    rendered_html = template.render(results)
    with open('output.html', 'w') as f:
        f.write(rendered_html)

def main():
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
    cve_db = Database("cve.db")
    cve_db.create_table("cve", {
            "id": "INTEGER PRIMARY KEY AUTOINCREMENT",
            "cve": "TEXT UNIQUE NOT NULL",
            "score": "REAL"
        })

    results = []
    for file in os.listdir("scan_results"):
        filepath = os.path.join("scan_results", file)
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
            target_url = get_domain(data["target_url"])
            print(target_url)
            plugins = []
            for plugin in data["plugins"]:
                vulns = []
                for vuln in data["plugins"][plugin]["vulnerabilities"]:
                    cves = []
                    for cve in vuln["references"]["cve"]:
                        cve = f"CVE-{cve}"
                        score = get_cve_score(cve, cve_db)
                        cves.append({
                            "id":cve,
                            "score":score
                        })
                    vulns.append({
                        "vuln":vuln["title"],
                        "cves":cves
                    })
                plugins.append({
                    "plugin":plugin,
                    "vulns":vulns
                })
            results.append({
                "target_url":target_url,
                "plugins":plugins
            })

    write_out_html({ "results":results })

if __name__ == "__main__":
    main()