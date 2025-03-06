import os
import json
import logging
from jinja2 import Environment, FileSystemLoader
from database import Database

def read_json_dir(directory):
    results = []
    for file in os.listdir(directory):
        filepath = os.path.join(directory, file)
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
            results.append(data)
    return results

def write_out_html(results):
    env = Environment(loader=FileSystemLoader('templates'))
    template = env.get_template('template.html')
    rendered_html = template.render(results)
    with open('output.html', 'w') as f:
        f.write(rendered_html)

def main():
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
    directory = "scan_results"
    results = read_json_dir(directory)

    cve_db = Database("cve.db")
    cve_db.create_table("cve", {
            "id": "INTEGER PRIMARY KEY AUTOINCREMENT",
            "cve": "TEXT UNIQUE NOT NULL",
            "score": "REAL"
        })

    data = []
    for site in results:
        plugins = site["plugins"]
        url = site["target_url"]
        for plugin in plugins:
            vulnerabilities = plugins[plugin]["vulnerabilities"]
            print(url, plugin)
            for vuln in vulnerabilities:
                print(vuln["title"])

'''
Each site has plugins
Each plugin has vulnerabilities
Each vulnerability has a CVE
Each CVE has a score
'''

if __name__ == "__main__":
    main()