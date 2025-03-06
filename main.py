import logging
import subprocess
import json
import requests
import os
from dotenv import load_dotenv
from urllib.parse import urlparse
from datetime import datetime, timedelta
from database import Database

def run_command(command, quiet=False):
    if not quiet:
        logging.debug(f"Running command `{command}`")
    command_arr = command.split(" ")
    result = subprocess.run(command_arr, capture_output=True, text=True)
    return result

def get_result_json(result):
    logging.debug(f"Parsing json output")
    return json.loads(result.stdout)

def check_wordpress(url):
    logging.debug(f"Checking if {url} is wordpress")
    result = run_command(f"docker run --rm wpscanteam/wpscan --url https://{url} --detection-mode passive --format json")
    if result.returncode != 0:
        logging.error("Error in running command")
        logging.error(result.stderr)
    return result.returncode == 0

def scan_sites(sites, wpscan_api_keys):
    for site, api_key in zip(sites, wpscan_api_keys):
        result = run_command(f"docker run --rm wpscanteam/wpscan --url https://{site} --api-token {api_key} --enumerate vp --format json", quiet=True)
        json_result = get_result_json(result)
        filename = f"scan_results/{site.replace('.', '_')}.json"
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(json_result, f, indent=4)

def init_docker_image():
    logging.debug(f"Initalizing docker image wpscan.tar")
    run_command("docker load -i wpscan.tar")

def generate_query():
    today = datetime.today().strftime('%Y-%m-%d')
    yesterday = (datetime.today() - timedelta(days=1)).strftime('%Y-%m-%d')
    query = f"inurl:/wp-content after:{yesterday} before:{today}"
    return query

def get_domain(url):
    parsed_url = urlparse(url)
    full_domain = parsed_url.netloc
    domain = full_domain.split(':')[0]
    return domain

def google_dork(quantity, database):
    API_KEY = os.getenv("GOOGLE_API_KEY")
    SEARCH_ENGINE_ID = "119312effa6f545d5"
    url = "https://www.googleapis.com/customsearch/v1"
    query = generate_query()
    results_per_request = 10
    wordpress_sites = []
    start = 1

    while True:
        params = {
            "key": API_KEY,
            "cx": SEARCH_ENGINE_ID,
            "q": query,
            "start": start,
            "num": results_per_request
        }
        response = requests.get(url, params=params)

        if response.status_code != 200:
            logging.error(f"API request failed: {response.status_code}, {response.text}")
            break

        results = response.json()
        for item in results.get("items", []):
            domain = get_domain(item["link"])
            if check_wordpress(domain) and not database.contains("sites", "domain", domain):
                logging.debug(f"Found WordPress site: {domain}")
                wordpress_sites.append(domain)
                database.add("sites", { "domain": domain })
                logging.debug(f"Found {len(wordpress_sites)} wordpress sites")
                if len(wordpress_sites) >= quantity:
                    return wordpress_sites  
        start += results_per_request
    return None


def main():
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
    init_docker_image()
    load_dotenv()
    database = Database("sites.db")
    database.create_table("sites", {
            "id": "INTEGER PRIMARY KEY AUTOINCREMENT",
            "domain": "TEXT UNIQUE NOT NULL"
        })
    
    wpscan_api_keys = os.getenv("WPSCAN_API_KEYS").split(",")
    wordpress_sites = google_dork(len(wpscan_api_keys), database)
    scan_sites(wordpress_sites, wpscan_api_keys)

    database.close()

if __name__ == "__main__":
    main()