import requests
import argparse
# --target-url <URL> --headers <Pfad zur Header-Datei>
# Beispiel: python header_analyze.py --target-url http://example.com/ --headers pfad/zu/deiner/header_datei.txt

parser = argparse.ArgumentParser(description="Header Analyzer")
parser.add_argument("--target-url", required=True, help="Die Ziel-URL")
parser.add_argument("--headers", required=True, help="Pfad zur Header-Datei")
args = parser.parse_args()

url = args.target_url
headers_path = args.headers
# Lade die Header-Datei
try:
    response = requests.get(url, timeout=5)
    headers = response.headers
    print(f"Server: {headers.get('Server')}")
    print(f"X-Powered-By: {headers.get('X-Powered-By')}")
    # Weitere Header analysieren...
except requests.exceptions.RequestException as e:
    print(f"Fehler: {e}")