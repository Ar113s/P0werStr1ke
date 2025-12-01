#  This script enumerates virtual hosts on a web server by sending HTTP requests with different Host headers.
#  --target-ip <IP-Adresse> --hostnames <Liste von Hostnamen>
import argparse
import requests

parser = argparse.ArgumentParser(description="Virtual Host Enumerator")
parser.add_argument("--target-ip", required=True, help="Die IP-Adresse des Zielservers")
parser.add_argument("--hostnames", nargs="+", required=True, help="Liste von Hostnamen")
args = parser.parse_args()

target_ip = args.target_ip
hostnames = args.hostnames

for hostname in hostnames:
    headers = {"Host": hostname}
    try:
        # Wichtig: Hier muss die IP-Adresse direkt angesprochen werden, nicht der Hostname via DNS
        response = requests.get(f"http://{target_ip}", headers=headers, timeout=3, verify=False) # verify=False bei HTTPS und selbstsignierten Certs (mit Vorsicht!)
        print(f"Anfrage für {hostname} an {target_ip}: Status {response.status_code}, Länge {len(response.content)}")
        # Inhalt analysieren, um Unterschiede festzustellen
    except requests.exceptions.RequestException as e:
        print(f"Fehler bei Anfrage für {hostname}: {e}")