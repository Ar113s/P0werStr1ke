import requests
import threading
import argparse
# Ein einfaches Verzeichnis-Enumeration-Skript mit Threads oder asynchroner Verarbeitung
# --target-url <URL> --wordlist <Pfad zur Wortliste> --threads <Anzahl der Threads>
# Beispiel: python directory_enum.py --target-url http://example.com/ --wordlist pfad/zu/deiner/wortliste.txt --threads 10

TARGET_URL = "http://example.com/"
WORDLIST_PATH = "pfad/zu/deiner/wortliste.txt" # Wichtig: Pfad anpassen!
NUM_THREADS = 10

def check_path(path):
    try:
        url = f"{TARGET_URL}{path}"
        response = requests.get(url, timeout=3, allow_redirects=False) # Redirects oft separat behandeln
        if response.status_code in [200, 204, 301, 302, 307, 401, 403]:
            print(f"[{response.status_code}] Gefunden: {url}")
    except requests.exceptions.RequestException:
        pass # Fehler ignorieren oder loggen

with open(WORDLIST_PATH, "r") as f:
    paths = [line.strip() for line in f]

threads = []
for i in range(0, len(paths), NUM_THREADS):
    batch = paths[i:i+NUM_THREADS]
    for path_item in batch:
        thread = threading.Thread(target=check_path, args=(path_item,))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join() # Auf Beendigung der Threads im aktuellen Batch warten
    threads = [] # Liste für den nächsten Batch leeren


    # Ascynktio aLternaative

    ```
import asyncio
import aiohttp

TARGET_URL = "http://example.com/"
WORDLIST_PATH = "pfad/zu/deiner/wortliste.txt" # Wichtig: Pfad anpassen!
CONCURRENT_REQUESTS = 50

async def check_path_async(session, path):
    url = f"{TARGET_URL}{path}"
    try:
        async with session.get(url, timeout=3, allow_redirects=False) as response:
            if response.status in [200, 204, 301, 302, 307, 401, 403]:
                print(f"[{response.status}] Gefunden: {url}")
    except (aiohttp.ClientError, asyncio.TimeoutError):
        pass # Fehler ignorieren oder loggen

async def main():
    with open(WORDLIST_PATH, "r") as f:
        paths = [line.strip() for line in f]

    async with aiohttp.ClientSession() as session:
        tasks = []
        for path_item in paths:
            if len(tasks) >= CONCURRENT_REQUESTS:
                await asyncio.gather(*tasks) # Auf einige Tasks warten, bevor neue hinzugefügt werden
                tasks = []
            tasks.append(check_path_async(session, path_item))
        if tasks:
            await asyncio.gather(*tasks) # Verbleibende Tasks ausführen

if __name__ == "__main__":
    asyncio.run(main())
    ````^^