import dns.resolver
import argparse

parser = argparse.ArgumentParser(description="Subdomain Enumeration")
parser.add_argument("--domain", required=True, help="Die Ziel-Domain")
parser.add_argument("--record-types", nargs="+", default=["A", "AAAA", "CNAME", "MX", "TXT"], help="Die Record-Typen, die abgefragt werden sollen")
args = parser.parse_args()

domain = args.domain
record_types = args.record_types

for record_type in record_types:
    try:
        answers = dns.resolver.resolve(domain, record_type)
        for rdata in answers:
            print(f"{domain} {record_type} {rdata.to_text()}")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
        pass
    except Exception as e:
        print(f"Fehler bei DNS-Abfrage für {record_type}: {e}")