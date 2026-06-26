import requests
import time
from colorama import Fore, init

init(autoreset=True)

class CVELookup:
    def __init__(self):
        self.nist_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def search(self, service_name, version=""):
        generic_services = ["http", "tcpwrapped", "unknown", "https", ""]
        if service_name.lower() in generic_services and not version:
            print(Fore.BLUE + f"[i] Skipping generic service: {service_name}")
            return []

        product_map = {
            "ssh": "openssh",
            "http": "apache",
            "ftp": "vsftpd",
            "smtp": "postfix",
            "mysql": "mysql",
            "netbios-ssn": "samba",
            "rpcbind": "rpcbind",
        }
        product = product_map.get(service_name.lower(), service_name)
        query = f"{product} {version}".strip()
        print(Fore.YELLOW + f"[*] Searching CVEs for: {query}")

        # استنى ثانيتين قبل كل request عشان ما يحجبنا الـ API
        time.sleep(2)

        try:
            params = {
                "keywordSearch": query,
                "resultsPerPage": 5
            }
            response = requests.get(
                self.nist_url,
                params=params,
                timeout=20
            )

            if response.status_code != 200 or not response.text.strip():
                print(Fore.BLUE + f"[i] No CVEs found for: {query}")
                return []

            data = response.json()
            cves = []

            for item in data.get("vulnerabilities", []):
                cve = item.get("cve", {})
                cve_id = cve.get("id", "N/A")
                descriptions = cve.get("descriptions", [])
                desc = next((d["value"] for d in descriptions if d["lang"] == "en"), "No description")

                metrics = cve.get("metrics", {})
                score = "N/A"
                severity = "N/A"

                if "cvssMetricV31" in metrics:
                    cvss = metrics["cvssMetricV31"][0]["cvssData"]
                    score = cvss.get("baseScore", "N/A")
                    severity = cvss.get("baseSeverity", "N/A")
                elif "cvssMetricV2" in metrics:
                    cvss = metrics["cvssMetricV2"][0]["cvssData"]
                    score = cvss.get("baseScore", "N/A")
                    severity = metrics["cvssMetricV2"][0].get("baseSeverity", "N/A")

                cve_data = {
                    "id": cve_id,
                    "description": desc[:200],
                    "score": score,
                    "severity": severity
                }
                cves.append(cve_data)
                self._print_cve(cve_data)

            if not cves:
                print(Fore.BLUE + f"[i] No CVEs found for: {query}")

            return cves

        except requests.exceptions.Timeout:
            print(Fore.RED + "[✘] CVE lookup timeout, NIST API slow")
            return []
        except Exception as e:
            print(Fore.RED + f"[✘] CVE lookup error: {e}")
            return []

    def _print_cve(self, cve):
        severity_colors = {
            "CRITICAL": Fore.RED,
            "HIGH": Fore.LIGHTRED_EX,
            "MEDIUM": Fore.YELLOW,
            "LOW": Fore.GREEN,
            "N/A": Fore.WHITE
        }
        color = severity_colors.get(cve["severity"], Fore.WHITE)
        print(color + f"  [{cve['severity']}] {cve['id']} - Score: {cve['score']}")
        print(Fore.WHITE + f"  → {cve['description'][:100]}")
