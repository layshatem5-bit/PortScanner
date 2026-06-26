import argparse
import os
from datetime import datetime
from colorama import Fore, Style, init
from modules.port_scanner import PortScanner
from modules.cve_lookup import CVELookup
from modules.report import ReportGenerator

init(autoreset=True)

def banner():
    print(Fore.RED + """
╔═══════════════════════════════════════╗
║         Vulnerability Scanner         ║
║         Coded by: [Laith]             ║
╚═══════════════════════════════════════╝
    """)

def main():
    parser = argparse.ArgumentParser(description="Vulnerability Scanner Tool")
    parser.add_argument("-t", "--target", required=True, help="Target IP or domain")
    parser.add_argument("-p", "--ports", default="1-1024", help="Port range (default: 1-1024)")
    parser.add_argument("-o", "--output", default="", help="Output PDF report name")
    args = parser.parse_args()

    banner()

    # Step 1: Port Scanning
    print(Fore.CYAN + "\n[PHASE 1] Port Scanning\n" + "="*40)
    scanner = PortScanner(args.target)
    scan_results = scanner.scan(ports=args.ports)

    if not scan_results:
        print(Fore.RED + "[✘] No results found. Exiting.")
        return

    # Step 2: CVE Lookup
    print(Fore.CYAN + "\n[PHASE 2] CVE Lookup\n" + "="*40)
    cve_lookup = CVELookup()
    cve_results = {}

    for result in scan_results:
        if result["state"] == "open" and result["name"] != "unknown":
            service_key = f"{result['name']} {result['version']}".strip()
            if service_key not in cve_results:
                cve_results[service_key] = cve_lookup.search(
                    result["name"],
                    result["version"]
                )

    # Step 3: Generate Report
    print(Fore.CYAN + "\n[PHASE 3] Generating Report\n" + "="*40)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_name = args.output if args.output else f"reports/scan_{args.target}_{timestamp}.pdf"
    os.makedirs("reports", exist_ok=True)

    report = ReportGenerator(args.target, scan_results, cve_results)
    report.generate(output_name)

    print(Fore.GREEN + f"\n[✔] Scan Complete!")
    print(Fore.GREEN + f"[✔] Report saved to: {output_name}")

if __name__ == "__main__":
    main()
