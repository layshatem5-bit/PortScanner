import nmap
import socket
from colorama import Fore, Style, init

init(autoreset=True)

class PortScanner:
    def __init__(self, target):
        self.target = target
        self.nm = nmap.PortScanner()
        self.results = []

    def resolve_target(self):
        try:
            ip = socket.gethostbyname(self.target)
            print(Fore.GREEN + f"[✔] Target resolved: {self.target} → {ip}")
            return ip
        except socket.gaierror:
            print(Fore.RED + f"[✘] Cannot resolve target: {self.target}")
            return None

    def scan(self, ports="1-1024", arguments="-sV -T4"):
        ip = self.resolve_target()
        if not ip:
            return []

        print(Fore.YELLOW + f"[*] Scanning {ip} on ports {ports}...")
        
        try:
            self.nm.scan(hosts=ip, ports=ports, arguments=arguments)
        except Exception as e:
            print(Fore.RED + f"[✘] Scan error: {e}")
            return []

        for proto in self.nm[ip].all_protocols():
            for port in sorted(self.nm[ip][proto].keys()):
                service = self.nm[ip][proto][port]
                result = {
                    "port": port,
                    "protocol": proto,
                    "state": service["state"],
                    "name": service["name"],
                    "version": service.get("version", ""),
                    "product": service.get("product", "")
                }
                self.results.append(result)
                self._print_result(result)

        return self.results

    def _print_result(self, r):
        state_color = Fore.GREEN if r["state"] == "open" else Fore.RED
        print(
            state_color +
            f"[{r['state'].upper()}] "
            f"Port {r['port']}/{r['protocol']} - "
            f"{r['name']} {r['product']} {r['version']}"
        )
