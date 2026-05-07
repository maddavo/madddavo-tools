# This script provides a Windows GUI LAN scanner for quickly identifying
# active devices on a local IPv4 subnet, defaulting to 192.168.0.0/24.
# It scans each host using ICMP ping and common TCP port checks, then
# displays responding devices in a table with IP address, ping status,
# open ports, DNS name, NetBIOS name, MAC address, likely manufacturer,
# and a short inferred summary such as web UI, SMB/NAS, printer, RTSP
# camera, MQTT/IoT, RDP, SSH, or ADB/Android/Fire TV. Results are
# populated progressively while scanning, kept numerically sorted by IP
# address, enriched afterward with ARP/MAC and OUI/vendor information
# where available, and can be exported to CSV for later reference.

import csv
import ipaddress
import os
import queue
import re
import socket
import subprocess
import threading
import time
import tkinter as tk
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from tkinter import filedialog, messagebox, ttk


CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)

DEFAULT_TARGET = "192.168.0.X"

DEFAULT_PORTS = (
    "21,22,23,25,53,80,110,139,143,443,445,548,554,587,"
    "631,993,995,1883,3306,3389,5000,5357,5555,8000,8080,8443,9100"
)

PORT_NAMES = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    139: "netbios",
    143: "imap",
    443: "https",
    445: "smb",
    548: "afp",
    554: "rtsp",
    587: "smtp-sub",
    631: "ipp",
    993: "imaps",
    995: "pop3s",
    1883: "mqtt",
    3306: "mysql",
    3389: "rdp",
    5000: "upnp/web",
    5357: "wsdapi",
    5555: "adb",
    8000: "http-alt",
    8080: "http-alt",
    8443: "https-alt",
    9100: "jetdirect",
}

# Not comprehensive. Add to this if you see repeated unknown MAC prefixes.
BUILTIN_OUI = {
    "001A11": "Google",
    "001B63": "Apple",
    "001C42": "Parallels",
    "0024E4": "Withings",
    "0026BB": "Apple",
    "0050C2": "IEEE Assigned",
    "0080C8": "D-Link",
    "00D09E": "Apple",
    "00E04C": "Realtek",
    "00FC8B": "Amazon",
    "04D4C4": "ASUSTek",
    "08606E": "ASUSTek",
    "0C9D92": "Raspberry Pi",
    "10FEED": "TP-Link",
    "18E829": "Ubiquiti",
    "1C61B4": "Apple",
    "20F85E": "Delta",
    "24A160": "Espressif",
    "28CD1C": "Eufy/Anker",
    "2C3A6A": "Raspberry Pi",
    "3C6105": "Amazon",
    "3C71BF": "Espressif",
    "40A36B": "Synology",
    "44D9E7": "Ubiquiti",
    "50C7BF": "TP-Link",
    "50D4F7": "TP-Link",
    "54E1AD": "Apple",
    "5CCF7F": "Espressif",
    "60A423": "Ubiquiti",
    "64B708": "TP-Link",
    "68C63A": "Huawei",
    "6C2995": "Intel",
    "704F57": "TP-Link",
    "74883F": "Ubiquiti",
    "74DA38": "Edimax",
    "78E103": "Amazon",
    "7C10C9": "TP-Link",
    "7C9EBD": "Espressif",
    "84CCA8": "Espressif",
    "8C8590": "Apple",
    "B827EB": "Raspberry Pi",
    "BCDDC2": "Espressif",
    "C83A35": "TP-Link",
    "CC50E3": "Raspberry Pi",
    "D03745": "TP-Link",
    "D850E6": "ASUSTek",
    "DC4F22": "Espressif",
    "DCA632": "Raspberry Pi",
    "E45F01": "Raspberry Pi",
    "ECFA5C": "Apple",
    "F4F5D8": "Google",
    "F80F84": "Natural Security",
}


@dataclass
class ScanResult:
    ip: str
    ping: bool
    open_ports: list[int]
    dns_name: str = ""
    netbios_name: str = ""
    mac: str = ""
    vendor: str = ""
    summary: str = ""


def parse_target_to_network(text: str) -> ipaddress.IPv4Network:
    text = text.strip()

    # Accept "192.168.0.X"
    if "x" in text.lower():
        parts = text.replace("X", "x").split(".")
        if len(parts) == 4 and parts[-1].lower() == "x":
            text = ".".join(parts[:3] + ["0"]) + "/24"

    # Accept "192.168.0."
    if text.endswith("."):
        text = text + "0/24"

    # Accept "192.168.0"
    if re.fullmatch(r"\d{1,3}\.\d{1,3}\.\d{1,3}", text):
        text = text + ".0/24"

    # Accept single IP and treat as /24
    if "/" not in text:
        text = text + "/24"

    return ipaddress.ip_network(text, strict=False)


def parse_ports(text: str) -> list[int]:
    ports = []

    for item in text.split(","):
        item = item.strip()
        if not item:
            continue

        port = int(item)

        if not 1 <= port <= 65535:
            raise ValueError(f"Invalid port: {port}")

        ports.append(port)

    return sorted(set(ports))


def ping_host(ip: str, timeout_ms: int = 350) -> bool:
    try:
        result = subprocess.run(
            ["ping", "-n", "1", "-w", str(timeout_ms), ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=2,
            creationflags=CREATE_NO_WINDOW,
        )
        return result.returncode == 0
    except Exception:
        return False


def tcp_port_open(ip: str, port: int, timeout: float = 0.25) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except Exception:
        return False


def reverse_dns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def netbios_lookup(ip: str) -> str:
    try:
        result = subprocess.run(
            ["nbtstat", "-A", ip],
            capture_output=True,
            text=True,
            timeout=1.5,
            creationflags=CREATE_NO_WINDOW,
            errors="replace",
        )
    except Exception:
        return ""

    output = result.stdout or ""

    # Prefer <00> UNIQUE names.
    for line in output.splitlines():
        upper = line.upper()
        if "<00>" in upper and "UNIQUE" in upper:
            name = line.split("<")[0].strip()
            if name and "__MSBROWSE__" not in name.upper():
                return name

    # Fallback to <20> server service name.
    for line in output.splitlines():
        upper = line.upper()
        if "<20>" in upper and "UNIQUE" in upper:
            name = line.split("<")[0].strip()
            if name:
                return name

    return ""


def get_arp_table() -> dict[str, str]:
    table = {}

    try:
        result = subprocess.run(
            ["arp", "-a"],
            capture_output=True,
            text=True,
            timeout=3,
            creationflags=CREATE_NO_WINDOW,
            errors="replace",
        )
    except Exception:
        return table

    output = result.stdout or ""

    for line in output.splitlines():
        match = re.match(
            r"^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F-]{17})\s+\w+",
            line,
        )
        if match:
            ip = match.group(1)
            mac = match.group(2).replace("-", ":").upper()
            table[ip] = mac

    return table


def load_oui_database() -> dict[str, str]:
    """
    Built-in small OUI map plus optional local files.

    Optional files in the same folder as this script:
      - oui.csv
      - nmap-mac-prefixes.txt
      - manuf.txt
    """
    db = dict(BUILTIN_OUI)
    base = os.path.dirname(os.path.abspath(__file__))

    for filename in ("oui.csv", "nmap-mac-prefixes.txt", "manuf.txt"):
        path = os.path.join(base, filename)
        if not os.path.exists(path):
            continue

        try:
            with open(path, "r", encoding="utf-8", errors="replace", newline="") as f:
                if filename.endswith(".csv"):
                    reader = csv.reader(f)
                    for row in reader:
                        if len(row) < 3:
                            continue

                        prefix = re.sub(r"[^0-9A-Fa-f]", "", row[1]).upper()
                        vendor = row[2].strip()

                        if len(prefix) >= 6 and vendor:
                            db[prefix[:6]] = vendor

                else:
                    for line in f:
                        line = line.strip()

                        if not line or line.startswith("#"):
                            continue

                        # Accept:
                        # B827EB Raspberry Pi Foundation
                        # B8:27:EB Raspberry Pi Foundation
                        match = re.match(
                            r"^([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){2}|[0-9A-Fa-f]{6})\s+(.+)$",
                            line,
                        )

                        if match:
                            prefix = re.sub(r"[^0-9A-Fa-f]", "", match.group(1)).upper()
                            vendor = match.group(2).strip()

                            if len(prefix) >= 6 and vendor:
                                db[prefix[:6]] = vendor

        except Exception:
            pass

    return db


def vendor_from_mac(mac: str, oui_db: dict[str, str]) -> str:
    prefix = re.sub(r"[^0-9A-Fa-f]", "", mac).upper()[:6]

    if not prefix:
        return ""

    return oui_db.get(prefix, "")


def format_ports(ports: list[int]) -> str:
    parts = []

    for port in ports:
        name = PORT_NAMES.get(port, "")

        if name:
            parts.append(f"{port}/{name}")
        else:
            parts.append(str(port))

    return ", ".join(parts)


def build_summary(result: ScanResult) -> str:
    ports = set(result.open_ports)
    hints = []

    if ports & {80, 443, 5000, 8000, 8080, 8443}:
        hints.append("web UI")

    if ports & {139, 445}:
        hints.append("SMB/Windows/NAS")

    if 22 in ports:
        hints.append("SSH")

    if 23 in ports:
        hints.append("Telnet")

    if 3389 in ports:
        hints.append("Windows RDP")

    if ports & {631, 9100}:
        hints.append("printer")

    if 554 in ports:
        hints.append("RTSP camera/media")

    if 1883 in ports:
        hints.append("MQTT/IoT")

    if 53 in ports:
        hints.append("DNS/router possible")

    if 3306 in ports:
        hints.append("MySQL/MariaDB")

    if 548 in ports:
        hints.append("Apple AFP")

    if 5555 in ports:
        hints.append("ADB/Android/Fire TV possible")

    vendor_upper = result.vendor.upper()

    if "RASPBERRY" in vendor_upper:
        hints.append("Raspberry Pi")

    if "ESPRESSIF" in vendor_upper:
        hints.append("ESP/IoT device")

    if "TP-LINK" in vendor_upper:
        hints.append("TP-Link device")

    if "UBIQUITI" in vendor_upper:
        hints.append("Ubiquiti network device")

    if "APPLE" in vendor_upper:
        hints.append("Apple device")

    if "SYNOLOGY" in vendor_upper:
        hints.append("Synology NAS")

    names = [x for x in [result.dns_name, result.netbios_name] if x]

    if names:
        hints.append("name: " + " / ".join(sorted(set(names))))

    if not hints:
        if result.ping:
            hints.append("ping response only")
        else:
            hints.append("TCP response")

    return "; ".join(dict.fromkeys(hints))


def scan_one_host(ip: str, ports: list[int]) -> ScanResult | None:
    ping_ok = ping_host(ip)
    open_ports = []

    for port in ports:
        if tcp_port_open(ip, port):
            open_ports.append(port)

    if not ping_ok and not open_ports:
        return None

    result = ScanResult(ip=ip, ping=ping_ok, open_ports=open_ports)

    result.dns_name = reverse_dns(ip)

    # NetBIOS is most useful on Windows/NAS/SMB devices.
    # Also try it when ping responded but DNS is blank.
    if 139 in open_ports or 445 in open_ports or (ping_ok and not result.dns_name):
        result.netbios_name = netbios_lookup(ip)

    result.summary = build_summary(result)

    return result


class LanScannerApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("LAN Scanner")
        self.root.geometry("1250x650")

        self.queue = queue.Queue()
        self.scanning = False
        self.last_rows: list[ScanResult] = []
        self.ip_to_item = {}
        self.results_by_ip = {}

        self._build_ui()

    def _build_ui(self):
        outer = ttk.Frame(self.root, padding=10)
        outer.pack(fill=tk.BOTH, expand=True)

        controls = ttk.Frame(outer)
        controls.pack(fill=tk.X)

        ttk.Label(controls, text="Subnet:").pack(side=tk.LEFT)

        self.target_var = tk.StringVar(value=DEFAULT_TARGET)
        ttk.Entry(controls, textvariable=self.target_var, width=24).pack(
            side=tk.LEFT,
            padx=(5, 15),
        )

        ttk.Label(controls, text="TCP ports:").pack(side=tk.LEFT)

        self.ports_var = tk.StringVar(value=DEFAULT_PORTS)
        ttk.Entry(controls, textvariable=self.ports_var, width=85).pack(
            side=tk.LEFT,
            padx=(5, 15),
            fill=tk.X,
            expand=True,
        )

        self.scan_button = ttk.Button(controls, text="Scan", command=self.start_scan)
        self.scan_button.pack(side=tk.LEFT)

        self.export_button = ttk.Button(controls, text="Export CSV", command=self.export_csv)
        self.export_button.pack(side=tk.LEFT, padx=(8, 0))

        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(outer, textvariable=self.status_var).pack(anchor=tk.W, pady=(8, 4))

        self.progress = ttk.Progressbar(outer, mode="determinate")
        self.progress.pack(fill=tk.X, pady=(0, 8))

        table_frame = ttk.Frame(outer)
        table_frame.pack(fill=tk.BOTH, expand=True)

        columns = (
            "ip",
            "ping",
            "ports",
            "dns",
            "netbios",
            "mac",
            "vendor",
            "summary",
        )

        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings")

        self.tree.heading("ip", text="IP address")
        self.tree.heading("ping", text="Ping")
        self.tree.heading("ports", text="Open TCP ports")
        self.tree.heading("dns", text="DNS name")
        self.tree.heading("netbios", text="NetBIOS")
        self.tree.heading("mac", text="MAC address")
        self.tree.heading("vendor", text="Manufacturer")
        self.tree.heading("summary", text="Summary")

        self.tree.column("ip", width=110, anchor=tk.W)
        self.tree.column("ping", width=60, anchor=tk.CENTER)
        self.tree.column("ports", width=230, anchor=tk.W)
        self.tree.column("dns", width=180, anchor=tk.W)
        self.tree.column("netbios", width=140, anchor=tk.W)
        self.tree.column("mac", width=145, anchor=tk.W)
        self.tree.column("vendor", width=170, anchor=tk.W)
        self.tree.column("summary", width=360, anchor=tk.W)

        yscroll = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self.tree.yview)
        xscroll = ttk.Scrollbar(table_frame, orient=tk.HORIZONTAL, command=self.tree.xview)

        self.tree.configure(yscrollcommand=yscroll.set, xscrollcommand=xscroll.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        yscroll.grid(row=0, column=1, sticky="ns")
        xscroll.grid(row=1, column=0, sticky="ew")

        table_frame.rowconfigure(0, weight=1)
        table_frame.columnconfigure(0, weight=1)

    def start_scan(self):
        if self.scanning:
            return

        try:
            network = parse_target_to_network(self.target_var.get())
            ports = parse_ports(self.ports_var.get())
        except Exception as e:
            messagebox.showerror("Invalid scan settings", str(e))
            return

        if network.version != 4:
            messagebox.showerror("Invalid subnet", "Only IPv4 networks are supported.")
            return

        host_count = network.num_addresses - 2 if network.prefixlen < 31 else network.num_addresses

        if host_count <= 0:
            messagebox.showerror("Invalid subnet", "No usable hosts in that network.")
            return

        if host_count > 4096:
            messagebox.showerror(
                "Subnet too large",
                f"{network} contains {host_count} hosts. Use a smaller subnet.",
            )
            return

        self.tree.delete(*self.tree.get_children())
        self.progress["value"] = 0
        self.progress["maximum"] = host_count
        self.status_var.set(f"Scanning {network}...")
        self.scan_button.configure(state=tk.DISABLED)

        self.scanning = True
        self.last_rows = []
        self.ip_to_item = {}
        self.results_by_ip = {}

        thread = threading.Thread(
            target=self._scan_worker,
            args=(network, ports),
            daemon=True,
        )
        thread.start()

        self.root.after(100, self._process_queue)

    def _scan_worker(self, network: ipaddress.IPv4Network, ports: list[int]):
        started = time.time()
        hosts = [str(ip) for ip in network.hosts()]

        max_workers = min(128, max(16, len(hosts)))

        results: list[ScanResult] = []
        completed = 0

        try:
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {
                    executor.submit(scan_one_host, ip, ports): ip
                    for ip in hosts
                }

                for future in as_completed(futures):
                    completed += 1

                    try:
                        result = future.result()

                        if result:
                            results.append(result)

                            # Populate the table immediately while scanning.
                            self.queue.put(("found", result))

                    except Exception:
                        pass

                    self.queue.put(("progress", completed, len(hosts), len(results)))

            # MAC/manufacturer data is usually most reliable after ARP has been populated.
            arp_table = get_arp_table()
            oui_db = load_oui_database()

            for result in results:
                result.mac = arp_table.get(result.ip, "")
                result.vendor = vendor_from_mac(result.mac, oui_db) if result.mac else ""
                result.summary = build_summary(result)

                # Update existing table row with MAC/vendor/summary.
                self.queue.put(("update", result))

            results.sort(key=lambda r: ipaddress.ip_address(r.ip))

            elapsed = time.time() - started
            self.queue.put(("done", results, elapsed))

        except Exception as e:
            self.queue.put(("error", str(e)))

    def _row_values(self, row: ScanResult):
        return (
            row.ip,
            "yes" if row.ping else "no",
            format_ports(row.open_ports),
            row.dns_name,
            row.netbios_name,
            row.mac,
            row.vendor,
            row.summary,
        )

    def _insert_or_update_sorted(self, row: ScanResult):
        self.results_by_ip[row.ip] = row

        self.last_rows = sorted(
            self.results_by_ip.values(),
            key=lambda r: ipaddress.ip_address(r.ip),
        )

        values = self._row_values(row)

        existing_item = self.ip_to_item.get(row.ip)

        if existing_item and self.tree.exists(existing_item):
            self.tree.item(existing_item, values=values)
            return

        row_ip = ipaddress.ip_address(row.ip)

        insert_index = "end"

        for index, item_id in enumerate(self.tree.get_children("")):
            existing_ip_text = self.tree.set(item_id, "ip")

            try:
                existing_ip = ipaddress.ip_address(existing_ip_text)
            except ValueError:
                continue

            if existing_ip > row_ip:
                insert_index = index
                break

        new_item = self.tree.insert("", insert_index, values=values)
        self.ip_to_item[row.ip] = new_item

    def _process_queue(self):
        try:
            while True:
                message = self.queue.get_nowait()
                kind = message[0]

                if kind == "progress":
                    completed, total, found = message[1], message[2], message[3]

                    self.progress["maximum"] = total
                    self.progress["value"] = completed

                    self.status_var.set(
                        f"Scanning... {completed}/{total} checked, {found} responding"
                    )

                elif kind == "found":
                    row = message[1]
                    self._insert_or_update_sorted(row)

                elif kind == "update":
                    row = message[1]
                    self._insert_or_update_sorted(row)

                elif kind == "done":
                    rows, elapsed = message[1], message[2]
                    self.last_rows = rows

                    self.status_var.set(
                        f"Done. {len(rows)} responding host(s). Elapsed: {elapsed:.1f} s"
                    )

                    self.scan_button.configure(state=tk.NORMAL)
                    self.scanning = False

                elif kind == "error":
                    self.status_var.set("Error")
                    self.scan_button.configure(state=tk.NORMAL)
                    self.scanning = False
                    messagebox.showerror("Scan error", message[1])

        except queue.Empty:
            pass

        if self.scanning:
            self.root.after(100, self._process_queue)

    def export_csv(self):
        if not self.last_rows:
            messagebox.showinfo("Nothing to export", "Run a scan first.")
            return

        path = filedialog.asksaveasfilename(
            title="Export scan results",
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            initialfile="lan_scan.csv",
        )

        if not path:
            return

        try:
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)

                writer.writerow(
                    [
                        "IP address",
                        "Ping",
                        "Open TCP ports",
                        "DNS name",
                        "NetBIOS name",
                        "MAC address",
                        "Manufacturer",
                        "Summary",
                    ]
                )

                for row in self.last_rows:
                    writer.writerow(
                        [
                            row.ip,
                            "yes" if row.ping else "no",
                            format_ports(row.open_ports),
                            row.dns_name,
                            row.netbios_name,
                            row.mac,
                            row.vendor,
                            row.summary,
                        ]
                    )

            messagebox.showinfo("Export complete", path)

        except Exception as e:
            messagebox.showerror("Export failed", str(e))


def main():
    root = tk.Tk()
    LanScannerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
