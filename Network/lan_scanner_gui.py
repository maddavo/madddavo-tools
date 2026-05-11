# This script provides a Windows GUI LAN scanner for quickly identifying
# active devices on a local IPv4 subnet, defaulting to 192.168.0.0/23.
# It scans each host using ICMP ping and common TCP port checks, then
# displays remembered/responding devices in a table with IP address,
# ping status, open ports, DNS name, MAC address, likely
# manufacturer, and a short inferred summary such as web UI, SMB/NAS,
# printer, RTSP camera, MQTT/IoT, RDP, SSH, or ADB/Android/Fire TV.
# Results are populated progressively while scanning, kept numerically
# sorted by IP address, enriched afterward with ARP/MAC and OUI/vendor
# information where available, saved as local JSON working memory, and
# can be exported to CSV for later reference.

import csv
import ipaddress
import json
import os
import queue
import re
import socket
import subprocess
import threading
import time
import tkinter as tk
import webbrowser
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from tkinter import filedialog, messagebox, simpledialog, ttk


CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)
CREATE_NEW_CONSOLE = getattr(subprocess, "CREATE_NEW_CONSOLE", 0)

APP_VERSION = "v1.16"
DEFAULT_TARGET = "192.168.0.0/23"
MEMORY_FILENAME = "lan_scanner_gui_memory.json"
MEMORY_VERSION = 2
DEFAULT_PING_TIMEOUT_MS = 850
DEFAULT_TCP_TIMEOUT_SEC = 0.65

AGE_MARKERS = {
    "green": "🟢",
    "yellow": "🟡",
    "red": "🔴",
    "grey": "⚪",
}

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
    router_name: str = ""
    reserved: str = ""
    lease: str = ""
    summary: str = ""
    scanned_at: float = 0.0
    last_router_seen: float = 0.0
    source: str = ""
    ever_responded: bool = False


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


def ping_host(ip: str, timeout_ms: int = DEFAULT_PING_TIMEOUT_MS) -> bool:
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


def tcp_port_open(ip: str, port: int, timeout: float = DEFAULT_TCP_TIMEOUT_SEC) -> bool:
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


def web_url_for_result(result: ScanResult) -> str:
    ports = set(result.open_ports)

    # Prefer normal ports first.
    if 443 in ports:
        return f"https://{result.ip}"

    if 80 in ports:
        return f"http://{result.ip}"

    # Then common alternate web ports.
    if 8443 in ports:
        return f"https://{result.ip}:8443"

    for port in (8080, 8000, 5000):
        if port in ports:
            return f"http://{result.ip}:{port}"

    return ""


def memory_path() -> str:
    base = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base, MEMORY_FILENAME)


def router_config_path() -> str:
    base = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base, "router_config.json")


def format_timestamp(timestamp: float) -> str:
    if not timestamp:
        return ""

    try:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp))
    except Exception:
        return ""


def export_status_text(row: ScanResult) -> str:
    sources = set(filter(None, str(row.source or "").split("+")))

    if not row.ever_responded and sources & {"router_client", "router_reservation"}:
        return "router-only"

    if not row.scanned_at:
        return "router-only"

    if row.ping or row.open_ports:
        age = time.time() - row.scanned_at

        if age <= 3600:
            return "responded <1h"

        if age <= 86400:
            return "responded <24h"

        return "responded old"

    return "no response"


def default_router_config() -> dict:
    return {
        "selected_router": "home_ax72",
        "routers": {
            "home_ax72": {
                "type": "tplink_archer_ax72",
                "label": "Home TP-Link AX72",
                "base_url": "http://192.168.0.1",
                "password": "",
                "password_storage": "plaintext",
            }
        },
    }


def read_router_config_file() -> dict:
    path = router_config_path()

    if not os.path.exists(path):
        return default_router_config()

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        if not isinstance(data, dict):
            return default_router_config()

        default = default_router_config()
        data.setdefault("selected_router", default["selected_router"])
        data.setdefault("routers", {})

        if data["selected_router"] not in data["routers"]:
            data["routers"][data["selected_router"]] = default["routers"]["home_ax72"]

        return data

    except Exception:
        return default_router_config()


def write_router_config_file(data: dict) -> None:
    path = router_config_path()
    temp_path = path + ".tmp"

    with open(temp_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True)

    os.replace(temp_path, path)


def normalise_mac(mac: str) -> str:
    cleaned = re.sub(r"[^0-9A-Fa-f]", "", str(mac or "")).upper()

    if len(cleaned) != 12:
        return ""

    return ":".join(cleaned[i:i + 2] for i in range(0, 12, 2))


def result_to_record(result: ScanResult) -> dict:
    return {
        "ip": result.ip,
        "ping": result.ping,
        "open_ports": list(result.open_ports),
        "dns_name": result.dns_name,
        "netbios_name": result.netbios_name,
        "mac": result.mac,
        "vendor": result.vendor,
        "router_name": result.router_name,
        "reserved": result.reserved,
        "lease": result.lease,
        "summary": result.summary,
        "scanned_at": result.scanned_at,
        "last_router_seen": result.last_router_seen,
        "source": result.source,
        "ever_responded": bool(result.ever_responded),
    }


def result_from_record(record: dict) -> ScanResult | None:
    try:
        ip = str(ipaddress.ip_address(str(record.get("ip", ""))))
    except ValueError:
        return None

    try:
        open_ports = [int(port) for port in record.get("open_ports", [])]
        open_ports = [port for port in open_ports if 1 <= port <= 65535]
    except Exception:
        open_ports = []

    return ScanResult(
        ip=ip,
        ping=bool(record.get("ping", False)),
        open_ports=sorted(set(open_ports)),
        dns_name=str(record.get("dns_name", "") or ""),
        netbios_name=str(record.get("netbios_name", "") or ""),
        mac=str(record.get("mac", "") or ""),
        vendor=str(record.get("vendor", "") or ""),
        router_name=str(record.get("router_name", "") or ""),
        reserved=str(record.get("reserved", "") or ""),
        lease=str(record.get("lease", "") or ""),
        summary=str(record.get("summary", "") or ""),
        scanned_at=float(record.get("scanned_at", 0.0) or 0.0),
        last_router_seen=float(record.get("last_router_seen", 0.0) or 0.0),
        source=str(record.get("source", "") or ""),
        ever_responded=bool(record.get("ever_responded", False)),
    )


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
        elif result.open_ports:
            hints.append("TCP response")
        else:
            hints.append("no response on last scan")

    return "; ".join(dict.fromkeys(hints))


def scan_one_host(ip: str, ports: list[int]) -> ScanResult | None:
    ping_ok = ping_host(ip)
    open_ports = []

    for port in ports:
        if tcp_port_open(ip, port):
            open_ports.append(port)

    if not ping_ok and not open_ports:
        return None

    result = ScanResult(
        ip=ip,
        ping=ping_ok,
        open_ports=open_ports,
        scanned_at=time.time(),
        ever_responded=True,
    )

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
        self.root.title(f"MadDavo's LAN Scanner {APP_VERSION}")
        self.root.geometry("1500x760")

        self.queue = queue.Queue()
        self.scanning = False
        self.last_rows: list[ScanResult] = []
        self.ip_to_item = {}
        self.results_by_ip = {}
        self.router_config_geometry = ""
        self.export_dir = ""
        self.age_icons = self._create_age_icons()
        self.tree_style_name = "LanScanner.Treeview"
        self.tree_style = ttk.Style(self.root)
        self._configure_tree_style()

        self._build_ui()
        self.load_memory()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.root.after(60000, self.refresh_age_indicators)

    def _configure_tree_style(self):
        """Keep the status icon in the leftmost tree column.

        The status circle is an image in the Treeview #0 column so it can
        update reliably.  A normal tree column reserves space for the
        expand/collapse indicator, which pushes the image right.  This
        custom item layout removes that indicator for this scanner table.
        """
        self.tree_style.configure(self.tree_style_name, indent=0)

        try:
            self.tree_style.layout(
                f"{self.tree_style_name}.Item",
                [
                    (
                        "Treeitem.padding",
                        {
                            "sticky": "nswe",
                            "children": [
                                ("Treeitem.image", {"side": "left", "sticky": ""}),
                                ("Treeitem.text", {"side": "left", "sticky": ""}),
                            ],
                        },
                    )
                ],
            )
        except tk.TclError:
            # Some Tk builds/themes do not allow the item layout to be
            # overridden.  The scanner still works; the icon may just sit a
            # few pixels further right on those systems.
            pass

    def _create_age_icons(self) -> dict[str, tk.PhotoImage]:
        colours = {
            "green": "#00e83a",
            "yellow": "#ffe600",
            "red": "#ff4444",
            "grey": "#9a9a9a",
        }
        icons = {}

        for name, colour in colours.items():
            image = tk.PhotoImage(width=14, height=14)

            if name == "grey":
                # Router-only entries are shown as a square so they are
                # visually distinct from scan-age circles.
                for x in range(2, 12):
                    for y in range(2, 12):
                        if x in (2, 11) or y in (2, 11):
                            image.put("#555555", (x, y))
                        else:
                            image.put(colour, (x, y))
            else:
                cx = cy = 7
                radius = 4.8

                for x in range(14):
                    for y in range(14):
                        distance = ((x - cx) ** 2 + (y - cy) ** 2) ** 0.5
                        if distance <= radius:
                            image.put(colour, (x, y))
                        elif radius < distance <= radius + 1.0:
                            image.put("#555555", (x, y))

            icons[name] = image

        return icons

    def _build_ui(self):
        outer = ttk.Frame(self.root, padding=10)
        outer.pack(fill=tk.BOTH, expand=True)

        controls = ttk.Frame(outer)
        controls.pack(fill=tk.X)

        settings_row = ttk.Frame(controls)
        settings_row.pack(fill=tk.X)

        button_row = ttk.Frame(controls)
        button_row.pack(fill=tk.X, pady=(8, 0))

        ttk.Label(settings_row, text="Subnet:").pack(side=tk.LEFT)

        self.target_var = tk.StringVar(value=DEFAULT_TARGET)
        ttk.Entry(settings_row, textvariable=self.target_var, width=24).pack(
            side=tk.LEFT,
            padx=(5, 15),
        )

        ttk.Label(settings_row, text="TCP ports:").pack(side=tk.LEFT)

        self.ports_var = tk.StringVar(value=DEFAULT_PORTS)
        ttk.Entry(settings_row, textvariable=self.ports_var, width=85).pack(
            side=tk.LEFT,
            padx=(5, 0),
            fill=tk.X,
            expand=True,
        )

        self.full_scan_button = ttk.Button(
            button_row,
            text="Full Scan",
            command=lambda: self.start_scan("full"),
        )
        self.full_scan_button.pack(side=tk.LEFT)

        self.refresh_button = ttk.Button(
            button_row,
            text="Refresh",
            command=lambda: self.start_scan("refresh"),
        )
        self.refresh_button.pack(side=tk.LEFT, padx=(8, 0))

        self.missing_scan_button = ttk.Button(
            button_row,
            text="Scan missing",
            command=lambda: self.start_scan("missing"),
        )
        self.missing_scan_button.pack(side=tk.LEFT, padx=(8, 0))

        self.router_sync_button = ttk.Button(
            button_row,
            text="Router Sync",
            command=self.start_router_sync,
        )
        self.router_sync_button.pack(side=tk.LEFT, padx=(8, 0))

        self.router_config_button = ttk.Button(
            button_row,
            text="Router Config",
            command=self.open_router_config_dialog,
        )
        self.router_config_button.pack(side=tk.LEFT, padx=(8, 0))

        self.export_button = ttk.Button(button_row, text="Export CSV", command=self.export_csv)
        self.export_button.pack(side=tk.LEFT, padx=(8, 0))

        self.legend_frame = ttk.Frame(button_row)
        self.legend_frame.pack(side=tk.LEFT, padx=(24, 0))
        ttk.Label(self.legend_frame, text="Key:").pack(side=tk.LEFT)

        legend_items = (
            ("green", "responded <1h"),
            ("yellow", "responded <24h"),
            ("red", "no response / old"),
            ("grey", "router only"),
        )

        for icon_key, label_text in legend_items:
            ttk.Label(self.legend_frame, image=self.age_icons[icon_key]).pack(
                side=tk.LEFT,
                padx=(8, 2),
            )
            ttk.Label(self.legend_frame, text=label_text).pack(side=tk.LEFT)

        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(outer, textvariable=self.status_var).pack(anchor=tk.W, pady=(8, 4))

        self.progress = ttk.Progressbar(outer, mode="determinate")
        self.progress.pack(fill=tk.X, pady=(0, 8))

        table_frame = ttk.Frame(outer)
        table_frame.pack(fill=tk.BOTH, expand=True)

        columns = (
            "ip",
            "mac",
            "ping",
            "ports",
            "dns",
            "router_name",
            "reserved",
            "lease",
            "summary",
        )

        self.tree = ttk.Treeview(
            table_frame,
            columns=columns,
            show="tree headings",
            style=self.tree_style_name,
        )

        self.tree.heading("#0", text="")
        self.tree.heading("ip", text="IP address", command=self.sort_by_ip)
        self.tree.heading("mac", text="MAC address", command=self.sort_by_mac)
        self.tree.heading("ping", text="Ping")
        self.tree.heading("ports", text="Open TCP ports")
        self.tree.heading("dns", text="DNS name")
        self.tree.heading("router_name", text="Name on Router")
        self.tree.heading("reserved", text="Reserved")
        self.tree.heading("lease", text="Lease")
        self.tree.heading("summary", text="Summary")

        self.tree.column("#0", width=18, minwidth=18, stretch=False, anchor=tk.W)
        self.tree.column("ip", width=110, anchor=tk.W)
        self.tree.column("mac", width=145, anchor=tk.W)
        self.tree.column("ping", width=60, anchor=tk.CENTER)
        self.tree.column("ports", width=230, anchor=tk.W)
        self.tree.column("dns", width=180, anchor=tk.W)
        self.tree.column("router_name", width=155, anchor=tk.W)
        self.tree.column("reserved", width=75, anchor=tk.CENTER)
        self.tree.column("lease", width=90, anchor=tk.W)
        self.tree.column("summary", width=420, anchor=tk.W)

        yscroll = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self.tree.yview)
        xscroll = ttk.Scrollbar(table_frame, orient=tk.HORIZONTAL, command=self.tree.xview)

        self.tree.configure(yscrollcommand=yscroll.set, xscrollcommand=xscroll.set)
        self.tree.tag_configure("yellow", background="#fff2a8")
        self.tree.bind("<Double-1>", self.open_selected_web_ui)
        self.tree.bind("<Button-3>", self.show_row_context_menu)
        self.tree.bind("<Button-2>", self.show_row_context_menu)

        self.tree.grid(row=0, column=0, sticky="nsew")
        yscroll.grid(row=0, column=1, sticky="ns")
        xscroll.grid(row=1, column=0, sticky="ew")

        table_frame.rowconfigure(0, weight=1)
        table_frame.columnconfigure(0, weight=1)

    def set_scan_buttons(self, state: str):
        self.full_scan_button.configure(state=state)
        self.refresh_button.configure(state=state)
        self.missing_scan_button.configure(state=state)
        self.router_sync_button.configure(state=state)
        self.router_config_button.configure(state=state)

    def sort_by_ip(self):
        rows = sorted(
            self.results_by_ip.values(),
            key=lambda r: ipaddress.ip_address(r.ip),
        )
        self._display_rows(rows)

    def sort_by_mac(self):
        def mac_key(row: ScanResult):
            cleaned = re.sub(r"[^0-9A-Fa-f]", "", row.mac or "")
            if len(cleaned) != 12:
                return (1, 0, ipaddress.ip_address(row.ip))
            return (0, int(cleaned, 16), ipaddress.ip_address(row.ip))

        rows = sorted(self.results_by_ip.values(), key=mac_key)
        self._display_rows(rows)

    def _display_rows(self, rows: list[ScanResult]):
        self.tree.delete(*self.tree.get_children())
        self.ip_to_item = {}
        self.last_rows = list(rows)

        for row in rows:
            item_id = self.tree.insert(
                "",
                tk.END,
                values=self._row_values(row),
                image=self._age_icon(row),
                tags=self._row_tags(row),
            )
            self.ip_to_item[row.ip] = item_id

    def start_scan(self, mode: str = "full"):
        if self.scanning:
            return

        try:
            ports = parse_ports(self.ports_var.get())
        except Exception as e:
            messagebox.showerror("Invalid scan settings", str(e))
            return

        if mode == "refresh":
            target_ips = sorted(self.results_by_ip.keys(), key=ipaddress.ip_address)
            scan_label = "Refresh"
            known_ips = set(target_ips)

            if not target_ips:
                self.progress["value"] = 0
                self.progress["maximum"] = 1
                self.status_var.set("Refresh: no listed addresses to scan.")
                return

        else:
            try:
                network = parse_target_to_network(self.target_var.get())
            except Exception as e:
                messagebox.showerror("Invalid subnet", str(e))
                return

            if network.version != 4:
                messagebox.showerror("Invalid subnet", "Only IPv4 networks are supported.")
                return

            all_hosts = [str(ip) for ip in network.hosts()]
            host_count = len(all_hosts)

            if host_count <= 0:
                messagebox.showerror("Invalid subnet", "No usable hosts in that network.")
                return

            if host_count > 4096:
                messagebox.showerror(
                    "Subnet too large",
                    f"{network} contains {host_count} hosts. Use a smaller subnet.",
                )
                return

            if mode == "missing":
                target_ips = [
                    ip for ip in all_hosts
                    if ip not in self.results_by_ip
                    or (
                        self.results_by_ip[ip].last_router_seen
                        and not self.results_by_ip[ip].scanned_at
                    )
                ]
                scan_label = "Scan missing"
                known_ips = set(self.results_by_ip.keys())

            else:
                # A full scan refreshes the whole list. Remembered rows are
                # cleared immediately, then the table is repopulated with
                # responding hosts from the current scan only.
                target_ips = all_hosts
                scan_label = "Full scan"
                known_ips = set()
                self.tree.delete(*self.tree.get_children())
                self.last_rows = []
                self.ip_to_item = {}
                self.results_by_ip = {}

            if not target_ips:
                self.progress["value"] = 0
                self.progress["maximum"] = 1
                self.status_var.set(f"{scan_label}: no addresses to scan.")
                return

        self.progress["value"] = 0
        self.progress["maximum"] = len(target_ips)
        self.status_var.set(f"{scan_label}: scanning {len(target_ips)} address(es)...")
        self.set_scan_buttons(tk.DISABLED)

        self.scanning = True

        thread = threading.Thread(
            target=self._scan_worker,
            args=(target_ips, ports, known_ips, scan_label),
            daemon=True,
        )
        thread.start()

        self.root.after(100, self._process_queue)

    def _scan_worker(
        self,
        target_ips: list[str],
        ports: list[int],
        known_ips: set[str],
        scan_label: str,
    ):
        started = time.time()
        max_workers = min(128, max(16, len(target_ips)))

        results: list[ScanResult] = []
        completed = 0

        try:
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {
                    executor.submit(scan_one_host, ip, ports): ip
                    for ip in target_ips
                }

                for future in as_completed(futures):
                    ip = futures[future]
                    completed += 1

                    try:
                        result = future.result()

                        if result:
                            results.append(result)

                            # Populate the table immediately while scanning.
                            self.queue.put(("found", result))

                        elif ip in known_ips:
                            # Existing remembered rows remain visible but are
                            # marked as checked with no response.
                            self.queue.put(("missed", ip, time.time()))

                    except Exception:
                        pass

                    self.queue.put(("progress", completed, len(target_ips), len(results), scan_label))

            # MAC/manufacturer data is usually most reliable after ARP has been populated.
            arp_table = get_arp_table()
            oui_db = load_oui_database()

            for result in results:
                result.mac = arp_table.get(result.ip, result.mac)
                result.vendor = vendor_from_mac(result.mac, oui_db) if result.mac else ""
                result.summary = build_summary(result)

                # Update existing table row with MAC/vendor/summary.
                self.queue.put(("update", result))

            results.sort(key=lambda r: ipaddress.ip_address(r.ip))

            elapsed = time.time() - started
            self.queue.put(("done", results, elapsed, scan_label, len(target_ips)))

        except Exception as e:
            self.queue.put(("error", str(e)))

    def _row_values(self, row: ScanResult):
        return (
            row.ip,
            row.mac,
            "yes" if row.ping else "no",
            format_ports(row.open_ports),
            row.dns_name,
            row.router_name,
            row.reserved,
            row.lease,
            row.summary,
        )

    def _is_router_only(self, row: ScanResult) -> bool:
        sources = set(filter(None, str(row.source or "").split("+")))
        router_sources = {"router_client", "router_reservation"}
        return bool(sources & router_sources) and not row.ever_responded

    def _age_key(self, row: ScanResult) -> str:
        if self._is_router_only(row):
            return "grey"

        if not row.scanned_at:
            return "grey"

        if not row.ping and not row.open_ports:
            return "red"

        age_seconds = time.time() - row.scanned_at

        if age_seconds <= 3600:
            return "green"

        if age_seconds <= 86400:
            return "yellow"

        return "red"

    def _age_icon(self, row: ScanResult) -> tk.PhotoImage:
        return self.age_icons[self._age_key(row)]

    def _has_duplicate_mac(self, row: ScanResult) -> bool:
        mac = normalise_mac(row.mac)

        if not mac:
            return False

        count = 0

        for existing in self.results_by_ip.values():
            if normalise_mac(existing.mac) == mac:
                count += 1
                if count >= 2:
                    return True

        return False

    def _row_tags(self, row: ScanResult) -> tuple[str, ...]:
        if self._age_key(row) == "yellow" or self._has_duplicate_mac(row):
            return ("yellow",)

        return ()

    def _refresh_row_styles(self):
        for ip, item_id in list(self.ip_to_item.items()):
            row = self.results_by_ip.get(ip)
            if row and self.tree.exists(item_id):
                self.tree.item(
                    item_id,
                    values=self._row_values(row),
                    image=self._age_icon(row),
                    tags=self._row_tags(row),
                )

    def _remove_duplicate_reserved_mac_rows(self, row: ScanResult):
        """Remove stale duplicate rows once a reserved MAC responds at its IP.

        Router sync can leave both an old DHCP address and a reserved address
        for the same MAC.  When a scan confirms the reserved address is alive,
        keep that row and remove the older duplicate MAC rows.
        """
        row_mac = normalise_mac(row.mac)

        if not row_mac:
            return

        if row.reserved != "yes":
            return

        if not (row.ping or row.open_ports):
            return

        duplicate_ips = []

        for ip, existing in list(self.results_by_ip.items()):
            if ip == row.ip:
                continue

            if normalise_mac(existing.mac) != row_mac:
                continue

            if not row.vendor:
                row.vendor = existing.vendor
            if not row.router_name:
                row.router_name = existing.router_name
            if not row.lease:
                row.lease = existing.lease
            if not row.dns_name:
                row.dns_name = existing.dns_name
            if not row.last_router_seen:
                row.last_router_seen = existing.last_router_seen

            sources = set(filter(None, str(row.source or "").split("+")))
            sources.update(filter(None, str(existing.source or "").split("+")))
            row.source = "+".join(sorted(sources))

            duplicate_ips.append(ip)

        for ip in duplicate_ips:
            item_id = self.ip_to_item.pop(ip, None)
            self.results_by_ip.pop(ip, None)

            if item_id and self.tree.exists(item_id):
                self.tree.delete(item_id)

    def _insert_or_update_sorted(self, row: ScanResult):
        current = self.results_by_ip.get(row.ip)

        if current:
            if not row.mac:
                row.mac = current.mac
            if not row.vendor:
                row.vendor = current.vendor
            if not row.router_name:
                row.router_name = current.router_name
            if not row.reserved:
                row.reserved = current.reserved
            if not row.lease:
                row.lease = current.lease
            if not row.last_router_seen:
                row.last_router_seen = current.last_router_seen
            row.ever_responded = bool(row.ever_responded or current.ever_responded)

            sources = set(filter(None, str(current.source or "").split("+")))
            sources.update(filter(None, str(row.source or "").split("+")))
            if row.ping or row.open_ports:
                sources.add("scan")
            row.source = "+".join(sorted(sources))

        elif (row.ping or row.open_ports) and not row.source:
            row.source = "scan"

        self._remove_duplicate_reserved_mac_rows(row)

        if not row.summary:
            row.summary = build_summary(row)

        self.results_by_ip[row.ip] = row

        self.last_rows = sorted(
            self.results_by_ip.values(),
            key=lambda r: ipaddress.ip_address(r.ip),
        )

        values = self._row_values(row)
        existing_item = self.ip_to_item.get(row.ip)

        if existing_item and self.tree.exists(existing_item):
            self.tree.item(
                existing_item,
                values=values,
                image=self._age_icon(row),
                tags=self._row_tags(row),
            )
            self._refresh_row_styles()
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

        new_item = self.tree.insert(
            "",
            insert_index,
            values=values,
            image=self._age_icon(row),
            tags=self._row_tags(row),
        )
        self.ip_to_item[row.ip] = new_item
        self._refresh_row_styles()

    def mark_known_host_missed(self, ip: str, scanned_at: float):
        current = self.results_by_ip.get(ip)

        if not current:
            return

        summary = current.summary
        if current.ever_responded:
            summary = "no response on last scan"

        missed = ScanResult(
            ip=current.ip,
            ping=False,
            open_ports=[],
            dns_name=current.dns_name,
            netbios_name=current.netbios_name,
            mac=current.mac,
            vendor=current.vendor,
            router_name=current.router_name,
            reserved=current.reserved,
            lease=current.lease,
            summary=summary,
            scanned_at=scanned_at,
            last_router_seen=current.last_router_seen,
            source=current.source,
            ever_responded=current.ever_responded,
        )

        self._insert_or_update_sorted(missed)

    def _process_queue(self):
        try:
            while True:
                message = self.queue.get_nowait()
                kind = message[0]

                if kind == "progress":
                    completed, total, found, scan_label = message[1], message[2], message[3], message[4]

                    self.progress["maximum"] = total
                    self.progress["value"] = completed

                    self.status_var.set(
                        f"{scan_label}: {completed}/{total} checked, {found} responding"
                    )

                elif kind == "found":
                    row = message[1]
                    self._insert_or_update_sorted(row)

                elif kind == "missed":
                    ip, scanned_at = message[1], message[2]
                    self.mark_known_host_missed(ip, scanned_at)

                elif kind == "update":
                    row = message[1]
                    self._insert_or_update_sorted(row)

                elif kind == "router_action_done":
                    action, clients, reservations, elapsed = message[1], message[2], message[3], message[4]
                    added, updated = self.merge_router_data(clients, reservations)
                    self.save_memory()
                    self.status_var.set(
                        f"Router {action} done. {added} added, {updated} updated. "
                        f"Elapsed: {elapsed:.1f} s"
                    )
                    self.set_scan_buttons(tk.NORMAL)
                    self.scanning = False

                elif kind == "router_sync_done":
                    clients, reservations, elapsed = message[1], message[2], message[3]
                    added, updated = self.merge_router_data(clients, reservations)
                    self.save_memory()
                    self.status_var.set(
                        f"Router Sync done. {added} added, {updated} updated. "
                        f"Elapsed: {elapsed:.1f} s"
                    )
                    self.set_scan_buttons(tk.NORMAL)
                    self.scanning = False

                elif kind == "done":
                    rows, elapsed, scan_label, scanned_count = message[1], message[2], message[3], message[4]
                    self.last_rows = sorted(
                        self.results_by_ip.values(),
                        key=lambda r: ipaddress.ip_address(r.ip),
                    )

                    self.save_memory()

                    self.status_var.set(
                        f"{scan_label} done. {len(rows)} responding from "
                        f"{scanned_count} scanned. Elapsed: {elapsed:.1f} s"
                    )

                    self.set_scan_buttons(tk.NORMAL)
                    self.scanning = False

                elif kind == "error":
                    self.status_var.set("Error")
                    self.set_scan_buttons(tk.NORMAL)
                    self.scanning = False
                    messagebox.showerror("Scan error", message[1])

        except queue.Empty:
            pass

        if self.scanning:
            self.root.after(100, self._process_queue)

    def refresh_age_indicators(self):
        self._refresh_row_styles()
        self.root.after(60000, self.refresh_age_indicators)

    def load_memory(self):
        path = memory_path()

        if not os.path.exists(path):
            return

        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)

            ui = data.get("ui", {}) if isinstance(data, dict) else {}

            subnet = str(ui.get("subnet", "") or "")
            tcp_ports = str(ui.get("tcp_ports", "") or "")
            geometry = str(ui.get("geometry", "") or "")
            router_config_geometry = str(ui.get("router_config_geometry", "") or "")
            export_dir = str(ui.get("export_dir", "") or "")

            if subnet:
                self.target_var.set(subnet)

            if tcp_ports:
                self.ports_var.set(tcp_ports)

            if geometry and re.fullmatch(r"\d+x\d+(?:[+-]\d+){0,2}", geometry):
                self.root.geometry(geometry)

            if router_config_geometry and re.fullmatch(r"\d+x\d+(?:[+-]\d+){0,2}", router_config_geometry):
                self.router_config_geometry = router_config_geometry

            if export_dir and os.path.isdir(export_dir):
                self.export_dir = export_dir

            rows = []
            for record in data.get("rows", []):
                row = result_from_record(record)
                if row:
                    rows.append(row)

            rows.sort(key=lambda r: ipaddress.ip_address(r.ip))

            for row in rows:
                self._insert_or_update_sorted(row)

            if rows:
                self.status_var.set(f"Ready. Loaded {len(rows)} remembered row(s).")

        except Exception as e:
            self.status_var.set(f"Ready. Could not load memory file: {e}")

    def save_memory(self):
        rows = sorted(
            self.results_by_ip.values(),
            key=lambda r: ipaddress.ip_address(r.ip),
        )

        data = {
            "version": MEMORY_VERSION,
            "saved_at": time.time(),
            "ui": {
                "geometry": self.root.winfo_geometry(),
                "router_config_geometry": self.router_config_geometry,
                "subnet": self.target_var.get().strip(),
                "tcp_ports": self.ports_var.get().strip(),
                "export_dir": self.export_dir,
            },
            "rows": [result_to_record(row) for row in rows],
        }

        path = memory_path()
        temp_path = path + ".tmp"

        try:
            with open(temp_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, sort_keys=True)

            os.replace(temp_path, path)

        except Exception as e:
            self.status_var.set(f"Could not save memory file: {e}")

    def on_close(self):
        self.save_memory()
        self.root.destroy()

    def selected_result(self) -> ScanResult | None:
        selected = self.tree.selection()

        if not selected:
            return None

        item_id = selected[0]
        ip = self.tree.set(item_id, "ip")

        return self.results_by_ip.get(ip)

    def show_row_context_menu(self, event):
        item_id = self.tree.identify_row(event.y)

        if not item_id:
            return

        self.tree.selection_set(item_id)
        self.tree.focus(item_id)

        result = self.selected_result()

        if not result:
            return

        ports = set(result.open_ports)
        has_mac = bool(result.mac)
        has_web = bool(web_url_for_result(result))
        has_ssh = 22 in ports
        has_smb = bool(ports & {139, 445})
        can_rescan = not self.scanning
        router_available = os.path.exists(router_config_path()) and not self.scanning
        is_reserved = str(result.reserved).lower() == "yes"
        can_reserve = router_available and has_mac and bool(result.ip) and not is_reserved
        can_edit_reservation = router_available and is_reserved and bool(result.ip or result.mac)
        can_delete_reservation = can_edit_reservation

        menu = tk.Menu(self.root, tearoff=0)

        menu.add_command(
            label="Rescan",
            command=self.rescan_selected_host,
            state=tk.NORMAL if can_rescan else tk.DISABLED,
        )

        menu.add_command(
            label="Delete",
            command=self.delete_selected_row,
            state=tk.NORMAL if self._age_key(result) == "red" else tk.DISABLED,
        )

        menu.add_command(
            label="Copy MAC Address",
            command=self.copy_selected_mac,
            state=tk.NORMAL if has_mac else tk.DISABLED,
        )

        menu.add_separator()

        menu.add_command(
            label="Router: Reserve this IP",
            command=self.router_reserve_selected_ip,
            state=tk.NORMAL if can_reserve else tk.DISABLED,
        )
        menu.add_command(
            label="Router: Edit reservation",
            command=self.router_edit_selected_reservation,
            state=tk.NORMAL if can_edit_reservation else tk.DISABLED,
        )
        menu.add_command(
            label="Router: Delete reservation",
            command=self.router_delete_selected_reservation,
            state=tk.NORMAL if can_delete_reservation else tk.DISABLED,
        )

        menu.add_separator()

        menu.add_command(
            label="Open in Browser",
            command=self.open_selected_web_ui,
            state=tk.NORMAL if has_web else tk.DISABLED,
        )

        menu.add_command(
            label="SSH",
            command=self.ssh_selected_host,
            state=tk.NORMAL if has_ssh else tk.DISABLED,
        )

        menu.add_command(
            label="Open in Explorer",
            command=self.open_selected_smb,
            state=tk.NORMAL if has_smb else tk.DISABLED,
        )

        menu.tk_popup(event.x_root, event.y_root)
        menu.grab_release()

    def delete_selected_row(self):
        result = self.selected_result()

        if not result or self._age_key(result) != "red":
            return

        item_id = self.ip_to_item.pop(result.ip, None)
        self.results_by_ip.pop(result.ip, None)
        self.last_rows = sorted(
            self.results_by_ip.values(),
            key=lambda r: ipaddress.ip_address(r.ip),
        )

        if item_id and self.tree.exists(item_id):
            self.tree.delete(item_id)

        self._refresh_row_styles()
        self.save_memory()
        self.status_var.set(f"Deleted remembered row: {result.ip}")

    def copy_selected_mac(self):
        result = self.selected_result()

        if not result or not result.mac:
            return

        self.root.clipboard_clear()
        self.root.clipboard_append(result.mac)
        self.status_var.set(f"Copied MAC address for {result.ip}: {result.mac}")

    def open_selected_web_ui(self, event=None):
        result = self.selected_result()

        if not result:
            return

        url = web_url_for_result(result)

        if not url:
            messagebox.showinfo(
                "No web UI detected",
                f"No recognised web UI port is open on {result.ip}.",
            )
            return

        webbrowser.open(url)

    def ssh_selected_host(self):
        result = self.selected_result()

        if not result or 22 not in result.open_ports:
            return

        try:
            subprocess.Popen(
                ["cmd.exe", "/k", "ssh", result.ip],
                creationflags=CREATE_NEW_CONSOLE,
            )
        except Exception as e:
            messagebox.showerror("SSH failed", str(e))

    def open_selected_smb(self):
        result = self.selected_result()

        if not result or not (set(result.open_ports) & {139, 445}):
            return

        unc_path = f"\\\\{result.ip}"

        try:
            if hasattr(os, "startfile"):
                os.startfile(unc_path)
            else:
                subprocess.Popen(["explorer.exe", unc_path])
        except Exception as e:
            messagebox.showerror("Explorer failed", str(e))

    def rescan_selected_host(self):
        if self.scanning:
            return

        result = self.selected_result()

        if not result:
            return

        try:
            ports = parse_ports(self.ports_var.get())
        except Exception as e:
            messagebox.showerror("Invalid scan settings", str(e))
            return

        self.progress["value"] = 0
        self.progress["maximum"] = 1
        self.status_var.set(f"Rescan: scanning {result.ip}...")
        self.set_scan_buttons(tk.DISABLED)
        self.scanning = True

        thread = threading.Thread(
            target=self._scan_worker,
            args=([result.ip], ports, {result.ip}, "Rescan"),
            daemon=True,
        )
        thread.start()

        self.root.after(100, self._process_queue)

    def router_reserve_selected_ip(self):
        result = self.selected_result()

        if not result or not result.mac or not result.ip:
            return

        if str(result.reserved).lower() == "yes":
            messagebox.showinfo(
                "Already reserved",
                f"{result.ip} is already marked as reserved.",
            )
            return

        default_name = result.router_name or result.dns_name or ""
        hostname = simpledialog.askstring(
            "Reserve DHCP address",
            (
                f"Reserve this address on the router?\n\n"
                f"IP:  {result.ip}\n"
                f"MAC: {result.mac}\n\n"
                "Hostname/comment:"
            ),
            initialvalue=default_name,
            parent=self.root,
        )

        if hostname is None:
            return

        if not messagebox.askyesno(
            "Confirm DHCP reservation",
            (
                f"Add DHCP reservation?\n\n"
                f"IP:       {result.ip}\n"
                f"MAC:      {result.mac}\n"
                f"Hostname: {hostname}"
            ),
            parent=self.root,
        ):
            return

        self.start_router_reservation_action(
            action="reserve",
            match_ip=result.ip,
            match_mac=result.mac,
            new_ip=result.ip,
            new_mac=result.mac,
            new_hostname=hostname,
        )

    def router_edit_selected_reservation(self):
        result = self.selected_result()

        if not result or str(result.reserved).lower() != "yes":
            return

        new_ip = simpledialog.askstring(
            "Edit DHCP reservation",
            "Reserved IP address:",
            initialvalue=result.ip,
            parent=self.root,
        )

        if new_ip is None:
            return

        new_ip = new_ip.strip()

        try:
            ipaddress.ip_address(new_ip)
        except ValueError:
            messagebox.showerror("Invalid IP address", new_ip)
            return

        default_name = result.router_name or result.dns_name or ""
        new_hostname = simpledialog.askstring(
            "Edit DHCP reservation",
            "Hostname/comment:",
            initialvalue=default_name,
            parent=self.root,
        )

        if new_hostname is None:
            return

        if not messagebox.askyesno(
            "Confirm reservation edit",
            (
                f"Update DHCP reservation?\n\n"
                f"Current IP: {result.ip}\n"
                f"New IP:     {new_ip}\n"
                f"MAC:        {result.mac}\n"
                f"Hostname:   {new_hostname}"
            ),
            parent=self.root,
        ):
            return

        self.start_router_reservation_action(
            action="edit",
            match_ip=result.ip,
            match_mac=result.mac,
            new_ip=new_ip,
            new_mac=result.mac,
            new_hostname=new_hostname,
        )

    def router_delete_selected_reservation(self):
        result = self.selected_result()

        if not result or str(result.reserved).lower() != "yes":
            return

        if not messagebox.askyesno(
            "Confirm reservation delete",
            (
                f"Delete DHCP reservation?\n\n"
                f"IP:   {result.ip}\n"
                f"MAC:  {result.mac}\n"
                f"Name: {result.router_name}"
            ),
            parent=self.root,
        ):
            return

        self.start_router_reservation_action(
            action="delete",
            match_ip=result.ip,
            match_mac=result.mac,
        )

    def start_router_reservation_action(
        self,
        *,
        action: str,
        match_ip: str = "",
        match_mac: str = "",
        new_ip: str = "",
        new_mac: str = "",
        new_hostname: str = "",
    ):
        if self.scanning:
            return

        self.progress["value"] = 0
        self.progress["maximum"] = 1
        self.status_var.set(f"Router {action}: logging in and updating DHCP reservation...")
        self.set_scan_buttons(tk.DISABLED)
        self.scanning = True

        thread = threading.Thread(
            target=self._router_reservation_worker,
            kwargs={
                "action": action,
                "match_ip": match_ip,
                "match_mac": match_mac,
                "new_ip": new_ip,
                "new_mac": new_mac,
                "new_hostname": new_hostname,
            },
            daemon=True,
        )
        thread.start()

        self.root.after(100, self._process_queue)

    def _router_reservation_worker(
        self,
        *,
        action: str,
        match_ip: str,
        match_mac: str,
        new_ip: str,
        new_mac: str,
        new_hostname: str,
    ):
        started = time.time()

        try:
            config = self.load_router_config()

            if config.get("type") != "tplink_archer_ax72":
                raise RuntimeError(f"Unsupported router type: {config.get('type')}")

            from router_tplink_ax72 import TPLinkAX72Router

            router = TPLinkAX72Router(
                base_url=config["base_url"],
                password=config["password"],
            )

            router.login()

            try:
                if action == "reserve":
                    router.add_dhcp_reservation(
                        mac=new_mac,
                        ip=new_ip,
                        hostname=new_hostname,
                    )
                elif action == "edit":
                    router.update_dhcp_reservation(
                        match_ip=match_ip or None,
                        match_mac=None,
                        new_ip=new_ip,
                        new_hostname=new_hostname,
                    )
                elif action == "delete":
                    router.delete_dhcp_reservation(
                        match_ip=match_ip or None,
                        match_mac=None,
                    )
                else:
                    raise RuntimeError(f"Unknown router action: {action}")

                clients = router.get_dhcp_clients()
                reservations = router.get_dhcp_reservations()
            finally:
                router.logout()

            elapsed = time.time() - started
            self.queue.put(("router_action_done", action, clients, reservations, elapsed))

        except Exception as e:
            self.queue.put(("error", f"Router {action} failed: {e}"))

    def open_router_config_dialog(self):
        data = read_router_config_file()
        selected = data.get("selected_router", "home_ax72")
        router = dict(data.get("routers", {}).get(selected, {}))
        default = default_router_config()["routers"]["home_ax72"]

        for key, value in default.items():
            router.setdefault(key, value)

        dialog = tk.Toplevel(self.root)
        dialog.title("Router Config")
        dialog.transient(self.root)
        dialog.grab_set()
        dialog.resizable(False, False)

        if self.router_config_geometry:
            dialog.geometry(self.router_config_geometry)

        def close_dialog():
            self.router_config_geometry = dialog.winfo_geometry()
            dialog.destroy()

        dialog.protocol("WM_DELETE_WINDOW", close_dialog)

        frame = ttk.Frame(dialog, padding=12)
        frame.pack(fill=tk.BOTH, expand=True)

        router_type_var = tk.StringVar(value="TP-Link Archer AX72 / AX5400")
        label_var = tk.StringVar(value=str(router.get("label", "Home TP-Link AX72") or ""))
        base_url_var = tk.StringVar(value=str(router.get("base_url", "http://192.168.0.1") or ""))
        password_var = tk.StringVar(value=str(router.get("password", "") or ""))
        status_var = tk.StringVar(value="")

        row = 0
        ttk.Label(frame, text="Router type:").grid(row=row, column=0, sticky=tk.W, pady=4)
        type_box = ttk.Combobox(
            frame,
            textvariable=router_type_var,
            values=("TP-Link Archer AX72 / AX5400",),
            state="readonly",
            width=34,
        )
        type_box.grid(row=row, column=1, sticky=tk.EW, pady=4)

        row += 1
        ttk.Label(frame, text="Label:").grid(row=row, column=0, sticky=tk.W, pady=4)
        ttk.Entry(frame, textvariable=label_var, width=38).grid(row=row, column=1, sticky=tk.EW, pady=4)

        row += 1
        ttk.Label(frame, text="Base URL:").grid(row=row, column=0, sticky=tk.W, pady=4)
        ttk.Entry(frame, textvariable=base_url_var, width=38).grid(row=row, column=1, sticky=tk.EW, pady=4)

        row += 1
        ttk.Label(frame, text="Password:").grid(row=row, column=0, sticky=tk.W, pady=4)
        ttk.Entry(frame, textvariable=password_var, width=38, show="*").grid(row=row, column=1, sticky=tk.EW, pady=4)

        row += 1
        ttk.Label(frame, textvariable=status_var).grid(
            row=row, column=0, columnspan=2, sticky=tk.W, pady=(8, 4)
        )

        button_frame = ttk.Frame(frame)
        button_frame.grid(row=row + 1, column=0, columnspan=2, sticky=tk.E, pady=(10, 0))

        def current_router_config() -> dict:
            base_url = base_url_var.get().strip().rstrip("/")
            password = password_var.get()

            if not base_url:
                raise ValueError("Base URL is required.")

            if not password:
                raise ValueError("Password is required.")

            return {
                "type": "tplink_archer_ax72",
                "label": label_var.get().strip() or "Home TP-Link AX72",
                "base_url": base_url,
                "password": password,
                "password_storage": "plaintext",
            }

        def test_login():
            try:
                config = current_router_config()
                status_var.set("Testing login...")
                dialog.update_idletasks()

                from router_tplink_ax72 import TPLinkAX72Router

                router_obj = TPLinkAX72Router(
                    base_url=config["base_url"],
                    password=config["password"],
                )
                router_obj.login()
                router_obj.logout()
                status_var.set("Test login OK.")
                messagebox.showinfo("Router Config", "Test login OK.", parent=dialog)

            except Exception as e:
                status_var.set("Test login failed.")
                messagebox.showerror("Router Config", f"Test login failed:\n\n{e}", parent=dialog)

        def save_config():
            try:
                config = current_router_config()
                new_data = {
                    "selected_router": "home_ax72",
                    "routers": {"home_ax72": config},
                }
                write_router_config_file(new_data)
                self.status_var.set(f"Router config saved: {router_config_path()}")
                close_dialog()

            except Exception as e:
                messagebox.showerror("Router Config", str(e), parent=dialog)

        ttk.Button(button_frame, text="Test Login", command=test_login).pack(side=tk.LEFT)
        ttk.Button(button_frame, text="Save", command=save_config).pack(side=tk.LEFT, padx=(8, 0))
        ttk.Button(button_frame, text="Cancel", command=close_dialog).pack(side=tk.LEFT, padx=(8, 0))

        frame.columnconfigure(1, weight=1)
        dialog.bind("<Escape>", lambda _event: close_dialog())
        dialog.wait_window()

    def start_router_sync(self):
        if self.scanning:
            return

        self.progress["value"] = 0
        self.progress["maximum"] = 1
        self.status_var.set("Router Sync: logging in and reading DHCP data...")
        self.set_scan_buttons(tk.DISABLED)
        self.scanning = True

        thread = threading.Thread(
            target=self._router_sync_worker,
            daemon=True,
        )
        thread.start()

        self.root.after(100, self._process_queue)

    def _router_sync_worker(self):
        started = time.time()

        try:
            config = self.load_router_config()

            if config.get("type") != "tplink_archer_ax72":
                raise RuntimeError(f"Unsupported router type: {config.get('type')}")

            from router_tplink_ax72 import TPLinkAX72Router

            router = TPLinkAX72Router(
                base_url=config["base_url"],
                password=config["password"],
            )

            router.login()

            try:
                clients = router.get_dhcp_clients()
                reservations = router.get_dhcp_reservations()
            finally:
                router.logout()

            elapsed = time.time() - started
            self.queue.put(("router_sync_done", clients, reservations, elapsed))

        except Exception as e:
            self.queue.put(("error", f"Router Sync failed: {e}"))

    def load_router_config(self) -> dict:
        path = router_config_path()

        if not os.path.exists(path):
            raise RuntimeError(
                f"router_config.json not found: {path}. "
                "Use the Router Config button to create it."
            )

        data = read_router_config_file()

        selected = data.get("selected_router")
        routers = data.get("routers", {})

        if not selected or selected not in routers:
            raise RuntimeError("router_config.json has no valid selected_router")

        router = dict(routers[selected])

        for key in ("type", "base_url", "password"):
            if not router.get(key):
                raise RuntimeError(f"router_config.json selected router is missing {key!r}")

        return router

    def merge_router_data(self, clients, reservations) -> tuple[int, int]:
        now = time.time()
        added = 0
        updated = 0

        client_list = clients if isinstance(clients, list) else []
        reservation_list = reservations if isinstance(reservations, list) else []

        reservations_by_mac = {}
        reservations_by_ip = {}

        for item in reservation_list:
            if not isinstance(item, dict):
                continue

            mac = normalise_mac(item.get("mac", ""))
            ip = str(item.get("ip", "") or "").strip()

            if mac:
                reservations_by_mac[mac] = item
            if ip:
                reservations_by_ip[ip] = item

        seen_keys = set()

        for item in client_list:
            if not isinstance(item, dict):
                continue

            mac = normalise_mac(item.get("macaddr", ""))
            ip = str(item.get("ipaddr", "") or "").strip()

            if not ip:
                continue

            reservation = reservations_by_ip.get(ip)

            # If a MAC has a reservation for a different IP, keep the
            # current DHCP-client row at its live lease address.  The
            # reservation row is added separately below as a grey/router-only
            # target until the device renews/reboots onto that reserved IP.
            if reservation and mac and normalise_mac(reservation.get("mac", "")) != mac:
                reservation = None

            changed = self.merge_one_router_row(
                ip=ip,
                mac=mac,
                router_name=str(item.get("name", "") or ""),
                lease=str(item.get("leasetime", "") or ""),
                reservation=reservation,
                now=now,
                source_hint="router_client",
            )

            if changed == "added":
                added += 1
            elif changed == "updated":
                updated += 1

            seen_keys.add((mac, ip))

        for item in reservation_list:
            if not isinstance(item, dict):
                continue

            mac = normalise_mac(item.get("mac", ""))
            ip = str(item.get("ip", "") or "").strip()

            if not ip or (mac, ip) in seen_keys:
                continue

            changed = self.merge_one_router_row(
                ip=ip,
                mac=mac,
                router_name=str(item.get("hostname", "") or item.get("comment", "") or ""),
                lease="",
                reservation=item,
                now=now,
                source_hint="router_reservation",
            )

            if changed == "added":
                added += 1
            elif changed == "updated":
                updated += 1

        return added, updated

    def merge_one_router_row(
        self,
        ip: str,
        mac: str,
        router_name: str,
        lease: str,
        reservation: dict | None,
        now: float,
        source_hint: str,
    ) -> str:
        row = None

        # Reservation-only rows should not steal/move the currently leased
        # DHCP-client row for the same MAC.  After editing a reservation, the
        # router may show the old live lease and the new reservation at the
        # same time.  Keep both until the device actually appears at the new
        # reserved address.
        if source_hint == "router_reservation":
            row = self.results_by_ip.get(ip)
        else:
            if mac:
                for existing in self.results_by_ip.values():
                    if normalise_mac(existing.mac) == mac:
                        row = existing
                        break

            if not row:
                row = self.results_by_ip.get(ip)

        old_ip = row.ip if row else ""
        was_new = row is None

        if row and row.ip != ip:
            old_item = self.ip_to_item.pop(row.ip, None)
            self.results_by_ip.pop(row.ip, None)
            if old_item and self.tree.exists(old_item):
                self.tree.delete(old_item)
            row.ip = ip

        if was_new:
            row = ScanResult(
                ip=ip,
                ping=False,
                open_ports=[],
                mac=mac,
                summary="router DHCP entry",
            )

        if mac and not row.mac:
            row.mac = mac

        if router_name and router_name != "--":
            row.router_name = router_name

        if lease:
            row.lease = lease

        if reservation:
            row.reserved = "yes" if reservation.get("enable", "on") == "on" else "off"
            reserved_name = str(
                reservation.get("hostname", "")
                or reservation.get("comment", "")
                or ""
            )
            if reserved_name and reserved_name != "--":
                row.router_name = row.router_name or reserved_name

        else:
            row.reserved = ""

        row.last_router_seen = now

        sources = set(filter(None, str(row.source or "").split("+")))
        sources.add(source_hint)
        if row.ping or row.open_ports:
            sources.add("scan")
        row.source = "+".join(sorted(sources))

        if not row.scanned_at and not row.open_ports:
            if row.reserved:
                row.summary = "DHCP reservation"
            else:
                row.summary = "router DHCP entry"

        self._insert_or_update_sorted(row)
        return "added" if was_new else "updated"

    def export_csv(self):
        if not self.last_rows:
            messagebox.showinfo("Nothing to export", "Run a scan or router sync first.")
            return

        initial_name = time.strftime("lan_scan_%Y%m%d_%H%M%S.csv")
        dialog_kwargs = {
            "title": "Export scan results",
            "defaultextension": ".csv",
            "filetypes": [("CSV files", "*.csv"), ("All files", "*.*")],
            "initialfile": initial_name,
        }

        if self.export_dir and os.path.isdir(self.export_dir):
            dialog_kwargs["initialdir"] = self.export_dir

        path = filedialog.asksaveasfilename(**dialog_kwargs)

        if not path:
            return

        try:
            rows = sorted(
                self.last_rows,
                key=lambda r: ipaddress.ip_address(r.ip),
            )

            with open(path, "w", newline="", encoding="utf-8-sig") as f:
                writer = csv.writer(f)

                writer.writerow(
                    [
                        "Status",
                        "IP address",
                        "MAC address",
                        "Ping",
                        "Alive",
                        "Open TCP ports",
                        "DNS name",
                        "Name on Router",
                        "Reserved",
                        "Lease",
                        "Manufacturer",
                        "Summary",
                        "Source",
                        "Last scanned",
                        "Last router seen",
                        "Age seconds",
                        "Web URL",
                    ]
                )

                now = time.time()

                for row in rows:
                    age_seconds = ""
                    if row.scanned_at:
                        age_seconds = str(int(max(0, now - row.scanned_at)))

                    writer.writerow(
                        [
                            export_status_text(row),
                            row.ip,
                            row.mac,
                            "yes" if row.ping else "no",
                            "yes" if (row.ping or row.open_ports) else "no",
                            format_ports(row.open_ports),
                            row.dns_name,
                            row.router_name,
                            row.reserved,
                            row.lease,
                            row.vendor,
                            row.summary,
                            row.source,
                            format_timestamp(row.scanned_at),
                            format_timestamp(row.last_router_seen),
                            age_seconds,
                            web_url_for_result(row),
                        ]
                    )

            self.export_dir = os.path.dirname(os.path.abspath(path))
            self.save_memory()
            self.status_var.set(f"Exported {len(rows)} row(s) to {path}")
            messagebox.showinfo("Export complete", f"Exported {len(rows)} row(s).")

        except Exception as e:
            messagebox.showerror("Export failed", str(e))


def main():
    root = tk.Tk()
    LanScannerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
