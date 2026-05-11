# LAN Scanner with TP-Link AX72 Router Integration

A Windows Python GUI tool for scanning a local IPv4 network, identifying
responding devices, enriching results with router DHCP data, and managing
TP-Link Archer AX72 / AX5400 DHCP reservations.

The application is designed for local network administration and device
inventory. It combines direct network scanning with data read from the
router's built-in web interface.

## Main Features

- Scan a local IPv4 subnet for active devices.
- Default subnet supports CIDR notation, for example:

  ```text
  192.168.0.0/23
  ```

- Detect devices using:
  - ICMP ping
  - common TCP port checks
  - DNS lookup
  - Windows ARP table
  - router DHCP client list
  - router DHCP reservation list

- Display results in a sortable table showing:
  - IP address
  - MAC address
  - ping result
  - open TCP ports
  - DNS name
  - name reported by router
  - DHCP reservation status
  - DHCP lease time
  - summary of likely device/service type

- Status indicator beside each row:
  - bright green circle: device responded recently
  - bright yellow circle: device responded within the last day
  - red circle: previously known device, not recently responding
  - grey square: router-only record, not yet verified by scanner

- Persistent memory:
  - remembers previous scan results
  - remembers router-discovered devices
  - remembers window position
  - remembers subnet and TCP port list
  - remembers export location

- Right-click actions:
  - rescan selected row
  - delete stale red rows
  - copy MAC address
  - open web UI in browser
  - open SSH session
  - open SMB device in Windows Explorer
  - reserve IP on router
  - edit DHCP reservation
  - delete DHCP reservation

- CSV export with timestamped filename.

## Scan Modes

### Full Scan

Clears the current list and scans the entire selected subnet from scratch.

### Refresh

Scans every IP address currently shown in the table.

### Scan Missing

Scans IP addresses in the configured subnet that are not already listed, plus
router-only rows that have not yet been verified by the scanner.

### Router Sync

Logs into the configured TP-Link router, reads DHCP client and reservation
data, and merges that data into the scanner table.

Router-known devices are added even if they are currently offline. These appear
as grey router-only entries until the scanner verifies that the device is alive.

## Router Support

Currently implemented router support:

```text
TP-Link Archer AX72 / AX5400
```

The router is accessed through its built-in web interface. The script reproduces
the router's encrypted login and encrypted request format using Python.

Supported router operations:

- login
- read DHCP server settings
- read DHCP client list
- read DHCP reservations
- add DHCP reservation
- edit DHCP reservation
- delete DHCP reservation

## Requirements

### Operating System

Tested for Windows.

The script uses Windows-specific tools/features:

- `ping`
- `arp -a`
- `nbtstat`
- Windows Explorer SMB opening
- `cmd.exe` for SSH launch

### Python

Python 3.11 or later recommended.

### Python Packages

Install dependencies with:

```cmd
pip install requests pycryptodome
```

`tkinter` is also required. It is normally included with the standard Windows
Python installer.

### Optional Tools

For SSH right-click support, Windows must have an available SSH client:

```cmd
ssh
```

Modern Windows 10/11 installations usually include this.

## Files

Recommended directory:

```text
D:\Scripts\Network
```

Main files:

```text
lan_scanner_gui.py
router_tplink_ax72.py
router_config.json
lan_scanner_gui_memory.json
```

### `lan_scanner_gui.py`

Main GUI application.

### `router_tplink_ax72.py`

Router adapter for the TP-Link Archer AX72 / AX5400 web interface.

### `router_config.json`

Local router configuration. This file contains the router password if plaintext
storage is used.

Do not commit this file to a public repository.

Example:

```json
{
  "selected_router": "home_ax72",
  "routers": {
    "home_ax72": {
      "type": "tplink_archer_ax72",
      "label": "Home TP-Link AX72",
      "base_url": "http://192.168.0.1",
      "password": "",
      "password_storage": "plaintext"
    }
  }
}
```

### `lan_scanner_gui_memory.json`

Local application memory containing scan history, router-discovered devices,
window position, subnet, TCP port list, and export location.

Do not commit this file to a public repository.

## Running

From the script directory:

```cmd
cd /d D:\Scripts\Network
python lan_scanner_gui.py
```

Optional `.cmd` wrapper:

```bat
@echo off
start "" /D "%~dp0" pythonw.exe "%~dp0lan_scanner_gui.py" %*
exit /b
```

This allows launching the GUI without leaving a console window open.

## Default TCP Ports

The scanner checks a configurable list of common TCP ports, including services
such as:

- HTTP / HTTPS
- SSH
- Telnet
- SMB
- DNS
- SMTP / IMAP / POP3
- IPP / printer ports
- RTSP
- MQTT
- MySQL
- RDP
- ADB
- common alternate web ports

The TCP port list can be edited in the GUI and is remembered between runs.

## Privacy and Repository Notes

Safe to commit:

```text
lan_scanner_gui.py
router_tplink_ax72.py
README.md
requirements.txt
.gitignore
router_config.example.json
```

Do not commit:

```text
router_config.json
lan_scanner_gui_memory.json
lan_scan_*.csv
router capture files
browser screenshots
router session tokens
router JavaScript captures
```

Suggested `.gitignore`:

```gitignore
# Local credentials
router_config.json

# Local LAN inventory and app memory
lan_scanner_gui_memory.json
lan_scan_memory.json

# Exports
lan_scan_*.csv
*.csv

# Captures / temporary diagnostics
Downloads.zip
chrome_*.png
Pasted text.txt

# Python cache
__pycache__/
*.pyc
```

## Safety Notes

Only use this tool on networks and routers that you own or are authorised to
administer.

The TP-Link router integration uses the router's private web interface rather
than a stable public API. Firmware updates may change login or DHCP behaviour
and could require changes to the adapter module.
