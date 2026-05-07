# MadDavo Tools
A collection of Python scripts that I find useful

## lan_scanner_gui.py / lanscan
This script provides a Windows GUI LAN scanner for quickly identifying
active devices on a local IPv4 subnet, defaulting to 192.168.0.0/24.
It scans each host using ICMP ping and common TCP port checks, then
displays responding devices in a table with IP address, ping status,
open ports, DNS name, NetBIOS name, MAC address, likely manufacturer,
and a short inferred summary such as web UI, SMB/NAS, printer, RTSP
camera, MQTT/IoT, RDP, SSH, or ADB/Android/Fire TV. Results are
populated progressively while scanning, kept numerically sorted by IP
address, enriched afterward with ARP/MAC and OUI/vendor information
where available, and can be exported to CSV for later reference.

`lanscan` simply calls wpython to run lan_scanner_gui in a process.
