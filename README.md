# MadDavo Tools
A collection of Python scripts that I find useful

## lan_scanner_gui.py / lanscan
The origin of this script was a replacement for Fing.  I needed something
to just scan my network that was small, light, no fuss.  Then things
kinda blew up.

This script provides a Windows GUI LAN scanner for quickly identifying
active devices on a local IPv4 subnet, defaulting to 192.168.0.0/24.
It scans each host using ICMP ping and common TCP port checks, then
displays responding devices in a table with IP address, ping status,
open ports, DNS name, MAC address, and a short inferred summary such
as web UI, SMB/NAS, printer, RTSP camera, MQTT/IoT, RDP, SSH, or
ADB/Android/Fire TV. Results are populated progressively while
scanning, kept numerically sorted by IP address, enriched afterward
with ARP/MAC and OUI/vendor information where available, and can be
exported to CSV for later reference.

But wait, there's more.  The DHCP admin interface on my router is WOEFUL.
So I thought, hey I hate going back and forth from this list to my web
browser, can't I just script the bejebus out of this?  And so yeah, that
happened.  I went down a rabbit hole and came up with this very very
specific tool for my router.  Does it support any other routers? No. But
it could if one needed to - there's a facility to use an as yet unwritten
plugin.  So at some point when this router inevitably blows up then I'll
be writing another extension for this.  For all the features of this tool
see the separate README.

`lanscan` simply calls wpython to run lan_scanner_gui in a process.

## rollback_photos.ps1 / rollback_photos.bat
Ah, don't you love it when Microsoft takes something that has been
solid, reliable and completely XXXX's it up? Say hello to Microsoft
Photos. An update released on 14th March 2026 diverged the path of
this photo viewing/editing app. The 'new' version with new workflow
basically screwed everyone up so they released Photos Legacy and users
then had a choice to use the new or the legacy. But of course what
MS didn't account for was that both are XXXX compared with the
brain-dead yet reliable old 2024 version. So in a fit of frustration
I wrote this script to rollback Photos to the earlier version which
of course was still on my PC due to Microsoft's leaky clean up
policy.

To use: DISABLE Microsoft Store automatic updates (which I could only
do for five weeks max). Then use the batch file to run the PowerShell
script.
