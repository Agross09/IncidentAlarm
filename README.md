# IncidentAlarm
Basic incident alarm that analyzes live streams of packets off an interface and from PCAP files using Python 3, Pcapy, and Scapy.

### Usage: 
`alarm.py [-h] [-i INTERFACE] [-r PCAPFILE]`
`-i INTERFACE: Sniff on a specified network interface`
`-r PCAPFILE: Read in a PCAP file`
`-h: Display message on how to use tool`

### Building:
`pip install -r requirements.txt` 
See requirements.txt for required pip packages.