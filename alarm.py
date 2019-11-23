#!/usr/bin/python3
###############################################################################
# Andrew Gross
# COMP 116 - Fall 2019 - Ming Chow
# alarm.py
#
# USAGE: alarm.py [-h] [-i INTERFACE] [-r PCAPFILE]
# `-i INTERFACE: Sniff on a specified network interface`
# `-r PCAPFILE: Read in a PCAP file`
# `-h: Display message on how to use tool`
#
# Example 1: python3 alarm.py -h will print out the usage information.
# Example 2: python3 alarm.py -r set2.pcap will read the packets from set2.pcap.
# Example 3: python3 alarm.py -i en0 will sniff packets on a 
#            wireless interface en0.
###############################################################################

from scapy.all import *
import pcapy
import argparse
import base64
from ipwhois import IPWhois

NULL_SCAN = ''
FIN_SCAN = 'F'
XMAS_SCAN = 'FPU'
incidents = 0
ftp_user = None
ftp_pass = None
ip_hash_table = {}

# Print function to print alert with out username and password pair.
def print_alert(incident, src_port, protocol):
  global incidents
  incidents += 1
  print("ALERT {0}: {1} is detected from {2} ({3})!".format(incidents, incident, src_port, protocol))

# Print function to print alert withi username and password pair.
def print_alert_plaintext(incident, src_port, protocol, payload):
  global incidents
  incidents += 1
  print("ALERT {0}: {1} is detected from {2} ({3}) ({4})!".format(incidents, incident, src_port, protocol, payload))

# Parses packet to retrieve username and password pair if sent in clear
# over HTTP.
def get_http_user_pass(packet):
  data = str(packet[Raw].load)
  username = None
  password = None
  if "Authorization: Basic " in data:
    index_of_basic = data.find("Basic ")
    offset = 6
    if index_of_basic != -1:
      user_password_data = data[index_of_basic + offset:]
      index_of_end = user_password_data.find("\\r")
      user_pass = user_password_data[:index_of_end]
      decoded_user_pass = base64.b64decode(user_pass).decode('UTF-8')
      column_index = decoded_user_pass.find(":")
      username = decoded_user_pass[:column_index]
      password = decoded_user_pass[column_index + 1:]
    else:
      return None
    if username != None and password != None:
      return "username: " + username + ", password: " + password
    else:
      return None
  else:
    return None

# Sets global variables ftp_user and ftp_pass in order
# to pair usernames and passwords sent in the clear via FTP.
def set_global_ftp_user_pass(packet, ftp_user, ftp_pass):
  data = str(packet[Raw].load)
  if ftp_user == None:
    index_of_user = data.find("USER")
    if index_of_user != -1:
      index_of_end = data[index_of_user:].find("\\r")
      ftp_user = data[index_of_user + 5:index_of_end + 2]
      return (ftp_user, ftp_pass)
  else:
    index_of_pass = data.find("PASS")
    if index_of_pass != -1:
      index_of_end = data[index_of_pass:].find("\\r")
      ftp_pass = data[index_of_pass + 5:index_of_end + 2]
      return (ftp_user, ftp_pass)
    

# Take packet. Return bool if threat
def check_port(packet):
  global ftp_user
  global ftp_pass
  if packet[TCP].dport == 80:
    if "Nikto" in str(packet[Raw].load):
      print_alert("Nikto scan", packet[IP].src, str.upper(packet.sprintf("%IP.proto%")))
    payload = get_http_user_pass(packet)
    if payload != None:
      print_alert_plaintext("Usernames and passwords sent in-the-clear", packet[IP].src, packet[TCP].dport, payload)
        
  if packet[TCP].dport == 21:
    (ftp_user, ftp_pass) = set_global_ftp_user_pass(packet, ftp_user, ftp_pass)
    if ftp_user != None and ftp_pass != None:
      payload = "username: " + ftp_user + ", password: " + ftp_pass
      print_alert_plaintext("Usernames and passwords sent in-the-clear", packet[IP].src, packet[TCP].dport, payload)
      ftp_user = None 
      ftp_pass = None

# Checks the owner of novel IPs and alerts if from
# Russia or Facebook. Stores each novel IP in dictionary
# to reduce frequency of IPWhois query.
def check_ip(packet):
  ip = str(packet[IP].src)
  if ip not in ip_hash_table:
    obj = IPWhois(packet[IP].src)
    results = obj.lookup_rdap(depth=1)
    is_russian = results["asn_country_code"] == "RU"
    is_facebook = "FACEBOOK" in results["asn_description"]
    if is_russian:
      ip_hash_table[ip] = ("Source IP address is from Russia", packet[IP].src, str.upper(packet.sprintf("%IP.proto%")))
      print_alert("Source IP address is from Russia", packet[IP].src, str.upper(packet.sprintf("%IP.proto%")))
    if is_facebook:
      ip_hash_table[ip] = ("Source IP address belongs to Facebook", packet[IP].src, str.upper(packet.sprintf("%IP.proto%")))
      print_alert("Source IP address belongs to Facebook", packet[IP].src, str.upper(packet.sprintf("%IP.proto%")))
    if (is_russian is not True) and (is_facebook is not True):
      ip_hash_table[ip] = -1
  else:
    print_data = ip_hash_table[ip]
    print_alert(print_data[0], print_data[1], print_data[2])

# Checks the flags of the given packet match the scans:
# NULL, XMAS, and FIN
def check_scans(packet):
  if packet.sprintf('%TCP.flags%') == NULL_SCAN:
    print_alert("NULL scan", packet[IP].src, packet[TCP].dport)
  elif packet.sprintf('%TCP.flags%') == XMAS_SCAN:
    print_alert("XMAS scan", packet[IP].src, packet[TCP].dport)
  elif packet.sprintf('%TCP.flags%') == FIN_SCAN:
    print_alert("FIN scan", packet[IP].src, packet[TCP].dport)

# packetcallback called on each packet to check ports for passwords
# sent in the clear, ip for Russian/Facebook ownership, and flags for scans
def packetcallback(packet):
  try:
    check_port(packet)
  except:
    pass
  try:
    check_ip(packet)
  except:
    pass
  try:
    check_scans(packet)
  except:
    pass 

# main thread
parser = argparse.ArgumentParser(description='A network sniffer that identifies basic vulnerabilities')
parser.add_argument('-i', dest='interface', help='Network interface to sniff on', default='eth0')
parser.add_argument('-r', dest='pcapfile', help='A PCAP file to read')
args = parser.parse_args()
if args.pcapfile:
  try:
    print("Reading PCAP file %(filename)s..." % {"filename" : args.pcapfile})
    sniff(offline=args.pcapfile, prn=packetcallback)    
  except:
    print("Sorry, something went wrong reading PCAP file %(filename)s!" % {"filename" : args.pcapfile})
else:
  print("Sniffing on %(interface)s... " % {"interface" : args.interface})
  try:
    sniff(iface=args.interface, prn=packetcallback)
  except pcapy.PcapError:
    print("Sorry, error opening network interface %(interface)s. It does not exist." % {"interface" : args.interface})
  except:
    print("Sorry, can\'t read network traffic. Are you root?")
