import scapy.all as scapy
import argparse
#scanning and appending the result to a list of target clients
#creating an arp request packing with the an ip 
#creating ether part of the packet
#appending arp_request to the ether part 
#sending this merged packet 
#answered list contains response to the question asked (what is an ip for the current ip) which is the mac address
#put the result into a list of dictionary 
def scan(ip):
	arp_request = scapy.ARP(pdst=ip)
	broadcast = scapy.Ether(dst = 'ff:ff:ff:ff:ff:ff')
	arp_request_broadcast = broadcast/arp_request
	answered = scapy.srp(arp_request_broadcast,timeout=1,verbose=False)[0]
	clients_list = []
	for element in answered:
		client = {"ip" : element[1].psrc ,"mac" :element[1].hwsrc}
		clients_list.append(client)
	return clients_list
#printing the clients in a table matter
def print_clients(client_list):
	print("IP\t\t\tMAC ADDRESS\n------------------------------------------")
	for element in client_list:
		print(element["ip"]+"\t\t"+element["mac"])
#parsing input and using commandline to call this tool
def get_input():
	parser = argparse.ArgumentParser()
	parser.add_argument("-t","--target",help = "enter a target ip for scanning",required = True)
	#create dict of option contains target
	options = vars(parser.parse_args())
	return options

clients_list = scan(get_input()["target"])
print_clients(clients_list)
