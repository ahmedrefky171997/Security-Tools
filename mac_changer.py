import subprocess
from optparse import OptionParser
#change mac address
def mac_changer(interface,mac_address):
	subprocess.call(["ifconfig",interface,"down"])
	subprocess.call(["ifconfig",interface,"hw","ether",mac_address])
	subprocess.call(["ifconfig",interface,"up"])

#use command line to change the mac address
def get_input():
	parser = OptionParser()
	parser.add_option("-i","--interface",dest = "interface",help = "select interface")
	parser.add_option("-m","--mac",dest = "mac_address",help = "enter mac address")
	(options,_) = parser.parse_args()
	if not options.interface:
		parser.error("[-] Please satisfy an interface")
		exit(0)
	elif not options.mac_address:
		parser.error("[-] Please satisfy a mac address")
		exit(0)
	return options


options = get_input()
interface = options.interface
mac_address = options.mac_address
mac_changer(interface,mac_address)
print("[+] MAC has been successfully changed to "+mac_address)
