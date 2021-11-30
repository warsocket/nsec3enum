#!/usr/bin/env pypy3
from nsec3enum import dns_types, mk_raw_dns_pkt, dns_shake, uncompress_record, domain2wire, wire2parts, dns_alphabet
import sys
import socket
import random
import _socket


################################################################################
#                                  NSEC FUNCTIONS                              #
################################################################################

full_alphabet = sorted(dns_alphabet + ["_"])

def incname(wirename, addsub=False):

	#the most insignificant increate is alsways adding a 00 subdomain part
	# return b'\x01\x00' + wirename

	#but since some servers dont adhere to the rfc that allows for that this is the next best thing
	#we might miss some binary domains, but those are rare at best
	if addsub:
		return b'\x01-' + wirename

	#and that really just dives stright into subdomains
	#se again lets try appending a dash
	else:
		l = wirename[0]

		return( bytes([l+1]) + wirename[1:l+1] + b'-' + wirename[l+1:] )


def main(domain):
	################################################################################
	#                                   DNS PREP                                   #
	################################################################################
	wiredomain = domain2wire(domain)
	dps = len(wire2parts(wiredomain))

	#Get nameserver names from default nameserver
	ns_pkt = mk_raw_dns_pkt(dns_types["NS"], wiredomain)
	nameservers_reponse = dns_shake(ns_pkt)

	#Resolve all nameserver ip's using default nameserver
	ipv4 = [] #will contain all ipv4 adresses of nameservers (ipv4 mapped ipv6)
	ipv6 = [] #will contain all ipv6 addresses of nameservers

	#parse data, which are hostnames for dns servers (whichg ened to be expanded)
	nameservers = [uncompress_record(nameservers_reponse["raw_data"],x["data"]) for x in nameservers_reponse["answers"] if x["type"] == dns_types["NS"]]
	for nameserver in nameservers:
		pkt_ipv4 = mk_raw_dns_pkt(dns_types["A"], nameserver) #query IPv4's of naemserver
		reply_ipv4 = dns_shake(pkt_ipv4)

		pkt_ipv6 = mk_raw_dns_pkt(dns_types["AAAA"], nameserver) #query IPv6's of naemserver
		reply_ipv6 = dns_shake(pkt_ipv6)

		ipv4 += [socket.inet_ntop(socket.AF_INET, x["data"]) for x in reply_ipv4["answers"] if x["type"] == dns_types["A"]] #addIP's to totoal IPv4 list
		ipv6 += [socket.inet_ntop(socket.AF_INET6, x["data"]) for x in reply_ipv6["answers"] if x["type"] == dns_types["AAAA"]] #addIP's to totoal IPv6 list

	ip_ns = [f'::ffff:{ip}' for ip in ipv4]
	#ip_ns += ipv6 #THis needs to be off for poeple with no IPv6 connectivity


	#main loop


	nextdomain = incname(wiredomain, True)
	print(domain) # list domain itself
	endset = set() #set to log which items we already got

	# print(nextdomain)
	while True:
		
		#we can afford to be more concise in our code and less bent on performance since no crakcing will be needed
		pkt = mk_raw_dns_pkt(dns_types["A"], nextdomain, True)
		reply = dns_shake(pkt, ip=random.choice(ip_ns)) #Could improve to queue later for more torughput, but usually 1 dns server is already sufficient
		
		end = nextdomain #wen we have no NSEC record we just increase

		for name, data in [(nsec["name"],nsec["data"]) for nsec in reply["authorities"] if nsec["type"] == dns_types["NSEC"]]:
			begin, end = (name, uncompress_record(reply["raw_data"],data))
			if end in endset: continue
			# print(".".join(map(lambda x: x.decode("ascii"), wire2parts(begin))) , ".".join(map(lambda x: x.decode("ascii"), wire2parts(end))))
			break
		# print(n)

		if end == wiredomain: break
		endset.add(end)
		print(".".join(map(lambda x: x.decode("ascii"), wire2parts(end))))
	
		# print(end, wiredomain)
		# print(f"EMD: {end}")
		# print("")
		nextdomain = incname(end)
		# print(nextdomain)



################################################################################
################################################################################
################################################################################

if __name__ == "__main__": 
	main(sys.argv[1])
