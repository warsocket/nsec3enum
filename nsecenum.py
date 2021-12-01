#!/usr/bin/env pypy3
from nsec3enum import dns_types, mk_raw_dns_pkt, dns_shake, uncompress_record, domain2wire, wire2parts, dns_alphabet, get_nameservers
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
		if l >= 63: return incname(wirename, True)
		return( bytes([l+1]) + wirename[1:l+1] + b'-' + wirename[l+1:] )


def main(domain):
	################################################################################
	#                                   DNS PREP                                   #
	################################################################################
	wiredomain = domain2wire(domain)
	dps = len(wire2parts(wiredomain))

	wiredomain = domain2wire(domain)
	ipv4, ipv6 = get_nameservers(wiredomain)
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
		sys.stdout.flush()
	
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
