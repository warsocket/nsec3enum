#!/usr/bin/env pypy3
from nsec3enum import dns_types, get_nameservers, mk_raw_dns_pkt, uncompress_record, dns_shake, domain2wire
import sys
import random

def main():
	################################################################################
	#                                   DNS PREP                                   #
	################################################################################

	#main loop
	line = True
	while line:
		line = sys.stdin.readline()

		domain = line.rstrip()
		wiredomain = domain2wire(domain)
		ipv4, ipv6 = get_nameservers(wiredomain, True, attempts=3)
		ip_ns = [f'::ffff:{ip}' for ip in ipv4]
		#ip_ns += ipv6 #This needs to be off for poeple with no IPv6 connectivity

		if not ip_ns:
			print(f"{domain}\tNO NS")
			continue

		pkt = mk_raw_dns_pkt(dns_types["A"], b"\x01 " + wiredomain, True)
		reply = dns_shake(pkt, attempts=5, ip=random.choice(ip_ns)) #Could improve to queue later for more torughput, but usually 1 dns server is already sufficient

		if not reply:
			print(f"{domain}\tNO NS REPLY")
			continue	

		# print(reply)
		types = [x["type"] for x in reply["authorities"]]
		if dns_types["NSEC3"] in types:
			print(f"{domain}\tNSEC3")
		elif dns_types["NSEC"] in types:
			print(f"{domain}\tNSEC")
		else:
			print(f"{domain}\t-")

		sys.stdout.flush()
		


################################################################################
################################################################################
################################################################################

if __name__ == "__main__": 
	main()