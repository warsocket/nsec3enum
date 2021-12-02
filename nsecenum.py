#!/usr/bin/env pypy3
from nsec3enum import dns_types, mk_raw_dns_pkt, dns_shake, uncompress_record, domain2wire, wire2domain, dns_alphabet, get_nameservers
import sys
import socket
import random
import _socket
import threading
import queue

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


def get_nsec_records(wirename, **kwarg):
	pkt = mk_raw_dns_pkt(dns_types["A"], wirename, True)
	reply = dns_shake(pkt, **kwarg) #Could improve to queue later for more torughput, but usually 1 dns server is already sufficient

	return ([(nsec["name"],uncompress_record(reply["raw_data"],nsec["data"])) for nsec in reply["authorities"] if nsec["type"] == dns_types["NSEC"]])

	# for name, data in [(nsec["name"],nsec["data"]) for nsec in reply["authorities"] if nsec["type"] == dns_types["NSEC"]]:
	# 	begin, end = (name, uncompress_record(reply["raw_data"],data))


def nsec_gen(start_point, known_nsec=set(), **kwarg):
	next_dname = [start_point]

	# print(start_point, known_nsec)

	while next_dname:
		# print("loop")
		nxt = next_dname.pop()
		ret = get_nsec_records(nxt, **kwarg)

		# print(ret)
		for record in [nsec for nsec in ret if nsec not in known_nsec]:
			next_dname.append(incname(record[1]))
			known_nsec.add(record)
			yield(record)




def main(domain, num_threads=1):
	################################################################################
	#                                   DNS PREP                                   #
	################################################################################
	wiredomain = domain2wire(domain)
	ipv4, ipv6 = get_nameservers(wiredomain)
	ip_ns = [f'::ffff:{ip}' for ip in ipv4]
	#ip_ns += ipv6 #THis needs to be off for poeple with no IPv6 connectivity


	################################################################################
	#                                   MAIN LOOP                                  #
	################################################################################

	if num_threads > 1:
		#for now max len(full_alphabet) threads
		q = queue.Queue()

		begin = set()
		step = len(full_alphabet) / num_threads

		acc = 0.0
		for n in range(num_threads):
			wirestart = domain2wire(f'{full_alphabet[round(acc)]}-.{domain}')
			begin |= set(get_nsec_records(wirestart, ip=ip_ns[0]))
			acc += step


		def thread_func(q, start, known, **kwarg):
			ret = []
			for x in nsec_gen(start, known, **kwarg):
				ret.append(x)
			q.put(ret)



		threads = []
		for b in begin:
			# print(b[1])
			threads.append( threading.Thread(target=thread_func, args=(q, incname(b[1]), begin.copy()), kwargs={"ip":ip_ns[0]}) )
			threads[-1].start()

		for t in threads:
			t.join()

		ret = []
		for t in threads:
			ret += q.get()

		for item in [d[0] for d in ret]:
			print(wire2domain(item))


	else:
		for x,_ in nsec_gen(incname(wiredomain, True), ip=ip_ns[0]): #double inc'ed sub do -- to begin
			print(wire2domain(x))


################################################################################
################################################################################
################################################################################

if __name__ == "__main__": 
	if len(sys.argv) >= 3:
		main(sys.argv[1], int(sys.argv[2]))
	else:
		main(sys.argv[1])