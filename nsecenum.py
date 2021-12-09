#!/usr/bin/env pypy3
from nsec3enum import dns_types, mk_raw_dns_pkt, dns_shake, uncompress_record, domain2wire, wire2domain, wire2parts, dns_alphabet, get_nameservers
import sys
import socket
import random
import _socket
import threading
import queue
import time
import os

################################################################################
#                                  NSEC FUNCTIONS                              #
################################################################################

full_alphabet = sorted(dns_alphabet + ["_"])

def dnssorted(l):

	nametree = {}
	for name in (map(wire2parts, l)):
		ptr = nametree #reset to root

		while name:
			part = name.pop().decode("ASCII") # lets just make it text
			if part not in ptr: ptr[part] = {}
			ptr = ptr[part]
		ptr[""] = {}

	#now we recursively add the stuff to a list
	def slist(node):
		if not node: #empty leaf
			return [""]
		else:
			return [leaf+"."+key for key in sorted(list(node.keys())) for leaf in slist(node[key])] #cartesian product of domain with superdomain

	return map(lambda x: x[2:], slist(nametree))
		

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
		q = queue.Queue()

		begin = set()

		init_list = full_alphabet[:]
		while len(init_list) < num_threads:
			init_list += [i+j for i in init_list[:] for j in full_alphabet]

		step = len(init_list) / num_threads

		acc = 0.0
		for n in range(num_threads):
			wirestart = domain2wire(f'{init_list[int(acc)]}-.{domain}')
			begin |= set(get_nsec_records(wirestart, ip=random.choice(ip_ns)))
			acc += step


		def thread_func(q, start, known, result_set, **kwarg):
			for x in nsec_gen(start, known, **kwarg):
				result_set.add(x)
			q.put(result_set)


		threads = []
		result_set = []
		for b in begin:
			# print(b[1])
			retset = set()
			result_set.append(retset)
			threads.append( threading.Thread(target=thread_func, args=(q, incname(b[1]), begin.copy(), retset), kwargs={"ip": random.choice(ip_ns)}) )
			threads[-1].start()

		#stuff for progress monitoring
		if args.progress:
			def progress(rsets):
				while True:
					time.sleep(0.1)
					print(f"\033[1K\033[0G\033[37mSubdomains found: \033[31m{sum(map(len, result_set))}\033[0m    ", end="", file=sys.stderr) #wipe to start of line, place cursos start of line
					sys.stderr.flush()

			pthread = threading.Thread(target=progress, args=(result_set,))
			pthread.daemon = True
			pthread.start()


		#from here we wait for completion
		for t in threads:
			t.join()

		for t in threads:
			begin |= q.get()

		for item in dnssorted([d[0] for d in begin]): #sorting might not totally adhere to DNS order, but it way betyer than the random stuff
			print(item)


	else:
		for x,_ in nsec_gen(incname(wiredomain, True), ip=ip_ns[0]): #double inc'ed sub do -- to begin
			print(wire2domain(x))


################################################################################
################################################################################
################################################################################

if __name__ == "__main__": 
	import argparse
	
	parser = argparse.ArgumentParser(description="Enumerate NSEC3 records form a domain")
	parser.add_argument("domain", help="the domain to enumerate")
	parser.add_argument("--threads", default=1, type=int, help="Number of threads to use for hasing subdomain names (1 thread = streaming data >1 cahches data end emits sorted at the end)")
	parser.add_argument("--progress", action="store_true", help="Show progress by displaying current subdpomain bein evaluated")
	args = parser.parse_args()

	if args.progress and args.threads == 1:
		print("threads=1 streams output, so also setting --progress ise useless, so choose more threads, or use the streaming output", file=sys.stderr)
		os.exit(1)

	main(args.domain, args.threads)
