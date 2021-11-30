#!/usr/bin/env pypy3
import socket
import sys
import re
import random
import json
import hashlib
import _socket
import multiprocessing as mp

################################################################################
#                                 DNS FUNCTIONS                                #
################################################################################

dns_types = {
	"NS": b'\x00\x02',
	"A": b'\x00\x01',
	"AAAA": b'\x00\x1c',
	"NSEC3PARAM": b'\x00\x33',
	"NSEC3": b'\x00\x32',
	"NSEC": b'\x00\x2f',
}

def domain2wire(domain):
	b = bytearray()

	for sub in domain.split("."):
		if not sub : continue
		b.append(len(sub))
		b += sub.encode("ASCII")

	b.append(0)
	return bytes(b)

def wire2parts(domainbytes):
	index = 0
	parts = []

	byt = domainbytes[0]
	while byt:
		index += 1
		parts.append(domainbytes[index:index+byt])
		index += byt
		byt = domainbytes[index]

	return parts



def word2num(word): #lsb word
	return word[0] << 0x8 | word[1]


def mk_raw_dns_pkt(raw_dns_type, raw_name, add_dnssec=False):
	b = bytearray()
	b += b'\x00\x00' #Transaction Id
	b += b'\x01\x20' #Recusion flag + AD flag
	b += b'\x00\x01' #Questions
	b += b'\x00\x00' #Answer RR's
	b += b'\x00\x00' #Authorithy RR's
	if add_dnssec:
		b += b'\x00\x01' #Additional Records
	else:
		b += b'\x00\x00' #Additional Records
	b += raw_name 
	b += raw_dns_type 
	b += b'\x00\x01'  # Class IN
	answer_offset = len(b)
	if add_dnssec:
		b += b'\x00' # root
		b += b'\x00\x29' # type OPT
		b += b'\x10\x00' # UPD payload size (4k)
		b += b'\x00' # Higher bits in extended RCODE
		b += b'\x00' # EDNS0 version
		b += b'\x80\x00' # msb bit = accept DNSSEC security RR's
		b += b'\x00\x00' # 0byte extra COOKIE
	return bytes(b)


#for records that are DNS names, if a label length has 2 msb bits high, its a pointer not a length
def uncompress_record(pkt, rdata): #Warning No endless loop protection, yet? (costly!)
	r = bytearray()
	index = 0
	data = rdata
	while True:
		
		l = data[index]
		if l >= 0b11000000: # both high bits set
			index = word2num(data[index:index+2]) - 0b1100000000000000
			data = pkt # we now keep stepping in packet until end
			continue

		skip = l+1
		append = data[index:index+skip]
		r += append
		if append == b"\x00": break
		index += skip

	return bytes(r)

#TODO we gonna do real parsing form now on, so no more need for hacky offset
def dns_shake(pkt, timeout=0.1, ip="::ffff:127.0.0.53"):

	def get_name_range(data, start=0):
		index = start

		skip = data[index] #first byte of domain name wire format
		while skip:
			if skip >= 0b11000000: return (start, index+2) #is this a pointer it ends here

			#normal label
			index += skip+1 #position index on next label length (or ptr)
			skip = data[index]

		return(start,index+1)# +1 to skip past the last 00 byte


	sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
	sock.settimeout(timeout)
	
	n = 0
	while True: #keep re-trying
		try:
			n += 1
			sock.sendto(pkt, (ip, 53))
			data, raddr = sock.recvfrom(0xFFFF)
			break
		except _socket.timeout:
			print(f"timeout on DNS server {ip}, commencing retry attempt {n}", file=sys.stderr)

	sock.close()

	#dns packetr parsing start here
	ret = {"raw_data": data}
	ret["transaction"] = data[0:2]
	ret["flags"] = data[2:4]
	ret["questionrecords"] = word2num(data[4:6])
	ret["answerrecords"] = word2num(data[6:8])
	ret["authorityrecords"] = word2num(data[8:10])
	ret["additionalrecords"] = word2num(data[10:12])

	ret["sections_indices"] = [12]
	index = ret["sections_indices"][-1] # Queries start here

	ret["queries"] = []
	for _ in range(ret["questionrecords"]):
		start, index = get_name_range(data, index)
		ret["queries"].append({"name": uncompress_record(data, data[start:index]), "type": data[index:index+2], "class": data[index+2:index+4] })
		index += 4 #skip past static fields
	ret["sections_indices"].append(index)

	def get_answers(count, data, index): #helper function to prevent code duplication (has side effects)
		answers = []
		for _ in range(count):
			answer = {}
			start, index = get_name_range(data, index)
			answer["name"] = uncompress_record(data, data[start:index])
			answer["type"] = data[index:index+2]
			answer["class"] = data[index+2:index+4]
			answer["ttl"] = data[index+4:index+8]
			data_len = word2num(data[index+8:index+10])
			answer["data"] = data[index+10:index+10+data_len]
			answers.append(answer)
			index += 10+data_len #skip past parsed record
		ret["sections_indices"].append(index)
		return answers

	ret["answers"] = get_answers(ret["answerrecords"], data, ret["sections_indices"][-1])
	ret["authorities"] = get_answers(ret["authorityrecords"], data, ret["sections_indices"][-1])
	#TODO addiotional records parsing, bnuyt since they are of no use to use this is deemed Nice to have
			
	return ret


def nsec3_get_ranges(reply):
	result = []
	for base32_from, data in [(record["name"][1:record["name"][0]+1], record["data"]) for record in reply["authorities"] if record["type"] == dns_types["NSEC3"]]:

		#get hash from next hashed owner
		len_salt = data[4]
		hash_index = 6+len_salt
		len_hash = data[hash_index-1]
		last = data[hash_index:hash_index+len_hash]

		#get hash from base32'd domain name part
		first = b32hex_decode(base32_from.decode().lower())
		result.append((first,last))

	return result			

################################################################################
#                               HASHING FUNCTIONS                              #
################################################################################

dns_alphabet_sans = list(map(chr, range(97,123))) + list(map(str, range(10)))
dns_alphabet = ["-"] + dns_alphabet_sans
dns_alphabet_sans_underscore = ["_"] + dns_alphabet_sans



def crude6_gen(include_empty_string=False):
	if include_empty_string: yield ""

	for x in dns_alphabet_sans_underscore:
		yield x

	for a in dns_alphabet:
		for x in dns_alphabet_sans_underscore:
			yield "".join([x,a])

	for b in dns_alphabet:
		for a in dns_alphabet:
			for x in dns_alphabet_sans_underscore:
				yield "".join([x,a,b])

	for c in dns_alphabet:
		for b in dns_alphabet:
			for a in dns_alphabet:
				for x in dns_alphabet_sans_underscore:
					yield "".join([x,a,b,c])

	for d in dns_alphabet:
		for c in dns_alphabet:
			for b in dns_alphabet:
				for a in dns_alphabet:
					for x in dns_alphabet_sans_underscore:
						yield "".join([x,a,b,c,d])

	for e in dns_alphabet:
		for d in dns_alphabet:
			for c in dns_alphabet:
				for b in dns_alphabet:
					for a in dns_alphabet:
						for x in dns_alphabet_sans_underscore:
							yield "".join([x,a,b,c,d,e])


def brute_gen(include_empty_string=False):

	#we ache at 4 chars, since thats doable
	def cart(gen_a, gen_b):
		for b in gen_b():
			for a in gen_a():
				yield a+b

	def seq(*it_list):
		for it in it_list:
			for item in it():
				yield item

	#make generators from generator factories
	mkcart = lambda a,b: lambda: cart(a,b)
	mkseq = lambda *a: lambda: seq(*a)


	#We all greacet then as generator factories like the mnethods above
	left_1 = lambda: (x for x in dns_alphabet_sans_underscore)
	mid_1 = lambda: (x for x in dns_alphabet)
	ramp_left_1 = left_1
	ramp_mid_1 = mid_1

	# left_2 = mkcart(left_1, mid_1)
	# mid_2 = mkcart(mid_1, mid_1)
	# ramp_left_2 = left_1
	# ramp_mid_2 = mid_1

	# left_4 = mkcart(left_2, mid_2)
	# mid_4 = mkcart(mid_2, mid_2)
	# ramp_left_4 = mkseq(left_2,mid_2)
	# ramp_mid_4 = mkseq(mid_2,mid_2)


	#That commeted above we will be doing only then in more general form :)
	left = [left_1]
	mid = [mid_1]
	ramp_left = [ramp_left_1]
	ramp_mid = [ramp_mid_1]

	for x in range(6): #2**6 = 64 which is max domain part length
		
		l = left[-1]
		m = mid[-1]
		rl = ramp_left[-1]
		rm = ramp_mid[-1]

		left.append( mkcart(l,m) )
		mid.append( mkcart(m,m) )
		ramp_left.append( mkseq(rl,mkcart(l,rm)) )
		ramp_mid.append( mkseq(rm,mkcart(m,rm)) )
		# ramp_left.append( mkseq(rl,l,mkcart(l,rm),left[-1]) )
		# ramp_mid.append( mkseq(rm,m,mkcart(m,rm),mid[-1]) )


	#THis cache seems slower then the original, so we stick with non-cahced
		if x == 1: #1 = 2nd loop and 3rd item in list so index 2 which matches with 4 chars 2**2
			orig = left.pop()
			cache_left = list(orig())
			cached = lambda: (val for val in cache_left)
			left.append(cached)

			orig = mid.pop()
			cache_mid = list(orig())
			cached = lambda: (val for val in cache_mid)
			mid.append(cached)

			orig = ramp_left.pop()
			cache_ramp_left = list(orig())
			cached = lambda: (val for val in cache_ramp_left)
			ramp_left.append(cached)

			orig = ramp_mid.pop()
			cache_ramp_mid = list(orig())
			cached = lambda: (val for val in cache_ramp_mid)
			ramp_mid.append(cached)				 

	if include_empty_string: yield ""
	for x in seq(ramp_left[6], left[6]):
		yield x

def broken_brute_gen(include_empty_string=False): #keep this here for timing purposes
	def left_gen():
		for item in dns_alphabet_sans_underscore: yield item

	def mid_gen():
		for item in dns_alphabet: yield item

	#we work per 4
	left_build = []
	for left in left_gen():
		left_build.append(left)

	for c in mid_gen():
		for left in mid_gen():
			left_build.append("".join([left,c]))

	for b in mid_gen():
		for c in mid_gen():
			for left in left_gen():
				left_build.append("".join([left,c,b]))
	# left_build.reverse()


	left_full = []
	for a in mid_gen():
		for b in mid_gen():
			for c in mid_gen():
				for left in left_gen():
					left_full.append("".join([left,c,b,a]))
	# left_full.reverse()


	mid_build = []
	for d in mid_gen():
		mid_build.append(d)

	for c in mid_gen():
		for d in mid_gen():
			mid_build.append("".join([d,c]))

	for b in mid_gen():
		for c in mid_gen():
			for d in mid_gen():
				mid_build.append("".join([d,c,b]))

	for a in mid_gen():
		for b in mid_gen():
			for c in mid_gen():
				for d in mid_gen():
					mid_build.append("".join([d+c+b]))
	# mid_build.reverse()


	mid_full = []
	for a in mid_gen():
		for b in mid_gen():
			for c in mid_gen():
				for d in mid_gen():
					mid_full.append(d+c+b+a)
	mid_full.reverse()

	#now we start blasting
	if include_empty_string: yield ""
	for item in left_build: yield item
	for item in left_full: yield item

	for a in mid_build:
		for l in left_full:
			yield "".join([l,a])

	for a in mid_full:
		for l in left_full:
			yield "".join([l,a])


def hostname_generator(leading_alphabet=dns_alphabet_sans, center_alphabet=dns_alphabet, trailing_alphabet=dns_alphabet_sans): #so only valid hostnames (a-z0-9 and - someplaces) remember domainnames may contain all chars.

	class node():

		def __init__(self, carrynode=None, alphabet=center_alphabet):
			self.__alphabet = alphabet
			self.__carrynode = carrynode
			self.__it = alphabet.__iter__()
			self.__value = ""
			self.__listcache = None

		def next(self):
			#invalidate cache
			self.__listcache = None

			try:
				self.__value = next(self.__it)
				if self.__value == "-": #no adjecent dashes nor at rightmost char
					if self.__carrynode.get() in set(["-", ""]):
						self.next()
				
			except StopIteration:
				self.__it = self.__alphabet.__iter__()
				if self.__carrynode: 
					self.__carrynode.next()
				else:
					raise StopIteration #out of chars
				self.next()

		def get(self):
			return self.__value

		def getlist(self):
			if self.__listcache: return self.__listcache[:]

			if self.__carrynode: 
				l = self.__carrynode.getlist() 
				l.append(self.get())
				self.__listcache = l[:]
				return l
			else:
				l = [self.get()]
				self.__listcache = l[:]
				return [self.get()]


	#64 char generator
	last = node(None, trailing_alphabet) #leftmost (64thj) char
	for _ in range(62): last = node(last)
	last = node(last, leading_alphabet) #rightmost char

	while True:
		last.next()
		yield "".join(last.getlist())


def leading_underscore_hostname_generator():
	g = hostname_generator(dns_alphabet_sans_underscore)
	for item in g:
		yield item[::-1]


b32hexlist = list(map(str,range(10))) + list(map(chr,range(97,119)))
b32hexmap = dict(zip(b32hexlist, range(32)))

def b32hex_decode(b32string): #see rfc4648
	#generate bitlist
	bitlist = []
	for char in b32string:
		num = b32hexmap[char]
		bitlist.append(bool(num & 0b10000))
		bitlist.append(bool(num & 0b1000))
		bitlist.append(bool(num & 0b100))
		bitlist.append(bool(num & 0b10))
		bitlist.append(bool(num & 0b1))

	ba = bytearray()
	shift = 7
	b=0
	for bit in bitlist:
		b |= (bit << shift)

		if not shift: #we did the 0 shift
			ba.append(b) 
			shift = 7
			b=0
		else:
			shift -= 1

	return bytes(ba)


def b32hex_encode(bytestring): #see rfc4648
	#generate bitlist
	bitlist = []
	for num in bytestring:
		bitlist.append(bool(num & 0b10000000))
		bitlist.append(bool(num & 0b1000000))
		bitlist.append(bool(num & 0b100000))
		bitlist.append(bool(num & 0b10000))
		bitlist.append(bool(num & 0b1000))
		bitlist.append(bool(num & 0b100))
		bitlist.append(bool(num & 0b10))
		bitlist.append(bool(num & 0b1))

	#start popping form original start
	buffer = []
	bitlist.reverse()
	while len(bitlist) >= 5:
		acc=0
		acc |= int(bitlist.pop()) << 4
		acc |= int(bitlist.pop()) << 3
		acc |= int(bitlist.pop()) << 2
		acc |= int(bitlist.pop()) << 1
		acc |= int(bitlist.pop()) << 0
		# print(acc)
		buffer.append(b32hexlist[acc])

	return "".join(buffer)



def nsec3_hash(raw_domain, salt, iters):
	d = hashlib.sha1(raw_domain+salt).digest()
	for _ in range(iters): d = hashlib.sha1(d+salt).digest()
		
	return d

#We dont need the encoding variant so thats a nice to have


################################################################################
#                                OTHER FUNCTIONS                               #
################################################################################

class nsec3_intervals():
	def __init__(self, intervals=[]):
		self.__intervals = intervals

	def __contains__(self, value):
		pivot=None
		lbound = 0
		ubound = len(self.__intervals) -1

		while lbound < ubound:
			pivot = (lbound+ubound) // 2
			b,e = self.__intervals[pivot]
			if value > e:
				lbound = pivot+1
			elif value < b:
				ubound = pivot-1
			else:
				return True

		# print(lbound, pivot, ubound)
		if not self.__intervals: return False
		b,e = self.__intervals[lbound]
		return b <= value <= e


	# def __contains__(self, value):
	# 	for b,e in self.__intervals:
	# 		if b <= value <= e: return True
	# 	return False


	def add(self, interval):
		b,e = interval
		if b and e < b: #its the one wrappng interval (if not b then its the last one)
			self.add((b, b'\xff'*len(b))) #interval for end of list
			self.add((b'', e)) #interval for begin of list
		else:
			if interval not in self.__intervals:
				self.__intervals.append(interval)
				self.__intervals.sort(key=lambda x: x[0])


	def complete(self):
		last = None
		for b,e in self.__intervals:
			if not last: 
				last = e
				continue
			
			if b != last: return False
			last = e
		return True

	def get(self):
		return self.__intervals

	def clone(self):
		return nsec3_intervals(self.__intervals[:])


def main(domain, hash_procs):
	wiredomain = domain2wire(domain)

	################################################################################
	#                                   DNS PREP                                   #
	################################################################################

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

	#Get NSEC3PARAM Record
	pkt = mk_raw_dns_pkt(dns_types["NSEC3PARAM"], wiredomain, True)
	for record in dns_shake(pkt, ip=ip_ns[0])["answers"]:
		if record["type"] == dns_types["NSEC3PARAM"]:
			iters = word2num(record["data"][2:4])
			salt = record["data"][5:5+record["data"][4]]
			break

	################################################################################
	#                             Enumerating hashes                               #
	################################################################################
	
	

	def main_loop():
		nsec3log = nsec3_intervals()
		#domain names (as apposed to hostnames, can contain any character even binary)
		#This seems like a good middle ground (all valid hostnames + prefix underscores for records like _spf)
		# for sub in leading_underscore_hostname_generator():
		for sub in brute_gen():
			#get fqdn subdomain wire name
			wiresubfulldomain = bytes([len(sub)]) + sub.encode("ASCII") + wiredomain

			#hash it
			d = nsec3_hash(wiresubfulldomain, salt, iters)
			if not d in nsec3log:
				pkt = mk_raw_dns_pkt(dns_types["A"], wiresubfulldomain, True)
				reply = dns_shake(pkt, ip=random.choice(ip_ns)) #Could improve to queue later for more torughput, but usually 1 dns server is already sufficient
				for interval in nsec3_get_ranges(reply):
					nsec3log.add(interval)

			if nsec3log.complete(): break

		return {"salt":salt.hex(), "iters":iters, "domain":domain, "alg": 1, "flags": 1, "hashes":[b32hex_encode(h[0]) for h in nsec3log.get()[1:]] }



	def main_loop_multi(nproc):
		nsec3log = nsec3_intervals()
		target = 1
		gen = brute_gen()
		pipes = []
		process = []
		q = mp.Queue()


		def proc(p, q):
			while True:
				items_per_proc, log = p.recv()
				if not items_per_proc: return

				for x in range(items_per_proc):
					sub = p.recv()
					wiresubfulldomain = bytes([len(sub)]) + sub.encode("ASCII") + wiredomain

					d = nsec3_hash(wiresubfulldomain, salt, iters)
					if d not in log:
						q.put(wiresubfulldomain)
				q.put(None) #signal done


		for _ in range(nproc):
			pipes.append(mp.Pipe())

		for _,p in pipes: #len(pipes) == NPROC
			process.append( mp.Process(target=proc, args=(p,q)) )
			process[-1].start()



		def nextitems(items_per_proc, nsec3log):
			clone = nsec3log.clone() #only 1 clone needed since the procs only perform read actions
			for p,_ in pipes:
				p.send((items_per_proc, clone))

			for _ in range(items_per_proc):
				for p,_ in pipes:
					p.send(next(gen))



		while True:
			nextitems(target, nsec3log) #start next procs and burst subdomains in there

			count = nproc
			hit = False
			while count:
				data = q.get()

				if data == None:
					count -= 1
				else: # got a sub thats fresh
					if hit: #more than one found, so recheck, if its in range
						d = nsec3_hash(data, salt, iters)
						send_pkt = not d in nsec3log
					else:
						hit = True
						send_pkt = True

					if send_pkt:
						pkt = mk_raw_dns_pkt(dns_types["A"], data, True)
						reply = dns_shake(pkt, ip=random.choice(ip_ns)) #Could improve to queue later for more torughput, but usually 1 dns server is already sufficient
						for interval in nsec3_get_ranges(reply):
							nsec3log.add(interval)			
			if not hit: 
				target <<= 1 #double the capacity

			if nsec3log.complete(): 
				for p,_ in pipes: #len(pipes) == NPROC
					p.send((0, None))

				for p in process:
					p.join()
				# p.close() #needs python 3.7

				break

		return {"salt":salt.hex(), "iters":iters, "domain":domain, "alg": 1, "flags": 1, "hashes":[b32hex_encode(h[0]) for h in nsec3log.get()[1:]] }
			
	if hash_procs > 1:
		obj = main_loop_multi(hash_procs)
	else:
		obj = main_loop()

	json.dump(obj, sys.stdout, indent=4)




################################################################################
################################################################################
################################################################################

if __name__ == "__main__": 
	if len(sys.argv) >= 3:
		main(sys.argv[1], int(sys.argv[2]))
	else:
		main(sys.argv[1], 1)


	#TODO need to do stuff with ipv6 server being off by default
	#And a choice of generator

	# import cProfile
	# with cProfile.Profile() as pr:
	# 	main(sys.argv[1])
	# pr.print_stats()
