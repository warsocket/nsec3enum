#!/usr/bin/env pypy3
import socket
import sys
import re
import random
import hashlib
import _socket

################################################################################
#                                 DNS FUNCTIONS                                #
################################################################################

dns_types = {
	"NS": b'\x00\x02',
	"A": b'\x00\x01',
	"AAAA": b'\x00\x1c',
	"NSEC3PARAM": b'\x00\x33',
	"NSEC3": b'\x00\x32',
}

def domain2wire(domain):
	b = bytearray()

	for sub in domain.split("."):
		b.append(len(sub))
		b += sub.encode("ASCII")

	b.append(0)
	return bytes(b)


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
def dns_shake(pkt, timeout=0.5, ip="::ffff:127.0.0.53"):

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
		n+=1
		try:
			sock.sendto(pkt, (ip, 53))
			data, raddr = sock.recvfrom(0xFFFF)
			break
		except _socket.timeout:
			print(f"timeout on DNS server {ip}, commencing retry attempt {n}", file=sys.stderr)

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

def b32hex_decode(b32string): #see rfc4648
	b32hexlist = list(map(str,range(10))) + list(map(chr,range(97,119)))
	b32hexmap = dict(zip(b32hexlist, range(32)))

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

def nsec3_hash(raw_domain, salt, iters):
	d = hashlib.sha1(raw_domain+salt).digest()
	for _ in range(iters): d = hashlib.sha1(d+salt).digest()
		
	return d

#We dont need the encoding variant so thats a nice to have


################################################################################
#                                OTHER FUNCTIONS                               #
################################################################################

class nsec3_intervals():
	def __init__(self):
		self.__intervals = []

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


def main():
	domain = sys.argv[1]
	wiredomain = domain2wire(domain)
	################################################################################
	#                                    TODO                                      #
	################################################################################

	# Handle UDP timeouts better then just failing after half a second

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
	
	nsec3log = nsec3_intervals()

	#domain names (as apposed to hostnames, can contain any character even binary)
	#This seems like a good middle ground (all valid hostnames + prefix underscores for records like _spf)
	for sub in leading_underscore_hostname_generator():
		#get fqdn subdomain wire name
		t = bytearray()
		t.append(len(sub))
		wiresubfulldomain = t + sub.encode("ASCII") + wiredomain

		# print(wiresubfulldomain)

		#hash it
		d = nsec3_hash(wiresubfulldomain, salt, iters)
		if not d in nsec3log:
			pkt = mk_raw_dns_pkt(dns_types["A"], wiresubfulldomain, True)
			reply = dns_shake(pkt, ip=random.choice(ip_ns)) #Could improve to queue later for more torughput, but usually 1 dns server is already sufficient
			for interval in nsec3_get_ranges(reply):
				nsec3log.add(interval)

		if nsec3log.complete(): break

	for line in ([x[0] for x in nsec3log.get()[1:]]):
		print(line)




################################################################################
################################################################################
################################################################################

if __name__ == "__main__": 
	main()

	# import cProfile
	# with cProfile.Profile() as pr:
	# 	main()
	# pr.print_stats()