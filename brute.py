#!/usr/bin/env pypy3
from nsec3enum import b32hex_encode, nsec3_hash, b32hex_decode, domain2wire

import json
import sys

# def fast_encode(string):
# 	p = []
# 	for char in string:
# 		p.append(ord(char))
# 	return bytes(p)

def main(jsonfile, file):

	with open(jsonfile, "r") as f:
		obj = json.load(f)

	salt = bytes.fromhex(obj["salt"])
	iters = obj["iters"]
	hashes = set(map(b32hex_decode, obj["hashes"]))
	domain = obj["domain"]
		
	wiredomain = domain2wire(domain)

	while True:
		try:
			with open(file, "r") as f:
				line = f.readline()
				while line:
					sub = line[:-1] #.strip()

					if sub:
						#get fqdn subdomain wire name
						wiresubfulldomain = bytes([len(sub)]) + sub.encode("ASCII") + wiredomain
					else:

						wiresubfulldomain = wiredomain

					h = nsec3_hash(wiresubfulldomain, salt, iters)
					if h in hashes: 
						print(f"{b32hex_encode(h)}\t{sub}.{domain}")
						sys.stdout.flush()
					line = f.readline()
			break
		except FileNotFoundError:
			pass


if __name__ == "__main__": 
	import argparse
	
	parser = argparse.ArgumentParser(description="Generate candidate subdomains using various means, and optinally spread them to multiple files / pipes")
	parser.add_argument("jsonfile", type=str, help="the json file from nsec3enum script")
	parser.add_argument("file", type=str, help="the file / fifo to get the attempts from")
	args = parser.parse_args()

	main(args.jsonfile, args.file)

	# import cProfile
	# with cProfile.Profile() as pr:
	# 	main(sys.argv[1], sys.argv[2])
	# pr.print_stats()