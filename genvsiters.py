#!/usr/bin/env pypy3
#test generators vs iterations
from nsec3enum import brute_gen, leading_underscore_hostname_generator, nsec3_hash, crude6_gen
import time

def main():
	salt = b"\x00"*8
	iters = 0
	wiredomain = b"\x07example\x03com\x00"

	start = time.time()
	# generator = leading_underscore_hostname_generator #generator which only generates domain name swith valid dash spacing (eg only valid hostnames + leading underscores)
	# for sub in generator():
	# 	if len(sub) > 5: break
	# 	wiresubfulldomain = bytes([len(sub)]) + sub.encode("ASCII") + wiredomain
	# 	# h = nsec3_hash(wiresubfulldomain, salt, iters)

	middle = time.time()
	generator = brute_gen # geenrates somple cartethic produc of everything only fist char is _ instead of - (which isdisallowed there anyway)
	for sub in generator():
		if len(sub) > 5: break
		# print(sub)
		# wiresubfulldomain = bytes([len(sub)]) + sub.encode("ASCII") + wiredomain
		# h = nsec3_hash(wiresubfulldomain, salt, iters)
	stop = time.time()


	print(f"complete_gen: {middle - start}")
	print(f"brute_gen: {stop - middle}")



if __name__ == "__main__": 
	main()
	exit()
	#TODO need to do stuff with ipv6 server being off by default
	#And a choice of generator

	import cProfile
	with cProfile.Profile() as pr:
		main()
	pr.print_stats()



#bare recrusive brute_generator
#$ ./genvsiters.py (5 chars)
#complete_gen: 50.45578622817993
#brute_gen: 13.320074081420898


#length 4 cache vn non-cache generator
#$ ./genvsiters.py (6 chars)
#non-cached: 13.536959886550903
#cahced: 7.617264986038208

#And thus brute-gen becomes default for everything that can handle domain names with dahsen on ofifcially invalid places (eg: a--n.com)

#./crack.py bol.json 5 15  963,17s user 4,01s system 1213% cpu 1:19,73 total crude6 cracking
#./crack.py bol.json 5 15  985,28s user 4,08s system 1265% cpu 1:18,20 total brute crakcing And thats including the cache buildup which is bug but constant time
#brute wins again

