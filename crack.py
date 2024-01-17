#!/usr/bin/env pypy3
import brute
import gensublists
import multiprocessing as mp
import sys

def main(jsonfile, crackstring, NUMFILES=16, fsuffix=None):
	if not fsuffix:
		subgen = mp.Process(target=gensublists.main, args=(crackstring, NUMFILES))
		subgen.start()
	#in the case of generating, just use gensublists directly

	proc = []
	for n,x in enumerate(range(NUMFILES)):
		if not fsuffix:
			fifo = f"{n}.fifo"
		else:
			fifo = f"{n}{fsuffix}" #its a file nota fifo but hey
			
		proc.append(mp.Process(target=brute.main, args=(jsonfile, fifo)))
		proc[-1].start()


if __name__ == "__main__": 
	import argparse
	
	parser = argparse.ArgumentParser(description="Generate candidate subdomains using various means, and optinally spread them to multiple files / pipes")
	parser.add_argument("jsonfile", type=str, help="the json file from nsec3enum script")
	parser.add_argument("crackstring", nargs="+", help="the domain to enumerate")
	parser.add_argument("--numfiles", default=1, type=int, help="Number of files / pipes to use for emitting subdomain names")
	parser.add_argument("--fsuffix", help="suffix of file names emitted, not settings this option uses the .pipe fifo's")
	args = parser.parse_args()

	if "fsuffix" in args:
		main(args.jsonfile, args.crackstring, args.numfiles, args.fsuffix)
	else:
		main(args.jsonfile, args.crackstring, args.numfiles)

	# import cProfile
	# with cProfile.Profile() as pr:
	# 	main()
	# pr.print_stats()