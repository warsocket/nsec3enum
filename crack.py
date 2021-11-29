#!/usr/bin/env pypy3
import brute
import gensublists
import multiprocessing as mp
import sys

def main(jsonfile, max_chars, NUMFILES=16):
	subgen = mp.Process(target=gensublists.main, args=(max_chars, NUMFILES))
	subgen.start()

	proc = []
	for n,x in enumerate(range(NUMFILES)):
		fifo = f"{n}.fifo"
		proc.append(mp.Process(target=brute.main, args=(jsonfile, fifo)))
		proc[-1].start()


if __name__ == "__main__": 
	if len(sys.argv) >= 4:
		main(sys.argv[1], sys.argv[2], int(sys.argv[3]))
	else:
		main(sys.argv[1], sys.argv[2])

	# import cProfile
	# with cProfile.Profile() as pr:
	# 	main()
	# pr.print_stats()