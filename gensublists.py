#!/usr/bin/env pypy3
import sys
import os
from nsec3enum import dns_alphabet_sans, dns_alphabet, dns_alphabet_sans_underscore, brute_gen, crude6_gen


def main(max_chars, NUMFILES=16):
	if max_chars > 8: 
		print("8 max chars for the moment", file=sys.stderr)
		exit()

	files=[]
	for n in range(NUMFILES):
		# f = open(f"sub{n:02d}.txt", "w")
		name = f"{n}.fifo"

		try:
			os.mkfifo(name)
		except FileExistsError:
			pass

		f = open(name, "w")
		print(f"{name} hooked by comsuming process", file=sys.stderr)
		files.append(f)

	print(f"All fifo's hooked, commencing feeding", file=sys.stderr)


	# for n, sub in enumerate(brute_gen(True)):
	for n, sub in enumerate(brute_gen(True)):
		if len(sub) > max_chars: return
		print(sub, file = files[n % NUMFILES])


if __name__ == "__main__": 
	if len(sys.argv) >= 3:
		main(int(sys.argv[1]),int(sys.argv[2]))
	else:
		main(int(sys.argv[1]))

	# import cProfile
	# with cProfile.Profile() as pr:
	# 	main()
	# pr.print_stats()