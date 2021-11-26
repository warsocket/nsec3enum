#!/usr/bin/env pypy3
import sys
import os
from nsec3enum import dns_alphabet_sans, dns_alphabet, dns_alphabet_sans_underscore


#8 chars max now
def brute_gen():
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
	yield ""
	for item in left_build: yield item
	for item in left_full: yield item

	for a in mid_build:
		for l in left_full:
			yield "".join([l,a])

	for a in mid_full:
		for l in left_full:
			yield "".join([l,a])


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


	for n, sub in enumerate(brute_gen()):
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