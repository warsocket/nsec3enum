#!/usr/bin/env pypy3
import sys
import os
from nsec3enum import dns_alphabet_sans, dns_alphabet, dns_alphabet_sans_underscore, brute_gen, crude6_gen


def main(crackstring, NUMFILES=1, fsuffix = None):
	files=[]
	for n in range(NUMFILES):
		# f = open(f"sub{n:02d}.txt", "w")

		if not fsuffix:
			name = f"{n}.fifo"
			try:
				os.mkfifo(name)
			except FileExistsError:
				pass
		else:
			name = f"{n}{fsuffix}"


		f = open(name, "w")
		print(f"{name} hooked by comsuming process", file=sys.stderr)
		files.append(f)

	print(f"All fifo's hooked, commencing feeding", file=sys.stderr)

	#craking definitions

	def brute_feed(params):
		max_chars = int(params[0])
		for n, sub in enumerate(brute_gen(True)):
			if len(sub) > max_chars: return
			yield sub


	def cartself(params):
		files = params

		for rfile in files:
			with open(rfile, "r") as r: 
				rline = r.readline()
				while rline:
					rline = r.readline()
					rsub = rline.rstrip()
					if not rsub: continue
					yield rsub

					for lfile in files:
						with open(lfile, "r") as l:
							lline = l.readline()
							while lline:
								lline = l.readline()
								lsub = lline.rstrip()
								if not lsub: continue
								yield f"{lsub}{rsub}"
								yield f"{lsub}-{rsub}"


	def cartselfcache(params):
		subs = []
		files = params
		for file in files:
			with open(file) as f:
				subs += [line.rstrip() for line in f]

		subs = set(subs)

		for sub in subs:
			yield sub

		for n, suba in enumerate(subs):
			print(f"{n}/{len(subs)}", file = sys.stderr)
			for subb in subs:

				ret = f"{suba}{subb}"
				if len(ret) <= 6: continue
				yield ret

				ret = f"{suba}-{subb}"
				if len(ret) <= 6: continue
				yield ret



	def openfile(params):
		with open(params[0], "r") as f:
			line = f.readline()
			while line:
				yield line.rstrip()
				line = f.readline()


	methods = {
		"brute": brute_feed,
		"cartself": cartself,
		"cartselfcache": cartselfcache,
		"file": openfile,
	}

	#####################

	for n, sub in enumerate(methods[crackstring[0]](crackstring[1:])):
		print(sub, file = files[n % NUMFILES])


if __name__ == "__main__": 
	import argparse
	
	parser = argparse.ArgumentParser(description="Generate candidate subdomains using various means, and optinally spread them to multiple files / pipes")
	parser.add_argument("crackstring", nargs="+", help="the domain to enumerate")
	parser.add_argument("--numfiles", default=1, type=int, help="Number of files / pipes to use for emitting subdomain names")
	parser.add_argument("--fsuffix", help="suffix of file names emitted, not settings this option uses the .pipe fifo's")
	args = parser.parse_args()

	if "fsuffix" in args:
		main(args.crackstring, args.numfiles, args.fsuffix)
	else:
		main(args.crackstring, args.numfiles)

	# import cProfile
	# with cProfile.Profile() as pr:
	# 	main()
	# pr.print_stats()