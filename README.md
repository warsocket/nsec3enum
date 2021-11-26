# nsec3enum
nsec3 hash enumerator which is super fast, due to everything begin low level coded in (eg: dns handling, base32hex decoding, etc)
Also contains a cpu cracker which is quite performant.

## Usage example
Lets try politie.nl as example, they use 10 iterations which is way more than most other domains who use just 0 or 1.

Get parameters and hashes
`./nsec3enum.py politie.nl | tee politie.nl.json`

Brute force them up till 4 chars using 16 cores (each attempt need to perform 10 sha-1 hashing functions)
`./crack.py politie.nl.json 4 16`
