# This script is based off of: https://github.com/ShellCollectingClub/csaw2017/tree/master/bananascript

# Import the libraries
import itertools
import string
import sys


# Establish the encrypted flag
encFlag = "baNANAs banAnAS banANaS banaNAs BANANAs BANaNas BANAnas bANanAS baNaNAs banaNAs bANaNas BaNaNaS baNanas BaNaNas BaNanas BaNANas baNAnaS banaNAS bANAnAs banANAS bAnaNAs BANAnAS BANAnas BaNANas bAnANas BaNaNaS banAnAs bANAnAs baNaNas BanaNaS bANANas banaNas bAnANaS bANANaS BaNAnas baNanAs baNanAS BaNAnAs bANANas banAnas bAnanaS banANaS bANaNAS banANaS baNanAS BaNanAS BANAnAS BaNanaS"

# Establish the first five bytes of the key, which we know
knownKey = [ 0x64, 0x7f, 0x72, 0x7f, 0x56] 

# Establish the characters we expect to be in the flag
flagChars = string.ascii_letters + string.digits + "_"

'''
Establish a map which will map `bananas` permutations to individual characters. 
Thing is the start at `BANANAS` with `a`, then work there way down the list of ascii 
characters with lower `BANANAS` permutations (think of them as segments of 1s and 0s)
'''

encMap = {}
charsNum = 0b1111111
alphabet = string.ascii_lowercase + string.ascii_uppercase + ' \n' + string.digits + ',./;\[]=-`~!@#$%^&*()_+{}|\\:"?><'

for i in alphabet:
	encMap[charsNum] = i
	charsNum -= 1 

# Establish a function to convert `bananas` permutations to ints (essentially converting binary to int)
def bananasToInt(bananas):
	intnum = ''
	for i in bananas:
		if i.isupper():
			intnum += '1'
		else:
			intnum += '0'
	return int(intnum, 2)


# Establish a function to convert `bananas` permutations to their mapped characters
def lineToString(line):
	string = []
	for b in line.split(' '):
		string.append(encMap[bananasToInt(b)])
	return "".join(string)

# Establish a function which will tokenize the bananas string
def tokenize(inp):
	tokens = []
	for word in inp.split(" "):
		token = Token(word)
		tokens.append(token)
	return tokens

# Establish a function to simulate the xor
def xorOp(encrFlag, key):
	flag = []
	for i, c in enumerate(encrFlag):
		x = c ^ key[i % len(key)]
		flag.append(x)
	return flag


# Take the encrypted flag, and split it up into integers we can xor
encBanannas = encFlag.split(" ")
enc = []
for i in encBanannas:
	enc.append(bananasToInt(i))


# Start the loop that will brute for the three bytes
for i, seq in enumerate(itertools.product(range(256), repeat=3)):
	# Come up with the key instance for the iteration
	keyIteration = knownKey + list(seq)
	# Xor it
	flagOut = xorOp(enc, keyIteration)
	try:
		# Convert it into a string and see if it matches the flag format, meaning it ends with `}`, has all ASCII characters, and has only characters we would expect to be in the flag (we can assume this by the typical ctf flag format)
		flagOut = "".join(encMap[i] for i in flagOut)
		if all(i in string.printable for i in flagOut) and flagOut[-1] == '}' and all(i in flagChars for i in flagOut[5:-1]):
			# If the string meets the format, print it
			print flagOut
	except:
		pass