# unholy

This writeup is based off of this other writeup: `https://github.com/smokeleeteveryday/CTF_WRITEUPS/tree/master/2016/BKPCTF/reversing/unholy`

We are given a tar file. Let's see what's inside of it:
```
$	cd unholy
$	ls
main.rb  unholy.so
$	file unholy.so 
unholy.so: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, BuildID[sha1]=bd427479f69b029eec5923ccffb1e6dc76a7743e, not stripped
$	cat main.rb 
require_relative 'unholy'
include UnHoly
python_hi
puts ruby_hi
puts "Programming Skills: PRIMARILY RUBY AND PYTHON BUT I CAN USE ANY TYPE OF GEM TO CONTROL ANY TYPE OF SNAKE"
puts "give me your flag"
flag = gets.chomp!
arr = flag.unpack("V*")
is_key_correct? arr
```

So we can see here, we have a ruby file and a x64 shared library. The ruby script appears to simply scan in input, and then passed it to the shared library to be checked. Let's take a look at the shared library to see how it checks the input. 

```
    i = 0LL;
    do
    {                                           // Returns the int element of the ruby array passed as an argument
      LODWORD(i_item) = rb_ary_entry(argument, i);
      if ( i_item & 1 )                         // Convert the inth element into an int
        transfer_matrix_int = rb_fix2int(i_item);
      else
        transfer_matrix_int = rb_num2int(i_item);
      matrix[i++] = transfer_matrix_int;        // Store the inth element in the matrix
    }
    while ( i != 9 );
    matrix[9] = 0x61735320;                     // Append a 4 byte hex string as the final item in the matrix
```

This chunk of code appears to take the values passed to it, and stores the first 8 values as integers in the matrix `matrix`. For the last value `matrix[9]` it sets it equal to the hex string `0x61735320`.  So this organizes our input into a matrix.

```
      v8 = 0;
      LODWORD(v9) = *(_QWORD *)&matrix[i0];
      v10 = *(_QWORD *)&matrix[i0] >> 32;
      do
      {                                         // This is where the input altering starts
        v11 = v8 + key[(unsigned __int64)(v8 & 3)];
        v8 -= -0x9E3779B9;                      // This was originally 0x61c88647, had to invert the sign. 
        v9 = (v11 ^ ((16 * (_DWORD)v10 ^ ((unsigned int)v10 >> 5)) + (_DWORD)v10)) + (unsigned int)v9;
        v10 = ((v8 + key[(unsigned __int64)((v8 >> 11) & 3)]) ^ ((16 * (_DWORD)v9 ^ ((unsigned int)v9 >> 5)) + (_DWORD)v9))
            + (unsigned int)v10;
      }
      while ( v8 != 0xC6EF3720 );
```

Looking at this section of the code, we see that this performs various binary operations using the matrix which was made in the previous code block. Now we could reverse this, or if we googled the hard coded hex string `0x9E3779B9`we see results for the encryption algorithms TEA and XTEA. Looking at the source code for XTEA encryption (https://en.wikipedia.org/wiki/XTEA) it looks rather similar to the code above:

This sample code is from `https://en.wikipedia.org/wiki/XTEA`:
```
void encipher(unsigned int num_rounds, uint32_t v[2], uint32_t const key[4]) {
    unsigned int i;
    uint32_t v0=v[0], v1=v[1], sum=0, delta=0x9E3779B9;
    for (i=0; i < num_rounds; i++) {
        v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
        sum += delta;
        v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum>>11) & 3]);
    }
    v[0]=v0; v[1]=v1;
}
```

Looking at these two, we can tell that we are dealing with an XTEA encryption algorithm (operating in ECB Mode). Luckily for us we can decrypt it, provided we have the key and what the encrypted data is. In an earlier piece of the code we can see the key:

```
  key[0] = 0x74616877;                          // key = whatisgoingonhere
  key[1] = 0x696F6773;
  key[2] = 0x6E6F676E;
  key[3] = 0x65726568;
```

Here we can see the four pieces of the key, each a four byte hex string that when you convert it to ascii spells `whatisgoingonhere`. Now  the only thing left is to figure out what the encrypted data is, and this is where python comes into the mix.

```
    if ( matrix[9] == 0x4DE3F9FD )
    {                                           // This essentially executes the python code writen with the sprintf call
      __sprintf_chk(
        stacker,
        1LL,
        5000LL,
        "exec \"\"\"\\nimport struct\\ne=range\\nI=len\\nimport sys\\nF=sys.exit\\nX=[[%d,%d,%d],[%d,%d,%d],[%d,%d,%d]]\\"
        "nY = [[383212,38297,8201833],[382494 ,348234985,3492834886],[3842947 ,984328,38423942839]]\\nn=[5034563854941868"
        ",252734795015555591,55088063485350767967,-2770438152229037,142904135684288795,-33469734302639376803,-36335073107"
        "95117,195138776204250759,-34639402662163370450]\\ny=[[0,0,0],[0,0,0],[0,0,0]]\\nA=[0,0,0,0,0,0,0,0,0]\\nfor i in"
        " e(I(X)):\\n for j in e(I(Y[0])):\\n  for k in e(I(Y)):\\n   y[i][j]+=X[i][k]*Y[k][j]\\nc=0\\nfor r in y:\\n for"
        " x in r:\\n  if x!=n[c]:\\n   print \"dang...\"\\n   F(47)\\n  c=c+1\\nprint \":)\"\\n\"\"\"",
        matrix[0],
        matrix[1]);
      Py_Initialize(stacker, 1LL);
      PyRun_SimpleStringFlags(stacker, 0LL);
      Py_Finalize(stacker, 0LL);
    }
```

This essentially writes python code to `stacker`, then runs it. Looking at the python code that it runs, we can see how the encrypted data is verified:

```python
#Import libraries
import struct
import sys

#Establish alliases
e=range
I=len
F=sys.exit

#This is the matrix which stores the output of the XTEA encryption in here
X=[[%d,%d,%d],[%d,%d,%d],[%d,%d,%d]]

#This is a matrix which stores static values which will be multiplied against the values of the matrix X, and then stored in the matrix Y 
Y = [[383212,38297,8201833],[382494 ,348234985,3492834886],[3842947 ,984328,38423942839]]

#This is what our input will be checked against
n=[5034563854941868,252734795015555591,55088063485350767967,-2770438152229037,142904135684288795,-33469734302639376803,-3633507310795117,195138776204250759,-34639402662163370450]

#This is a matrix which will store the output of the operatins with matrixes X and Y, then checked against the values of n
y=[[0,0,0],[0,0,0],[0,0,0]]

#This is never actually used
A=[0,0,0,0,0,0,0,0,0]

#This section of code multiplies together the values of matrixes X and Y, and then stores them in the matrix y
for i in e(I(X)):
 for j in e(I(Y[0])):
  for k in e(I(Y)):
   y[i][j]+=X[i][k]*Y[k][j]

#Establish and set the index for n equal to 0 for the next part
c=0

#This section of code checks to see if the values in the matrix y are equal to the values in n. If they aren't, it exits the program
for r in y:
 for x in r:
 #Check to see if we have the desired input
  if x!=n[c]:
   print "dang...\"
   F(47)
  c=c+1
  print ":)\"
```

Here we can see that the output from the XTEA function is multiplied against static values stored in the Y matrix, then compared against the values in the n array. With this we can use Z3 to figure out what values we need in order to pass those checks, and then using the key from earlier decrypt those values using the XTEA python library to find what the correct input is.

```
#This script is based off of the writeup from: https://github.com/smokeleeteveryday/CTF_WRITEUPS/tree/master/2016/BKPCTF/reversing/unholy

#Import libraries
from z3 import *
import xtea
from struct import *

def solvePython():
	z = Solver()

	#Establish the input that z3 has control over
	X=[[BitVec(0,32), BitVec(1,32), BitVec(2,32)], [BitVec(3,32), BitVec(4,32), BitVec(5,32)], [BitVec(6,32), BitVec(7,32), BitVec(8,32)]]
	
	#Establish the other necissary constants
	Y = [[383212,38297,8201833],[382494 ,348234985,3492834886],[3842947 ,984328,38423942839]]
	n=[5034563854941868,252734795015555591,55088063485350767967,-2770438152229037,142904135684288795,-33469734302639376803,-3633507310795117,195138776204250759,-34639402662163370450]
	y=[[0,0,0],[0,0,0],[0,0,0]]
	
	#A=[0,0,0,0,0,0,0,0,0]

	#Pass the z3 input through the input altering algorithm
	for i in range(len(X)):
		for j in range(len(Y[0])):
			for k in range(len(Y)):
				y[i][j]+=X[i][k]*Y[k][j]
	c=0

	for r in y:
		for x in r:
			#Add the condition for it to pass the check
			#if x!=n[c]:
			z.add(x == n[c])
			c=c+1

	#Check to see if the z3 conditions are possible to solve
	if z.check() == sat:
		print "The condition is satisfiable, would still recommend crying: " + str(z.check())
		#Solve it, store it in matrix, then return
		solution = z.model()
		matrix = [[0, 0, 0], [0, 0, 0], [0, 0, 0]]
		for i0 in xrange(len(matrix)):
			for i1 in xrange(len(matrix)):
				matrix[i0][i1] = solution[X[i0][i1]].as_long()
		return matrix
	else:
		print "The condition is not satisfiable, would recommend crying alot: " + str(z.check())
  
def xteaDecrypt(matrix):
	#Establish the key
	key = "tahwiogsnognereh"

	#Take the imported matrix, convert it into a string
	enc_data = ''
	for i0 in xrange(3):
		for i1 in xrange(3):
			#Unpack the matrix entries as four byte Integers in Big Endian 
			enc_data += pack('>I', matrix[i0][i1])

	#Because of the check prior to python code running in the shared library we know the last value before decryption should be this
	enc_data += pack('>I', 0x4de3f9fd)

	#Establish the key, and mode for xtea
	enc = xtea.new(key, mode=xtea.MODE_ECB)

	#Decrypt the encrypted data
	decrypted = enc.decrypt(enc_data)
	
	#We have to reformat the decrypted data
	data = ''
	for i in range(0, len(decrypted), 4):
		data += decrypted[i:i+4][::-1]

	#We check to ensure that the last four characters match the four that are appended prior to encryption
	if data[len(data) - 4:len(data)] == " Ssa":
		return data

#Run the code
matrix = solvePython()
flag = xteaDecrypt(matrix)
print "The flag is: " + flag
```

and when we run it:

```
$	python reverent.py 
The condition is satisfiable, would still recommend crying: sat
The flag is: BKPCTF{hmmm _why did i even do this} Ssa
```

Just like that, we captured the flag!
