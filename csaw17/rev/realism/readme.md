# Csaw 17 Reversing 400 Realism

This writeup is based off of: `https://github.com/DMArens/CTF-Writeups/blob/master/2017/CSAWQuals/reverse/realism-400.md`

Let's take a look at what we have:

```
$	file main.bin 
main.bin: DOS/MBR boot sector
```

So we are given a boot record. We are also given the command `qemu-system-i386 -drive format=raw,file=main.bin`, which when we run it displays a screen which prompts us for the flag.

## MBR

A couple of things about Master Boot Records that are extreamly helpful to know going forward. They are always loaded into memory at the address `0x7c00`. So in gdb, we can just look at the assembly code by examining the memory starting at `0x7c00`. Secondly the code for this program is a sixteen bit assembly, in the `i8086` architecture. You will have to load it as 16 bit assembly in IDA in order to actually see the assembly code. The third thing, in IDA when you load in the binary the code will start at the address `0x0`. If you want, you can reload the binary to start at the address `0x7c00`, because that is what the address `0x0` will correlate to when it runs. For instance the address `0x1dc` in IDA would translate to the address `0x7ddc` when it runs (I use both address types interchangeably) 

## Dynamic Analysis

When reversing this, using gdb to analyze the program as it is running is very helpful. Luckily for us, qemu has built in gdb support with the `-gdb` flag. Here is the command you need to run if you want to run the program with a listener on port `1234` (ip is localhost) for gdb:

```
$	qemu-system-i386 -drive format=raw,file=main.bin -gdb tcp::1234
```

and if you want to connect to the listener on localhost on port `1234` (before that we will set the architecture to `i8086`, so we can view the instructions properly):

```
gdb-peda$ set architecture i8086
warning: A handler for the OS ABI "GNU/Linux" is not built into this configuration
of GDB.  Attempting to continue with the default i8086 settings.

The target architecture is assumed to be i8086
gdb-peda$ target remote localhost:1234
Remote debugging using localhost:1234
Warning: not running or target is remote
0x0000c073 in ?? ()
```

Now that we have attached the process to gdb, let's see if the instructions begin where we would expec them to at `0x7c00`:

```
gdb-peda$ x/20i 0x7c00
   0x7c00:	mov    ax,0x13
   0x7c03:	int    0x10
   0x7c05:	mov    eax,cr0
   0x7c08:	and    ax,0xfffb
   0x7c0b:	or     ax,0x2
   0x7c0e:	mov    cr0,eax
   0x7c11:	mov    eax,cr4
   0x7c14:	or     ax,0x600
   0x7c17:	mov    cr4,eax
   0x7c1a:	mov    WORD PTR ds:0x1266,0xa
   0x7c20:	mov    bx,0x0
   0x7c23:	mov    BYTE PTR [bx+0x1234],0x5f
   0x7c28:	inc    bx
   0x7c29:	cmp    bx,0x15
   0x7c2c:	jle    0x7c23
   0x7c2e:	mov    BYTE PTR ds:0x7dc8,0x0
   0x7c33:	mov    cx,0x1
   0x7c36:	xor    dx,dx
   0x7c38:	mov    ah,0x86
   0x7c3a:	int    0x15
```

So we can see here the same instructions that we see at the start of the program (so we know that we know where the start of the code segment in memory is). Now the next step of reversing this is to identify the segment of code where the actual check happens. The elf is only `512` bytes long, so there isn't a lot of code to parse through. However this is my first time reversing this type of architecture, and thus I am very lost. 

So what I decided to do to figure out which code segments are responsible for the check, is set breakpoints at the start of various sub functions (in IDA they are titled something like `loc_8E`)

```
0x7c00

0x7c23

0x7c33

0x7c38

0x7c58

0x7c8e

0x7cdf

0x7d0d

0x7d31
```

When I ran the program normally, it just encountered the breakpoints at `0x7c58`, `0x7d0d`, `0x7c33` and `0x7c38` (in that order). So those four code segments are probably used in handling input and the display. However when we enter in `20` characters and trigger a check, we encounter a breakpoint at `0x7cdf`. So we know that `0x7cdf` is a part of the check. That code path `loc_DF or 0x7cdf` is called in two different places, at `0x7d55` and `0x7cd1`. When we run the program again, and set breakpoints for `0x7d55` and `0x7cd1` we see that the one that we hit which actually leads to the check is `0x7d55`. This is apart of the subroutine `loc_14D`, which starts at `0x7d4d`. This is also called at two different places at `0x7c78` and `0x7cba`. When we do the same trial by running the program again with setting a breakpoint at `0x7c78` and `0x7cba` to see where the call actually happens, we see that it is called at `0x7c78`.

The actual instruction at `0x7c78` is a `jnz` instruction for the prevous `cmp` instruction at `0x7c6f`. Specifically this is the instruction:

```
seg000:006F                 cmp     dword ptr ds:1234h, 'galf'
```

So it is comparing something against the string `flag` (it's displayed backwards, I'm pretty sure it's because of least endian). It is probably checking to see if the input we gave it starts with `flag`. When we try running the code again with input that starts with `flag{` and ends in `}`, we see something interesting happen. It passes the check at `0x7c6f` and doesn't execute the jump at `0x7c78`. It just continues execution into `loc_8e` where it enters into a for loop. However when it is in the for loop, we don't get the error message that we're wrong and we should feel bad.

So with this new discovery, I'm pretty sure whatwe though the check happened at `0x7cdf` isn't actually a part of the check, it's the part of the program that happens after the check if we're wrong at tells us we're bad and should feel bad. The actual check begins at `0x7c66`, where it just sees how many characters of input we've given it. If it is less than or equal to `0x13` (`19`) it just jumps to `0x7d0d` and continues with the loop. However when it reaches `20` characters of input (the amount that we need to enter to trigger the check) it skips the jump and starts actually checking the input at `0x6f` with seeing if the first four characters are `flag`, then continues into the actual check in `loc_8e` at `0x7c8e`.
e 
## The Check

So now that we know where the check occurs, we can start reversing it. Below is the code that is relevant to the check:

```
seg000:0066                 cmp     byte ptr ds:7DC8h, 13h
seg000:006B                 jle     loc_10D
seg000:006F                 cmp     dword ptr ds:1234h, 67616C66h
seg000:0078                 jnz     loc_14D
seg000:007C                 movaps  xmm0, xmmword ptr ds:1238h
seg000:0081                 movaps  xmm5, xmmword ptr ds:7C00h
seg000:0086                 pshufd  xmm0, xmm0, 1Eh
seg000:008B                 mov     si, 8
seg000:008E
seg000:008E loc_8E:                                 ; CODE XREF: seg000:00C1j
seg000:008E                 movaps  xmm2, xmm0
seg000:0091                 andps   xmm2, xmmword ptr [si+7D90h]
seg000:0096                 psadbw  xmm5, xmm2
seg000:009A                 movaps  xmmword ptr ds:1268h, xmm5
seg000:009F                 mov     di, ds:1268h
seg000:00A3                 shl     edi, 10h
seg000:00A7                 mov     di, ds:1270h
seg000:00AB                 mov     dx, si
seg000:00AD                 dec     dx
seg000:00AE                 add     dx, dx
seg000:00B0                 add     dx, dx
seg000:00B2                 cmp     edi, [edx+7DA8h]
seg000:00BA                 jnz     loc_14D
seg000:00BE                 dec     si
seg000:00BF                 test    si, si
seg000:00C1                 jnz     short loc_8E
seg000:00C3                 mov     byte ptr ds:1278h, 0Ah
seg000:00C8                 mov     bx, ds:1266h
seg000:00CC                 mov     di, 7D70h
seg000:00CF                 test    bx, bx
seg000:00D1                 jz      short loc_DF
seg000:00D3                 dec     word ptr ds:1266h
seg000:00D7                 xor     cx, cx
seg000:00D9                 mov     dx, 14h
seg000:00DC                 jmp     loc_38
```

The code between `0x66 ` - `0x78` was discussed above (it just checks the length to see if a check is needed, and if the string starts with `flag`). Procceding that we see the following code:

```
seg000:007C                 movaps  xmm0, xmmword ptr ds:1238h
seg000:0081                 movaps  xmm5, xmmword ptr ds:7C00h
```

Both of these commands are just moving in data in memory into the `xmm0` and `xmm5` registers. The instruction at `0x7c` is moving the `16` bytes of our input into the `xmm0` register, which we can see with gdb (depicted below). The instruction at `0x81` is loading the first `16` bytes of the program (since the code for the program starts at `0x7c00`, since it is a MBR, check it with gdb if you want) into the `xmm5` register. These registers are used later:

```
Breakpoint 1, 0x00007c7c in ?? ()
gdb-peda$ x/x $ds+0x1238
0x1238:	0x7430677b
gdb-peda$ x/s $ds+0x1238
0x1238:	"{g0ttem_b0yzzzz}__"
```

and on the next line of assembly code, we have this:

```
seg000:0086                 pshufd  xmm0, xmm0, 1Eh
```

This instruction essentially just rearranges our input. It inserts the contents of argument two (the `xmm0` register) into the first argument (also the `xmm0` register) at the position of the third argument `0x1e`. We can see how it rearranges it in gdb (below the input string it is dealing with is `0123456789abcdef`):

before `pshufd`:
```
Breakpoint 1, 0x00007c86 in ?? ()
gdb-peda$ p $xmm0
$1 = {
  v4_float = {4.14885903e-08, 1.08604327e-05, 1.03866012e+21, 2.70818433e+23}, 
  v2_double = {9.9583343788967447e-43, 1.817948654379013e+185}, 
  v16_int8 = {0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 
    0x61, 0x62, 0x63, 0x64, 0x65, 0x66}, 
  v8_int16 = {0x3130, 0x3332, 0x3534, 0x3736, 0x3938, 0x6261, 0x6463, 0x6665}, 
  v4_int32 = {0x33323130, 0x37363534, 0x62613938, 0x66656463}, 
  v2_int64 = {0x3736353433323130, 0x6665646362613938}, 
  uint128 = 0x66656463626139383736353433323130
}
```

after `pshufd`:
```
0x00007c8b in ?? ()
gdb-peda$ p $xmm0
$2 = {
  v4_float = {1.03866012e+21, 2.70818433e+23, 1.08604327e-05, 4.14885903e-08}, 
  v2_double = {1.817948654379013e+185, 4.4222647410633844e-62}, 
  v16_int8 = {0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x34, 0x35, 
    0x36, 0x37, 0x30, 0x31, 0x32, 0x33}, 
  v8_int16 = {0x3938, 0x6261, 0x6463, 0x6665, 0x3534, 0x3736, 0x3130, 0x3332}, 
  v4_int32 = {0x62613938, 0x66656463, 0x37363534, 0x33323130}, 
  v2_int64 = {0x6665646362613938, 0x3332313037363534}, 
  uint128 = 0x33323130373635346665646362613938
}
```

The exact order that this instance of `pshufd` shuffles our input is this:
```
0.) last eight bytes first
1.) second group of four bytes
2.) first group of four bytes
```
next we have this line of assembly:

```
seg000:008B                 mov     si, 8
```

This just moves the value `8` into the `si` register. This is going to be used for an iteration count for the loop we are about to enter (starts at `0x8e`) which will run `8` times.

## The loop portion of the check

Now we enter the loop. The first line just moves the contents of the `xmm0` register into the `xmm2` register:

```
seg000:008E                 movaps  xmm2, xmm0
```

The next line of code ands together the `xmm2` register with the values stored at `si+0x7d90`, and stores the output in the `xmm2` register. The value at `si+0x7d90` is two `0xffffffffffffff00` segments. The end result is the eight and sixteen bytes of `xmm2` are set to `0x00`. 

```
seg000:0091                 andps   xmm2, xmmword ptr [si+7D90h]
```

next we have the `psadbw` instruction:

```
seg000:0096                 psadbw  xmm5, xmm2
```

this insturction computes the absolute sum of differences between the `xmm5` and `xmm2` registers, and stores it in the `xmm5` register. So essentially what it does is it subtracts each byte of the `xmm2` register, from each byte of the `xmm5` register. It then takes the absolute values of the differences, and adds them together. Also it does two additions, one for the first eight bytes and the second eight bytes. For an example, here we can see the `xmm2` and `xmm5` registers before and after the `psadbw` instruction (this time the input string is `{g0ttem_b0yzzzz}`):

before:
```
gdb-peda$ p $xmm2
$11 = {
  v4_float = {3.23463868e+35, 2.08089334e+37, 1.71060788e+19, 5.5904729e+31}, 
  v2_double = {2.7057520980982879e+296, 4.6979905997385002e+251}, 
  v16_int8 = {0x0, 0x30, 0x79, 0x7a, 0x7a, 0x7a, 0x7a, 0x7d, 0x0, 0x65, 0x6d, 0x5f, 0x7b, 0x67, 
    0x30, 0x74}, 
  v8_int16 = {0x3000, 0x7a79, 0x7a7a, 0x7d7a, 0x6500, 0x5f6d, 0x677b, 0x7430}, 
  v4_int32 = {0x7a793000, 0x7d7a7a7a, 0x5f6d6500, 0x7430677b}, 
  v2_int64 = {0x7d7a7a7a7a793000, 0x7430677b5f6d6500}, 
  uint128 = 0x7430677b5f6d65007d7a7a7a7a793000
}
gdb-peda$ p $xmm5
$12 = {
  v4_float = {-134298496, -2.50091934, -1.48039995e-36, 1.93815862e-18}, 
  v2_double = {-8.0294250547975565, 1.241726856953559e-144}, 
  v16_int8 = {0xb8, 0x13, 0x0, 0xcd, 0x10, 0xf, 0x20, 0xc0, 0x83, 0xe0, 0xfb, 0x83, 0xc8, 0x2, 0xf, 
    0x22}, 
  v8_int16 = {0x13b8, 0xcd00, 0xf10, 0xc020, 0xe083, 0x83fb, 0x2c8, 0x220f}, 
  v4_int32 = {0xcd0013b8, 0xc0200f10, 0x83fbe083, 0x220f02c8}, 
  v2_int64 = {0xc0200f10cd0013b8, 0x220f02c883fbe083}, 
  uint128 = 0x220f02c883fbe083c0200f10cd0013b8
}
```

after:
```
0x00007c9a in ?? ()
gdb-peda$ p $xmm5
$13 = {
  v4_float = {1.10282189e-42, 0, 1.01594139e-42, 0}, 
  v2_double = {3.8882966327706103e-321, 3.5819759323490374e-321}, 
  v16_int8 = {0x13, 0x3, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xd5, 0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, 
  v8_int16 = {0x313, 0x0, 0x0, 0x0, 0x2d5, 0x0, 0x0, 0x0}, 
  v4_int32 = {0x313, 0x0, 0x2d5, 0x0}, 
  v2_int64 = {0x313, 0x2d5}, 
  uint128 = 0x00000000000002d50000000000000313
}
```

and here are the calculations that happened:

```
0xb8 - 0x0 = 184
0x30 - 0x13 = 29
0x79 - 0x0 = 121
0xcd - 0x7a = 83
0x7a - 0x10 = 106
0x7a - 0xf = 107
0x7a - 0x20 = 90
0xc0 - 0x7d = 67
hex(184 + 29 + 121 + 83 + 106 + 107 + 90 + 67) = 0x313

0x83 - 0x0 = 131
0xe0 - 0x65 = 123
0xfb - 0x6d = 142
0x83 - 0x5f = 36
0xc8 - 0x7b = 77
0x67 - 0x2 = 101
0x30 - 0xf = 33
0x74 - 0x22 = 82
hex(131 + 123 + 142 + 36 + 77+ 101 + 33 + 82) = 0x2d5
```

Proceeding that we have the rest of the check:

```
seg000:009A                 movaps  xmmword ptr ds:1268h, xmm5
seg000:009F                 mov     di, ds:1268h
seg000:00A3                 shl     edi, 10h
seg000:00A7                 mov     di, ds:1270h
seg000:00AB                 mov     dx, si
seg000:00AD                 dec     dx
seg000:00AE                 add     dx, dx
seg000:00B0                 add     dx, dx
seg000:00B2                 cmp     edi, [edx+7DA8h]
seg000:00BA                 jnz     loc_14D
```

Essentially what this section of code does, it takes the two values obtained from the previous `psadbw` instruction, arranges them in the `edi` register (`0x313` first then `0x2d5`) and compares it against a value stored in memory. If the check is successful, the the loop continues for another iteration where it repeats the loop. The loop will run for eight times, and if we pass all of the checks, we have the correct flag. To find the values that we need to be equal to to pass this check, we can use gdb, and then just jump to the next iteration to see the next value (btw the check happens at `0x7cb2`, our input is in the `edi` register and the value we are comparing it against is in `edx+0x7da8`):

```
Breakpoint 1, 0x00007cb2 in ?? ()
gdb-peda$ x/x $edx+0x7da8
0x7dc4:	0x02df028f
gdb-peda$ j *0x7cbe
Continuing at 0x7cbe.
Warning: not running or target is remote

Breakpoint 1, 0x00007cb2 in ?? ()
gdb-peda$ x/x $edx+0x7da8
0x7dc0:	0x0290025d
```

and you can continue to do that untill you have all eight values.

## z3

Now that we have reversed the algorithm that our input is sent through, and we know the end value it is being compared to, we can use z3 to figure out what the flag is. Below is my z3 script I wrote to find the flag:

```
# This script is from a solution here: https://github.com/DMArens/CTF-Writeups/blob/master/2017/CSAWQuals/reverse/realistic.py
# I basically just added comments to it

# One thing about this script, it uses z3, which uses special data types so it can solve things. As a result, we have to do some special things such as write our own absolute value function instead of using pythons built in functions.

# First import the needed libraries
from pprint import pprint
from z3 import *
import struct

# Establish the values which our input will be checked against after each of the 8 iterations
resultZ = [ (0x02df, 0x028f), (0x0290, 0x025d), (0x0209, 0x0221), (0x027b, 0x0278), (0x01f9, 0x0233), (0x025e, 0x0291), (0x0229, 0x0255), (0x0211, 0x0270) ]

# Establish the first value for the xmm5 register, which is the first 16 bytes of the elf
xmm5Z = [ [0xb8, 0x13, 0x00, 0xcd, 0x10, 0x0f, 0x20, 0xc0, 0x83, 0xe0, 0xfb, 0x83, 0xc8, 0x02, 0x0f, 0x22], ]

# Establish the solver
z = Solver()

# Establish the value `0` as a z3 integer, for later use
zero = IntVal(0)

# Establish a special absolute value function for z3 values
def abz(x):
	return If( x >= 0, x, -x)

# This function does the `psadbw` (sum of absolute differences) instruction at 0x7c96
def psadbw(xmm5, xmm2):
	x = Sum([abz(x0 - x1) for x0, x1 in zip(xmm5[:8], xmm2[:8])])
	y = Sum([abz(y0 - y1) for y0, y1 in zip(xmm5[8:], xmm2[8:])])
	return x, y

# Now we will append the values in resultZ to xmm5Z. The reason for this being while xmm5Z contains the initial value that it should have, it's value carries over to each iteration. And if we passed the check, it's starting value at each iteration after the first, should be the value that we needed to get to pass the previous check.
for i in resultZ[:-1]:
	xmm5Z.append(list(map(ord, struct.pack('<Q', i[0]) + struct.pack('<Q', i[1]))))

# Now we will establush the values that z3 has control over, which is our input. We will also add a check that each byte has to be within the Ascii range, so we can type it in. We make sure to have the string `flag` in each of the characters names so we can parse them out later
inp = [Int('flag{:02}'.format(i)) for i in range(16)]
for i in inp:
	z.add(i > 30, i < 127)

# Now we will move establish z3 data types with the previously established values in xmm5Z and resultZ. This is so we can use them with z3
xmm5z = [ [IntVal(x) for x in row] for row in xmm5Z]
results = [ [IntVal(x) for x in row] for row in resultZ]

# Now here where we run the algorithm in the loop (btw when I say registers below, I don't mean the actual ones on our computer, just the data values we use to simulate the algorithm)
for i in range(8):
	# First we set the xmm5 register to it's correct value
	xmm5 = xmm5z[i]
	# We set the xmm2 register to be out input
	xmm2 = list(inp)
	# Zero out the corresponding bytes from the andps instruction at 0x7c96
	xmm2[i] = zero
	xmm2[i + 8] = zero
	x,y = psadbw(xmm5, xmm2)
	z.add(x == results[i][0])
	z.add(y == results[i][1])

# Check if it z3 can solve the problem
if z.check() == sat:
	print "z3 can solve it"
elif z.check() == unsat:
	print "The condition isn't satisified, I would recommend crying."
	exit(0)

# Model the solution (it makes z3 come up with a solution), and then filter out the flag and convert it ASCII

model = z.model()
# Create a list to store the various inputs which meet the criteria
solutions = []

# Search for our flag values that we made on line 37, and append them to solutions
for i in model.decls():
	if 'flag' in i.name():
		solutions.append((int(i.name()[4:]), chr(model[i].as_long())))

# Sort out all of the various solutions, then join them together for the needed input
solutions = sorted(solutions, key=lambda x: x[0])
solutions = [x[1] for x in solutions]
flag = ''.join(solutions)

# Next we need to essentially undo the `pshfud` instruction which occurs at `0x7c86`, that way when we give the flag and it applies the instruction, it will have the string needed to pass the eight checks
flag = flag[12:] + flag[8:12] + flag[:8]
print "flag{}".format(flag)
```

and when we run it:
```
$	python reverent.py 
z3 can solve it
flag{4r3alz_m0d3_y0}
```

Just like that, we captured the flag! 

## tl ; dr

*	MBR loads code into memory at the address `0x7c00` / assembly code is 16 bit / architecture is `i8086`
*	check starts at `0x7c66`
*	check requires 20 characters
*	check checks if input starts with `flag`
*	check scrambles input, then runs it through loop eight times
*	each iteration of loop computes the sum of absoulte differences between scrambled input and remainder of last loop (starts with first 16 bytes of code)
*	checks to see if output is correct, if not exits loop
*	use z3 to solve
*	This writeup is based off of: `https://github.com/DMArens/CTF-Writeups/blob/master/2017/CSAWQuals/reverse/realism-400.md`