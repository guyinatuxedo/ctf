# h3machine

I would just like to thank Gerogia Tech for putting on a great CTF, and having some really fun challenges to solve like this one.

Here is the series of reversing challenges from hungry hungry hackers. It is a custom architecture with a custom emulator, dissassembler, assembler, and great documentation. All fo that can be found in the `h3-machine-emulator.tar.gz` file.

## h3machine0

This challenge just verified that you are able to use the emulator to run code:

```
$	./h3emu --trace challenge0.h3i 
0001: push $0004
0002: setf 8000
0003: halt
Stack:
ffff: flag{f10b5307}

Registers:
IP: 0004
SP: ffff
Flags:   F
```

Just like that, we got the flag.

## h3machine1

For this one, using the dissasembler that came with the tar file to view the assembly code is really helpful:

```
$	./h3disasm challenge1.h3i 
0001: 12040000 push 0000
0002: 41040800 jz 0008
0003: 12044281 push 8142
0004: 37041000 lshift 0010
0005: 1204c0a9 push a9c0
0006: 31000000 or 
0007: 50040080 setf 8000
0008: 00000000 halt 
```

So we can see here, the assembly code for this program consists of just 8 instructions. The second address we can see a `jz` instruction, which should jump to the instruction `0008`, which just runs the halt unstruction, thus ending the program. Because of this, we will never be able to execute the instructions between `0003` and `0007`. Since from the wonderful documentaion, we know a lot regarding the assembly, we can simply patch the code to jump to the instruction `0003` instead of `0008`, thus running the segment of code that we should be missing.

This is the program before we patch it:
```
00000000: 00 00 00 00 12 04 00 00 41 04 08 00 12 04 42 81  ........A.....B.
00000010: 37 04 10 00 12 04 c0 a9 31 00 00 00 50 04 00 80  7.......1...P...
00000020: 00 00 00 00                                      ....
```

This is the program after we patch it:

```
00000000: 00 00 00 00 12 04 00 00 41 04 03 00 12 04 42 81  ........A.....B.
00000010: 37 04 10 00 12 04 c0 a9 31 00 00 00 50 04 00 80  7.......1...P...
00000020: 00 00 00 00                                      ....
```

As you can see, we only had to change one byte (the argument to the `jz` instruction). Let's try to run the patched version now:

```
./h3emu --trace challenge1_patched.h3i
0001: push 0000
0002: jz 0003
0003: push 8142
0004: lshift 0010
0005: push a9c0
0006: or
0007: setf 8000
0008: halt
Stack:
ffff: 00000000
fffe: flag{8142a9c0}

Registers:
IP: 0009
SP: fffe
Flags:   F
```

When we run the patched version, we can see that the rest of the code does run. Even more so, we can see that the flag is loaded onto the stack for us. Just like that, we captured the flag.

# h3machine2

For this part, I found it helpful to patch in halts into the code (just change the oppcode for the instruction you want to break out to the opcode of halt which is 00)

Let's take a look at the assembly code for this challenge:

```
$	./h3disasm challenge2.h3i 
0001: 12040000 push 0000
0002: 60041400 call 0014
0003: 41040500 jz 0005
0004: 00000000 halt 
0005: 10000000 drop 
0006: 60042400 call 0024
0007: 41040900 jz 0009
0008: 00000000 halt 
0009: 10000000 drop 
000a: 60043400 call 0034
000b: 41040d00 jz 000d
000c: 00000000 halt 
000d: 10000000 drop 
000e: 60044400 call 0044
000f: 41041100 jz 0011
0010: 00000000 halt 
0011: 10000000 drop 
0012: 50040080 setf 8000
0013: 00000000 halt 
0014: 11000000 swap 
0015: 12040c10 push 100c
0016: 37041000 lshift 0010
0017: 1204852b push 2b85
0018: 31000000 or 
0019: 21000000 sub 
001a: 41041c00 jz 001c
001b: 61000000 ret 
001c: 10000000 drop 
001d: 12040c10 push 100c
001e: 37041000 lshift 0010
001f: 1204852b push 2b85
0020: 31000000 or 
0021: 33000000 xor 
0022: 12040000 push 0000
0023: 61000000 ret 
0024: 11000000 swap 
0025: 12040187 push 8701
0026: 37041000 lshift 0010
0027: 12049803 push 0398
0028: 31000000 or 
0029: 21000000 sub 
002a: 41042c00 jz 002c
002b: 61000000 ret 
002c: 10000000 drop 
002d: 12040187 push 8701
002e: 37041000 lshift 0010
002f: 12049803 push 0398
0030: 31000000 or 
0031: 33000000 xor 
0032: 12040000 push 0000
0033: 61000000 ret 
0034: 11000000 swap 
0035: 12040918 push 1809
0036: 37041000 lshift 0010
0037: 1204d9f0 push f0d9
0038: 31000000 or 
0039: 21000000 sub 
003a: 41043c00 jz 003c
003b: 61000000 ret 
003c: 10000000 drop 
003d: 12040918 push 1809
003e: 37041000 lshift 0010
003f: 1204d9f0 push f0d9
0040: 31000000 or 
0041: 33000000 xor 
0042: 12040000 push 0000
0043: 61000000 ret 
0044: 11000000 swap 
0045: 1204f5ab push abf5
0046: 37041000 lshift 0010
0047: 1204e7ed push ede7
0048: 31000000 or 
0049: 21000000 sub 
004a: 41044c00 jz 004c
004b: 61000000 ret 
004c: 10000000 drop 
004d: 1204f5ab push abf5
004e: 37041000 lshift 0010
004f: 1204e7ed push ede7
0050: 31000000 or 
0051: 33000000 xor 
0052: 12040000 push 0000
0053: 61000000 ret 
```

First off the bat, we can see that there are 53 instructions (a lot more than the previous challenge). Before we start going through the assembly, let's run it:

```
$	./h3emu --trace challenge2.h3i 
0001: push 0000
0002: call 0014
0014: swap
Stack:

Registers:
IP: 0015
SP: 0000
Flags: Z  
Stack underflow!
$	./h3emu --trace challenge2.h3i 15935728
0001: push 0000
0002: call 0014
0014: swap
0015: push 100c
0016: lshift 0010
0017: push 2b85
0018: or
0019: sub
001a: jz 001c
001b: ret
0003: jz 0005
0004: halt
Stack:
ffff: 00000000
fffe: 05872ba3

Registers:
IP: 0005
SP: fffe
Flags:    
```

So we can see that the program requires input. We can also see that our input that we entered doesn't appear to be on the stack, so after it scans it in it probably alters it. 

At the start of the program, we can see that it calls the address `14`. Let's see what that does:

```
0014: 11000000 swap 
0015: 12040c10 push 100c
0016: 37041000 lshift 0010
0017: 1204852b push 2b85
0018: 31000000 or 
0019: 21000000 sub 
001a: 41041c00 jz 001c
```

So we can see that it pushes the hex value `0x100c`, sifts it over to the right by two bytes (so it is now `0x100c0000`), then pushes `0x2b85` onto the stack. Proceeding that it ors the two hex strings together, leaving us with `0x100c2b85`, then runs the sub instruction with our input and that hex string. If the output is zero, it will jump to the address `001c`, so we probably need to give it the input `100c2b85` in order to pass this check (btw the program interprets our input as hex characters, not asci):

```
$	./h3emu --trace challenge2.h3i 100c2b85
0001: push 0000
0002: call 0014
0014: swap
0015: push 100c
0016: lshift 0010
0017: push 2b85
0018: or
0019: sub
001a: jz 001c
001c: drop
001d: push 100c
001e: lshift 0010
001f: push 2b85
0020: or
0021: xor
0022: push 0000
0023: ret
0003: jz 0005
0005: drop
0006: call 0024
0024: swap
Stack:

Registers:
IP: 0025
SP: 0000
Flags: Z  
Stack underflow!

```

So we can see that we passed the check. Proceeding that, it says that there is another Stack underflow, so we need to give it more input:

```
$	./h3emu --trace challenge2.h3i 15935728 100c2b85
0001: push 0000
0002: call 0014
0014: swap
0015: push 100c
0016: lshift 0010
0017: push 2b85
0018: or
0019: sub
001a: jz 001c
001c: drop
001d: push 100c
001e: lshift 0010
001f: push 2b85
0020: or
0021: xor
0022: push 0000
0023: ret
0003: jz 0005
0005: drop
0006: call 0024
0024: swap
0025: push 8701
0026: lshift 0010
0027: push 0398
0028: or
0029: sub
002a: jz 002c
002b: ret
0007: jz 0009
0008: halt
Stack:
ffff: 100c2b85
fffe: 8e925390

Registers:
IP: 0009
SP: fffe
Flags:  C 
```

So we can see with the new input, that there is a new check. This new check is seeing if our second input is equal to the hex string `87010398`. Let's see what happens when we pass it that hex string for the second input:

```
$	./h3emu --trace challenge2.h3i 87010398 100c2b85
0001: push 0000
0002: call 0014
0014: swap
0015: push 100c
0016: lshift 0010
0017: push 2b85
0018: or
0019: sub
001a: jz 001c
001c: drop
001d: push 100c
001e: lshift 0010
001f: push 2b85
0020: or
0021: xor
0022: push 0000
0023: ret
0003: jz 0005
0005: drop
0006: call 0024
0024: swap
0025: push 8701
0026: lshift 0010
0027: push 0398
0028: or
0029: sub
002a: jz 002c
002c: drop
002d: push 8701
002e: lshift 0010
002f: push 0398
0030: or
0031: xor
0032: push 0000
0033: ret
0007: jz 0009
0009: drop
000a: call 0034
0034: swap
Stack:

Registers:
IP: 0035
SP: 0000
Flags: Z  
Stack underflow!
```

So we can see that we passed the check, and it expects more input. So for the first two checks, it just sees if our input is equal to a certain hex string. Let's see how far we can get by essentially replacing the same process of sending it the hex string that it looks for:

```
$	./h3emu --trace challenge2.h3i 15935728 87010398 100c2b85
0001: push 0000
0002: call 0014
0014: swap
0015: push 100c
0016: lshift 0010
0017: push 2b85
0018: or
0019: sub
001a: jz 001c
001c: drop
001d: push 100c
001e: lshift 0010
001f: push 2b85
0020: or
0021: xor
0022: push 0000
0023: ret
0003: jz 0005
0005: drop
0006: call 0024
0024: swap
0025: push 8701
0026: lshift 0010
0027: push 0398
0028: or
0029: sub
002a: jz 002c
002c: drop
002d: push 8701
002e: lshift 0010
002f: push 0398
0030: or
0031: xor
0032: push 0000
0033: ret
0007: jz 0009
0009: drop
000a: call 0034
0034: swap
0035: push 1809
0036: lshift 0010
0037: push f0d9
0038: or
0039: sub
003a: jz 003c
003b: ret
000b: jz 000d
000c: halt
Stack:
ffff: 970d281d
fffe: fd89664f

Registers:
IP: 000d
SP: fffe
Flags:  C 
```

```
$	./h3emu --trace challenge2.h3i 1809f0d9 87010398 100c2b85
0001: push 0000
0002: call 0014
0014: swap
0015: push 100c
0016: lshift 0010
0017: push 2b85
0018: or
0019: sub
001a: jz 001c
001c: drop
001d: push 100c
001e: lshift 0010
001f: push 2b85
0020: or
0021: xor
0022: push 0000
0023: ret
0003: jz 0005
0005: drop
0006: call 0024
0024: swap
0025: push 8701
0026: lshift 0010
0027: push 0398
0028: or
0029: sub
002a: jz 002c
002c: drop
002d: push 8701
002e: lshift 0010
002f: push 0398
0030: or
0031: xor
0032: push 0000
0033: ret
0007: jz 0009
0009: drop
000a: call 0034
0034: swap
0035: push 1809
0036: lshift 0010
0037: push f0d9
0038: or
0039: sub
003a: jz 003c
003c: drop
003d: push 1809
003e: lshift 0010
003f: push f0d9
0040: or
0041: xor
0042: push 0000
0043: ret
000b: jz 000d
000d: drop
000e: call 0044
0044: swap
Stack:

Registers:
IP: 0045
SP: 0000
Flags: Z  
Stack underflow!
```

```
$	./h3emu --trace challenge2.h3i 15935728 1809f0d9 87010398 100c2b85
0001: push 0000
0002: call 0014
0014: swap
0015: push 100c
0016: lshift 0010
0017: push 2b85
0018: or
0019: sub
001a: jz 001c
001c: drop
001d: push 100c
001e: lshift 0010
001f: push 2b85
0020: or
0021: xor
0022: push 0000
0023: ret
0003: jz 0005
0005: drop
0006: call 0024
0024: swap
0025: push 8701
0026: lshift 0010
0027: push 0398
0028: or
0029: sub
002a: jz 002c
002c: drop
002d: push 8701
002e: lshift 0010
002f: push 0398
0030: or
0031: xor
0032: push 0000
0033: ret
0007: jz 0009
0009: drop
000a: call 0034
0034: swap
0035: push 1809
0036: lshift 0010
0037: push f0d9
0038: or
0039: sub
003a: jz 003c
003c: drop
003d: push 1809
003e: lshift 0010
003f: push f0d9
0040: or
0041: xor
0042: push 0000
0043: ret
000b: jz 000d
000d: drop
000e: call 0044
0044: swap
0045: push abf5
0046: lshift 0010
0047: push ede7
0048: or
0049: sub
004a: jz 004c
004b: ret
000f: jz 0011
0010: halt
Stack:
ffff: 8f04d8c4
fffe: 699d6941

Registers:
IP: 0011
SP: fffe
Flags:  C 
```

```
./h3emu --trace challenge2.h3i abf5ede7 1809f0d9 87010398 100c2b85
0001: push 0000
0002: call 0014
0014: swap
0015: push 100c
0016: lshift 0010
0017: push 2b85
0018: or
0019: sub
001a: jz 001c
001c: drop
001d: push 100c
001e: lshift 0010
001f: push 2b85
0020: or
0021: xor
0022: push 0000
0023: ret
0003: jz 0005
0005: drop
0006: call 0024
0024: swap
0025: push 8701
0026: lshift 0010
0027: push 0398
0028: or
0029: sub
002a: jz 002c
002c: drop
002d: push 8701
002e: lshift 0010
002f: push 0398
0030: or
0031: xor
0032: push 0000
0033: ret
0007: jz 0009
0009: drop
000a: call 0034
0034: swap
0035: push 1809
0036: lshift 0010
0037: push f0d9
0038: or
0039: sub
003a: jz 003c
003c: drop
003d: push 1809
003e: lshift 0010
003f: push f0d9
0040: or
0041: xor
0042: push 0000
0043: ret
000b: jz 000d
000d: drop
000e: call 0044
0044: swap
0045: push abf5
0046: lshift 0010
0047: push ede7
0048: or
0049: sub
004a: jz 004c
004c: drop
004d: push abf5
004e: lshift 0010
004f: push ede7
0050: or
0051: xor
0052: push 0000
0053: ret
000f: jz 0011
0011: drop
0012: setf 8000
0013: halt
Stack:
ffff: flag{24f13523}

Registers:
IP: 0014
SP: ffff
Flags: Z F
```

and just like that, we captured the flag.

## h3machine3

For this challenge, let's look at the assembly code:

```
$	./h3disasm challenge3.h3i 
0001: 12010000 push +0000
0002: 12040400 push 0004
0003: 11000000 swap 
0004: 12010100 push +0001
0005: 32000000 not 
0006: 1204ff00 push 00ff
0007: 30000000 and 
0008: 33000000 xor 
0009: 38040800 rotate 0008
000a: 11000000 swap 
000b: 21040100 sub 0001
000c: 41040e00 jz 000e
000d: 40040300 jmp 0003
000e: 11000000 swap 
000f: 21021600 sub $0016
0010: 41041200 jz 0012
0011: 40041500 jmp 0015
0012: 10000000 drop 
0013: 10000000 drop 
0014: 50040080 setf 8000
0015: 00000000 halt 
0016: 5b6d517c 
```

So this program only has 16 instructions. However we can see what appears to be a for loop here:

```
0002: 12040400 push 0004
0003: 11000000 swap 
0004: 12010100 push +0001
0005: 32000000 not 
0006: 1204ff00 push 00ff
0007: 30000000 and 
0008: 33000000 xor 
0009: 38040800 rotate 0008
000a: 11000000 swap 
000b: 21040100 sub 0001
000c: 41040e00 jz 000e
000d: 40040300 jmp 0003
```

Here what is happening is it is pushing the value `0004` onto the stack, running the binary operation not on it to give us `fffb`, then anding it with `00ff` to give us `00fb`. Procceding that xors that with our input, so effectively xoring the least significan byte of our input with `fb`. Then it shifts our input to the right by `0x8` bits (or one byte). Proceeding that it decremnts the iteration count by one, and if it is not equal to zero it will rerun the loop. Let;s see how many times it runs:

```
$	./h3emu --trace challenge3.h3i 00000000
0001: push +0000
0002: push 0004
0003: swap
0004: push +0001
0005: not
0006: push 00ff
0007: and
0008: xor
0009: rotate 0008
000a: swap
000b: sub 0001
000c: jz 000e
000d: jmp 0003
0003: swap
0004: push +0001
0005: not
0006: push 00ff
0007: and
0008: xor
0009: rotate 0008
000a: swap
000b: sub 0001
000c: jz 000e
000d: jmp 0003
0003: swap
0004: push +0001
0005: not
0006: push 00ff
0007: and
0008: xor
0009: rotate 0008
000a: swap
000b: sub 0001
000c: jz 000e
000d: jmp 0003
0003: swap
0004: push +0001
0005: not
0006: push 00ff
0007: and
0008: xor
0009: rotate 0008
000a: swap
000b: sub 0001
000c: jz 000e
000e: swap
000f: sub $0016
0010: jz 0012
0011: jmp 0015
0015: halt
Stack:
ffff: 00000000
fffe: 00000000
fffd: 82ac8fa0

Registers:
IP: 0016
SP: fffd
Flags:   
```

So here we can see that the loop is ran 4 times. So effictively it just xors each byte of our input. One thing to notice is that the byte it xors our input by is incremented by one each time the loop is ran. so our least signifcant byte is xored by `0xfb`, or secondby `0xfc`, our third by `0xfd`, and our forth by `0xfe`.

Continuing after that process, let's look at what happens when the loop finishes:

```
000e: 11000000 swap 
000f: 21021600 sub $0016
0010: 41041200 jz 0012
0011: 40041500 jmp 0015
0012: 10000000 drop 
0013: 10000000 drop 
0014: 50040080 setf 8000
0015: 00000000 halt 
0016: 5b6d517c 
```

So looking here, we can essentially see that it is subtracting the result of the previous loop by `0x7c516d5b` (remember it scans it in least endian) is equal to zero. So effectively in order to solve this challenge, we just have to find out what hex string will output `0x7c516d5b` from the previous loop. Since we have what the output should be, and what it is being xored by, we can just xor the two together to get the input:

```
>>> hex(0x5b ^ 0xfb)
'0xa0'
>>> hex(0x6d ^ 0xfc)
'0x91'
>>> hex(0x51 ^ 0xfd)
'0xac'
>>> hex(0x7c ^ 0xfe)
'0x82'
```

and when we put it all toghether:

```
./h3emu --trace challenge3.h3i 82ac91a0
0001: push +0000
0002: push 0004
0003: swap
0004: push +0001
0005: not
0006: push 00ff
0007: and
0008: xor
0009: rotate 0008
000a: swap
000b: sub 0001
000c: jz 000e
000d: jmp 0003
0003: swap
0004: push +0001
0005: not
0006: push 00ff
0007: and
0008: xor
0009: rotate 0008
000a: swap
000b: sub 0001
000c: jz 000e
000d: jmp 0003
0003: swap
0004: push +0001
0005: not
0006: push 00ff
0007: and
0008: xor
0009: rotate 0008
000a: swap
000b: sub 0001
000c: jz 000e
000d: jmp 0003
0003: swap
0004: push +0001
0005: not
0006: push 00ff
0007: and
0008: xor
0009: rotate 0008
000a: swap
000b: sub 0001
000c: jz 000e
000e: swap
000f: sub $0016
0010: jz 0012
0012: drop
0013: drop
0014: setf 8000
0015: halt
Stack:
ffff: flag{82ac91a0}

Registers:
IP: 0016
SP: ffff
Flags: Z F
```

Just like that we captured the flag! 

