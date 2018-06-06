# Shellphish how2heap single_null_byte_poisoning

This is another section from the CTF team Shellphish's educational series on how to do heap exploitation. 

For a ctf that uses this attack: https://github.com/guyinatuxedo/ctf/tree/master/0ctf/pwn/babyheap

This section essentially covers how to get heap consolidation, with a single null byte overflow. The goal is to get the heap to consolidate past an allocated chunk, then allocate a chunk that overlaps with the "forgotten" chunk.

## Process

First we will allocate three chunks of memory for us to work with:
```
0:	0x100	0x565541f1f010
1:	0x200	0x565541f1f120
2:	0x100	0x565541f1f330
```

Proceeding that we will free chunk `1`. This will free up some space in between chunks `0` & `1` for us to work with:
```
0:	0x100	0x565541f1f010
1:	0x200 (freed)
2:	0x100	0x565541f1f330
```

Next is the overflow. We will overflow a single null byte from chunk `0` into the size value for chunk `1`stored at `0x565541f1f008` (this will help us set up to allocate space in that region). Right now the size value stored in the old chunk `1` is `0x211` (`0x200` bytes for the size, `0x10` bytes for the heap metadata, and `0x1` byte for the previous chunk in use bit). Our overflow of the byte `0x00` will change that to `0x200`, since we will be overwriting `0x11` with `0x00`.  Now a new check that was introduced into recent versions of `malloc` that we have to lookout for is `Chunksize(P) == prev_size(next chunk(P))`. For that `Chunksize(P)` is the size value for chunk `1` *(the chunk we just overflowed). For `prev_size(next chunk(P))`, that is the previous size value for chunk `2` stored at `0x565541f1f320`. To deal with this, we just write the value to `0x200` to it (would probably have to use another bug to do so):
```
0:	0x100	0x565541f1f010 (overflowed chunk 1)
1:	0x200 (freed, size overflowed to 0x200 using null byte overflow from 0)
2:	0x100	0x565541f1f330
```

Now that we have editied the metadata properly for chunk `3` (and chunk `2` to pass the new check in malloc) we can allocate where chunk `1` used to be:

```
0:	0x100	0x565541f1f010
3:	0x100	0x565541f1f120
	(free space) 0x90 (chunk 3 takes up 0x110 space because of heap metadata)
2:	0x100	0x565541f1f330
```

Proceeding that, we will allocate another chunk within the remainning space of the old chunk `1`, inbetween chunks `3` & `2`

```
0:	0x100	0x565541f1f010
3:	0x100	0x565541f1f120
4:	0x80  	0x565541f1f230 (fills up entire 0x90 byte chunk mecause of 0x10 bytes of heap metadata)
2:	0x100	0x565541f1f330
```

Now we will free chunks `3` and `2`. This will cause the heap to consolidate where chunk `0` is, and effectively forget about chunk `4`:

```
0:	0x100	0x565541f1f010
3:	0x100	0x565541f1f120 (freed)
4:	0x80  	0x565541f1f230 (chunk has been forgotten about, since heap consolidated to chunk 0)
2:	0x100	0x565541f1f330 (freed)
```

Next we can just allocate a chunk of memory of size `0x300`. This will go where chunk `3` used to be (at the same exact address). However due to the fact of it's size (and that chunk `4` has been forgotten about) it will overlap with chunk `4`. This will allow us to edit chunk `4` just by editing chunk `3` (which can allow us to edit that chunk in ways we shouldn't be able to, and further exploit the program):

```
0:	0x100	0x565541f1f010
5:	0x300	0x565541f1f120 (overlaps with chunk 4 after 0x110 bytes)
4:	0x80  	0x565541f1f230 (is overlapped by chunk 5)
```
With that, we have chunk `5` which directly overlaps chunk `4`.

## Code Running

Below you can see the code running:
```
$	./single_null_byte 
Welcome to poison null byte 2.0!
Tested in Ubuntu 14.04 64bit.
This technique can be used when you have an off-by-one into a malloc'ed region with a null byte.
We allocate 0x100 bytes for 'a'.
a: 0x565541f1f010
Since we want to overflow 'a', we need to know the 'real' size of 'a' (it may be more than 0x100 because of rounding): 0x108
b: 0x565541f1f120
c: 0x565541f1f330
In newer versions of glibc we will need to have our updated size inside b itself to pass the check 'chunksize(P) != prev_size (next_chunk(P))'
b.size: 0x211
b.size is: (0x200 + 0x10) | prev_in_use
We overflow 'a' with a single null byte into the metadata of 'b'
b.size: 0x200
c.prev_size is 0x210
We will pass the check since chunksize(P) == 0x200 == 0x200 == prev_size (next_chunk(P))
b1: 0x565541f1f120
Now we malloc 'b1'. It will be placed where 'b' was. At this point c.prev_size should have been updated, but it was not: 210
Interestingly, the updated value of c.prev_size has been written 0x10 bytes before c.prev_size: f0
We malloc 'b2', our 'victim' chunk.
b2: 0x565541f1f230
Current b2 content:
BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB
Now we free 'b1' and 'c': this will consolidate the chunks 'b1' and 'c' (forgetting about 'b2').
Finally, we allocate 'd', overlapping 'b2'.
d: 0x565541f1f120
Now 'd' and 'b2' overlap.
New b2 content:
DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD
Thanks to http://www.contextis.com/documents/120/Glibc_Adventures-The_Forgotten_Chunks.pdf for the clear explanation of this technique.
```
