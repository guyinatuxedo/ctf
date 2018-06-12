# Shellphish how2heap overlapping_chunks_2

This is another writeup of a section of Shellphish's educational how2heap series. 

This section covers how to get overlapping chunks, by overwriting a size value for an allocated chunk, freeing it, then reallocating it:

## Exploitation Process

First we allocate 5 chunks:

```
0:	0x3e8	0x555555757010
1:	0x3e8	0x555555757400
2:	0x3e8	0x5555557577f0
3:	0x3e8	0x555555757be0
4:	0x3e8	0x555555757fd0
```

First up, we will free chunk `3`:

```
0:	0x3e8	0x555555757010
1:	0x3e8	0x555555757400
2:	0x3e8	0x5555557577f0
3:	0x3e8	(freed)
4:	0x3e8	0x555555757fd0
```

Proceeding that we will trigger the vulnerabillity. This vulnerabillity will overwrite the size value of chunk `1`. The value we will overwrite it with, is the size of chunk `1` plus the size of chunk `2`. This can be done with a heap overflow from chunk `0`.  

This is what the size value for chunk `1` (located at `0x5555557573f8`) looks like prior to the overwrite. It is `0x3f1`, since the space we allocated is `0x3e8` bytes large plus the `0x8` bytes for the heap metadata, plus `0x1`for the `previous_chunk_in_use`:
```
gdb-peda$ x/4g 0x5555557573f8
0x5555557573f8:	0x00000000000003f1	0x4242424242424242
0x555555757408:	0x4242424242424242	0x4242424242424242
```

We will overwrite it with the value `0x7e1` (2017). This is because there is `2000` bytes for the two heap chunks, `16` bytes for the heap metadata, and `1` byte for the `previous_chunk_in_use`:

```
gdb-peda$ x/4g 0x5555557573f8
0x5555557573f8:	0x00000000000007e1	0x4242424242424242
0x555555757408:	0x4242424242424242	0x4242424242424242
```

With that, we get the following chunk layout:

```
0:	0x3e8	0x555555757010
1:	0x3e8	(size overwritten with 0x7e1)
2:	0x3e8	0x5555557577f0
3:	0x3e8	(freed)
4:	0x3e8	0x555555757fd0
```

Next we will free chunk `1`. Due to the previous overwrite, and the fact that the current size of chunk `1` with the position of chunk `1` will equal to the address of the old chunk `3`. This will cause the free to efficitively free the space between chunks `1` and `3`, including chunk `2`:

```
0:  0x3e8
1:  0x3e8 (freed)
2:  0x3e8 (included in free chunk)
3:  0x3e8 (freed)
4:  0x3e8
```

Now we can allocate an area of heap space of size `2000` (which is equivalent to the size of chunks `1` & `2`). This will allocate a single chunk beginning where chunk `1` used to be, and ending where chunk `3` used to be. This chunk will include chunk `2`, which we haven't freed:

```
0:  0x3e8
5:	0x7d0 (overlaps with chunk 2 after 0x3f0 bytes )
2:  0x3e8 (included in free chunk)
4:  0x3e8
```

With that we now have overlapping chunks. Chunk `5` overlaps with chunk `2` after 0x3f0 (`1008` bytes, `1000` bytes for the old heap chunk and `8` bytes for the heap ) bytes. This is beneficial since we can edit chunk `2` using chunk `5` and vice versa, which can lead to us being able to edit the data in ways that we shouldn't be able to. In addition to that, we can edit the metadata for Chunk `2` my editing Chunk `5`.

## Code Running

Here is the code from this section running

```
This is a simple chunks overlapping problem
This is also referenced as Nonadjacent Free Chunk Consolidation Attack

Let's start to allocate 5 chunks on the heap:

chunk p1 from 0x555555757010 to 0x5555557573f8
chunk p2 from 0x555555757400 to 0x5555557577e8
chunk p3 from 0x5555557577f0 to 0x555555757bd8
chunk p4 from 0x555555757be0 to 0x555555757fc8
chunk p5 from 0x555555757fd0 to 0x5555557583b8

Let's free the chunk p4.
In this case this isn't coealesced with top chunk since we have p5 bordering top chunk after p4

Let's trigger the vulnerability on chunk p1 that overwrites the size of the in use chunk p2
with the size of chunk_p2 + size of chunk_p3

Now during the free() operation on p2, the allocator is fooled to think that 
the nextchunk is p4 ( since p2 + size_p2 now point to p4 ) 

This operation will basically create a big free chunk that wrongly includes p3

Now let's allocate a new chunk with a size that can be satisfied by the previously freed chunk

Our malloc() has been satisfied by our crafted big free chunk, now p6 and p3 are overlapping and 
we can overwrite data in p3 by writing on chunk p6

chunk p6 from 0x555555757400 to 0x555555757bd8
chunk p3 from 0x5555557577f0 to 0x555555757bd8

Data inside chunk p3: 

CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC�

Let's write something inside p6

Data inside chunk p3: 

FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC�

```
