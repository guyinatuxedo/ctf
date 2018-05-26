# Shellphish how2heap 

This isn't a challenge, it's another section of the Shellphish how2heap github repo. Just like with the first, the elf documents itself and explains everything.

So the elf starts off by allocating three fastbins, each eight bytes large:
```
8:	0x55e3f232f010
8:	0x55e3f232f030
8:	0x55e3f232f050
```

So here are our three eight byte chunks. Let's start of by freeing the first one at `0x55e3f232f010`:
```
8:	0x55e3f232f010 (freed)
8:	0x55e3f232f030
8:	0x55e3f232f050
```

So the first chunk `0x55e3f232f010` is freed, and has been added to the free list. We can free that chunk again to add it to the list again, however we need to free a second chunk first. The reason for this being is that `0x55e3f232f010` is at the top of the free list, and if we try to free a ptr that is at the top of the free list the program will crash:
```
8:	0x55e3f232f010 (freed)
8:	0x55e3f232f030 (freed)
8:	0x55e3f232f050
```

So now `0x55e3f232f010` and `0x55e3f232f030` are bothe freed. With this we can free the ptr `0x55e3f232f010` again since it is no longer at the top of the free list:
```
8:	0x55e3f232f010 (freed twice)
8:	0x55e3f232f030 (freed)
8:	0x55e3f232f050
```

So now our free list looks starts with the pointers `0x55e3f232f010`, `0x55e3f232f030`, and `0x55e3f232f010` (in that order). With this we can allocate three additional chunks of the same size, and it will allocate `0x55e3f232f010` twice (while allocating `0x55e3f232f030` in between those two):
```
8:  0x55e3f232f010 (freed twice)
8:  0x55e3f232f030 (freed)
8:  0x55e3f232f050
8:	0x55e3f232f010 (same address as chunks 1 & 6)
8:	0x55e3f232f030 (same address as chunk 2)
8:	0x55e3f232f010 (same address as chunks 1 & 4)
```

So using the double free, we have sucessfully got malloc to return the same `ptr` twice. This is beneficial as it could allow us to manipulate the data in ways we couldn't have before, or create a fake chunk like in this challenge: https://github.com/guyinatuxedo/ctf/tree/master/RCTF/pwn/babyheap

Here is the elf actually running, which explains everything too:
```
$	./fastbin_dup 
This file demonstrates a simple double-free attack with fastbins.
Allocating 3 buffers.
1st malloc(8): 0x55e3f232f010
2nd malloc(8): 0x55e3f232f030
3rd malloc(8): 0x55e3f232f050
Freeing the first one...
If we free 0x55e3f232f010 again, things will crash because 0x55e3f232f010 is at the top of the free list.
So, instead, we'll free 0x55e3f232f030.
Now, we can free 0x55e3f232f010 again, since it's not the head of the free list.
Now the free list has [ 0x55e3f232f010, 0x55e3f232f030, 0x55e3f232f010 ]. If we malloc 3 times, we'll get 0x55e3f232f010 twice!
1st malloc(8): 0x55e3f232f010
2nd malloc(8): 0x55e3f232f030
3rd malloc(8): 0x55e3f232f010
```
