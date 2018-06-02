# Shellphish how2heap fastbin_dup_consolidate
This is another section from the CTF team Shellphish's well documented section on heap exploitation. This section covers fastbin duplication without having to free a third chunk while doing the double free.

For a look at a ctf challenge that uses this, check out: https://github.com/guyinatuxedo/ctf/tree/master/Hitcon16/pwn/sleepyholder

First we allocate two seperate fast bins:
```
0x40:	Chunk 0
0x40:	Chunk 1
```

Proceeding that we will free Chunk `0`:

```
0x40:	Chunk 0 (freed)
0x40:	Chunk 1
```

Now that Chunk 0 is freed, it is at the top of the free list. If we were to go ahead and free it again, it would cause a crash since it is at the top of the fast bin free. However what we can do about that is allocate a large bin which would trigger a malloc consolidation:

```
0x40:	Chunk 0 (freed)
0x40:	Chunk 1
0x400:	Chunk 2
```  

Now that we have allocated a large bin, we have triggered a call to `malloc_consolidate()`. When we called that, chunk `0` was moved from the fast bin freelist to the unsorted bin free list. As a result, we can free Chunk `0` and pass the check in `malloc`, and not cause a crash:

```
0x40:	Chunk 0 (freed twice)
0x40:	Chunk 1
0x400:	Chunk 2
``` 

Now the address of Chunk `0` at the top of the fast bin and unsorted bin free lists. So if we malloc two more chunks of size `0x40`, we will get two chunks with the same address as chunk `0` (which they will just be duplicates of chunk `0`):

```
0x40:	Chunk 0 (freed twice)
0x40:	Chunk 1
0x400:	Chunk 2
0x40:	Chunk 3 (Same chunk as chunk `0`)
0x40:	Chunk 4 (Same chunk as Chunk `0`)
```

Now we have successfully allocated the same chunk of memory twice. Below you will find the section itself running:

```
Allocated two fastbins: p1=0x55b887ea2010 p2=0x55b887ea2060
Now free p1!
Allocated large bin to trigger malloc_consolidate(): p3=0x55b887ea20b0
In malloc_consolidate(), p1 is moved to the unsorted bin.
Trigger the double free vulnerability!
We can pass the check in malloc() since p1 is not fast top.
Now p1 is in unsorted bin and fast bin. So we'will get it twice: 0x55b887ea2010 0x55b887ea2010
```
