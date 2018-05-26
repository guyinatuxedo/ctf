# Shellphish how2heap first_fit

This isn't a challenge, and the documentation from the section itself is great. Literally by running the elf, it explains everything. I will just be briefly explainning how the memory managment works:

First two sections of memory are allocated:
```
512:	0x556cb7d3f010
256:	0x556cb7d3f220
```

So we have two chunks of memory allocated, one 512 bytes large at `0x556cb7d3f010`, and the other 256 bytes large at `0x556cb7d3f220`. Proceeding that we write the string `this is A!` to the first chunk at `0x556cb7d3f220`:
```
512:	0x556cb7d3f010 "this is A!"
256:	0x556cb7d3f220 
```

Now that the first chunk `0x556cb7d3f010` is pointing to the string `this is A!`, we will free it to show how malloc will reuse that chunk:

```
512:	0x556cb7d3f010 "this is A!" (freed)
256:	0x556cb7d3f220 
```

Now the chunk `0x556cb7d3f010` is freed, however it still points to the string `this is A!`. Proceeding that we can allocate another chunk that is smaller than `512`, and malloc will reuse that chunk and produce another chunk that starts at `0x556cb7d3f010`:

```
512:	0x556cb7d3f010 "this is A!" (freed)
256:	0x556cb7d3f220 
500:	0x556cb7d3f010 "this is A!"
```

So we allocated another 500 bytes of data and it did end up at `0x556cb7d3f010`. Just like the first chunk, it points to the string `this is A!`. If we were to write to the third chunk, we would also be changing the value of the third chunk. Let's write the string `this is C!` to the third chunk:
```
512:	0x556cb7d3f010 "this is C!" (freed)
256:	0x556cb7d3f220 
500:	0x556cb7d3f010 "this is C!"
```

So we wrote the string `this is C!` to the third chunk, and that changed the value of the first chunk. The opposite would also be true if we wrote to the first chunk, we would be changing the value of the third chunk. This is useful in a use-after-free situation since this would allow us to edit a legitamite chunk by editing a stale pointer, vice versa, or we could potentially make a chunk with data left over from something else (which would allow us to have data in that chunk that we shouldn't have). 

Here is the actual output of the elf, which it provides a lot of great documentation regarding what is going on:

```
$	./first_fit 
This file doesn't demonstrate an attack, but shows the nature of glibc's allocator.
glibc uses a first-fit algorithm to select a free chunk.
If a chunk is free and large enough, malloc will select this chunk.
This can be exploited in a use-after-free situation.
Allocating 2 buffers. They can be large, don't have to be fastbin.
1st malloc(512): 0x556cb7d3f010
2nd malloc(256): 0x556cb7d3f220
we could continue mallocing here...
now let's put a string at a that we can read later "this is A!"
first allocation 0x556cb7d3f010 points to this is A!
Freeing the first one...
We don't need to free anything again. As long as we allocate less than 512, it will end up at 0x556cb7d3f010
So, let's allocate 500 bytes
3rd malloc(500): 0x556cb7d3f010
And put a different string here, "this is C!"
3rd allocation 0x556cb7d3f010 points to this is C!
first allocation 0x556cb7d3f010 points to this is C!
```
