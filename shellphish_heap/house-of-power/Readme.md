# Shellphish how2heap House of Force

This is another section from Shellphish's educational heap series how2heap. All of the information in here can be found in the section, however this is just a writeup I made for that section.

For a ctf challenge that uses this attack check out: https://github.com/guyinatuxedo/ctf/tree/master/bkp16/pwn/cookbook

This time, we will be covering a House of Force attack (I've also heard it called a House of Power). Essentially what it is, is overwriting the integer which stores the amount of bytes left in the heap wilderness with a larger value, so we can allocate space outside of the heap. With that we can use pointers returned by `calloc` and `malloc` to edit memory outside of the heap.

## Exploitation

First we will allocate a single chunk:

```
0:	0x100
```

Now the heap has 0x100 less bytes from the wilderness. The heap receives memory from the operating system by calling mmap. After it allocates space, the space that is not used is stored in the wilderness. When space is allocated on the heap through the use of `malloc` or `calloc`, space is taken from the wilderness to supply the memory. When you try to allocate more space than what is remaining in the heap, then the program will request more memory from the operating system.

Now how the program keeps track of how much space is left in the heap is with an integer known as the Wilderness Value. This value is kept at the front of the wilderness, and essentially is equal to the amount of bytes left in the wilderness. When a new chunk is allocated (assuming that the program doesn't request more memory for the heap), the wilderness chunk will have the amount of space allocated subtracted from it, to reflect the new size of the wilderness.

We can see the wilderness value here at `0x555555757118` (after Chunk `0` has been allocated, since prior to that the program hasn't requested any space from the Operating System for the heap) which is after the end of chunk `0`. It curently holds the value `0x20ef1`:
```
gdb-peda$ x/g 0x555555757118
0x555555757118:	0x0000000000020ef1
```


 Now how this attack works is by overwriting the Wilderness Value (this can be done with a heap overflow) with a value larger than what was there originally (preferably `0xffffffffffffffff` so we can allocate as much space as we want). That way we can go ahead and allocate space with `malloc` or `calloc`, and due to the fact that it thinks the heap has more space than it actually does (due to a higher wilderness value) it will actually allocate space outside of the heap, into other sections of memory. With that, you can edit other sections of memory such as the `got` table or `libc` with memory allocated from `malloc` or `calloc`. After we do the overwrite, we can see that the value for the Wilderness Value is `0xffffffffffffffff`:

```
gdb-peda$ x/g 0x555555757118
0x555555757118:	0xffffffffffffffff
```

Now that we have overwritten the wilderness value with `0xffffffffffffffff`, we can overflow the heap into other sections of memory that are within that many bytes, and have a lower address. With that we can overwrite the global variable we were trying to overwrite at `0x555555756020`. However we will want to allocate the space to write there in two chunks. The first chunk will bring the heap right up before the address `0x555555756020`. Then when we allocate another chunk, the data section (section of the chunk after the header/metadata) will be at `0x555555756020`. To figure out the amount of space we need to allocate in order to do that, we can just follow the formula that Shellphish put in this section:

First the start of the new Wilderness (also known as the Top Chunk, which contains Wilderness metadat) is equal to the previous Wilderness Start plus the amount of bytes that have been allocated. 

```
new_wilderness_start = old_wilderness_start + amount_of_bytes_allocated
```

Doing some simple math to flip it around:

```
amount_of_bytes_allocated = new_wilderness_start - old_wilderness_start
```

Now the amount of bytes that are allocated is equal to the amount of bytes requested plus an additional `0x10` bytes for heap metadata for that chunk:

```
amount_of_bytes_allocated = amount_of_bytes_requested + 0x10
```

In addition to that, the new Wilderness start has to be equal to our destination (`0x555555756020`) minus `0x10` bytes for heap metadata, that way when we allocate another chunk, the data section of that chunk (area of the chunk after the header/metadata where we can start writing data to) will be at our destination:
```
new_wilderness_start = destination - 0x10
```

substituing in the two top values into our equation:
```
amount_of_bytes_requested + 0x10 = destination - 0x10 - old_wilderness_start
```

and when we subtract `0x10` from both sides:
```
amount_of_bytes_requested = destination - 0x20 - old_wilderness_start
```

Thus to figure out the amount of bytes we need to allocate, we can use the above formula. However there is a slight complication with this. The address we are writing to is at `0x555555756020`, which is less than the value of `old_wilderness_start` `0x555555757110` (wilderness starts `0x8` bytes before the Wilderness Value).  As a result, we will have to do an integer overflow. Essentially how the math works out is we take the difference between the `old_wilderness_start` and our destination, add `0x20` to it, then subtract `0x1` from it (`0x555555757110 - 0x555555756020 + 0x20 - 0x1 = 0x110f`). 

Proceeding that we will take the value we got from that `0x110f` and subtract it from `0xffffffffffffffff` to get `0xffffffffffffeef0`. `0xffffffffffffeef0` is the amount of bytes that we need to allocate in order to reach the spot right before our destiantion. 

Proceeding that we can just allocate that many bytes:

```
0:	0x100
1:	0xffffffffffffeef0
```

Now we can see that the Wilderness value has been reduced to match the malloc. It is similar to the value we subtracted from `0xffffffffffffffff`, which is what we would expect it to be:

```
gdb-peda$ x/g 0x555555756018
0x555555756018:	0x00000000000010f9
```

Proceeding that, we can just allocate a new chunk, which will allow us to write directly to our destination `0x555555756020`:

```
0:	0x100
1:	0xffffffffffffeef0
2:	0x100
```

With that, we can use Chunk `2` to write over the value of the global variable stored at `0x555555756020`. Now this type of attack is helpful, because it can allow us to write anywhere in memory that we can allocate enough space to (which is determined by what we can overwrite the wilderness value with). This includes `libc`, and many other things. In addition to that, we only need to know the offset to the Wilderness Value, and then the offset to whatever in memory we are trying to overwrite. In some instances, this can be done without an infoleak.


## Code Running

Here is the code running for this section:

```
Welcome to the House of Force

The idea of House of Force is to overwrite the top chunk and let the malloc return an arbitrary value.
The top chunk is a special chunk. Is the last in memory and is the chunk that will be resized when malloc asks for more space from the os.

In the end, we will use this to overwrite a variable at 0x555555756020.
Its current value is: This is a string that we want to overwrite.

Let's allocate the first chunk, taking space from the wilderness.
The chunk of 256 bytes has been allocated at 0x555555756f90.

Now the heap is composed of two chunks: the one we allocated and the top chunk/wilderness.
Real size (aligned and all that jazz) of our allocated chunk is 280.

Now let's emulate a vulnerability that can overwrite the header of the Top Chunk

The top chunk starts at 0x555555757110

Overwriting the top chunk size with a big value so we can ensure that the malloc will never call mmap.
Old size of top chunk 0x20ef1
New size of top chunk 0xffffffffffffffff

The size of the wilderness is now gigantic. We can allocate anything without malloc() calling mmap.
Next, we will allocate a chunk that will get us right up against the desired region (with an integer
overflow) and will then be able to allocate a chunk right over the desired region.

The value we want to write to at 0x555555756020, and the top chunk is at 0x555555757110, so accounting for the header size,
we will malloc 0xffffffffffffeef0 bytes.
As expected, the new pointer is at the same place as the old top chunk: 0x555555757110

Now, the next chunk we overwrite will point at our target buffer.
malloc(100) => 0x555555756020!
Now, we can finally overwrite that value:
... old string: This is a string that we want to overwrite.
... doing strcpy overwrite with "YEAH!!!"...
... new string: YEAH!!!
```
