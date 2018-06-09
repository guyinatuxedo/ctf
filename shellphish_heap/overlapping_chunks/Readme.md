# Shellphish how2heap overlapping chunks

This is another section from Shellphish's educational heap exploiational series. 

This section covers getting malloc to allocate a chunk that overlaps with another allocated chunk of memory, by overwriting the size value of a freed chunk:

## Exploitation

So to do this, we will first start off by allocating three chunks o memory:

```
0:	0xf8	0x5600f6e19010
1:	0xf8	0x5600f6e19110
2:	0x78	0x5600f6e19210
```

Now we will free chunk `1`, which will store it in the unsorted bin:

```
0:	0xf8	0x5600f6e19010
1:	0xf8 (freed)
2:	0x78	0x5600f6e19210
```

Now that chunk `1` has been freed, due to it's size it is an unsorted bin. If we were to allocate a chunk with a similar size, we would get chunk `1` . Now here is where the vulnerabillity comes in. We will overwrite the size value for chunk `1` with the larger value `0x181` (this can be done with a heap overflow). This is a larger value then what we originally allocated for chunk `1`, so when we allocate it, it will overlap with chunk `2`. When we overflow the size value, we have to keep in mind that the last three bits hold the sepcific values such as the last bit holding the `previous_in_use_bit` which specifies if the previous chunk is in use (which it is). So when we overflow this value, we will need to make sure the least significant bit is `0x1` (which with the value `0x181` it's binary form is `110000001` which we can see has `0x1` as the least significant bit):

```
0:	0xf8	0x5600f6e19010
1:	0xf8 (Size Value overwritten to 0x181 & freed)
2:	0x78	0x5600f6e19210
```

Now chunk `1` is still an unsorted bin. If we were to allocate a space of `0x178`, we would get a the old chunk `1` however it would be `0x180` bytes large and overlaps with chunk `2` (the reason why we prompt for `0x178` bytes and get `0x180` is because of the heap metadata that goes along with the chunk). Let's go ahead and make that allocation:
```
0:  0xf8	0x5600f6e19010
3:  0x178	0x5600f6e19110 (overlaps with chunk 2 after 0x100 bytes)
2:  0x78	0x5600f6e19210
```

Now after writing `0x100` byes to chunk `3`, we will be right at the content section of chunk `2`. You can change the value of chunk `2` by changing the value of chunk `3`, and you can change the value of chunk `3` (anything past 0x100 bytes into it) by changin the value of chunk `2` (which the program demonstrates). We can also write to the metadata for chunk `2`. All of this is helpful since it can (and probably will)  allow us to edit data in the heap in ways that we shouldn't (and we might be able to get code execution from it). 

## Program Running

Here is a copy of the program running:

```
$	./overlapping_chunks 

This is a simple chunks overlapping problem

Let's start to allocate 3 chunks on the heap
The 3 chunks have been allocated here:
p1=0x5600f6e19010
p2=0x5600f6e19110
p3=0x5600f6e19210

Now let's free the chunk p2
The chunk p2 is now in the unsorted bin ready to serve possible
new malloc() of its size
Now let's simulate an overflow that can overwrite the size of the
chunk freed p2.
For a toy program, the value of the last 3 bits is unimportant; however, it is best to maintain the stability of the heap.
To achieve this stability we will mark the least signifigant bit as 1 (prev_inuse), to assure that p1 is not mistaken for a free chunk.
We are going to set the size of chunk p2 to to 385, which gives us
a region size of 376

Now let's allocate another chunk with a size equal to the data
size of the chunk p2 injected size
This malloc will be served from the previously freed chunk that
is parked in the unsorted bin which size has been modified by us

p4 has been allocated at 0x5600f6e19110 and ends at 0x5600f6e19cd0
p3 starts at 0x5600f6e19210 and ends at 0x5600f6e19490
p4 should overlap with p3, in this case p4 includes all p3.

Now everything copied inside chunk p4 can overwrites data on
chunk p3, and data written to chunk p3 can overwrite data
stored in the p4 chunk.

Let's run through an example. Right now, we have:
p4 = X
      u
\
3 = 333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333�

If we memset(p4, '4', 376), we have:
p4 = 444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444�
3 = 444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444�

And if we then memset(p3, '3', 80), we have:
p4 = 444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444333333333333333333333333333333333333333333333333333333333333333333333333333333334444444444444444444444444444444444444444�
3 = 333333333333333333333333333333333333333333333333333333333333333333333333333333334444444444444444444444444444444444444444�
```
