# Shellphish how2heap Unsorted Bin into Stack

This is another writeup from the ctf team Shellphish's educational heap exploitation series how2heap. 

This will only work if the `tcache-option` for libc is disabled. This time we will be covering how to use an overwrite for a freed unsorted bin to allocate a chunk in the stack.
 
## Exploitation

First we will allocate the victim chunk:
```
0:	0x100
```

Next we will allocate another chunk, so we will avoid consolidation:
```
0:	0x100
1:	0x100
```

Proceeding that we will free chunk `0`, and it will inserted into the unsorted bin:
```
0:	0x100 (free)
1:	0x100
```

Next we will create a false chunk on the stack, which we will be allocating with malloc. For this, we will need to write two integers to the stack. This first will be the size of our fake chunk, which needs to be `0x110` for the `0x100` bytes that we had allocated plus `0x10` for the heap metadata. The second value we need to write is the `bk` pointer (stores the previously allocated free chunk), with the value of our fake chunk on the stack (so it will point to the stack address of `0x0`). The following values below correspond with the locations, and for the two unused spots `0x0` and `0x10`, they should hold the `previous_size` and `fd` pointer values  :
```
0x0:
0x8:	0x110 
0x10:	
0x18:	A stack pointer to the fake chunk, which is at 0x0
```

Proceeding that, we will no execute the vulnerabillity where we can overwrite the values for the new freed chunk `0`'s `size` and `bk` pointer. The size value we are overwriting it with needs to be able to pass the check `2 * size > 16` (for x64 bit systems) and that it is less then the total available system memory. The `bk` pointer needs to be pointing to the stack chunk :

```
-0x8:	size 0x20
0x0		chunk 0 data section
0x8		bk pointer pointing to stack chunk
```

After we do that, we can allocate another chunk, which it will give us a ptr to the false chunk on the stack:

```
0:	(freed)
1:	0x100
2:	0x100	pointing to the stack, to the fake chunk we created on the stack
```

Just like that, we got malloc to return a pointer to the stack. This is beneficial, since depending on how we can edit the pointer, it will allow us to directly edit data on the stack (probably in ways that we shouldn't be able to). It might even let us overwrite the return address without overwritting the stack canary.
