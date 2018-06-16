# Shellphish how2heap unsorted bin attack

This is another writeup of a section from the CTF team Shellphish's educational heap exploitation series how2heap.

In order for this attack to work, you will need to compile the code with the `tcache-option` option disabled. This time we will be covering using an unsorted bin attack to write a value to the stack.

## Exploitation Process

So first on the stack, we have an unsigned long variable. It's value is just `0x0`:
```
stack_var:	0x0
```

Our goal is to overwrite that variable. The first step will be by allocating two chunks, the first of which needs to be large enough to be an unsorted bin, the second is there to avoid consolidation with the top chunk when we free the fist chunk:
```
0:	0x190
1:	0x1f4
```

Now we will free chunk `0`:
```
0:	0x190 (freed)
1:	0x1f4
```

Now here is where the vulnerabillity comes in. We will overwrite the `bk` address (points to the last free unsorted bin) with the address of `stack_var` minus `0x16` (`0x8` for 32 bit systems). This can be done with a heap overflow. 

```
0:	0x190 (freed) back pointer overflowed to the address of stack_var minus 0x16
1:	0x1f4
```

Proceeding that, we can just call `malloc` to allocate a size of `0x190` to get the unsorted bin allocated to us again. Durring this process, the write will happen to the `stack_var`:
