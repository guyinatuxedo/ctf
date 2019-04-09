# This is not finished, and is still being worked on

# Baby Aegis

When we take a look at the binary, we see this:

```
$	pwn checksec aegis 
[*] '/Hackery/0ctf/babyaegis/aegis/aegis'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    FORTIFY:  Enabled
    ASAN:     Enabled
    UBSAN:    Enabled
$	file aegis 
aegis: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/l, for GNU/Linux 3.2.0, not stripped
```

It is a 64 bit binary, with all of the standard binary mitigations. In addition to that it has Address Sanitization (ASAN) and Undefined Behavior Sanitization (UBSAN). 

### Reversing

Due to the address sanitization, a lot of code is inserted into the binary. So the assembly will look a bit weird.

##### Add Note

```
  ((void (__fastcall *)(const char *))printf)("Size: ");
  size = read_int();
  if ( size < 16 || size > 1024 )
    error();
  ptr = malloc((__asan *)size);
  if ( !ptr )
    error();
```

```
  ((void (__fastcall *)(const char *))printf)("Content: ");
  bytesRead = read_until_nl_or_max(ptr, size - 8);
  ((void (__fastcall *)(const char *))printf)("ID: ");
  LODWORD(id) = read_ul();
  end = bytesRead + ptr;
  if ( *(_BYTE *)((end >> 3) + 0x7FFF8000) )
    id = _asan_report_store8(end);
  *(_QWORD *)end = id;
```

So we can see here is the code which allows us to add a note. We can sepcify a size between `0x10` to `0x400`, which is then malloced. We can then scan up to the size we specified minus eight bytes into that region of memory as the content. We then append an integer to the end of our input for the content.

In addition to that, a pointer to the allocated data is stored in the next open spot in the `notes` array, which resides in the BSS at the address offset `0xfb0cc0`. Also we can only make 10 notes.

##### Remove Note

```
  ((void (__fastcall *)(const char *))printf)("Index: ");
  index = read_int();
  if ( index < 0 || index >= 10 )
    goto LABEL_16;
```

and later on:

```
  ptr = (unsigned __int64)&notes + 8 * index;
  if ( *(_BYTE *)((ptr >> 3) + 0x7FFF8000) )
    _asan_report_load8(ptr, a1);
  free(*(__sanitizer **)ptr);
  puts("Delete success!");
```

So it frees the pointer, however it doesn't clear out the pointer so we can still use it. So we have a Use After Free bug here.

##### Show Note

```
  ((void (__fastcall *)(const char *))printf)("Index: ");
  index = read_int();
  if ( index < 0 || index >= 10 )
   ptrCheck = (unsigned __int64)&notes + 8 * index;
  if ( *(_BYTE *)((ptrCheck >> 3) + 0x7FFF8000) )
    _asan_report_load8(ptrCheck, a1);
  if ( !*(_QWORD *)ptrCheck )
LABEL_20:
    error();
```

and later on:

```
  LODWORD(content_size) = ((int (__fastcall *)(__int64))strlen)(*(_QWORD *)v9);
  id = content_size + content_Ptr + 1;
  if ( *(_BYTE *)((id >> 3) + 0x7FFF8000) )
    _asan_report_load8(id, a1);
  ((void (__fastcall *)(const char *, __int64, _QWORD))printf)("Content: %s\nID: %lu\n", content, *(_QWORD *)id);
```

So for the show note function, we can see that it prompts us for an index of the `notes` function. Then it checks to make sure that there is indeed a non zero value there. Then It will try to print out the contents, and the ID of the note we specified.

##### Update Note

```
  ((void (__fastcall *)(const char *))printf)("Index: ");
  index = read_int();
  if ( index < 0 || index >= 10 )
    goto LABEL_29;
  ptrCheck = (unsigned __int64)&notes + 8 * index;
  if ( *(_BYTE *)((ptrCheck >> 3) + 0x7FFF8000) )
    _asan_report_load8(ptrCheck, a1);
  if ( !*(_QWORD *)ptrCheck )
LABEL_29:
    error();
```

followed by:

```
  LODWORD(sizeContent) = ((int (__fastcall *)(_QWORD))strlen)(*(_QWORD *)notePtr2);
  v6 = sizeContent + 1;
  bytesRead = read_until_nl_or_max(notePtr, sizeContent + 1);
```

followed by:

```
  ((void (__fastcall *)(const char *, signed __int64))printf)("New ID: ", v6);
  LODWORD(newId) = read_ul();
  if ( *(_BYTE *)((notePtr2 >> 3) + 0x7FFF8000) )
    newId = _asan_report_load8(notePtr2, a1);
  idPtr = bytesRead + *(_QWORD *)notePtr2;
  if ( *(_BYTE *)((idPtr >> 3) + 0x7FFF8000) )
    newId = _asan_report_store8(idPtr);
  *(_QWORD *)idPtr = newId;
```

So we can see that it first checks that we gave it an index with a pointer, then it will allow us to scan in a new contents and id. For the size of the contents, it just runs `strlen` on the old contents. However there is an issue with this. `strlen` will just keep on going until it reaches a null byte. Immediately after the contents there is an integer stored there that we control, so we could have it contain no null bytes. As a result we could get `strlen` to report that the size of the contents is eight bytes larger than it actually is. Then the new contents will fill up both the old contents and the ID. Then with our ID, we will be able to write 8 bytes past our old ID.

##### Secret

In addition to those, there is another menu option which is called when we input `666`:

```
__int64 secret()
{
  __int64 stackCanary; // ST08_8@1
  unsigned __int64 address; // rax@2

  stackCanary = *MK_FP(__FS__, 40LL);
  if ( secret_enable )
  {
    ((void (__fastcall *)(const char *))printf)("Lucky Number: ");
    LODWORD(address) = read_ul();
    if ( address >> 44 )
      address |= 0x700000000000uLL;
    *(_BYTE *)address = 0;
    secret_enable = 0;
  }
  else
  {
    puts("No secret!");
  }
  return *MK_FP(__FS__, 40LL);
}
```

This allows us to write a single null byte to an address we specify. However there are two restrictions. The first is that if the address is larger than `0xfffffffffff`, it gets ored by `0x700000000000`. The second is that when this function is called, `secret_enable` at the bss address `0x34b0c0` is set equal to `0`. When it is set equal to 0 we can't do the null byte write, so unless we can figure out a way to set it equal to a non-zero value we can only do the null byte write once.

### Address Sanitization

The hardest part of this challenge is dealing with the Address Sanitization (Address Sanitization is an open sourced project made by google to help find memory corruption bugs). 

How address sanitization works is when memory is allocated, there is shadow memory (in this case one shadow byte corresponds to eight actual bytes) which is set in response to the memory. If the byte is set to `0`, read and write operations will go through. If it is a non-zero value then an error will be reported and the binary will crash. For instance in the 

```
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf30│+0x0000: 0x0000000000000000	 ← $rsp
0x00007fffffffdf38│+0x0008: 0x0000602000000010  →  0x0000603000000010  →  "15935728"
0x00007fffffffdf40│+0x0010: 0x00007fffffffdf60  →  0x00007fffffffdf80  →  0x0000555555668ac0  →  <__libc_csu_init+0> push r15
0x00007fffffffdf48│+0x0018: 0x0000000055668210
0x00007fffffffdf50│+0x0020: 0x7ab122a6918ee700
0x00007fffffffdf58│+0x0028: 0x0000000000000000
0x00007fffffffdf60│+0x0030: 0x00007fffffffdf80  →  0x0000555555668ac0  →  <__libc_csu_init+0> push r15	 ← $rbp
0x00007fffffffdf68│+0x0038: 0x0000555555668a74  →  <main+228> jmp 0x555555668aa8 <main+280>
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555668699 <update_note+169> mov    rdi, QWORD PTR [rbp-0x28]
   0x55555566869d <update_note+173> mov    rax, rdi
   0x5555556686a0 <update_note+176> shr    rax, 0x3
 → 0x5555556686a4 <update_note+180> cmp    BYTE PTR [rax+0x7fff8000], 0x0
   0x5555556686ab <update_note+187> je     0x5555556686b2 <update_note+194>
   0x5555556686ad <update_note+189> call   0x555555638c40 <__asan_report_load8>
   0x5555556686b2 <update_note+194> mov    rbx, QWORD PTR [rdi]
   0x5555556686b5 <update_note+197> mov    rdi, QWORD PTR [rbp-0x28]
   0x5555556686b9 <update_note+201> mov    rax, rdi
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "aegis", stopped, reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555556686a4 → update_note()
[#1] 0x555555668a74 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  x/g $rax+0x7fff8000
0xc047fff8002:	0xfafafafafafa0000
```

Here we can see that the byte it is checking is `0x00`. When the memory is freed, that memory is set to a non zero value. Then when it goes to check the memory again prior to a read / write operation, it will see that it is not a non zero value. 

```
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf30│+0x0000: 0x0000000000000000	 ← $rsp
0x00007fffffffdf38│+0x0008: 0x0000602000000010  →  0x0000603061000001  →  0x0000000000000000
0x00007fffffffdf40│+0x0010: 0x00007fffffffdf60  →  0x00007fffffffdf80  →  0x0000555555668ac0  →  <__libc_csu_init+0> push r15
0x00007fffffffdf48│+0x0018: 0x0000000055668210
0x00007fffffffdf50│+0x0020: 0x7ab122a6918ee700
0x00007fffffffdf58│+0x0028: 0x0000000000000000
0x00007fffffffdf60│+0x0030: 0x00007fffffffdf80  →  0x0000555555668ac0  →  <__libc_csu_init+0> push r15	 ← $rbp
0x00007fffffffdf68│+0x0038: 0x0000555555668a74  →  <main+228> jmp 0x555555668aa8 <main+280>
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555668699 <update_note+169> mov    rdi, QWORD PTR [rbp-0x28]
   0x55555566869d <update_note+173> mov    rax, rdi
   0x5555556686a0 <update_note+176> shr    rax, 0x3
 → 0x5555556686a4 <update_note+180> cmp    BYTE PTR [rax+0x7fff8000], 0x0
   0x5555556686ab <update_note+187> je     0x5555556686b2 <update_note+194>
   0x5555556686ad <update_note+189> call   0x555555638c40 <__asan_report_load8>
   0x5555556686b2 <update_note+194> mov    rbx, QWORD PTR [rdi]
   0x5555556686b5 <update_note+197> mov    rdi, QWORD PTR [rbp-0x28]
   0x5555556686b9 <update_note+201> mov    rax, rdi
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "aegis", stopped, reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555556686a4 → update_note()
[#1] 0x555555668a74 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────

Breakpoint 2, 0x00005555556686a4 in update_note ()
gef➤  x/x $rax+0x7fff8000
0xc047fff8002:	0xfafafafafafafdfd
```

Here we can see that the byte is being checked has been set to `0xfd`. It will fail the check here and the program will stop running.

We can see that in the assembly code, that it maps the shadow memory to normal memory by taking the normal address and running it through the equation `((address >> 3) + 0x7fff8000) = shadow_address`.

### Exploitation

So we have three bugs. A Use After Free with the delete function, a null byte write with the secret function, and an heap overflow with the update function.

However to use the Use After Free, we will have to deal with an aspect of Address Sanitization first. The thing is with ASAN, it will try to not reuse freed memory until a certain amount has already been freed. The reason for this is it is designed to find memory corruption bugs instead of being efficient(like Use After Frees), so it will do this to hopefully find more bugs. So we will have to free a certain amount of memory before we can use the use after free. We can find out how much memory we need to free to cause freed memory to be reallocated like this:

```
$	export ASAN_OPTIONS=verbosity=1
$	./aegis 
==20689==AddressSanitizer: libc interceptors initialized
|| `[0x10007fff8000, 0x7fffffffffff]` || HighMem    ||
|| `[0x02008fff7000, 0x10007fff7fff]` || HighShadow ||
|| `[0x00008fff7000, 0x02008fff6fff]` || ShadowGap  ||
|| `[0x00007fff8000, 0x00008fff6fff]` || LowShadow  ||
|| `[0x000000000000, 0x00007fff7fff]` || LowMem     ||
MemToShadow(shadow): 0x00008fff7000 0x000091ff6dff 0x004091ff6e00 0x02008fff6fff
redzone=16
max_redzone=2048
quarantine_size_mb=256M
thread_local_quarantine_size_kb=1024K
malloc_context_size=30
SHADOW_SCALE: 3
SHADOW_GRANULARITY: 8
SHADOW_OFFSET: 0x7fff8000
==20689==Installed the sigaction for signal 11
==20689==Installed the sigaction for signal 7
==20689==Installed the sigaction for signal 8
==20689==T0: stack [0x7ffd2f036000,0x7ffd2f836000) size 0x800000; local=0x7ffd2f833b58
==20689==AddressSanitizer Init done
  ___   ____ _____ _____ _______ ____ _____ _____   ____   ___  _  ___  
 / _ \ / ___|_   _|  ___/ /_   _/ ___|_   _|  ___| |___ \ / _ \/ |/ _ \ 
| | | | |     | | | |_ / /  | || |     | | | |_      __) | | | | | (_) |
| |_| | |___  | | |  _/ /   | || |___  | | |  _|    / __/| |_| | |\__, |
 \___/ \____| |_| |_|/_/    |_| \____| |_| |_|     |_____|\___/|_|  /_/
```

We can see that we need to free `256` megabytes (the value of `quarantine_size_mb`). Now since we can't allocate that much memory in the code, we will need to jump through some hoops to do this. What we can do is overwrite the size of a chunk in it's header to be something like `0xffffffff`. Then when it frees the chunk with the overflowed memory, then it will have surpassed the `quarantine_size_mb` limit and we will be able to allocate freed chunks.

#### Header Overflow

Now for figuring out how to overwrite the header. First let's take a look at a chunk (keep in mind that with address sanitization it uses a custom malloc, so it's a bit different). This chunk is what we get when we allocate a `0x10` byte chunk with the contents `000000000` and id `0xffffffffffffffff`:

```
gef➤  x/40g 0x0000602000000000
0x602000000000:	0x2ffffff00000002	0x1e80000120000010
0x602000000010:	0x30303030303030	0xffffffffffffffff
0x602000000020:	0x2ffffff00000002	0x7180000120000010
0x602000000030:	0x602000000010	0x563d6b2a4ab0
```

So we can see here that this chunk is really two seperate chunks. The data section of the first chunk (`0x602000000010`-`0x602000000020`) contains the eight bytes of the contents and the eight byte ID. The data section fo the second chunk (`0x602000000030`-`0x602000000040`) contains an eight byte pointer to the first data section, and an eight byte instruction pointer which is executed when asan detects a bug.

There are two headers between `0x602000000000`-`0x602000000010` and `0x602000000020`-`0x602000000030`. The headers in this time contain the same data values. For the particular values in the heap header, the only one we need to really worry about what it represents is the size value. Through trial and error we see that the lower bytes of the second eight byte segment represents the size. In addition to that we see that if we allocate a chunk of the same size as the second one (`0x10`) the two chunks line up for our overflow. Also to not disturb the chunk header values there too much, we will just overwrite most of the header values with their initial values (except for the size which we will overwrite with `0xffffffff`).

However before we do the overflow, we will need to use the secret function to mark the area of memory we're writing to to be writeable for ASAN. Now we can only mark eight bytes as writeable with our one null byte write. The value we need to write to is at `0x602000000028`, however we need to write to `0x602000000020` as part of the overflow. However what we can do is do a partial overflow into the eight byte segment at `0x602000000020`. Then we do a second overflow where the size gets written before `0x602000000028`, however it will still overflow the size value at `0x602000000028`. This way we can do the overwrite with just marking the `0x602000000020` address as writeable. 

Since with ASAN doesn't have aslr in the heap, we can know heap addresses before the binary ever runs. Looking at how ASAN maps shadow memory to normal memory, the address we will pass the secret function will be ((0x602000000020 >> 3) + 0x7fff8000).

Now let's go over the overflow. First we will create the chunk of size `0x10`:

```
gef➤  x/40g 0x0000602000000000
0x602000000000:	0x02ffffff00000002	0x2080000220000010
0x602000000010:	0xff30303030303030	0xbeffffffffffffff
0x602000000020:	0x02ffffff00000002	0x7180000120000010
0x602000000030:	0x0000602000000010	0x0000563016b9fab0
```

Then we will overflow the second chunk. We will insert a null byte at `0x602000000024`, that way with our next overflow the ID will be able to overwrite the size value to what we want (although with this ID, we were able to overwrite the size with a `0x15`):
```
gef➤  x/40g 0x0000602000000000
0x602000000000:	0x02ffffff00000002	0x2080000220000010
0x602000000010:	0x0202020202020202	0x0202020202020202
0x602000000020:	0x02ffff0002020202	0x7180000120000015
0x602000000030:	0x0000602000000010	0x0000563016b9fab0
```

Now that everything is set up, we can overflow the size to be `0xffffffff`:

```
gef➤  x/40g 0x0000602000000000
0x602000000000:	0x02ffffff00000002	0x2080000220000010
0x602000000010:	0x0202020202020202	0x0202020202020202
0x602000000020:	0x02ffffff02020202	0x71800001ffffffff
0x602000000030:	0x0000602000000010	0x0000563016b9fab0
```

After that, we can just free that chunk and we will be able reallocate previously used chunks.

### Infoleak

Now that we can 
