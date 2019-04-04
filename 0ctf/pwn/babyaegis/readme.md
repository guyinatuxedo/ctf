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

### Exploitation

So we have three bugs. A Use After Free with the delete function, a null byte write with the secret function, and an 8 byte heap overflow with the update function.
