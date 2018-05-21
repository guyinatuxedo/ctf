# sign

This was a misc challenge (might as well been re) from RCTF 2018. This one I seriously overthought. We are given a file, let's see what it is:

```
$	file sign 
sign: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, BuildID[sha1]=94302ea5814315714a6d91c85d25a5b0eaa43d4d, stripped
$	./sign 
Segmentation fault (core dumped)
```

So we are given a 64 bit elf that crashes when we run it. When we look at in IDA, we see that it has several issues with the binary. However we see that there is a `WinMain` function. Let's try jumping to it in gdb:

```
gdb-peda$ b *main
Breakpoint 1 at 0x11cf0
gdb-peda$ r
Starting program: /Hackery/RCTF/sign/sign 

[----------------------------------registers-----------------------------------]
RAX: 0x0 
RBX: 0x0 
RCX: 0x0 
RDX: 0x0 
RSI: 0x0 
RDI: 0x0 
RBP: 0x0 
RSP: 0x7fffffffe050 --> 0x1 
RIP: 0x555555565cf0 (<main>:	push   rbp)
R8 : 0x0 
R9 : 0x0 
R10: 0x0 
R11: 0x0 
R12: 0x0 
R13: 0x0 
R14: 0x0 
R15: 0x0
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x555555565ce0 <__stack_chk_fail@plt>:	
    jmp    QWORD PTR [rip+0xa33a]        # 0x555555570020
   0x555555565ce6 <__stack_chk_fail@plt+6>:	push   0x1
   0x555555565ceb <__stack_chk_fail@plt+11>:	jmp    0x555555565cc0
=> 0x555555565cf0 <main>:	push   rbp
   0x555555565cf1 <main+1>:	push   rbx
   0x555555565cf2 <main+2>:	sub    rsp,0x98
   0x555555565cf9 <main+9>:	mov    rax,QWORD PTR fs:0x28
   0x555555565d02 <main+18>:	mov    QWORD PTR [rsp+0x88],rax
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe050 --> 0x1 
0008| 0x7fffffffe058 --> 0x7fffffffe38a ("/Hackery/RCTF/sign/sign")
0016| 0x7fffffffe060 --> 0x0 
0024| 0x7fffffffe068 --> 0x7fffffffe3a2 ("CLUTTER_IM_MODULE=xim")
0032| 0x7fffffffe070 --> 0x7fffffffe3b8 ("LS_COLORS=rs=0:di=01;34:ln=01;36:mh=00:pi=40;33:so=01;35:do=01;35:bd=40;33;01:cd=40;33;01:or=40;31;01:mi=00:su=37;41:sg=30;43:ca=30;41:tw=30;42:ow=34;42:st=37;44:ex=01;32:*.tar=01;31:*.tgz=01;31:*.arc"...)
0040| 0x7fffffffe078 --> 0x7fffffffe974 ("LESSCLOSE=/usr/bin/lesspipe %s %s")
0048| 0x7fffffffe080 --> 0x7fffffffe996 ("_=/usr/bin/gdb")
0056| 0x7fffffffe088 --> 0x7fffffffe9a5 ("LANG=en_US.UTF-8")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 1, 0x0000555555565cf0 in main ()
gdb-peda$ j *WinMain
Continuing at 0x55555556ce46.

Program received signal SIGSEGV, Segmentation fault.

[----------------------------------registers-----------------------------------]
RAX: 0x0 
RBX: 0x0 
RCX: 0x0 
RDX: 0x0 
RSI: 0x0 
RDI: 0x0 
RBP: 0x7fffffffe048 --> 0x0 
RSP: 0x7fffffffde08 --> 0x0 
RIP: 0x55555556ce54 (<WinMain+14>:	movaps XMMWORD PTR [rbp-0xc0],xmm6)
R8 : 0x0 
R9 : 0x0 
R10: 0x0 
R11: 0x0 
R12: 0x0 
R13: 0x0 
R14: 0x0 
R15: 0x0
EFLAGS: 0x10212 (carry parity ADJUST zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x55555556ce4b <WinMain+5>:	push   rsi
   0x55555556ce4c <WinMain+6>:	push   rbx
   0x55555556ce4d <WinMain+7>:	sub    rsp,0x228
=> 0x55555556ce54 <WinMain+14>:	movaps XMMWORD PTR [rbp-0xc0],xmm6
   0x55555556ce5b <WinMain+21>:	movaps XMMWORD PTR [rbp-0xb0],xmm7
   0x55555556ce62 <WinMain+28>:	movaps XMMWORD PTR [rbp-0xa0],xmm8
   0x55555556ce6a <WinMain+36>:	movaps XMMWORD PTR [rbp-0x90],xmm9
   0x55555556ce72 <WinMain+44>:	movaps XMMWORD PTR [rbp-0x80],xmm10
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffde08 --> 0x0 
0008| 0x7fffffffde10 --> 0x0 
0016| 0x7fffffffde18 --> 0x0 
0024| 0x7fffffffde20 --> 0x0 
0032| 0x7fffffffde28 --> 0x0 
0040| 0x7fffffffde30 --> 0x0 
0048| 0x7fffffffde38 --> 0x0 
0056| 0x7fffffffde40 --> 0x0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x000055555556ce54 in WinMain ()
gdb-peda$
```

So that didn't work. However when we decompile the function, we see something that is quite interesting:

```
    sub_12090(
      a1,
      a2,
      L"RCTF{WelCOme_To_RCTF}\n\n\u5700\u6168\u3f74\u5920\u756f\u6420\u6365\u6d6f\u6970\u656c\u2064\u656d\u3f3f",
      Globals[3]);
```

So that looks like a flag. Those hex characters after it look like ASCII, so let's use python to see what that string says:

```
>>> print "RCTF{WelCOme_To_RCTF}\n\n\x57\x68\x61\x74\x3f\x20\x59\x6f\x75\x20\x64\x65\x63\x6f\x6d\x70\x69\x6c\x65\x64\x20\x6d\x65\x3f\x3f"
RCTF{WelCOme_To_RCTF}

What? You decompiled me??
```

Yes we did decompile you. So it is clear that we have a flag. When we try it, we see that it is the correct flag. Just like that, we captured the flag.
