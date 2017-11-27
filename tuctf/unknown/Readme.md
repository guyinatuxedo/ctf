# unknown

Let's take a look at the binary:

```
$	file unknown 
unknown: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=53ec94bd1406ec6b9a28f5308a92e4d906444edb, stripped
$	./unknown 
Try again.
$	./unknown gimme_flag
Still nope.
```

So this is a 64 bit elf, that appears to take input as an argument. Let's look at the code:

```
signed __int64 __fastcall main(int argc, char **argv, char **a3)
{
  signed __int64 result; // rax@2
  unsigned int i; // [sp+14h] [bp-Ch]@5
  char *argument; // [sp+18h] [bp-8h]@5

  if ( argc == 2 )
  {
    if ( strlen(argv[1]) == 56 )
    {
      argument = argv[1];
      for ( i = 0; i < 0x38; ++i )
      {
        if ( (unsigned int)first_layer((__int64)argument, i) )
          check = 1;
      }
      if ( check )
        puts("Nope.");
      else
        printf("Congraz the flag is: %s\n", argument, argv);
      result = 0LL;
    }
    else
    {
      puts("Still nope.");
      result = 0xFFFFFFFELL;
    }
  }
  else
  {
    puts("Try again.");
    result = 0xFFFFFFFFLL;
  }
  return result;
}
```

So we can see here, it checks to see that the length of the first argument is 56 bytes. It then runs a for loop 56 (0x38) times in which it runs the function `first_layer` with the arguments being our input, and the iteration count. We see that it is ran in an if then statement, and if it is true `check` is set equal to one. We can see that if `check` is set equal to one, then we don't have the flag. So we need to make sure `first_layer` always outputs false. Let's take a look at `first_layer`:

```
__int64 __fastcall first_layer(__int64 argument, __int64 i)
{
  char *v2; // r15@1
  __int64 v3; // rdx@1
  int v4; // ebx@1
  signed __int64 v5; // rcx@1
  __int64 v6; // rax@3
  int v7; // eax@3
  char v9; // [sp+0h] [bp-8h]@1

  v2 = &v9 - 6004;
  v3 = 0LL;
  v4 = 0;
  v5 = 0LL;
  do
  {
    ++v5;
    v4 += 666;
  }
  while ( v5 < 0x2F );
  LOBYTE(v3) = *(_BYTE *)(argument + i);
  *((_QWORD *)v2 + 1) = v3;
  v6 = sub_400A1C((__int64)(v2 + 8), 1u);
  v7 = __ROL4__((v4 + 35) * (unsigned __int64)sub_401BDD((const char *)(v6 + 24), 16), 21);
  return v7 != (unsigned int)*(_QWORD *)((char *)&desired_output + 4 * i);
}
```

We can see there is a good bit going on here. However at the end of the day, that return value is all that matters. Let's set a breakpoint for that compare instruction in gdb (0x401f20) and see what the values are:

```
gdb-peda$ b *0x401f20
Breakpoint 1 at 0x401f20
gdb-peda$ r 00000000000000000000000000000000000000000000000000000000
Starting program: /Hackery/tuctf/unkown/unknown 00000000000000000000000000000000000000000000000000000000













[----------------------------------registers-----------------------------------]
RAX: 0x63e13f5f 
RBX: 0x7a69 ('iz')
RCX: 0x32449a7fdfab57a 
RDX: 0x0 
RSI: 0x0 
RDI: 0x7ffff7b85860 --> 0x2000200020002 
RBP: 0x7fffffffdf30 --> 0x401ce0 (push   r15)
RSP: 0x7fffffffdf00 --> 0x7fffffffdf30 --> 0x401ce0 (push   r15)
RIP: 0x401f20 --> 0x1b80a74c839 
R8 : 0x0 
R9 : 0x0 
R10: 0x7ffff7b84f60 --> 0x100000000 
R11: 0x7ffff7b85860 --> 0x2000200020002 
R12: 0x0 
R13: 0x7fffffffe010 --> 0x2 
R14: 0x7fffffffdf00 --> 0x7fffffffdf30 --> 0x401ce0 (push   r15)
R15: 0x7fffffffc78c --> 0x0
EFLAGS: 0x203 (CARRY parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x401f0f:	rol    eax,0x15
   0x401f12:	movabs rcx,0x401dac
   0x401f1c:	mov    rcx,QWORD PTR [rcx+rsi*4]
=> 0x401f20:	cmp    eax,ecx
   0x401f22:	je     0x401f2e
   0x401f24:	mov    eax,0x1
   0x401f29:	mov    rsp,r14
   0x401f2c:	pop    rbp
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffdf00 --> 0x7fffffffdf30 --> 0x401ce0 (push   r15)
0008| 0x7fffffffdf08 --> 0x401c82 (test   eax,eax)
0016| 0x7fffffffdf10 --> 0x7fffffffe018 --> 0x7fffffffe345 ("/Hackery/tuctf/unkown/unknown")
0024| 0x7fffffffdf18 --> 0x200400600 
0032| 0x7fffffffdf20 --> 0xffffe010 
0040| 0x7fffffffdf28 --> 0x7fffffffe363 ('0' <repeats 56 times>)
0048| 0x7fffffffdf30 --> 0x401ce0 (push   r15)
0056| 0x7fffffffdf38 --> 0x7ffff7a303f1 (<__libc_start_main+241>:	mov    edi,eax)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 1, 0x0000000000401f20 in ?? ()
gdb-peda$ p $eax
$1 = 0x63e13f5f
gdb-peda$ p $ecx
$2 = 0xfdfab57a
gdb-peda$ 
```
So the `eax` register hold the result of our input, and the `ecx` register holds the value that it is being compared against. We can tell this by the fact that `ecx` holds hex characters that are in `desired_output` when we check the data in it. In addition to that, when we go the next check, we see that the value in `ecx` changes while `eax` does not (all 56 bytes of our input were the same). This also tells us that the position of a specific character in our input doesn't change it's value.

Remember we need the function to output false, and the check is if the two values are not equal, so we need the two values to be equal.

So instead of going through and reversing this challenge, we can just skip that, look at  at if the values it is comparing it against, and the result of  what the output of characters we give it and use that to figure out what characters we need to in order to pass the checks.

Looking at the format of previous flags, we would probably have the eight characters `TUCTF{_}`, undercase characters and digits in the flag. It holds true with this. This is the output of all of those characters:

```
alphabet:
!:	0xba165ea7
_:	0xff20bdef
{:	0x59e2eb0d
}:	0xef1b84cd
q:	0x2c6485d5
w:	0x5ed756d7
e:	0xb623c6c1
r:	0xcd78354e
t:	0xc863df45
y:	0x12a92a61
u:	0xb59d1071
i:	0x67258d77
o:	0x408a2c4b
p:	0xf2184419
l:	0x9239bdf3
c:	0xf62c7f9b
m:	0xd6338e84
f:	0x388d9870
0:	0x63e13f5f
1:	0x3ca8bfdc
2:	0xdd0e6ec0
3:	0x5cfff023
4:	0xceecc5ba
5:	0xcc1be317
6:	0x2ff35144
7:	0xc51f928e
8:	0xb6705910
9:	0x26552da4
T:  0xfdfab57a
U:	0x032449a7
C:  0x5f383821
F:  0x25435e02
```

here is the list of the 56 checks it does:

```
checks:
0xfdfab57a	TUCFT{
0x032449a7
0x5f383821
0xfdfab57a
0x25435e02
0x59e2eb0d

0x5ed756d7 w3lc0m3_
0x5cfff023
0x9239bdf3
0xf62c7f9b
0x63e13f5f
0xd6338e84
0x5cfff023
0xff20bdef

0xc51f928e 70_
0x63e13f5f
0xff20bdef

0xc51f928e 7uc7f_
0xb59d1071
0xf62c7f9b
0xc51f928e
0x388d9870
0xff20bdef

0xceecc5ba 4nd_
0xa952136b
0x96710841
0xff20bdef

0xc51f928e 7th4nk_ check 7
0xf536dffd
0xceecc5ba
0xa952136b
0xc5d7dac4
0xff20bdef

0x12a92a61 y0u_
0x63e13f5f
0xb59d1071
0xff20bdef

0x388d9870 f0r_
0x63e13f5f
0xcd78354e
0xff20bdef

0xf2184419	p4r71c1p4y1n6!}
0xceecc5ba
0xcd78354e
0xc51f928e
0x3ca8bfdc
0xf62c7f9b
0x3ca8bfdc
0xf2184419
0xceecc5ba
0xc51f928e
0x3ca8bfdc
0xa952136b
0x2ff35144
0xba165ea7
0xef1b84cd
```

and putting all together (and skipping a lot of the reversing work):

```
$	./unknown TUCTF{w3lc0m3_70_7uc7f_4nd_7h4nk_y0u_f0r_p4r71c1p471n6\!}
Congraz the flag is: TUCTF{w3lc0m3_70_7uc7f_4nd_7h4nk_y0u_f0r_p4r71c1p471n6!}
```

We had to add a backslack in order to escape the `!`. Just like that, we captured the flag!
