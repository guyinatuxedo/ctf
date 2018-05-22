# babyc

This writeup is based off of: http://blog.terrynini.tw/en/2018-ASIS-Quals-reverse/

Let's take a look at the file we got:
```
$	file babyc 
babyc: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, stripped
$	./babyc 
15935728
Wrong!

```

So we can see that we have a 32 bit binary that prompts for input, evaluates it, then tells us if our input was correct or not. However when we look at it in ida or binja, we can see that is has been obfuscated using movuscator (this is a compiler that only uses the `mov` instruction: https://github.com/xoreaxeaxeax/movfuscator).  At first I tried to figure out the correct input using a side channel attack with perf, however that didn't work. Proceeding that I used this tool specifically designed for dealing with movuscated code, demovuscator: https://github.com/kirschju/demovfuscator

With it we can create a binary from the movuscated binary that is slightly cleaned up, and generate a `.dot` file which contains the code flow chart of the code:

```
$	./demov -g char.dot -o demov_babyc babyc
```

Then we can use `dot` to convert `chart.dot` to a pdf:
```
$	dot -Tpdf char.dot -o char.pdf
```

Then we can just view `char.pdf` to see the code flow execiton. We see that it starts at `0x804899e` and ends at `0x804b97c`. We can see that there is a string of conditionals, that if any of them fail it would lead to `0x804b5d0`. The conditionals that we see that we will need to RE are at the following addresses:

```
0x8049853:
0x8049b26:
0x8049e50:
0x804a17a:
0x804a6fc:
```

We take a look at the assembly code for the first check `0x8049853` (following assembly code is fromd demovuscated binary):
```
.text:08049847                 mov     eax, dword_81F5FE0
.text:0804984C                 test    eax, eax
.text:0804984E                 nop
.text:0804984F                 nop
.text:08049850                 nop
.text:08049851                 nop
.text:08049852                 nop
.text:08049853                 jnz     loc_804B5D0
```

Here we can see that the decision is made to jump is at `0x8049853`. However the evaluation which really determines if the jump is made is at `0x8049847`. Let's take a look there to see what is in the memory:

```
gdb-peda$ b *0x8049847
Breakpoint 1 at 0x8049847
gdb-peda$ r
Starting program: /Tools/demovuscator/demovfuscator/demov_babyc 
15935728

[----------------------------------registers-----------------------------------]
EAX: 0x85f61a8 --> 0x0 
EBX: 0xf7ffd000 --> 0x23f3c 
ECX: 0x1 
EDX: 0x0 
ESI: 0xffffd18c --> 0xffffd366 ("CLUTTER_IM_MODULE=xim")
EDI: 0x804829c (mov    DWORD PTR ds:0x83f6140,esp)
EBP: 0x0 
ESP: 0x85f6124 --> 0x85f6133 ("35728\n")
EIP: 0x8049847 (mov    eax,ds:0x81f5fe0)
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x804983b:	mov    DWORD PTR [eax+0x8],edx
   0x804983e:	mov    edx,DWORD PTR ds:0x804d07c
   0x8049844:	mov    DWORD PTR [eax+0xc],edx
=> 0x8049847:	mov    eax,ds:0x81f5fe0
   0x804984c:	test   eax,eax
   0x804984e:	nop
   0x804984f:	nop
   0x8049850:	nop
[------------------------------------stack-------------------------------------]
0000| 0x85f6124 --> 0x85f6133 ("35728\n")
0004| 0x85f6128 --> 0x804d036 ("m0vfu3c4t0r!")
0008| 0x85f612c --> 0xc ('\x0c')
0012| 0x85f6130 ("15935728\n")
0016| 0x85f6134 ("5728\n")
0020| 0x85f6138 --> 0xa ('\n')
0024| 0x85f613c --> 0x0 
0028| 0x85f6140 --> 0x0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 1, 0x08049847 in ?? ()
gdb-peda$
```

There we can see that the string `m0vfu3c4t0r!` is on the stack, right next to our input. In addition to that we can see that it starts comparing our input at the fourth character of our input `3`, so there are probably three characters before the string `m0vfu3c4t0r!`. Proceeding that we move to the next evaluation at `0x8049b26` (the assembly code is similar to that of this check). We can get to the next check by jumping to `0x8049859` (`j *0x8049859`) once we reach the `nop` instructions 

When we look at this evaluation at `0x8049b1a`, we don't see the string it is comparing it against like we did for the first check. However a couple of times before the check we can see the string `A` appear (such as at `0x8049ab8` in the EDX register). In addition to that durring the check we can see something interesting:

```
0x08049b1a in ?? ()
gdb-peda$ x/6w 0x81f5fe0
0x81f5fe0:	0x00000001	0x00000000	0x00000000	0x00000000
0x81f5ff0:	0x00000031	0x00000041
``` 

We can see there that the first character of our input `1` is stored at `0x81f5ff0`, and that the word proceeding that the character `A` is stored there. When we run this again with a different first character, we can see that the `1` changes to the new first character yet the `A` remains. So with this, it is probably checking to see if the first character us `A`. The process for reversing the proceeding checks is pretty similar. Here is a breif look at the reversing process for the next checks (keep in mind out input is `15935728`).

```
Breakpoint 3, 0x08049e44 in ?? ()
gdb-peda$ x/x 0x81f5fe0
0x81f5fe0:	0x00000001
gdb-peda$ x/6x 0x81f5fe0
0x81f5fe0:	0x00000001	0x00000000	0x00000000	0x00000000
0x81f5ff0:	0x00000035	0x00000068
```
Here we can see that it is comparing the second character of our input `5` with the character `h`.

```
Breakpoint 4, 0x0804a16e in ?? ()
gdb-peda$ x/x 0x81f5fe0
0x81f5fe0:	0x00000001
gdb-peda$ x/6x 0x81f5fe0
0x81f5fe0:	0x00000001	0x00000000	0x00000000	0x00000000
0x81f5ff0:	0x00000039	0x0000005f
```

Here we can see that it is comparing the third character of our input `9` with the character `_`. With that we have the following checks figure out:

```
0x8049853:	"m0vfu3c4t0r!" starting at character 4
0x8049b26:	"A" first character
0x8049e50:	"h" second character
0x804a17a:	"_" third character
```

Keep in mind, even though we don't have the full string in order to pass the check, the challenge only asks for the sha1 hash of the first 14 characters, which we have. So the flag is ASIS{sha1(Ah_m0vfu3c4t0r)} = ASIS{574a1ebc69c34903a4631820f292d11fcd41b906}. Just like that we got the flag.

