# Csaw 2017 bananascript reversing 450

This writeup is based off of: https://github.com/ShellCollectingClub/csaw2017/tree/master/bananascript

So starting off we see that we are given four files, `banana.script`, `monkeyDo`, `test1.script` and `test2.script`:


```
$	file test1.script test2.script banana.script monkeyDo 
test1.script:  ASCII text
test2.script:  ASCII text
banana.script: ASCII text, with very long lines
monkeyDo:      ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=4e3e2b95c29bcb0f0da9761171d309ce92564cb2, stripped
```

So we can see that we are given three text files, and a `64` bit elf. We also see that the contents of the text files are just the string `bananas` with different permutations of capitalized letters. Also when we run the binary, we see that it appears to need one of the text files for input:

```
$	./monkeyDo banana.script 
Hello! And welcome to the Flying Monkeys' Fantastic Falling Fan Trivia Game.
 
Here, the council of monkeys will ask you questions, which will determine whether they choose to lift you away save you from your plummeting fate.
 
"WRITE DOWN YOUR AGE," speaks the elder monkey.
 
...Only now do you notice the immense amount of banananasPiled around you on this falling stone platform.. The bananananasSeem to be used for everything, from the obvious food source to building materials to tooth brushes to toys to even glasses, but you can't imagine how well one could see through a pair of K-Vision goggles.
 
One such monkey wearing these goggles hobbles up to you now, carrying a pile of limp banananananasSkins and a bananananananaPointPen. As this monkey hands you these materials, the black ends of the banananananananas(Where eyes might ought to go?) seem to peer into your soul, as though they know everything and more that there is to know about you, and they are very, very deeply conflicted about you due to a familial disagreement back in the chain... "Disgrace to our fine culture," you think you hear, but so soft that it could have just been the wind.  The monkey moves in closer and closer, so close that it could, and actually does bump into you, obviously unaware of where you are due to some odd oblong fruit obscuring its vision.
 
100
 
~How can monkeys talk? And why am I following you their commands?~
 
"WRITE DOWN YOUR SSN/CVV's/privatekeys- err I mean favorite food!," speaks the elder monkey.
100
 
"GASP!" All the monkeys are dreadfully appaled, some of them even start to cry.  "How could you?" spits one monkey, covering the eyes of their child.  The conglomerate of monkeys take off from the platform, leaving you to fall to your death.
```

Durring the reversing process, it becomes clear that the binary is an interpreter. And that the text files contain the compiled code, which compiled into various permutations of the string `banana`.

## Setup

So when I threw this in IDA, immediately I can see that this is a huge binary. The first thing I see in IDA it that the program only takes in two arguments (so the only argument we can pass to it is the file containning the code to be interpreted):

```
  if ( argc != 2 )
  {
    std::operator<<<std::char_traits<char>>(&std::cout, "usage: monkeyDo [script]\n");
    exit(1);
  }
```

immediately after that, we have this block of code:

```
  std::allocator<char>::allocator(&v711);
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::basic_string(&filename, a2[1], &v711);
  readInput((__int64)&inputVec, (__int64)&filename);
  copy((__int64)&v709, (__int64)&inputVec);
  sub_40F2E6((__int64)&inputVec);
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string(&filename);
  std::allocator<char>::~allocator(&v711);
  mappingFunc((__int64)&v711);
```

We see that there are three custom functions `readInput()`, `copy()`, `sub_40f2e6` and `mappingFunc()`. The function `readInput` we can see it takes in two arguments, the second being the name of the file we provided to it `banana.script`:

```
[-------------------------------------code-------------------------------------]
   0x4070ba:	lea    rdx,[rbp-0xca0]
   0x4070c1:	mov    rsi,rdx
   0x4070c4:	mov    rdi,rax
=> 0x4070c7:	call   0x4056de
   0x4070cc:	lea    rdx,[rbp-0xcf0]
   0x4070d3:	lea    rax,[rbp-0xd10]
   0x4070da:	mov    rsi,rdx
   0x4070dd:	mov    rdi,rax
Guessed arguments:
arg[0]: 0x7fffffffd070 --> 0x0 
arg[1]: 0x7fffffffd0c0 --> 0x7fffffffd0d0 ("banana.script")
arg[2]: 0x7fffffffd0c0 --> 0x7fffffffd0d0 ("banana.script")
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffcee0 --> 0x7fffffffde48 --> 0x7fffffffe1da ("/Hackery/csaw17/rev/bananascript/monkeyDo")
0008| 0x7fffffffcee8 --> 0x200000000 
0016| 0x7fffffffcef0 --> 0x0 
0024| 0x7fffffffcef8 --> 0x0 
0032| 0x7fffffffcf00 --> 0x0 
0040| 0x7fffffffcf08 --> 0x0 
0048| 0x7fffffffcf10 --> 0x0 
0056| 0x7fffffffcf18 --> 0x0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 1, 0x00000000004070c7 in ?? ()
```

after that, we can see that it's first argument (`0x7fffffffd070`) contains a vector, which holds the various permutations of `banana` from `banana.script`:

```
[-------------------------------------code-------------------------------------]
   0x4070c1:	mov    rsi,rdx
   0x4070c4:	mov    rdi,rax
   0x4070c7:	call   0x4056de
=> 0x4070cc:	lea    rdx,[rbp-0xcf0]
   0x4070d3:	lea    rax,[rbp-0xd10]
   0x4070da:	mov    rsi,rdx
   0x4070dd:	mov    rdi,rax
   0x4070e0:	call   0x40fa6e
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffcee0 --> 0x7fffffffde48 --> 0x7fffffffe1da ("/Hackery/csaw17/rev/bananascript/monkeyDo")
0008| 0x7fffffffcee8 --> 0x200000000 
0016| 0x7fffffffcef0 --> 0x0 
0024| 0x7fffffffcef8 --> 0x0 
0032| 0x7fffffffcf00 --> 0x0 
0040| 0x7fffffffcf08 --> 0x0 
0048| 0x7fffffffcf10 --> 0x0 
0056| 0x7fffffffcf18 --> 0x0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x00000000004070cc in ?? ()
gdb-peda$ x/x 0x7fffffffd070
0x7fffffffd070:	0x0000000000645eb0
gdb-peda$ x/x 0x645eb0
0x645eb0:	0x00000000006301c0
gdb-peda$ x/10x 0x645eb0
0x645eb0:	0x00000000006301c0	0x0000000000630800
0x645ec0:	0x0000000000630800	0x0000000000630b40
0x645ed0:	0x0000000000631500	0x0000000000631500
0x645ee0:	0x0000000000631510	0x0000000000631610
0x645ef0:	0x0000000000631610	0x000000000062ff40
gdb-peda$ x/g 0x6301c0
0x6301c0:	0x00000000006301d0
gdb-peda$ x/s 0x6301d0
0x6301d0:	"banAnas"
``` 

for the function `copy`, when we see what it does to it's arguments in gdb, we see that it just copies the vector stored in it's secord argument to it's first. The third function `sub_40f2e6`, when I look at it's arguments in gdb I see that it's argument is just `0x0`, and in IDA I see that it doesn't return anything that is stored in a variable so I didn't pay much attention to it. And in the fourth function `mappingFunc()`, it appears that it actually maps specific permutations to individual characters (here are some snippets of code):

IDA Decompiled
```
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::basic_string(&v102, "BANANaS", &v99);
  LODWORD(v3) = sub_40F176(a1, &v102);
  *v3 = 'c';
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string(&v102);
  std::allocator<char>::~allocator(&v99);
  std::allocator<char>::allocator(&v99);
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::basic_string(&v103, "BANANas", &v99);
  LODWORD(v4) = sub_40F176(a1, &v103);
  *v4 = 'd';
```
Assembly code part 1
```
mov     esi, offset aBananas_1 ; "BANANaS"
mov     rdi, rax
call    __ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEC1EPKcRKS3_ ; std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::basic_string(char const*,std::allocator<char> const&)
lea     rdx, [rbp+var_BE0]
mov     rax, [rbp+var_C38]
mov     rsi, rdx
mov     rdi, rax
call    sub_40F176
mov     byte ptr [rax], 63h
```
Assembly code part 2
```
mov     esi, offset aBananas_2 ; "BANANas"
mov     rdi, rax
call    __ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEC1EPKcRKS3_ ; std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::basic_string(char const*,std::allocator<char> const&)
lea     rdx, [rbp+var_BC0]
mov     rax, [rbp+var_C38]
mov     rsi, rdx
mov     rdi, rax
call    sub_40F176
mov     byte ptr [rax], 64h
```

## Registers

Immediately after that block of code, we see that it establishes sixteen basic strings like this:

```
  std::allocator<char>::allocator(&inputVec);
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::basic_string(
    &r0,
    &unk_415747,
    &inputVec);
```

we can see either by checking the xreferences to the variable `v714` (choose this because it starts off as `0x0`, then after the function stores a pointer), or setting a read breakpoint with `rwatch` in gdb that these values are used in a variety of places throughout the code, that appear to be with checks for certain strings of `bananas`. Since we are dealing with a compiled code with a custom interpreter, these values are probably the registers used by the code. 

## Reversing Permutations

#### Characters

So now we begin the process of reversing individual `bananas` strings. I started off in the `mappingFunc` function. As we can see, it maps individual permutations of `bananas` to characters:

```
  std::allocator<char>::allocator(&v99);
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::basic_string(&v100, "BANANAS", &v99);
  LODWORD(v1) = sub_40F176(a1, &v100);
  *v1 = 'a';
```

here we can see that it maps the permutation `BANANAS` to the character `a`. Also the reason why I think that this is true, is because most of the permutations in this function (I didn't check through all of them) only are referenced twice throughout the code. And the second time that it is referenced, it appears to be doing the same thing:

```
  v103 = 'a';
  LODWORD(v2) = sub_40F6E4(&v104, &v103);
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::operator=(v2, "BANANAS");
```

I know that in this iteration the character comes before the basic string instance is made which might lead to some confusion as to exactly which character which permutation maps to (atleast for me), however if you look at the last instance of the `bananas` permutations where the second instance of the strings appear, you will see that there isn't a character following that, so it would lead me to believe that the character comes before it.

## Dynamic Analysis

So from here, I started using dynamic analysis to figure out what code does what exactly. What I would do is first I would set a breakpoint for this line of code on line 916 of the IDA dissassmbly (specifically the address  `0x4074d7`):

```
    LODWORD(v3) = sub_40FAD8(&v709);
```

The reason for this, is when the interpreter actually starts reading code and executing corresponding code based on it, it enters into a for loop:

```
  for ( i = 0LL; ; ++i )
  {
    LODWORD(v3) = sub_40FAD8(&v709);
    if ( v3 <= i )
      break;  
```

This for loop runs once for each line of `bananas` code (or if the code exits prematurely, because of a failed check.). What we are going to do, is see what the line of code we are dealing with is (stored in `v709`), let the code run, see what it did to the registers, and from that we should be able to figure out what the code does.

To help with this, I wrote a gdbinit script based off of the one in the writeup linked above. One thing you will notice, is that in it I print out the contents of `rsp+0x30`. This is the variable `i` in the chunk of code above, and holds which line of the code we are currently running (stored in `~/.gdbinit`):

```
# Set the breakpoint
b *0x4074d7
set print elements 0

# Establish a function to map variables to the registers
define setvm
set $r0 = (char *)*((char **)($rsp+0x2e0))
set $r1 = (char *)*((char **)($rsp+0x2c0))
set $r2 = (char *)*((char **)($rsp+0x2a0))
set $r3 = (char *)*((char **)($rsp+0x280))
set $r4 = (char *)*((char **)($rsp+0x260))
set $r5 = (char *)*((char **)($rsp+0x240))
set $r6 = (char *)*((char **)($rsp+0x220))
set $r7 = (char *)*((char **)($rsp+0x200))

set $a0 = (char *)*((char **)($rsp+0x3e0))
set $a1 = (char *)*((char **)($rsp+0x3c0))
set $a2 = (char *)*((char **)($rsp+0x3a0))
set $a3 = (char *)*((char **)($rsp+0x380))
set $a4 = (char *)*((char **)($rsp+0x360))
set $a5 = (char *)*((char **)($rsp+0x340))
set $a6 = (char *)*((char **)($rsp+0x320))
set $a7 = (char *)*((char **)($rsp+0x300))
end


# Estbalish a function to print all of the register values
define getvm
echo \n

echo \ line: \ 
x/wx $rsp+0x30

echo \n

echo \ r0: \ 
x/s $r0
echo \ r1: \ 
x/s $r1
echo \ r2: \ 
x/s $r2
echo \ r3: \ 
x/s $r3
echo \ r4: \ 
x/s $r4
echo \ r5: \ 
x/s $r5
echo \ r6: \ 
x/s $r6
echo \ r7: \ 
x/s $r7

echo \n

echo \ a0: \ 
x/s $a0
echo \ a1: \ 
x/s $a1
echo \ a2: \ 
x/s $a2
echo \ a3: \ 
x/s $a3
echo \ a4: \ 
x/s $a4
echo \ a5: \ 
x/s $a5
echo \ a6: \ 
x/s $a6
echo \ a7: \ 
x/s $a7
end

# Execute these commands at the breakpoint
commands 1
setvm
getvm
end

```

So starting off, we run the code and hit the breakpoint:

```
[-------------------------------------code-------------------------------------]
   0x4074c4:	mov    rdi,rax
   0x4074c7:	call   0x401e20 <_ZNSaIcED1Ev@plt>
   0x4074cc:	mov    QWORD PTR [rbp-0xe50],0x0
=> 0x4074d7:	lea    rax,[rbp-0xd10]
   0x4074de:	mov    rdi,rax
   0x4074e1:	call   0x40fad8
   0x4074e6:	cmp    rax,QWORD PTR [rbp-0xe50]
   0x4074ed:	seta   al
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffcee0 --> 0x7fffffffde48 --> 0x7fffffffe1da ("/Hackery/csaw17/rev/bananascript/monkeyDo")
0008| 0x7fffffffcee8 --> 0x200000000 
0016| 0x7fffffffcef0 --> 0x0 
0024| 0x7fffffffcef8 --> 0x0 
0032| 0x7fffffffcf00 --> 0x0 
0040| 0x7fffffffcf08 --> 0x0 
0048| 0x7fffffffcf10 --> 0x0 
0056| 0x7fffffffcf18 --> 0x0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 1, 0x00000000004074d7 in ?? ()
gdb-peda$ x/x $rbp-0xd10
0x7fffffffd050:	0x0000000000645eb0
gdb-peda$ x/10g 0x645eb0
0x645eb0:	0x00000000006301c0	0x0000000000630800
0x645ec0:	0x0000000000630800	0x0000000000630b40
0x645ed0:	0x0000000000631500	0x0000000000631500
0x645ee0:	0x0000000000631510	0x0000000000631610
0x645ef0:	0x0000000000631610	0x000000000062ff40
gdb-peda$ x/g 0x6301c0
0x6301c0:	0x00000000006301d0
gdb-peda$ x/s 0x6301d0
0x6301d0:	"banAnas"
```

so we can see that the first permutation of bananas is `banAnas`. This matches the first `bananas` permutation from the code. Now we will see what the registers are before and after this runs, that way we can get some introspection as to what it is doing:


before:
```
gdb-peda$ setvm
gdb-peda$ getvm

 line: 0x7fffffffcf10:	0x00000000

 r0: 0x7fffffffd1d0:	""
 r1: 0x7fffffffd1b0:	""
 r2: 0x7fffffffd190:	""
 r3: 0x7fffffffd170:	""
 r4: 0x7fffffffd150:	""
 r5: 0x7fffffffd130:	""
 r6: 0x7fffffffd110:	""
 r7: 0x7fffffffd0f0:	""

 a0: 0x7fffffffd2d0:	""
 a1: 0x7fffffffd2b0:	""
 a2: 0x7fffffffd290:	""
 a3: 0x7fffffffd270:	""
 a4: 0x7fffffffd250:	""
 a5: 0x7fffffffd230:	""
 a6: 0x7fffffffd210:	""
 a7: 0x7fffffffd1f0:	""
```

after:
```
gdb-peda$ setvm
gdb-peda$ getvm

 line: 0x7fffffffcf10:	0x00000001

 r0: 0x62e310:	"baNANAs banAnAS banANaS banaNAs BANANAs BANaNas BANAnas bANanAS baNaNAs banaNAs bANaNas BaNaNaS baNanas BaNaNas BaNanas BaNANas baNAnaS banaNAS bANAnAs banANAS bAnaNAs BANAnAS BANAnas BaNANas bAnANas BaNaNaS banAnAs bANAnAs baNaNas BanaNaS bANANas banaNas bAnANaS bANANaS BaNAnas baNanAs baNanAS BaNAnAs bANANas banAnas bAnanaS banANaS bANaNAS banANaS baNanAS BaNanAS BANAnAS BaNanaS"
 r1: 0x7fffffffd1b0:	""
 r2: 0x7fffffffd190:	""
 r3: 0x7fffffffd170:	""
 r4: 0x7fffffffd150:	""
 r5: 0x7fffffffd130:	""
 r6: 0x7fffffffd110:	""
 r7: 0x7fffffffd0f0:	""

 a0: 0x7fffffffd2d0:	""
 a1: 0x7fffffffd2b0:	""
 a2: 0x7fffffffd290:	""
 a3: 0x7fffffffd270:	""
 a4: 0x7fffffffd250:	""
 a5: 0x7fffffffd230:	""
 a6: 0x7fffffffd210:	""
 a7: 0x7fffffffd1f0:	""
```

so we can see that it loaded a massive string into the register `r0`. This string can be also found on the first line, after the second permutation of `bananas`. With this, we can say that the first two permutations of `bananas` (which are `banAnas baNanas`) are probably responsible for the code that is executed. Checking the xreferences to the two strings, we see that `banAnas` is called in a lot of different places, but whenever it is called it always references the register `r0`. `baNanas` on the other hand, is only called in two spots (once of which we can see it enters a loop which checks for eight different bananas permutations, which lead to different registers being referenced, one of which is `banAnas` and `r0`). With this we can probably say that the `baNanas` is the instruction for `mov` and `banAnas` signifies the register `r0`.

This theory is further supported by the next line of code, which it's second bananas permutations is `baNanas`, and it's first bananas permutations is `banANAS` which references the register `r7`:

```
Breakpoint 1, 0x00000000004074d7 in ?? ()
gdb-peda$ setvm
gdb-peda$ getvm

 line: 0x7fffffffcf10:	0x00000002

 r0: 0x62e310:	"baNANAs banAnAS banANaS banaNAs BANANAs BANaNas BANAnas bANanAS baNaNAs banaNAs bANaNas BaNaNaS baNanas BaNaNas BaNanas BaNANas baNAnaS banaNAS bANAnAs banANAS bAnaNAs BANAnAS BANAnas BaNANas bAnANas BaNaNaS banAnAs bANAnAs baNaNas BanaNaS bANANas banaNas bAnANaS bANANaS BaNAnas baNanAs baNanAS BaNAnAs bANANas banAnas bAnanaS banANaS bANaNAS banANaS baNanAS BaNanAS BANAnAS BaNanaS"
 r1: 0x7fffffffd1b0:	""
 r2: 0x7fffffffd190:	""
 r3: 0x7fffffffd170:	""
 r4: 0x7fffffffd150:	""
 r5: 0x7fffffffd130:	""
 r6: 0x7fffffffd110:	""
 r7: 0x62e6f0:	"bANaNas banaNas baNANAs banAnAS baNaNaS BanAnAS bAnanaS baNAnAs baNAnas bananAS bAnANAS baNaNAs baNanaS banAnAS baNaNAS banANAs baNaNAS banaNas bAnanaS baNanAS baNAnAS bANaNas banAnas banaNAS baNanaS bANaNas banAnAs banAnAS bananAS banAnas baNAnas banaNAs bAnanaS bAnaNAs baNaNaS banANaS baNANAS banaNas banANaS baNanAs BaNANAS bANaNas banAnAs bananas baNAnas baNanAS baNAnAS baNanAs banaNAs banAnas baNaNAS bANaNas banaNas bananas baNANAs banAnAS baNANaS banANaS baNANaS bANaNas banAnAs bananas baNAnas bANaNas bANaNAs baNanaS baNANaS baNaNaS baNANaS bananas bAnANAS bAnanas baNaNaS banANas baNanaS BananaS"

 a0: 0x7fffffffd2d0:	""
 a1: 0x7fffffffd2b0:	""
 a2: 0x7fffffffd290:	""
 a3: 0x7fffffffd270:	""
 a4: 0x7fffffffd250:	""
 a5: 0x7fffffffd230:	""
 a6: 0x7fffffffd210:	""
 a7: 0x7fffffffd1f0:	""
```

We can see that the string after the first two `banans` instruction is now in the `r7` register, which supports our theory.

Now for the rest of the lines, I'm not going to do as thorough of an explanation (I don't want this writeup to be 100s of pages long). So I will post an abridged version detailing the disassembly, and why I think it is what it is:

## banana.script disassembly

```
line 1: mov r0, "baNANAs banAnAS banANaS banaNAs BANANAs BANaNas BANAnas bANanAS baNaNAs banaNAs bANaNas BaNaNaS baNanas BaNaNas BaNanas BaNANas baNAnaS banaNAS bANAnAs banANAS bAnaNAs BANAnAS BANAnas BaNANas bAnANas BaNaNaS banAnAs bANAnAs baNaNas BanaNaS bANANas banaNas bAnANaS bANANaS BaNAnas baNanAs baNanAS BaNAnAs bANANas banAnas bAnanaS banANaS bANaNAS banANaS baNanAS BaNanAS BANAnAS BaNanaS" 

After this line, r0 has a new value, which is that string

line 2: mov r7, "bANaNas banaNas baNANAs banAnAS baNaNaS BanAnAS bAnanaS baNAnAs baNAnas bananAS bAnANAS baNaNAs baNanaS banAnAS baNaNAS banANAs baNaNAS banaNas bAnanaS baNanAS baNAnAS bANaNas banAnas banaNAS baNanaS bANaNas banAnAs banAnAS bananAS banAnas baNAnas banaNAs bAnanaS bAnaNAs baNaNaS banANaS baNANAS banaNas banANaS baNanAs BaNANAS bANaNas banAnAs bananas baNAnas baNanAS baNAnAS baNanAs banaNAs banAnas baNaNAS bANaNas banaNas bananas baNANAs banAnAS baNANaS banANaS baNANaS bANaNas banAnAs bananas baNAnas bANaNas bANaNAs baNanaS baNANaS baNaNaS baNANaS bananas bAnANAS bAnanas baNaNaS banANas baNanaS BananaS"

After this line, r7 has a new value, which is that string

line 3: mov r1, "BAnaNas BANANAS BAnAnAs BANANAS BAnAnAs BANANAS"

After this line, r1 has a new value, which is that string

line 4: xor r7, r1

We see that the value for r7 has changed. However it keeps the same length. After a bit of searching, we see that it is a bitwise XOR. However it is not xoring the individual character values like 'b' ^ 'B'. It is interpretting captialized characters as 1, and undercase characters as zero, and storing the result value accordingly.

line 5: puts r7

First thing that we see when this section runs, is that it prints text. It prints the string `Hello! And welcome to the Flying Monkeys' Fantastic Falling Fan Trivia Game.` which is 76 characters long. We can also see that this line references the string `banANAS`, which we have seen used before to reference the register r1, which holds 76 `bananas` strings. We can also see that the `bananas` strings in r1 map directly to the characters printed in the statement in the `mappingFunc` function.

line 6: mov r1, "BanAnAS"

pretty similar to line 3, only difference being the string constant

line 7: puts r1

pretty much line 5, but different register

line 8: mov r7, "bAnANAS banAnAs banAnAs banaNas BanaNaS bANAnAs baNANaS bananAs banAnAs bANAnAs baNAnaS banANAs baNanaS bananAS banANas banANaS banaNaS bANAnAs baNaNaS banaNaS bANanaS bananAs bananas banAnas banaNas banAnAs bananAS baNanAs bANanaS baNAnas banaNAs banANAs banaNaS bANAnAs baNAnAS baNanAs banANAS bANAnAs baNaNAs banAnAS baNAnAs bANAnAs banAnAS baNaNas bananaS baNANas baNANaS banANaS bananas bananAS banAnaS Bananas bANanaS baNAnas banAnaS banANaS banANas banAnaS bAnANAS baNaNAs banANaS banaNaS banaNaS bANanaS banANaS banAnAs banAnas banaNas baNaNas bananAs banaNAs banAnas banAnAs bANAnAs banANaS banaNAS bananaS baNANaS banAnaS bananaS baNANAS bANAnAs banAnas banaNAS bananaS baNaNAs bANAnAs banaNAS banAnaS bananas baNaNaS baNanAs bananaS bANAnAs baNANaS banAnAS bANAnAs banaNaS baNanAS banaNaS baNaNAs bANAnAs baNaNAs banAnAS baNAnAs bANAnAs baNAnAS baNaNAs banaNaS baNaNAs bANAnAs baNaNAS banANAs baNAnAS baNANAS bANaNas baNANaS bananas baNAnAs bANanaS banAnAS baNANAS baNaNaS banANas bANanaS baNaNAs bananas baNanaS baNANAS bANAnAs baNaNas banAnAS baNanaS bananAs bananAs bananaS baNANaS banaNAs baNaNAs banaNAs bANanaS banAnAS banANAs baNaNAs banAnAs BanANAS"

pretty similar to line 2, only difference being the string constant

line 9: mov r1, "BAnaNas BANANAS BANAnAs BANanaS BANanaS BANAnAs BANanaS BANanaS"

pretty similar to line 3, only difference being the string constant

line 10: xor r7, r1

This line is exactly the same as line 4

line 11: puts r7

line is exactly the same as line 5

line 12: mov r1, "BanAnAS"

line is exactly the same as line 6

line 13: puts r1

line is exactly the same as line 7

line 14: mov r7, "BaNAnas bAnanaS bAnAnAs bAnaNAs bANANas baNanAS bANanas banANas bAnaNaS bANaNas bANaNAs bANaNaS bANaNAs bANAnaS bAnanAS bAnANAS bAnaNaS baNaNAS bAnaNas banANAS BananaS BaNAnas bAnaNaS baNANAS banAnAS baNaNaS banANaS banANAs bananAS bANaNaS baNaNAS baNaNAs banAnaS bANanas baNaNaS banaNAs banaNAS baNaNaS baNanas bANanas baNANaS bananAS banAnaS baNAnAS banAnaS baNANas BaNanas"

This line is pretty much like line 2, except different string constant

line 15: mov r1, "BANANAs BANAnAS BAnANAs BANanAs BANAnAS BAnANAs BANanAs BANAnAS BAnANAs"

line is pretty ,uch like line 3, except different string constant

line 16: xor r7, r1

This line is exactly the same as line 4

line 17: puts r7

line is exactly the same as line 5

line 18: mov r1, "BanAnAS"

line is exactly the same as line 6

line 19: puts r1

line is exactly the same as line 7

line 20: mov r7, "BAnAnAs BaNAnAS BAnAnas bananaS baNanAS baNaNAs bANAnAs baNanAS bAnANas baNanas bANANaS bAnAnAs bAnanaS bAnAnas baNAnaS bANanAS baNaNas bANANaS baNANaS baNanAS baNanAS bANanaS bAnANAS bAnanAS baNAnAs baNANAS banANaS bAnaNaS bAnanAs baNAnaS bAnanAS baNaNAs bAnaNaS bAnANaS baNanAS banANAS bAnaNAs baNanAS bAnanaS baNanAs bAnaNaS banAnAs bAnANAS bANaNaS baNAnaS bAnaNaS baNANAS baNANaS bAnAnas baNANAs baNanas bAnanAs bAnAnAs bAnanaS baNanAS bAnAnAS banANas banAnAS bAnANAs bAnaNAs bAnANAS baNAnaS baNANaS bAnAnaS banANAS baNanAS bANaNAs bAnAnAs bAnanAs bAnAnAs bANanAS baNanas bANaNAs baNanAs bAnanAS bAnaNAs bAnANAs bANAnAs bAnANAs baNaNAs banANAS baNaNAs bAnanAs bAnanaS baNaNaS bAnanas baNaNAs bAnANAS bAnanas baNAnaS bANAnaS banAnaS bAnaNAS bAnaNas baNAnAs bAnAnaS bAnANaS bAnANas bAnanaS banANaS bAnANAs baNanas bANanAS bAnAnAs BAnANas BAnAnAs bAnANAs banaNas bAnANAs baNAnAs bAnAnaS bAnanAS bAnaNAS bAnANas baNANAs bAnaNAs baNANAs bAnANAS bAnaNAs bAnanas bAnAnAS banAnas banaNaS bAnANaS baNAnAs baNanaS baNaNAs bANaNas bAnANAS bAnAnAs bAnAnAs baNAnAs baNaNAs bANanAs bANANAS bAnANAS baNAnaS baNANaS bAnANas baNanas banANas baNaNAs bAnanAS bANaNas baNAnAs bANAnAs banaNAs bANanaS bAnanaS bAnaNaS bAnaNAs baNANas BAnAnaS baNANaS baNAnAS banANas bAnANas bAnAnAS baNaNaS banANaS bAnANas baNAnAs baNaNAs bAnAnas bAnANas bANANAs baNanAs bAnaNAS bANANaS banANas bAnAnaS bAnaNAS bAnAnaS bAnANAS baNANaS baNANAS banANas bAnANas bANanAs bANANas bAnAnaS baNANAs baNANaS bANAnAs baNanas bAnAnaS bAnanAS bANanAS bAnAnaS baNaNaS bAnAnas baNaNAs bAnANAS bAnanas baNAnaS bAnaNAS baNAnAs bANAnAs bAnANaS banANAS baNaNaS bAnanAs bAnANas bANanAS bAnAnAs bANAnas baNanas baNaNAs bANaNaS bAnanAS bAnaNaS banAnaS bAnANAs baNANaS baNANAS banANas bANaNAs bANaNaS bAnaNAs baNAnAs bANAnaS bAnAnAs bANanaS bAnAnas baNAnaS bANAnas baNaNas bANanaS bANAnAS bAnAnAs banANAs bAnANas baNanAS bAnaNaS banAnAS bAnANAS baNanAS baNaNAs bAnanas bAnaNAs bAnAnAS banAnas bANAnAS bAnANaS banANas BaNANaS baNaNAs bAnaNAs bANaNaS banANaS baNANAS banaNAs bAnANas bANanAs baNAnaS bAnAnaS baNAnAs bAnaNas BAnANaS banANaS bAnAnaS bAnAnAs bAnAnAS bAnanaS baNAnas bAnanAS baNanAS bAnaNAs baNanAs bAnAnAs bAnaNaS banANas baNANaS bANANAS baNAnAs baNaNAs bAnAnaS baNanAS bAnANAS baNanAS bAnANAS bAnAnAs bAnanas bAnAnas bANAnaS bAnanas baNAnaS baNANaS bANAnAS baNAnAs baNAnaS baNaNAs bANaNas bAnaNAs banANAS bAnaNaS banAnAs bAnaNas bAnanaS baNAnaS bAnAnAS bAnANAs bAnaNAs bAnAnaS baNaNAs banANas baNaNAs bAnAnaS bAnaNas bAnAnAs banANAS BaNaNAs banANaS bAnANAs bANANAS bAnanAS baNaNas bAnaNas baNANaS baNAnas baNanAS bAnaNas bAnanaS bAnAnAs baNAnAs bANAnaS BaNANAS"

line is pretty much line 2, except different string constant

##### After here, I will only be explainning new arguments, the rest I will just list their assembly equivalent

line 21: mov r1, "BaNANaS BaNAnaS BaNanAs BaNaNas BAnaNaS BaNaNAs BaNaNAs BAnanaS BAnanAs BaNANaS BaNAnas BaNANAs BAnanaS BaNaNas BAnanaS"

line 22: xor r7, r1

line 23: puts r7

line 24: mov r1, "BanAnAS"

line 25: puts r1

line 26: mov r7, "bAnaNaS banANaS banAnaS bANaNas bananas baNANas baNanas bANAnAs bANaNAs banAnAS banANAs baNANas banAnAs banaNAs banAnAS bANanas banaNAS baNaNAs bananaS baNanaS banaNaS banANaS banAnAS bANaNas bananaS banANAS baNaNAs bAnANAS banaNAs bANanAS banaNAs baNANAS banaNAs banaNas baNAnas bananas bananAS bAnaNAs banaNAs banANAs banANas bananaS banaNAs banaNas bananas bANANas banaNAs bANanAs bANaNAs baNaNas banANAs bAnaNaS baNAnas banANas banaNAS bANanas baNANas baNANas baNaNAS Bananas bANAnaS bananAs banANaS baNanaS bananAS baNanas baNAnAs bANanas banaNas bANanAS bananas bAnaNaS banANAS banAnAs baNAnas bananas bAnaNaS baNANas banaNas bANaNas banaNAs banAnas bananaS banANAS bAnaNAs banAnaS baNanAs bANanas bananAs banAnAs bananas baNANas bananas banANAS baNanAS banAnaS baNanaS bananas bAnANaS banAnAs banaNaS banANaS baNANAS bANaNas baNanAs banaNaS baNanaS banAnaS bananAs bANanAS bananaS baNanaS banANaS bananAs baNANAs banaNas baNANas baNanAs banANas bananas bananas bananas bananas bananas bANAnAS banaNAs baNAnAs bANanas baNanaS bAnANAs banaNas baNANas BananaS bANaNAs banAnaS baNaNAs bAnaNaS bananaS banaNAs banAnas baNANAS bANaNas bananaS banANAs baNANAS bananAs baNaNAs bAnaNaS bANaNAs bananas bananas baNANas bananAS baNanas bAnaNAS baNANas baNANAS banaNAs bANaNaS baNanAS banAnAs banaNas baNANAS banaNas bAnaNAs banaNas baNanAs bAnANAs banaNAs baNaNAs banAnas baNanaS banAnAS baNanas BaNanAS bANanas bananAs baNaNaS banaNaS bANaNas banANas banAnAS banANaS bananAs baNAnas bANANas baNaNAs bANanas bananaS baNaNaS bANaNas baNANAS banaNaS bANaNAs bananas bananAS baNaNaS bAnaNAs bananas bananas bananas bananas bananas bananas baNANAS banAnas baNANAS bANANaS banANAS banaNAS banANaS baNanaS banANaS bananAs bananaS BaNaNAS bAnanaS baNaNaS banaNaS baNanaS banAnaS bANaNas banAnaS baNAnas baNaNAs baNAnAs bAnaNAs bANanaS banAnAs bananaS banaNAS bananAs bANaNas banANas banaNAS bananAs baNaNAs bananaS bANaNaS baNanAS bananAS bANaNas banAnAS banANAs BanANAS BaNANas bAnaNAs bAnANAS banaNAs bananAS banANas bAnaNaS baNanAS banANas bAnaNAS banAnAS baNaNaS baNaNAs baNanas bANaNas banaNaS banANaS baNANAs banANAs bAnaNAs baNanas baNANas bAnAnaS baNanAS bANanAS baNanAs baNANAS baNaNas banAnaS BaNanAS bANanas baNanaS bananas bANaNaS baNanAS banAnAs banANAs baNAnaS banaNAs baNaNaS bANANas bananaS bANAnAs banaNAs baNANAS bANaNas baNAnAS banANaS banANas banaNaS bANanas baNaNaS banaNAS banaNaS baNanaS baNaNaS baNanAS banAnAs banAnas baNANAS banANAs bAnaNAs bANANaS banANAS banaNas bANaNas baNANaS banANAs baNanAS baNaNAS bANanas bananAs baNaNaS bananaS baNanAS bANAnaS baNanAS banAnAs banaNas bananAS banANas bAnaNAs bANaNaS baNanas bANanAS baNanAS baNANAS bANaNas banAnas baNANAs banAnAs banaNAS bAnaNAs bananaS bananaS bananAS baNaNas baNANAs bANaNas banAnAs banaNAs banaNAs BANANaS bANaNAs banaNAS banANaS baNanAs bANaNas baNanaS baNaNas bananas banAnaS bAnaNAs bananaS baNanaS banAnaS bANaNas baNAnas banaNas bananAS baNanas BaNanAs banAnaS baNaNAS bananAS baNanaS banAnaS bANaNas bananaS baNaNAS bananas baNANAs baNAnaS baNAnaS bANaNas banANAS banANAs bananas banaNaS baNAnaS bananas baNanas bAnANAs banaNAs banaNas bANaNas baNanaS bananaS banANas banaNAS baNaNAS bAnaNaS banAnAs banANAS baNaNas bANAnaS bananAS baNAnaS banaNas bAnaNAs baNAnAS baNANas banAnaS bananAs bANanAS banaNaS baNanaS banANas banAnAs baNAnas banANas baNanaS baNAnaS bANaNaS bananAS banaNaS baNanAs banANaS banaNAs bananAS banANas baNaNAs bANanaS banaNAs banAnAs baNanAS bAnaNaS bananaS bananAs baNanaS banANAs bAnaNaS baNAnAs banANas bANaNas baNANAs banaNAS banAnaS bANaNas baNanas banANAS baNanAs bANaNaS banANAS BanaNAs BananaS BaNanas bANaNas BaNANAs banANAs banANas bananAS baNaNas baNanas bananas banANAS banaNas bANAnaS baNanAS baNANas bANANas baNANas bAnAnaS baNanAS bANanAS banaNaS baNAnaS banANaS banaNAs bAnaNAS banaNAs banaNaS baNAnaS baNanAs baNaNas baNANas banaNas BanANaS BaNANas bAnaNAs baNanas baNANas bAnAnaS bANaNAs baNaNas banaNAS baNAnaS banANaS banAnas bAnaNAS baNANas baNANAS banaNAs bANaNaS banaNAS banAnaS bananas baNANas Bananas bAnaNAs banAnaS banaNAs bAnANAs bANaNAs baNaNaS banANAs bAnaNaS baNanAs banANas baNaNAs baNaNAS bAnaNaS bananaS banaNAs bananas baNANAs bANaNas banaNaS baNanAS bAnaNAs banAnAs baNANas bAnAnaS banAnaS banaNas bANaNas baNaNAs bananas baNaNAS baNaNAS bANanas baNAnas banaNAs baNanAS baNanAS bANAnaS bananaS banAnaS banaNas baNANAS bANANas bananaS bANAnAs banaNAs bANanAS baNaNAs baNAnaS banANaS bananaS BaNanAs bANanas bAnaNaS bANANAS banaNAs banaNas bANAnaS banANas bananAS banANaS baNAnas banANas banAnAs banAnaS banANAs banAnaS baNaNaS baNaNaS baNanAs bANaNAs baNAnAS banAnaS bAnaNaS baNanas banAnAs banANAs baNANAS banaNas baNANas bANaNas baNanAs banaNaS baNanaS banAnaS bananas banANas banANAs bananAS banaNas baNanAS BaNanAS bANanas bananAS baNANas bANaNaS bananAs banaNAs banANAs baNANAS banaNas bAnaNAs baNAnAS baNaNaS bANANaS baNanaS bANanAS banAnas bananAs bANaNas bananas baNANaS baNanas baNAnAs baNanaS BananaS bANaNas banANaS banANaS banANAs bANaNas baNanAs banAnAs bananaS bAnAnaS bananAs banANas banAnAS banAnaS bANaNas bananaS baNANaS bananas bananAS bAnaNAs bananas baNaNas bananaS banANAS bANAnaS banAnas baNANAS baNAnAS baNANas banAnaS baNAnAs banAnaS baNaNas BaNanaS bANaNas banANas baNanAs baNanaS baNAnaS baNANas baNaNaS baNanAs banaNAs baNAnas bANAnaS baNaNas baNANAS banAnas banaNas bANANaS baNanAS bananAS bANaNas baNANAS banaNaS bANaNAs banaNaS bananAS baNaNaS bananAS banaNaS bANaNas baNaNaS banANAs baNAnaS bANaNas baNanAs baNAnaS baNaNAs banAnaS bananaS baNanAS banaNas bAnaNaS baNanAS banANas bAnaNAS baNaNAs baNANAS baNANAs banaNaS bANaNas bananAS bananAS banANAs bANaNas baNANas banAnaS baNAnaS bANanAS banANAS bananaS bANaNas baNaNas baNanaS baNaNAs baNAnAS baNaNAS bAnaNaS baNANas bananas baNanAs banANAS baNaNas baNANas banAnas baNANAS banANAs bAnaNAs bANaNaS baNanaS baNaNaS bANaNas banaNas banAnas baNanas baNAnAS banAnAs baNANas BaNanAS"

line 27: mov r1, "BANANAs BANANAS BANanAs BANANAS BANanAs BANANAS BAnANaS BANaNAS BAnANaS BananAs BANANaS BANAnas BANANAS BAnANAs BANANAS BANANaS BAnANas BANAnAS BAnANAs BAnANaS"

line 28: xor r7, r1

line 29: puts r7

line 30: mov r1, "BanAnAS"

line 31: puts r1

line 32: gets r7 

This is a new operation here. It scans in input and stores it in the register `r7` (since it is the argument). The reason why I believe this, is since it prompts us for input, and after we give it to the program, we see the the ascii-bananas mapping designated in `mappingFunc` of our input stored in the `r7` register.

line 33: mov a7, "BanaNAS"

After this instruction runs, we can see that the `a7` register contains the `BanaNAS` flag. In addition to that in the next line of code, the first and third `banana` permutations are the same. In both cases, the fourth `bananas` permutations is what is stored as a string. In addition to that, the second `bananas` permutation probably signals the register (it is the only thing left that changes to account for the change in registers).

line 34: mov a6, "Bananas"

line 35: mov r2, "BanAnas BananaS"

We see that there is a new register r2, signified by `banAnAs`

line 36: cmp r7, r2

I believe that this is a compare statement for a couple of reasons. The first is that after this line is executed one of the two following lines will jump our execution to somewhere else, which is typical of a compare statement to be followed by a jump. The second is that this instruction is only called a couple of times throughout the code, which it is always followed by jump instructions. The third reason, it doesn't make any apparent changes to the values stored in the registers. When we set the value of `r7` and `r2` equal it skips the next instruction. Also if we set them equal, we see a different code path versus when they aren't.

line 37: jmp a7

This appears to be a jump instruction, since when we run it we end up on a different area of code (we can tell by the value of `line` that we end up on line 46). Also it helps that it is immediately preceeded by a cmp instruction.

line 38: jmp a6

line 39: mov r1, "BanAnAS"

line 40: puts r1

line 41: mov r7, "BaNaNas bANanas banaNAs baNanAS bANAnAs bANaNaS banAnaS bANaNAs baNANAS BaNAnAS BaNANaS BANANaS bAnANas banANAS banAnAs banANas banANas baNAnaS banANas bAnAnAs bananAS bANanas bAnaNAs BanANAs baNanaS bAnaNaS bAnANas bANANaS baNAnaS baNANaS banaNaS baNANAs bANAnAs bANanaS banAnaS bANaNAs baNANAS BaNANAS baNANAs bAnAnAs bAnANas baNanAS banANaS bAnAnaS baNaNAS baNaNAs baNaNAs bAnaNaS banAnAs bAnaNas bAnaNAs BANAnAS baNAnas bAnANas baNanAs baNAnaS baNanas banANAS BanAnaS bAnAnaS bANAnAs baNANAS banAnaS bANaNAs bAnaNAs BanAnAS baNaNAs bANanAs baNAnAs baNAnAs bANANas baNANaS baNAnAs bAnAnaS baNANaS bAnAnAs bananAS bAnAnAs bananAS BAnAnaS baNANaS bAnaNaS baNAnas banANAs banANAS baNAnaS baNAnaS banaNaS bANAnAs bANAnAS banANAS bAnANAS baNaNas BanANAS bAnanAs bANaNaS baNaNaS baNAnas banaNAs baNaNAs banAnAS bAnAnaS banANAs bANANas banAnaS bANaNAs baNANAS BaNANAs bAnanAs bANAnaS baNaNAs banAnaS BanAnas bAnAnaS banAnAs baNANaS baNANas bANANAs banANAS bAnANAS baNaNas BAnAnaS baNaNAs baNaNaS banAnAs baNAnAs banAnas baNANAs banaNAs banAnAS bANAnAs bANANAs bananas bAnanAs bananaS BAnAnaS banaNas bAnaNaS baNANas baNanaS baNAnAs bAnAnaS banAnas baNaNAs banaNaS BAnaNaS bananAS bAnANAS baNanas BaNanAS baNAnAs bAnANAs baNAnas banANAS baNAnAs baNaNaS banaNaS baNAnAS BanANAs baNAnaS banaNAS bANanas bAnaNAs BanANAs baNanaS bAnANAS banANas baNAnAS banANAS bAnAnaS baNAnAS baNAnAs banAnAs bANaNaS bANanAS bAnAnAs baNANAS BanANAs baNanAs bAnANas baNAnAS bAnAnaS baNAnAS baNanAS bANANas baNANAs banAnAs bANAnas banAnaS bANaNAs bananAS BAnAnaS banaNaS bAnaNAs baNANas bAnAnaS baNANAs baNanAS baNAnaS baNaNAs banANaS BAnANas bANanAS baNaNAs bANANAS BaNAnAs baNanAs baNaNaS banAnAS baNANaS bananAs baNAnaS bANANas baNanAS banAnAS BAnANaS bANanAS bANanaS baNaNaS BaNAnaS bAnanAs bAnanAS baNANAS baNanAS baNAnaS banAnaS baNAnAs bAnAnaS bananas bAnAnas bANanAS bANanaS baNaNaS BaNAnaS baNANAs bANanas bAnANas banAnAS bananas baNanas banANAs banANAS bANAnAs bAnANas bananAS bAnanAs bananaS BaNaNaS baNAnAS bAnaNAS bAnANas banAnAS bananas banANAs banANAS bAnAnaS baNANas bANAnaS banaNaS bAnaNaS bAnaNAs BaNaNaS baNAnAS bANanAs baNANas baNanas baNAnAs baNaNaS baNAnAS banaNaS bANAnAs bANANAs bananas bAnanAs bananaS BAnAnaS banANAs bAnANAS banANas BaNAnaS baNAnaS baNAnaS bANANas baNAnas bananas bANANas banaNaS bAnaNAs baNanaS BAnAnaS baNaNaS bAnANAS banANAs baNanas bANANas banANAs banaNAs bAnAnaS baNaNAs bAnanAS baNanAS bANanAS bAnaNAs BaNaNAS baNAnAS bAnaNaS baNANas banANAS bANANas banANAs banaNAs bAnAnaS banANAS bAnAnaS banaNAS bANanAS bAnaNAs BanANAs baNanaS bAnaNaS bAnANas banANAS banANAS baNAnaS banANas banANas bANAnAs bAnAnas banAnaS bANanAS baNanas BaNAnaS bAnanAs bAnANAS baNANaS bAnAnaS baNAnAS baNAnAs banANas bAnAnaS baNAnas bAnaNaS banAnAs bAnanaS bAnaNAs BaNANAS baNAnas bAnANaS baNanas baNanas banANAs bAnAnaS banAnAS baNanAS baNAnas bAnanas bANanAS bANaNAs baNANaS BaNanAS baNAnAS baNaNaS bananas baNanAS baNANas BaNANas bANANas bAnANAS bananas bANAnaS bANanAS bAnAnaS baNANas BaNanAS baNANas baNaNaS banANas baNanAs bANANas baNANaS baNAnAS bAnAnaS baNANaS bAnAnAs bananAS baNaNAs baNANAs BaNanAS baNAnAS bAnAnAS baNANas banaNaS baNAnAs BaNANaS bANANas baNanAS bananAS bAnAnaS bANanAS bAnAnaS baNanAs BanANAS banaNaS baNaNaS banAnAS baNaNaS banaNas baNAnaS BanAnas bAnAnaS baNaNAs bAnanAS baNanAS bANanAS bAnaNAs BaNAnaS banANAs bAnaNaS banAnAs bAnAnaS baNANAs baNAnaS bananAS baNaNAs banaNAs bAnanas bananaS baNaNAs banaNAs BaNanAs bAnanAs bANaNAS baNanas banANAs banANAS bAnAnaS baNAnAS baNAnaS banANAs bANANas baNaNaS baNaNAs baNAnAs BaNanas bAnanAs bAnanaS bAnANas baNAnas baNANas banANAs bananas baNaNAs banAnAs baNAnaS banaNAS bANanaS bananaS BaNAnaS baNAnAs bAnANAs banAnAS bAnAnaS baNAnAS baNanAS bANANas baNAnas banaNAs bAnAnAS bananas bANanaS bAnaNAs BanANAs baNanaS bAnaNaS bAnANas banAnAS bananas baNanas banAnAS BaNANas bANAnAs baNAnaS bANaNaS bAnANas banaNAs BAnAnaS banaNas bAnaNaS baNANas bAnAnaS baNAnAS baNAnAs banANas bAnAnaS bananAs bAnanAS banAnAs bAnAnas baNaNAs BanaNaS banaNas baNaNaS baNaNAS banANas banANas baNanAs banAnas banANas banaNAs bAnanas bananaS baNaNAs bananaS BaNAnAs baNanAs bAnAnaS banAnaS bAnAnaS banAnaS baNANaS banaNaS baNANaS bananAS bAnANaS banAnAs bAnanAs baNANAS BaNANaS baNAnAS bAnanaS baNaNaS baNANaS banaNaS baNANaS banaNaS baNANaS bAnANAs bANAnaS banAnAs bANanas bAnaNAs BanANAs baNAnas baNaNaS baNANaS baNaNaS baNAnaS baNAnaS bANANas banANAs banAnaS bAnAnaS banANAS bANanAS bAnaNAs BaNANas baNaNAs bAnANas baNAnas baNanas banAnas baNanas banAnas baNanas banANAs bAnanas banaNAS bAnANAS baNanAs BaNanas baNaNAs bAnANas baNAnas baNanas banAnas bANanaS banANAS baNAnaS banaNaS bAnaNAs baNaNaS BAnanAS bAnaNAs BAnAnaS bAnaNas bAnANAS banANas bAnAnaS banANAS baNAnaS banAnas banANas bANAnAs bANANAS banAnaS bAnANAs baNaNAs BaNanAS baNAnAS bAnaNaS bAnANas baNaNAs banAnas banAnaS banANAs baNAnAs banaNAs bAnanas bananaS baNaNAs bananas BaNanAS baNAnAs bAnaNaS banANAs baNAnAs banANas banANas banANas bAnAnaS banANAS bAnAnaS bananas bAnAnAs baNANAS BaNANAs bAnanAs bANAnaS baNaNAs banAnaS BanAnas bAnAnaS banAnaS banAnaS baNANaS baNAnaS banaNAs bAnaNAs baNaNAS BaNanAS banaNAS bAnaNaS bAnANas banaNaS banaNAs banAnaS bANANas baNANAS banANAs bAnanas bANanAS bANanaS banaNAs BanANas baNAnAS baNaNaS banAnAS baNanAS bANANas baNaNAs banaNAs baNanAS banaNas BAnANaS bANanAS bANanaS baNaNaS BaNAnaS bAnanAs bAnanas baNAnas baNanas banAnas baNanas banAnas bANanaS bananaS bAnaNAs banANAS bANanaS bananas baNANas"

line 42: mov r1, "BAnAnaS BaNANAs BAnaNAS BAnanAs BANaNAS BAnanAs BANaNAS BAnanAs BANanaS BaNanAs BANAnas BaNANaS BAnANaS bAnanAs"

line 43: xor r7, r1

line 44: puts r7

line 45: mov a7, "BanaNAS BanAnaS BanAnaS"

line 46: jmp a7

line 47: puts r1

line 48: mov r1, "BanaNas bAnANAS bananas baNaNAS bANaNas banANAS banANAs bananas bANAnAs bananAs bananas bananAS banAnAS banaNas baNaNaS baNANas bANAnaS baNANaS banANAs banaNaS banaNas BaNANas bANaNas baNaNAS bananAS banANAs bANAnAs baNAnas banAnaS baNaNAs bANaNaS bananas bananaS bANAnAs bAnANAS bANAnAs banAnAS bananas banaNaS banAnAs banANAs baNAnAS banaNAs bananas banAnas bANAnAs baNaNAs bananas baNaNaS bANaNas baNANAs banAnaS banAnaS banaNAs baNANAS bANAnAs banANas banANAS banANas bananaS banANAs bananas banANaS baNANas BaNanAS BanaNas"

line 49: mov r2, "BANANAs BANANAS BANanAs BANanaS BANanAs BANanaS BANanaS BANanaS BANanaS"

line 50: xor r1, r2

line 51: puts r1

line 52: mov r1, "BanAnAs"

line 53: puts r1

line 54: mov r4, "BaNaNAS baNAnaS bAnaNaS bAnaNaS banANaS bANaNAs bAnAnaS baNAnAs bAnANas bANAnAS banANAs bANAnAs bANaNaS banAnas banaNAs bANaNAs bANanAS bAnAnas bAnaNAS banANAs BanANas baNAnAS banANAS banaNAS BaNAnaS baNaNaS BanaNAs banaNas bANAnas banaNAs baNanAs bAnanas bANAnAS baNAnaS banANaS bananas baNanAS bANAnAS BanaNAs bANanAS bAnaNas bANAnaS banANas bANanAS bAnaNAs bANANAS bAnaNaS banAnAs banaNAS bAnANaS baNANas baNAnas banaNAS baNanaS banaNaS bANAnas banaNAs baNaNas bAnaNas baNANas baNAnas banAnaS banAnAs banAnas BAnanAs BanANAs BaNAnAS baNaNas bANAnAs baNanAs bananAS banaNas bananaS bANAnAS bANAnAs baNaNas bAnaNAS bAnANas bAnAnaS bananAS banANAS banAnas bAnANaS baNANAS bANanAS bAnANas bAnaNAs baNanas banANaS bananas baNanAS BAnAnas"

We see a new register `bananas` permutations, and we see `r4` has it's first value, so we know what `r4`'s bananas permuation is.

line 55: mov r1, "BANanaS BANAnas BaNANAS BaNaNAS BAnanAs BANAnas BANAnAS BANaNas BaNaNAs"

line 56: xor r4, r1

line 57: puts r4

line 58: gets r4

line 59: mov r2, "BAnaNas BANANAS BANanAs BANANAS BaNAnas BAnaNaS BAnANaS bANaNas"

line 60: mov a7, "BanaNAS"

line 61: mov a6, "Bananas"

line 62: cmp r4, r2

line 63: jmp a7

line 64: jmp a6

line 65: mov r1, "BanAnAS"

line 66: puts r1 

line 67: mov r4, "BaNanas bAnAnas banAnas bANANAs bANAnAs BanANas BaNAnas baNAnas bANaNas bAnANas bananAS bANAnas baNAnAS baNaNaS baNaNAs bAnaNAS banAnAS banAnAs bAnanaS bAnaNas bAnanAS baNanas baNANAs bANANas baNanAs bananAS baNaNAS bANanAS banaNAS bANANaS bAnAnAs bAnaNAS banAnAS banAnaS baNANas baNAnaS baNAnaS banAnAS bANanAS banaNas bAnanAS bAnanaS bAnaNAS bananAS banAnas banAnAS BaNanAs bAnaNAs bananaS banAnaS banAnas bAnAnas baNAnAs bAnAnaS banANaS bANAnas baNAnAS baNaNaS baNaNAs baNANAS bANanAS bananas bANAnaS bAnAnAs bAnAnAs bANANas baNANAs baNAnAS baNanAs bananAS bananas bANanAS baNaNAS bAnanAs baNAnAs bAnaNaS baNAnaS baNaNas BanAnaS bAnaNAs bAnaNAs BanANAS bAnaNAs banAnAs bANAnAs baNAnAs bAnaNaS banaNAs baNAnas bananAS baNanaS bAnaNAs banAnAS banAnaS baNanas BANanaS BANanAs baNanAS baNAnAs bananAS bananas bananaS bananas bAnaNAS banAnaS banAnaS bAnAnas baNAnAs bAnAnAS banaNAs bananaS bananAs baNaNAs banAnAs BaNanAS bANanAS banaNAs bAnanAs bANAnAS bAnanAS baNAnaS banaNas banaNaS baNaNas bAnaNAs bananas bananas bananas baNAnas bAnAnAs bANANAS banANas baNANAs bANANas baNANas baNaNAS bAnaNAS baNaNas bananAS bAnAnas bAnaNAs bANaNAs bANANas banANAs banANAS baNAnAs baNAnaS baNanas BanaNAs bANanas baNAnas bananAS bAnanas banANas bANAnas banAnAs baNANas baNANAS baNaNaS banANas banAnAs bAnanas bAnAnAs bANaNAs banAnas baNANAS banANas bAnaNAs baNANas baNaNAs bANanAS banAnas bAnanAs bAnanAS bAnANaS banANas baNaNas baNAnAs bAnaNAs bananaS baNanAS banANaS bananas baNAnas bAnanas bAnanAs banANaS bANAnas banANaS bananAS baNANas baNANAS bANanAS baNaNAS bAnAnAS bAnAnAs baNanAS banaNAS banaNAS banAnas bananaS baNaNAS baNANaS baNaNAs banAnas BAnANas baNAnAs bAnANas banANas banANas baNANaS baNAnAs baNANAS baNaNaS bANanAS baNANas bAnanAs bANAnAs baNanAS baNAnAS bananAs bANANas baNaNAS baNanAs baNAnas banANas bANanas bANANAS bAnanas baNanAS baNanas bananAs baNANas bananAS bAnaNAs baNanas bananAS banaNas bANANAS bAnAnaS BAnaNAs"
line 68: mov r1, "BANaNAS BANanAS BANaNAS BAnANaS BAnANaS BAnANas BANAnas BANAnAS BaNanAS BaNanaS BaNAnas"
line 69: xor r4, r1

line 70: puts r4

line 71: mov a7, "BanaNAS BanAnaS BanAnaS"

line 72: jmp a7

line 73: mov r1, "BanAnAS"

line 74: puts r1

line 75: mov r1, "banaNAS bANANas banAnaS baNaNaS bANANAs banANas banAnAs bAnAnaS banAnaS BanAnaS bANAnas baNaNAs banAnaS bananaS banANAS baNanas baNanas banAnas baNanas bANAnas bAnaNAs banaNAs banAnaS bANanas bANANAs baNanAS bananAS BanaNAS banAnas baNaNAs bANAnaS bananAs baNaNAs bAnANas baNanaS banAnAs BanANaS bananaS BanANAS bANAnaS BaNanaS BaNaNAS BanAnAS BanAnaS BanaNas"

line 76: mov r2, "bANanAs BANanAS BANanaS BANanAs BANaNaS BANAnAS BAnaNAS BAnanAs BANanaS"

line 77: xor r1, r2

line 78: puts r1

line 79: mov r1, "BanaNas bAnAnaS bananAS bANanas bAnANas bAnanaS bAnaNaS baNAnas bANanaS bANAnAs banaNAs bananas bAnanAs bAnANas bANaNas bANAnAs baNaNas bANanas banAnAs bANANas banANaS baNanAs baNANaS bANanAS bAnaNaS banAnAs bAnANAs banaNAs banaNaS banAnAS baNanAs baNaNas bAnANas bAnaNAs baNaNAs bAnaNAS baNaNAs bANANas banAnas bAnaNAs baNAnAs bAnaNAs BANaNAs BaNaNAs"

line 80: mov r2, "BaNANas BANanaS BANaNAS BANanAs BaNAnaS BAnaNAS BaNANaS BaNaNas BAnanAS"

line 81: xor r1, r2

line 82: puts r1

line 83: mov r1, "BanAnAS"

line 84: puts r1

line 85: mov r5, "BaNaNaS bANAnAs banAnaS bAnANAs bANanAs bANANas baNanAS bananAS bAnaNaS bANANAs bAnANAs bANANAs baNanas bAnaNas bANanaS banAnaS baNanAS bananaS baNaNAS bAnanaS bAnanaS bAnanaS bananas bAnanaS bananaS baNaNAs bANAnAS bANaNAs bAnAnas bAnaNAs bAnanAs BanAnAs BANANAs bANAnas banANaS bAnANaS bAnanAS baNANAs banaNAS baNANas bANANaS baNAnaS bAnaNaS banAnas bAnAnAS bAnaNAs bAnANas baNANaS banAnaS baNANAS bANANaS banaNAs bAnANas bananaS baNaNaS bAnaNAs bANANAS BaNANAS"

With this, we see the `bananas` permutation which represents the `r5` register

line 86: mov r1, "BANanAs BANanaS BANaNAs BANaNaS BaNANaS BANanAS BAnanas BaNANaS BaNAnas BAnanaS"

line 87: xor r5, r1

line 88: puts r5

line 89: gets r5

line 90: mov r1, "BanAnAS"

line 91: puts r1

line 92: mov r1, "BAnanaS banAnAS banAnaS bANAnAs bANanaS bAnAnAS baNaNaS baNANas bANaNas bananaS banAnas baNANas bananAs baNAnaS bANanAs baNAnaS bAnANas banANaS bANANas baNanAs BAnANas bAnAnAS bAnAnaS banANaS bANanAS baNAnaS banANAS bananAS bAnaNas baNAnas baNanaS baNaNAS bANaNas bananAS bANANas banaNAS bananAs bANaNaS bAnanas baNanas bAnANas banANAS banAnAS banaNas bAnAnas bAnAnAs baNANAs bAnAnAs bAnaNAs baNAnas baNaNas bANAnAs bANaNAs bANANAs baNAnaS banAnaS banaNAs bANaNAS baNAnAS banAnAs bananAs baNAnaS bAnANAs banANAS bAnanAs banAnAS bananas bANanAS bAnANas bAnaNas BaNANaS bAnAnAs bANAnaS baNAnas bananaS banAnas bANAnAs BAnANas bAnaNaS banAnas bananas baNanas banANas baNANas banANAs bAnANaS bAnAnAs banANas BANanaS BaNaNas"

line 93: mov r2, "BANaNAS BanANAS BaNaNAS BaNAnas BAnanAs BAnanaS BaNaNas BAnAnaS BANAnas BANanaS BaNANaS BaNanAS BAnANAs BANAnAS BANANAS BANANas BANaNAS BANanAs BANAnaS BaNanAs BaNANAs BAnanaS BaNanAS BAnanaS"

line 94: xor r1, r2

line 95: puts r1

line 96: mov r1, "BanAnAS"

line 97: puts r1 

line 98: mov r6, "BANAnAS bAnAnAs banANas bANAnas banAnAs banaNas bANaNaS baNANaS banANAS bAnAnAs bananas bAnANAs baNaNaS bANanAs banAnaS bANanaS baNanAS bANANaS bANANaS bANANas baNANAS Bananas BANAnAS bAnANAs bANaNaS baNaNaS bAnanAS baNAnAs bAnANaS banAnas baNanAS banAnaS bAnanas baNANAs bANaNaS banaNas bAnANas baNAnaS bAnanAS banAnAS baNanAS baNaNAs bAnAnaS baNaNAS bAnANaS baNANAs bANANAS BaNAnAS"

Here we see the permutation `banANAs` for `r6`

line 99: mov r2, "BANANAs BANANAS BaNAnas BAnaNaS BaNAnas BAnaNaS BaNAnas BAnaNaS BaNAnas BAnaNaS BaNAnas BAnaNaS BaNAnas BAnaNaS"

line 100: xor r6, r2	

line 101: puts r6

line 102: gets r6

line 103: puts r1

line 104: mov r1, "BanANAs bANaNaS banaNAS baNANas baNanAS baNanas bANAnAS bAnaNAs BaNaNaS banaNas bANAnAs baNaNAS bananaS bananAs banaNAS bananas baNANAs banaNAs bANAnAS baNANas banANas bananas bAnaNAs banaNAS baNanaS banAnaS baNanas bANanAS banAnAs baNaNAS bAnanas baNANas bananAS baNAnaS baNAnAs BanANAs bAnaNaS banAnaS baNanaS banANas banAnaS baNaNAS bANaNas bAnANaS BanAnAS banaNAS bANanas baNaNas banANAs baNAnaS banAnaS baNaNaS BanaNAs BanaNaS BaNanAS bAnanas baNaNas baNANAs bANaNAs baNanAs bAnAnaS banAnAS bAnAnaS BaNAnAs BaNANAS BanAnaS BaNAnaS"

line 105: mov r2, "BANANAS BANanas BANanas BANaNas BANAnAS BAnANaS BANANAS BAnANAs BANAnAS BAnANas BANAnas BANAnAS BAnANaS BAnAnAS BANanas BANAnAS BAnANAs BANaNAS BANanaS BAnANAs BANAnAs BAnANAs BAnAnAS BANaNAS BAnANas"

line 106: xor r1, r2

line 107: puts r1

line 108: mov r1, "BanAnAS"

line 109: puts r1

line 110: mix r4, r7

This is the first time that we see the `mix` operation. I did not full reverse this, since later on I realized I didn't need to.

line 111: mix r4, r6

line 112: mix r4, r5

line 113: xor r0, r4

line 114: mov r3, "BanANaS bAnAnaS baNaNAs baNANAS baNaNAs bANANas baNAnaS baNAnAs bAnaNAs bAnanAS bANanAS baNaNAs bAnaNaS baNaNAS bANaNAS baNaNas bANanAs BananAS BaNAnAs BaNaNas bAnaNAs baNANas baNANaS banANas baNanaS bananAs bananas bANAnAs bananaS banANAS baNaNaS bANANas baNaNAs banaNaS baNanaS banANas bananas bANANas baNANAs bananas baNANAS bananAs baNaNaS baNanas BaNanAS"

This is the first time we see the permutation `banAnAS` for `r3`

line 115: mov r2, "BANanaS BAnANaS BANaNAS BAnANAs BANaNAS BAnANaS"

line 116: xor r3, r2

line 117: puts r3

line 118: puts r0
```

here are the `bananas` permutations mappings to the registers/commands:

## Mappings

```
banAnas:	mov rX, string

rX banAnas string
```

```
baNanAS:	xor rX, rY

rX baNanAS rY
```

```
bananas:	puts rX

bananas rX

converts the contents of rX to Ascii, by the definition in `mappingFunc`, then prints it
```

```
bananaS: gets rX

bananaS rX

Scans in input from the user, converts it to bananas using the ASCII-bananas mapping from `mappingFunc`
```

```
bananAS: mov aX, string

bananAS aX baNanas string

Moves the string constant into the register `aX`
```

```
banaNAS: cmp rX, rY

banaNAS rX baNANaS rY

or

banaNAS rX baNANAS rY

Compares the contents of the `rX` register with the contents of the `rY` register. When they are equal, it skips the next instruction.
```

```
bananAs: jump aX

bananAs bananAS aX

Jumps to the value stored in the register aX
```

```
baNAnas: mix rX, rY
rX baNAnas rY

Performs a "mixing" operation between rX and rY, which the result gets stored in rX. I didn't reverse this operationm since it isn't necissary to get the flag.
```

```
r registers
banAnas:	r0
banAnaS:	r1
banAnAs:	r2
banAnAS:	r3
banANas:	r4
banANaS:	r5
banANAs:	r6
banANAS:	r7
```

```
a registers
banANAs:	a6
banANAS:	a7
```

## Checks

Throughout this code, we can see three different checks that happen throughout the code. The first appears on line 36:

```
32:	gets r7
.	.	.
35:	mov r2, "BanAnas BananaS"
36:	cmp r7, r2 
```

Now in `mappingFunc`, we can see that `BanAnas` maps to `1` and `BananaS` maps to `8`. So the input we need tog ive in order to pass this check is `18` (also kind of makes since with what it asks, which is our age).

The next check occurs on line `62`:

```
58:	gets r4
59:	mov r2, "BAnaNas BANANAS BANanAs BANANAS BaNAnas BAnaNaS BAnANaS bANaNas"
.	.	.
62:	cmp r4, r2
```

This is pretty much identical to the check above, except the string this time maps out to `BanaNAs!` (also make sence with what the question asked).

After we pass those two checks, we can see that it prompts us for two separate inputs, then performs some algorithm on them:

```
$	./monkeyDo banana.script 
Hello! And welcome to the Flying Monkeys' Fantastic Falling Fan Trivia Game.
 
Here, the council of monkeys will ask you questions, which will determine whether they choose to lift you away save you from your plummeting fate.
 
"WRITE DOWN YOUR AGE," speaks the elder monkey.
 
...Only now do you notice the immense amount of banananasPiled around you on this falling stone platform.. The bananananasSeem to be used for everything, from the obvious food source to building materials to tooth brushes to toys to even glasses, but you can't imagine how well one could see through a pair of K-Vision goggles.
 
One such monkey wearing these goggles hobbles up to you now, carrying a pile of limp banananananasSkins and a bananananananaPointPen. As this monkey hands you these materials, the black ends of the banananananananas(Where eyes might ought to go?) seem to peer into your soul, as though they know everything and more that there is to know about you, and they are very, very deeply conflicted about you due to a familial disagreement back in the chain... "Disgrace to our fine culture," you think you hear, but so soft that it could have just been the wind.  The monkey moves in closer and closer, so close that it could, and actually does bump into you, obviously unaware of where you are due to some odd oblong fruit obscuring its vision.
 
18
 
~How can monkeys talk? And why am I following you their commands?~
 
"WRITE DOWN YOUR SSN/CVV's/privatekeys- err I mean favorite food!," speaks the elder monkey.
BanaNAs!
 
~Why is he yelling? Old Monkey is mean. :(()~
~How does one write a frowning monkey face?~
 
"WRITE DOWN YOUR FAVORITE COLOR," speaks the elder monkey.
15935728
 
~Do they care that I'm typing at a keyboard and not using the provided, soggy, materials?~
 
"WRITE DOWN YOUR NAME," speaks the elder monkey.
75395128
 
~Maybe I'm getting the hand of this, maybe I'm going... BANANAS!!.~
 
"Here is THE FLAG!!" speaks the elder monkey.
ri;5zXSo:)w92;)JIp;k~hmI~?n_haUYn",|
```

So it appears that it takes our input, runs it through an algorithm that if we give it the right input, our input will end up being the flag, and then prints it. Looking at the disassebly, we can see that the value printed as the flag is stored in the `r0` register. Other than having a string loaded into it on the first line, the only other times it is called is an xor statement on line `113`, and when it is printed on line `118`. From seeing the values of the  registers from the `xor` operation on line `113`, that the value being xored in `r4` is eight `bananas` long. In addition to that, from the previous instructions we can tell that the value stored in `r4` is directly influenced by out last two inputs. From this we can inference that the flag encrypted is stored in `r0` at line one. And that the key that is used to decrypt it is eight `bananas` long. We can figure out the first five bytes since the first five characters is probably `flag{` (it is standard for ctf challenges). We can just xor the first five `bananas` character mappings with `flag{` to get the first five bytes of the key.

## Script

For the last three bytes of the key, we can just brute force it with a script, then do the xor operation ourself to get the flag. Here is a script based off of the writeup linked in the beginning that will do that:

```
# This script is based off of: https://github.com/ShellCollectingClub/csaw2017/tree/master/bananascript

# Import the libraries
import itertools
import string
import sys


# Establish the encrypted flag
encFlag = "baNANAs banAnAS banANaS banaNAs BANANAs BANaNas BANAnas bANanAS baNaNAs banaNAs bANaNas BaNaNaS baNanas BaNaNas BaNanas BaNANas baNAnaS banaNAS bANAnAs banANAS bAnaNAs BANAnAS BANAnas BaNANas bAnANas BaNaNaS banAnAs bANAnAs baNaNas BanaNaS bANANas banaNas bAnANaS bANANaS BaNAnas baNanAs baNanAS BaNAnAs bANANas banAnas bAnanaS banANaS bANaNAS banANaS baNanAS BaNanAS BANAnAS BaNanaS"

# Establish the first five bytes of the key, which we know
knownKey = [ 0x64, 0x7f, 0x72, 0x7f, 0x56] 

# Establish the characters we expect to be in the flag
flagChars = string.ascii_letters + string.digits + "_"

'''
Establish a map which will map `bananas` permutations to individual characters. 
Thing is the start at `BANANAS` with `a`, then work there way down the list of ascii 
characters with lower `BANANAS` permutations (think of them as segments of 1s and 0s)
'''

encMap = {}
charsNum = 0b1111111
alphabet = string.ascii_lowercase + string.ascii_uppercase + ' \n' + string.digits + ',./;\[]=-`~!@#$%^&*()_+{}|\\:"?><'

for i in alphabet:
	encMap[charsNum] = i
	charsNum -= 1 

# Establish a function to convert `bananas` permutations to ints (essentially converting binary to int)
def bananasToInt(bananas):
	intnum = ''
	for i in bananas:
		if i.isupper():
			intnum += '1'
		else:
			intnum += '0'
	return int(intnum, 2)


# Establish a function to convert `bananas` permutations to their mapped characters
def lineToString(line):
	string = []
	for b in line.split(' '):
		string.append(encMap[bananasToInt(b)])
	return "".join(string)

# Establish a function which will tokenize the bananas string
def tokenize(inp):
	tokens = []
	for word in inp.split(" "):
		token = Token(word)
		tokens.append(token)
	return tokens

# Establish a function to simulate the xor
def xorOp(encrFlag, key):
	flag = []
	for i, c in enumerate(encrFlag):
		x = c ^ key[i % len(key)]
		flag.append(x)
	return flag


# Take the encrypted flag, and split it up into integers we can xor
encBanannas = encFlag.split(" ")
enc = []
for i in encBanannas:
	enc.append(bananasToInt(i))


# Start the loop that will brute for the three bytes
for i, seq in enumerate(itertools.product(range(256), repeat=3)):
	# Come up with the key instance for the iteration
	keyIteration = knownKey + list(seq)
	# Xor it
	flagOut = xorOp(enc, keyIteration)
	try:
		# Convert it into a string and see if it matches the flag format, meaning it ends with `}`, has all ASCII characters, and has only characters we would expect to be in the flag (we can assume this by the typical ctf flag format)
		flagOut = "".join(encMap[i] for i in flagOut)
		if all(i in string.printable for i in flagOut) and flagOut[-1] == '}' and all(i in flagChars for i in flagOut[5:-1]):
			# If the string meets the format, print it
			print flagOut
	except:
		pass
```

when we run it, we can see we get a lot of different flags:

```
python reverent.py 
flag{lr4ng3_3R3_ch1pper_1_h474_n07_s4L_b4n4n4Ss}
flag{kr4ng3_3Q3_ch1ppfr_1_h475_n07_s4K_b4n4n4Ts}
flag{jr4ng3_3P3_ch1ppgr_1_h472_n07_s4N_b4n4n4Us}
flag{ir4ng3_3O3_ch1pphr_1_h473_n07_s4M_b4n4n4Vs}
flag{pr4ng3_3V3_ch1ppar_1_h478_n07_s4H_b4n4n4Os}
flag{or4ng3_3U3_ch1ppbr_1_h479_n07_s4G_b4n4n4Ps}
flag{nr4ng3_3T3_ch1ppcr_1_h476_n07_s4J_b4n4n4Qs}
flag{mr4ng3_3S3_ch1ppdr_1_h477_n07_s4I_b4n4n4Rs}
flag{dr4ng3_3J3_ch1ppmr_1_h47Y_n07_s4T_b4n4n4Ks}
flag{cr4ng3_3I3_ch1ppnr_1_h47Z_n07_s4S_b4n4n4Ls}
flag{br4ng3_3H3_ch1ppor_1_h47W_n07_s4V_b4n4n4Ms}
flag{ar4ng3_3G3_ch1pppr_1_h47X_n07_s4U_b4n4n4Ns}
flag{hr4ng3_3N3_ch1ppir_1_h470_n07_s4P_b4n4n4Gs}
flag{gr4ng3_3M3_ch1ppjr_1_h471_n07_s4O_b4n4n4Hs}
flag{zr4ng3_333_ch1ppwr_1_h47O_n07_s41_b4n4n48s}
flag{yr4ng3_323_ch1ppxr_1_h47P_n07_s40_b4n4n49s}
flag{Fr4ng3_393_ch1ppqr_1_h47U_n07_s4X_b4n4n42s}
flag{Er4ng3_383_ch1pprr_1_h47V_n07_s4W_b4n4n43s}
flag{Dr4ng3_373_ch1ppsr_1_h47S_n07_s4Z_b4n4n44s}
flag{Cr4ng3_363_ch1pptr_1_h47T_n07_s4Y_b4n4n45s}
flag{rr4ng3_3X3_ch1ppEr_1_h47G_n07_s49_b4n4n40s}
flag{qr4ng3_3W3_ch1ppFr_1_h47H_n07_s48_b4n4n41s}
flag{xr4ng3_313_ch1ppyr_1_h47M_n07_s43_b4n4n4Ws}
flag{wr4ng3_303_ch1ppzr_1_h47N_n07_s42_b4n4n4Xs}
flag{Rr4ng3_3l3_ch1ppKr_1_h47A_n07_s4f_b4n4n4ms}
flag{Qr4ng3_3k3_ch1ppLr_1_h47B_n07_s4e_b4n4n4ns}
flag{Pr4ng3_3j3_ch1ppMr_1_h47y_n07_s4h_b4n4n4os}
flag{Or4ng3_3i3_ch1ppNr_1_h47z_n07_s4g_b4n4n4ps}
flag{Vr4ng3_3p3_ch1ppGr_1_h47E_n07_s4b_b4n4n4is}
flag{Ur4ng3_3o3_ch1ppHr_1_h47F_n07_s4a_b4n4n4js}
flag{Tr4ng3_3n3_ch1ppIr_1_h47C_n07_s4d_b4n4n4ks}
flag{Sr4ng3_3m3_ch1ppJr_1_h47D_n07_s4c_b4n4n4ls}
flag{Jr4ng3_3d3_ch1ppSr_1_h47s_n07_s4n_b4n4n4es}
flag{Ir4ng3_3c3_ch1ppTr_1_h47t_n07_s4m_b4n4n4fs}
flag{Hr4ng3_3b3_ch1ppUr_1_h47q_n07_s4p_b4n4n4gs}
flag{Gr4ng3_3a3_ch1ppVr_1_h47r_n07_s4o_b4n4n4hs}
flag{Nr4ng3_3h3_ch1ppOr_1_h47w_n07_s4j_b4n4n4as}
flag{Mr4ng3_3g3_ch1ppPr_1_h47x_n07_s4i_b4n4n4bs}
flag{Lr4ng3_3f3_ch1ppQr_1_h47u_n07_s4l_b4n4n4cs}
flag{Kr4ng3_3e3_ch1ppRr_1_h47v_n07_s4k_b4n4n4ds}
flag{3r4ng3_3z3_ch1pp0r_1_h47i_n07_s4x_b4n4n4Es}
flag{2r4ng3_3y3_ch1pp1r_1_h47j_n07_s4w_b4n4n4Fs}
flag{9r4ng3_3F3_ch1ppWr_1_h47o_n07_s4r_b4n4n4ys}
flag{8r4ng3_3E3_ch1ppXr_1_h47p_n07_s4q_b4n4n4zs}
flag{7r4ng3_3D3_ch1ppYr_1_h47m_n07_s4t_b4n4n4As}
flag{6r4ng3_3C3_ch1ppZr_1_h47n_n07_s4s_b4n4n4Bs}
flag{Zr4ng3_3t3_ch1pp6r_1_h47c_n07_s4D_b4n4n4us}
flag{Yr4ng3_3s3_ch1pp7r_1_h47d_n07_s4C_b4n4n4vs}
flag{Xr4ng3_3r3_ch1pp8r_1_h47a_n07_s4F_b4n4n4ws}
flag{Wr4ng3_3q3_ch1pp9r_1_h47b_n07_s4E_b4n4n4xs}
flag{1r4ng3_3x3_ch1pp2r_1_h47g_n07_s4z_b4n4n4qs}
flag{0r4ng3_3w3_ch1pp3r_1_h47h_n07_s4y_b4n4n4rs}
```

however since the last flag is the only flag that makes sense (it actually spells something in leet speak) we can tell that `flag{0r4ng3_3w3_ch1pp3r_1_h47h_n07_s4y_b4n4n4rs}` is the correct flag. With that, we captured the flag!