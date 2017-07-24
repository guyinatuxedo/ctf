Let's see what we are dealing with here:
```
$	file deedeedee 
deedeedee: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=4fac9c863749015d039a3bf0a3a6c936f2f7eadd, not stripped
```

So we are dealing with a 64 bit Linux ELF. Let's run it and see what we get:
```
$	./deedeedee 
Your hexencoded, encrypted flag is: 676c60677a74326d716c6074325f6c6575347172316773616c6d686e665f68735e6773385e345e3377657379316e327d
I generated it at compile time. :)
Can you decrypt it for me?
```

So we see that our flag when hexencoded is:
```
676c60677a74326d716c6074325f6c6575347172316773616c6d686e665f68735e6773385e345e3377657379316e327d
```

and we can decode the flag using python:
```
>>> "676c60677a74326d716c6074325f6c6575347172316773616c6d686e665f68735e6773385e345e3377657379316e327d".decode("hex")
'gl`gzt2mql`t2_leu4qr1gsalmhnf_hs^gs8^4^3wesy1n2}'

```

Obviously the flag we got "gl`gzt2mql`t2_leu4qr1gsalmhnf_hs^gs8^4^3wesy1n2}" is encrypted. Now when we look at the functions that this binary has, we see a large amount. Let's see if we can find the encrypt function: 

```
$	objdump -x deedeedee | grep encrypt
000000000044cde0 g     F .text	000000000000158b              _D9deedeedee7encryptFNaNfAyaZAya
```

So we found the function `_D9deedeedee7encryptFNaNfAyaZAya` that might be used to encrypt the flag. Let's take a look at it's assembly code:

```
gdb-peda$ disas _D9deedeedee7encryptFNaNfAyaZAya
Dump of assembler code for function _D9deedeedee7encryptFNaNfAyaZAya:
   0x000000000044cde0 <+0>:	push   rbp
   0x000000000044cde1 <+1>:	mov    rbp,rsp
   0x000000000044cde4 <+4>:	sub    rsp,0x10
   0x000000000044cde8 <+8>:	mov    QWORD PTR [rbp-0x10],rdi
   0x000000000044cdec <+12>:	mov    QWORD PTR [rbp-0x8],rsi
   0x000000000044cdf0 <+16>:	mov    rdx,QWORD PTR [rbp-0x8]
   0x000000000044cdf4 <+20>:	mov    rax,QWORD PTR [rbp-0x10]
   0x000000000044cdf8 <+24>:	mov    rdi,rax
   0x000000000044cdfb <+27>:	mov    rsi,rdx
   0x000000000044cdfe <+30>:	call   0x451470 <_D9deedeedee21__T3encVAyaa3_313131Z3encFNaNfAyaZAya>
   0x000000000044ce03 <+35>:	mov    rdi,rax
   0x000000000044ce06 <+38>:	mov    rsi,rdx
   0x000000000044ce09 <+41>:	call   0x458280 <_D9deedeedee21__T3encVAyaa3_323232Z3encFNaNfAyaZAya>
   0x000000000044ce0e <+46>:	mov    rdi,rax
   0x000000000044ce11 <+49>:	mov    rsi,rdx
   0x000000000044ce14 <+52>:	call   0x458358 <_D9deedeedee21__T3encVAyaa3_333333Z3encFNaNfAyaZAya>
   0x000000000044ce19 <+57>:	mov    rdi,rax
   0x000000000044ce1c <+60>:	mov    rsi,rdx
   0x000000000044ce1f <+63>:	call   0x458430 <_D9deedeedee21__T3encVAyaa3_343434Z3encFNaNfAyaZAya>
```

Continued...

```
   0x000000000044e369 <+5513>:	leave  
   0x000000000044e36a <+5514>:	ret    
End of assembler dump.
```

So we see that in the "encrypt" function, it essentially just calls a lot of other functions. We see that for each function called, there are two arguments passed to it which are stored in the `rdi` and `rax` registers.Let's take a look at the first function it calls:
```
gdb-peda$ disas _D9deedeedee21__T3encVAyaa3_313131Z3encFNaNfAyaZAya
Dump of assembler code for function _D9deedeedee21__T3encVAyaa3_313131Z3encFNaNfAyaZAya:
   0x0000000000451470 <+0>:	push   rbp
   0x0000000000451471 <+1>:	mov    rbp,rsp
   0x0000000000451474 <+4>:	sub    rsp,0xb0
   0x000000000045147b <+11>:	mov    QWORD PTR [rbp-0xa8],rbx
   0x0000000000451482 <+18>:	mov    QWORD PTR [rbp-0x10],rdi
   0x0000000000451486 <+22>:	mov    QWORD PTR [rbp-0x8],rsi
   0x000000000045148a <+26>:	call   0x451548 <_D3std4conv9__T2toTiZ9__T2toTmZ2toFNaNfmZi>
   0x000000000045148f <+31>:	mov    BYTE PTR [rbp-0xa0],al
   0x0000000000451495 <+37>:	mov    ecx,0x6cf8a0
   0x000000000045149a <+42>:	xor    eax,eax
   0x000000000045149c <+44>:	mov    QWORD PTR [rbp-0x90],rax
   0x00000000004514a3 <+51>:	mov    QWORD PTR [rbp-0x88],rcx
   0x00000000004514aa <+58>:	mov    edx,0x49fa5c
   0x00000000004514af <+63>:	mov    esi,0x3
   0x00000000004514b4 <+68>:	lea    rdi,[rbp-0x40]
   0x00000000004514b8 <+72>:	call   0x4515e0 <_D3std5range14__T5cycleTAyaZ5cycleFNaNbNiNfAyaZS3std5range14__T5CycleTAyaZ5Cycle>
   0x00000000004514bd <+77>:	mov    rbx,rax
   0x00000000004514c0 <+80>:	push   QWORD PTR [rbx+0x18]
   0x00000000004514c3 <+83>:	push   QWORD PTR [rbx+0x10]
   0x00000000004514c6 <+86>:	push   QWORD PTR [rbx+0x8]
   0x00000000004514c9 <+89>:	push   QWORD PTR [rbx]
   0x00000000004514cb <+91>:	mov    rdx,QWORD PTR [rbp-0x8]
   0x00000000004514cf <+95>:	mov    rsi,QWORD PTR [rbp-0x10]
   0x00000000004514d3 <+99>:	lea    rdi,[rbp-0x80]
   0x00000000004514d7 <+103>:	call   0x451980 <_D3std5range46__T3zipTS3std5range14__T5CycleTAyaZ5CycleTAyaZ3zipFNaNbNiNfS3std5range14__T5CycleTAyaZ5CycleAyaZS3std5range46__T3ZipTS3std5range14__T5CycleTAyaZ5CycleTAyaZ3Zip>
   0x00000000004514dc <+108>:	add    rsp,0x20
   0x00000000004514e0 <+112>:	lea    rdi,[rbp-0x80]
   0x00000000004514e4 <+116>:	call   0x451a80 <_D3std5range46__T3ZipTS3std5range14__T5CycleTAyaZ5CycleTAyaZ3Zip5emptyMFNaNdNfZb>
   0x00000000004514e9 <+121>:	xor    al,0x1
   0x00000000004514eb <+123>:	je     0x45152e <_D9deedeedee21__T3encVAyaa3_313131Z3encFNaNfAyaZAya+190>
   0x00000000004514ed <+125>:	lea    rdi,[rbp-0x80]
   0x00000000004514f1 <+129>:	call   0x451c78 <_D3std5range46__T3ZipTS3std5range14__T5CycleTAyaZ5CycleTAyaZ3Zip5frontMFNaNdNfZS3std8typecons14__T5TupleTwTwZ5Tuple>
   0x00000000004514f6 <+134>:	mov    QWORD PTR [rbp-0x18],rax
   0x00000000004514fa <+138>:	lea    rax,[rbp-0x18]
   0x00000000004514fe <+142>:	mov    QWORD PTR [rbp-0x20],rax
   0x0000000000451502 <+146>:	mov    rcx,QWORD PTR [rbp-0x20]
   0x0000000000451506 <+150>:	lea    rdx,[rcx+0x4]
   0x000000000045150a <+154>:	mov    esi,DWORD PTR [rax]
   0x000000000045150c <+156>:	xor    esi,DWORD PTR [rdx]
   0x000000000045150e <+158>:	movzx  ebx,BYTE PTR [rbp-0xa0]
   0x0000000000451515 <+165>:	xor    esi,ebx
   0x0000000000451517 <+167>:	lea    rdi,[rbp-0x90]
   0x000000000045151e <+174>:	call   0x47913c <_d_arrayappendcd>
   0x0000000000451523 <+179>:	lea    rdi,[rbp-0x80]
   0x0000000000451527 <+183>:	call   0x451d98 <_D3std5range46__T3ZipTS3std5range14__T5CycleTAyaZ5CycleTAyaZ3Zip8popFrontMFNaNfZv>
   0x000000000045152c <+188>:	jmp    0x4514e0 <_D9deedeedee21__T3encVAyaa3_313131Z3encFNaNfAyaZAya+112>
   0x000000000045152e <+190>:	mov    rdx,QWORD PTR [rbp-0x88]
   0x0000000000451535 <+197>:	mov    rax,QWORD PTR [rbp-0x90]
   0x000000000045153c <+204>:	mov    rbx,QWORD PTR [rbp-0xa8]
   0x0000000000451543 <+211>:	leave  
   0x0000000000451544 <+212>:	ret    
End of assembler dump.
```

Out of that assembly, these lines pop out:
```
   0x00000000004514aa <+58>:	mov    edx,0x49fa5c
```
```
   0x000000000045150c <+156>:	xor    esi,DWORD PTR [rdx]
   0x000000000045150e <+158>:	movzx  ebx,BYTE PTR [rbp-0xa0]
   0x0000000000451515 <+165>:	xor    esi,ebx
```

So as you can see, it moves a static string into  the edx register, then xors it against the `rdx` register. So for encryption it is probably xoring the static string against the `rdx` register, which should be the same as the argument passed in the `rsi` register, since the content of the `rsi` register is moved into `rbp-0x8`, which is then moved into the `rdx` register. After that it appears to be XORing it against the `ebx` register, which just a guess is the length of the string being xored. Reasoning behind this is the function accepts `rsi` as an argument, which after being loaded into `rbp-0x8`, is loaded into `rbx` which `ebx` is the lower 16 bits:

```
   0x0000000000451486 <+22>:	mov    QWORD PTR [rbp-0x8],rsi
```

```
   0x00000000004514cb <+91>:	mov    rdx,QWORD PTR [rbp-0x8]
```

Now let's see what the static string is:
```
gdb-peda$ x/wx 0x49fa5c
0x49fa5c <_TMP75>:	0x00313131
```

So we can see that the static string is just `111` (in hex it is 0x313131)The good news that is if our assumptions are correct, then we should be able to decrypt the flag by just running the encryption algorithm on the encrypted string since XOR encryption is reversible. Before we do that we need to prove our assumptions:

First we need to start the program, and set a breakpoint for main and the encrypt function

```
gdb-peda$ b main
Breakpoint 1 at 0x474b0c
gdb-peda$ b _D9deedeedee7encryptFNaNfAyaZAya
Breakpoint 2 at 0x44cde4
gdb-peda$ r
```

Now we need to jump to the encrypt function

```
gdb-peda$ j _D9deedeedee7encryptFNaNfAyaZAya
Continuing at 0x44cde4.
```

Now we need to set the register values for `rdi` and `rsi`. The `rsi` register holds the string being xored, and the `rdi` register holds the length of the string in the `rsi` register.

```
Breakpoint 2, 0x000000000044cde4 in deedeedee.encrypt(immutable(char)[]) ()
gdb-peda$ b *0x451517
Breakpoint 3 at 0x451517
gdb-peda$ p strcpy($rsi, "00000")
$1 = 0xffffdf08
gdb-peda$ set $rdi=5
gdb-peda$ c
Continuing.
```

then finally we can see how it comes out
```
Breakpoint 3, 0x0000000000451517 in deedeedee.enc!("111").enc(immutable(char)[]) ()
gdb-peda$ p $ebx
$2 = 0x5
gdb-peda$ p $esi
$3 = 0x4
```

Everything came out as expected. The value of the `ebx` register hold the length of the string, and the `esi` register holds the value we would expect to get after encrypting it with this algorithm. The encryption works byte by byte, so let's work through the encryption algorithm:

```
0x30	^	0x31	=	0x1
0x1		^	0x5		=	0x4
```

Now that we know how the encryption works, we should be able to just run the program and give the encrypted flag and the length as paramters. Since XOR is reversible, it should just decrypt the flag for us. However we see a function being called in _Dmain that we should probably pay attention to before doing this:
```
   0x000000000044e442 <+58>:	mov    rsi,rdx
   0x000000000044e445 <+61>:	call   0x44e370 <_D9deedeedee9hexencodeFAyaZAya>
   0x000000000044e44a <+66>:	mov    rdi,rax
```

Looking at the function, it appears to take the rdi register as an argument, and returns data to it. We should probably set the rdi register equal to the Hex Decoded version of the encrypted flag before this function is called, so it can format it properly. Now let's take it from the top and decrypt the flag.

First let's set the breakpoints for the beginning of the Dmain function, and durring the beginning and end of the encrypt function. 
```
gdb-peda$ b Dmain
Breakpoint 1 at 0x44e40c
gdb-peda$ b _D9deedeedee21__T3encVAyaa3_313131Z3encFNaNfAyaZAya
Breakpoint 2 at 0x451474
gdb-peda$ b *0x44e36a
Breakpoint 3 at 0x44e36a
gdb-peda$ r
Starting program: /Hackery/ctf/csaw/reverse/deedeedee/deedeedee 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
```  

Next let's set the value of the `rsi` register, then jump to the encrypt function:
```
Breakpoint 1, 0x000000000044e40c in D main ()
gdb-peda$ p strcpy($rsi,"gl`gzt2mql`t2_leu4qr1gsalmhnf_hs^gs8^4^3wesy1n2}")
$1 = 0xffffdd00
gdb-peda$ j _D9deedeedee7encryptFNaNfAyaZAya
Continuing at 0x44cde4.
```

Next set the value of the `rdi` register equal to the length of the encrypted flag, and finish the algorithm:
```
Breakpoint 2, 0x0000000000451474 in deedeedee.enc!("111").enc(immutable(char)[]) ()
gdb-peda$ set $rdi=48
gdb-peda$ c
Continuing.
```

And once we reach the third breakpoint, we should be able to see a pointer to the flag in the `rdx` register:

```
Breakpoint 3, 0x000000000044e36a in deedeedee.encrypt(immutable(char)[]) ()
gdb-peda$ x/s $rdx
0x7ffff7edec80:	"flag{t3mplat3_met4pr0gramming_is_gr8_4_3very0n3}"
```

Lastly we have the flag `flag{t3mplat3_met4pr0gramming_is_gr8_4_3very0n3}`.

This writeup is based off of this `https://quanyang.github.io/csaw-ctf-quals-2016-deedeedee/`






