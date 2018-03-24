# Jit In My Pants

Let's take a look at the binary:

```
$	file jit 
jit: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=95c5981cb40078c171db488612fc1595e109b354, stripped
$	./jit 
Usage: ./jit flag
$	./jit flag_pls
Nope.
```

So it appears that we are dealing  with a 64 bit elf that simply requests input, checks it, and then tells us how bad we are. There are multiple ways to solve this. 

# Dynamic Analysis

This challenge can be solved with running it in gdb. Looking at the code in IDA, it is clear that the code has been obfuscated. Let's try just setting a read breakpoint for our input, and then seeing how our input is checked:

First set a breakpoint for the start of the main function, then run it:
```
gdb-peda$ b *0x437de3
Breakpoint 1 at 0x437de3
gdb-peda$ r 15935728
Starting program: /Hackery/bkp16/jit/jit 15935728

```

Now we can set our read breakpoint for our input:
```
Breakpoint 1, 0x0000000000437de3 in ?? ()
gdb-peda$ find 15935728
Searching for '15935728' in: None ranges
Found 1 results, display max 1 items:
[stack] : 0x7fffffffe32a ("15935728")
gdb-peda$ rwatch *0x7fffffffe32a
Hardware read watchpoint 2: *0x7fffffffe32a
gdb-peda$ c
```

and finally we see where our input is read, and we can step through the code and see how it is being checked:

```
[----------------------------------registers-----------------------------------]
RAX: 0x46 ('F')
RBX: 0x7fffffffdfe0 --> 0x7fffffffe32a ("15935728")
RCX: 0x0 
RDX: 0x7fffffffc37c ("FMTEPB}U3`_YEl0jj_hYcpp0emuYcv_Yu4Y355<w")
RSI: 0x46 ('F')
RDI: 0x7fffffffc378 --> 0x45544d4600000000 ('')
RBP: 0x7fffffffc440 --> 0x7fffffffdef0 --> 0x457620 (push   r15)
RSP: 0x7fffffffc220 --> 0x0 
RIP: 0x778333 --> 0x8349d38b4dda8b4d 
R8 : 0x0 
R9 : 0x7fffffffc37c ("FMTEPB}U3`_YEl0jj_hYcpp0emuYcv_Yu4Y355<w")
R10: 0x31 ('1')
R11: 0x7fffffffe32a ("15935728")
R12: 0x7fffffffc378 --> 0x45544d4600000000 ('')
R13: 0x7fffffffdfd0 --> 0x2 
R14: 0x0 
R15: 0x8
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x778328:	mov    r14,r11
   0x77832b:	lea    r11,[r10+r14*1]
   0x77832f:	movsx  r10,BYTE PTR [r11]
=> 0x778333:	mov    r11,r10
   0x778336:	mov    r10,r11
   0x778339:	xor    r10,0x5
   0x77833d:	lea    r11,[r10-0x1]
   0x778341:	cmp    rax,r11
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffc220 --> 0x0 
0008| 0x7fffffffc228 --> 0x0 
0016| 0x7fffffffc230 --> 0x400f50 (xor    ebp,ebp)
0024| 0x7fffffffc238 --> 0x7fffffffdecc --> 0x45762000000000 ('')
0032| 0x7fffffffc240 --> 0x7fffffffc440 --> 0x7fffffffdef0 --> 0x457620 (push   r15)
0040| 0x7fffffffc248 --> 0x7ffff7de6db4 (<_dl_fixup+212>:	mov    r8,rax)
0048| 0x7fffffffc250 --> 0x1 
0056| 0x7fffffffc258 --> 0x7ffff7de6e82 (<_dl_fixup+418>:	jmp    0x7ffff7de6deb <_dl_fixup+267>)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Hardware read watchpoint 2: *0x7fffffffe32a

Value = 0x33393531
0x0000000000778333 in ?? ()
gdb-peda$ p $r11
$1 = 0x7fffffffe32a
gdb-peda$ p $r10
$2 = 0x31
gdb-peda$ si

[----------------------------------registers-----------------------------------]
RAX: 0x46 ('F')
RBX: 0x7fffffffdfe0 --> 0x7fffffffe32a ("15935728")
RCX: 0x0 
RDX: 0x7fffffffc37c ("FMTEPB}U3`_YEl0jj_hYcpp0emuYcv_Yu4Y355<w")
RSI: 0x46 ('F')
RDI: 0x7fffffffc378 --> 0x45544d4600000000 ('')
RBP: 0x7fffffffc440 --> 0x7fffffffdef0 --> 0x457620 (push   r15)
RSP: 0x7fffffffc220 --> 0x0 
RIP: 0x778336 --> 0x4d05f28349d38b4d 
R8 : 0x0 
R9 : 0x7fffffffc37c ("FMTEPB}U3`_YEl0jj_hYcpp0emuYcv_Yu4Y355<w")
R10: 0x31 ('1')
R11: 0x31 ('1')
R12: 0x7fffffffc378 --> 0x45544d4600000000 ('')
R13: 0x7fffffffdfd0 --> 0x2 
R14: 0x0 
R15: 0x8
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x77832b:	lea    r11,[r10+r14*1]
   0x77832f:	movsx  r10,BYTE PTR [r11]
   0x778333:	mov    r11,r10
=> 0x778336:	mov    r10,r11
   0x778339:	xor    r10,0x5
   0x77833d:	lea    r11,[r10-0x1]
   0x778341:	cmp    rax,r11
   0x778344:	movabs r10,0x0
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffc220 --> 0x0 
0008| 0x7fffffffc228 --> 0x0 
0016| 0x7fffffffc230 --> 0x400f50 (xor    ebp,ebp)
0024| 0x7fffffffc238 --> 0x7fffffffdecc --> 0x45762000000000 ('')
0032| 0x7fffffffc240 --> 0x7fffffffc440 --> 0x7fffffffdef0 --> 0x457620 (push   r15)
0040| 0x7fffffffc248 --> 0x7ffff7de6db4 (<_dl_fixup+212>:	mov    r8,rax)
0048| 0x7fffffffc250 --> 0x1 
0056| 0x7fffffffc258 --> 0x7ffff7de6e82 (<_dl_fixup+418>:	jmp    0x7ffff7de6deb <_dl_fixup+267>)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0000000000778336 in ?? ()
gdb-peda$ si

[----------------------------------registers-----------------------------------]
RAX: 0x46 ('F')
RBX: 0x7fffffffdfe0 --> 0x7fffffffe32a ("15935728")
RCX: 0x0 
RDX: 0x7fffffffc37c ("FMTEPB}U3`_YEl0jj_hYcpp0emuYcv_Yu4Y355<w")
RSI: 0x46 ('F')
RDI: 0x7fffffffc378 --> 0x45544d4600000000 ('')
RBP: 0x7fffffffc440 --> 0x7fffffffdef0 --> 0x457620 (push   r15)
RSP: 0x7fffffffc220 --> 0x0 
RIP: 0x778339 --> 0xff5a8d4d05f28349 
R8 : 0x0 
R9 : 0x7fffffffc37c ("FMTEPB}U3`_YEl0jj_hYcpp0emuYcv_Yu4Y355<w")
R10: 0x31 ('1')
R11: 0x31 ('1')
R12: 0x7fffffffc378 --> 0x45544d4600000000 ('')
R13: 0x7fffffffdfd0 --> 0x2 
R14: 0x0 
R15: 0x8
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x77832f:	movsx  r10,BYTE PTR [r11]
   0x778333:	mov    r11,r10
   0x778336:	mov    r10,r11
=> 0x778339:	xor    r10,0x5
   0x77833d:	lea    r11,[r10-0x1]
   0x778341:	cmp    rax,r11
   0x778344:	movabs r10,0x0
   0x77834e:	setne  r10b
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffc220 --> 0x0 
0008| 0x7fffffffc228 --> 0x0 
0016| 0x7fffffffc230 --> 0x400f50 (xor    ebp,ebp)
0024| 0x7fffffffc238 --> 0x7fffffffdecc --> 0x45762000000000 ('')
0032| 0x7fffffffc240 --> 0x7fffffffc440 --> 0x7fffffffdef0 --> 0x457620 (push   r15)
0040| 0x7fffffffc248 --> 0x7ffff7de6db4 (<_dl_fixup+212>:	mov    r8,rax)
0048| 0x7fffffffc250 --> 0x1 
0056| 0x7fffffffc258 --> 0x7ffff7de6e82 (<_dl_fixup+418>:	jmp    0x7ffff7de6deb <_dl_fixup+267>)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0000000000778339 in ?? ()
gdb-peda$ p $r10
$3 = 0x31
gdb-peda$ si

[----------------------------------registers-----------------------------------]
RAX: 0x46 ('F')
RBX: 0x7fffffffdfe0 --> 0x7fffffffe32a ("15935728")
RCX: 0x0 
RDX: 0x7fffffffc37c ("FMTEPB}U3`_YEl0jj_hYcpp0emuYcv_Yu4Y355<w")
RSI: 0x46 ('F')
RDI: 0x7fffffffc378 --> 0x45544d4600000000 ('')
RBP: 0x7fffffffc440 --> 0x7fffffffdef0 --> 0x457620 (push   r15)
RSP: 0x7fffffffc220 --> 0x0 
RIP: 0x77833d --> 0x49c33b49ff5a8d4d 
R8 : 0x0 
R9 : 0x7fffffffc37c ("FMTEPB}U3`_YEl0jj_hYcpp0emuYcv_Yu4Y355<w")
R10: 0x34 ('4')
R11: 0x31 ('1')
R12: 0x7fffffffc378 --> 0x45544d4600000000 ('')
R13: 0x7fffffffdfd0 --> 0x2 
R14: 0x0 
R15: 0x8
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x778333:	mov    r11,r10
   0x778336:	mov    r10,r11
   0x778339:	xor    r10,0x5
=> 0x77833d:	lea    r11,[r10-0x1]
   0x778341:	cmp    rax,r11
   0x778344:	movabs r10,0x0
   0x77834e:	setne  r10b
   0x778352:	cmp    r10,0x0
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffc220 --> 0x0 
0008| 0x7fffffffc228 --> 0x0 
0016| 0x7fffffffc230 --> 0x400f50 (xor    ebp,ebp)
0024| 0x7fffffffc238 --> 0x7fffffffdecc --> 0x45762000000000 ('')
0032| 0x7fffffffc240 --> 0x7fffffffc440 --> 0x7fffffffdef0 --> 0x457620 (push   r15)
0040| 0x7fffffffc248 --> 0x7ffff7de6db4 (<_dl_fixup+212>:	mov    r8,rax)
0048| 0x7fffffffc250 --> 0x1 
0056| 0x7fffffffc258 --> 0x7ffff7de6e82 (<_dl_fixup+418>:	jmp    0x7ffff7de6deb <_dl_fixup+267>)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x000000000077833d in ?? ()
gdb-peda$ si

[----------------------------------registers-----------------------------------]
RAX: 0x46 ('F')
RBX: 0x7fffffffdfe0 --> 0x7fffffffe32a ("15935728")
RCX: 0x0 
RDX: 0x7fffffffc37c ("FMTEPB}U3`_YEl0jj_hYcpp0emuYcv_Yu4Y355<w")
RSI: 0x46 ('F')
RDI: 0x7fffffffc378 --> 0x45544d4600000000 ('')
RBP: 0x7fffffffc440 --> 0x7fffffffdef0 --> 0x457620 (push   r15)
RSP: 0x7fffffffc220 --> 0x0 
RIP: 0x778341 --> 0xba49c33b49 
R8 : 0x0 
R9 : 0x7fffffffc37c ("FMTEPB}U3`_YEl0jj_hYcpp0emuYcv_Yu4Y355<w")
R10: 0x34 ('4')
R11: 0x33 ('3')
R12: 0x7fffffffc378 --> 0x45544d4600000000 ('')
R13: 0x7fffffffdfd0 --> 0x2 
R14: 0x0 
R15: 0x8
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x778336:	mov    r10,r11
   0x778339:	xor    r10,0x5
   0x77833d:	lea    r11,[r10-0x1]
=> 0x778341:	cmp    rax,r11
   0x778344:	movabs r10,0x0
   0x77834e:	setne  r10b
   0x778352:	cmp    r10,0x0
   0x778356:	jne    0x7782b2
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffc220 --> 0x0 
0008| 0x7fffffffc228 --> 0x0 
0016| 0x7fffffffc230 --> 0x400f50 (xor    ebp,ebp)
0024| 0x7fffffffc238 --> 0x7fffffffdecc --> 0x45762000000000 ('')
0032| 0x7fffffffc240 --> 0x7fffffffc440 --> 0x7fffffffdef0 --> 0x457620 (push   r15)
0040| 0x7fffffffc248 --> 0x7ffff7de6db4 (<_dl_fixup+212>:	mov    r8,rax)
0048| 0x7fffffffc250 --> 0x1 
0056| 0x7fffffffc258 --> 0x7ffff7de6e82 (<_dl_fixup+418>:	jmp    0x7ffff7de6deb <_dl_fixup+267>)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0000000000778341 in ?? ()
gdb-peda$ p $r11
$4 = 0x33
gdb-peda$ p $rax
$5 = 0x46
gdb-peda$ 
```

So looking at what happened exactly, we can tell a couple of things. Firstly that the input is being checked one character at a time. We can also see how each character is being checked, and against what. Prior to this assembly code running, the character that our input is being checked against is stored in the `RAX` register (the entire string is stored in the `R9` and `RDX` registers)

```
   0x778333:    mov    r11,r10		 ; Character that is being checked from our input is moved into the r11 register (our entire input string is in r10 currently)
   0x778336:    mov    r10,r11		 ; Character that is being checked from our input is moved into the r10 register
   0x778339:    xor    r10,0x5		 ; Character that is being checked from our input is xored by 0x5
   0x77833d:    lea    r11,[r10-0x1] ; The output of the previous xor opperation has 0x1 subtracted from it 
   0x778341:    cmp    rax,r11       ; The output of the previous subtraction is checked against the desired character stored in the rax register
```

Luckily for us, this algorithm is rather simple and reversible. We have the entire string which it is being checked against ``FMTEPB}U3`_YEl0jj_hYcpp0emuYcv_Yu4Y355<w``. With a little bit of python, we should be able to get the desired input:

```
$	cat reverent.py 
enc_flag = "FMTEPB}U3`_YEl0jj_hYcpp0emuYcv_Yu4Y355<w"
flag = ""

for i in enc_flag:
    x = ((ord(i) + 1) ^ 0x5)
    flag += chr(x)

print "[+] The flag is: " + flag
guyinatuxedo@tux:/Hackery/bkp16/jit
```

and when we run it:

```
$	python reverent.py 
[+] The flag is: BKPCTF{S1de_Ch4nnel_att4cks_are_s0_1338}
```

Let's try this:

```
$	./jit BKPCTF{S1de_Ch4nnel_att4cks_are_s0_1338}
You've got the flag!
```

Just like that, we captured the flag!
