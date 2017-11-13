# Prophecy

Full Disclosure, I solved this challenge the day after the competition ended.

Let's take a look at the binary:
```
$	file prophecy 
prophecy: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, not stripped
```

So we can see it is a 64 bit elf. Let's run it!

```
$	./prophecy 
----------------------------------------------
|PROPHECY PROPHECY PROPHECY PROPHECY PROPHECY| 
----------------------------------------------
[*]Give me the secret name
>>guyinatuxedo
[*]Give me the key to unlock the prophecy
>>supersecretkey
```

So we can see that it prompts us for  a name and a key. When we look at the code in IDA, it is clear that the binary has been obfuscated. The program is ran in a while true loop, and the code has been split into a lot of diffenrent sections. Which section runs depends on the value of the integer `code_flow`. With that knowledge, let's find the pieces of code that scan in our name and secret.

Name: (address: 0x40254b)
```
LODWORD(v5) = std::operator<<<std::char_traits<char>>(&std::cout, "|PROPHECY PROPHECY PROPHECY PROPHECY PROPHECY| ");
LODWORD(v6) = std::ostream::operator<<(v5, &std::endl<char,std::char_traits<char>>);
v372 = v6;
LODWORD(v7) = std::operator<<<std::char_traits<char>>(&std::cout, "----------------------------------------------");
LODWORD(v8) = std::ostream::operator<<(v7, &std::endl<char,std::char_traits<char>>);
v371 = v8;
LODWORD(v9) = std::operator<<<std::char_traits<char>>(&std::cout, "[*]Give me the secret name");
LODWORD(v10) = std::ostream::operator<<(v9, &std::endl<char,std::char_traits<char>>);
v370 = v10;
LODWORD(v11) = std::operator<<<std::char_traits<char>>(&std::cout, ">>");
v369 = v11;
name_bytes_scanned = read(0, (void *)name_input, 0xC8uLL);
code_flow_trans0 = 0xAC75072E;
name_input_check = name_bytes_scanned > 0;
v14 = (((_BYTE)x_28 - 1) * (_BYTE)x_28 & 1) == 0;
if ( (~((unsigned __int8)~(y_29 < 10) | (unsigned __int8)~v14) & 1 | (unsigned __int8)((y_29 < 10) ^ v14)) & 1 )
  code_flow_trans0 = -1595152981;
code_flow = code_flow_trans0;
```

Here we can see that it prompts for the secret name. It scans in 200 bytes into `name_input` 200 bytes, then checks to see if it scanned in more than 0 bytes. Checkint the xreferences for `name_input` we find the following code block.

address: 0x402b57
```
does_input_contain_starcraft = strstr(name_input, ".starcraft");
v34 = -2012679336;
starcraft_exits_check = does_input_contain_starcraft != 0LL;
```

Looking here, we can see that it checks to see if `name_input` contains the string `.starcraft`. So the name we need to input is probably `.starcraft`

Secret: (address: 0x40289d)
```
{
  LODWORD(v21) = std::operator<<<std::char_traits<char>>(
  &std::cout,
  "[*]Give me the key to unlock the prophecy");
  LODWORD(v22) = std::ostream::operator<<(
  v21,
  &std::endl<char,std::char_traits<char>>);
  v364 = v22;
  LODWORD(v23) = std::operator<<<std::char_traits<char>>(
  &std::cout,
  ">>");
  v363 = v23;
  key_input_byte_count = read(0, key_input, 0x12CuLL);
  v25 = 0x661C008B;
  key_input_check = key_input_byte_count > 0;
  v26 = (((_BYTE)x_28 - 1) * (_BYTE)x_28 & 1) == 0;
  if ( (~((unsigned __int8)~(y_29 < 10) | (unsigned __int8)~v26) & 1 | (unsigned __int8)((y_29 < 10) ^ v26)) & 1 )
    v25 = 0xC0F1DACD;
  code_flow = v25;
}
```

Here we can see that it prints out `[*]Give me the key to unlock the prophecy`. Proceeding that it makes a read call, which it will scan 300 (0x12c) bytes into `key_input`. It then make sures that the read scanned in more than 0 bytes. Checking the xreferences for `key_input`we find a bit of code that alters `key_input`:

address:	0x402a3d
```
*((_BYTE *)key_input + strlen((const char *)key_input) - 1) = 0;
```

This line of code will essentially set the byte directly before the first null byte equal to a null byte. This is because `strlen` will count the amount of bytes untill a null byte. Read by itself does not null terminate. Proceeding that, after checking the xreferences for `name_input` and `key_input` we find the next code block.

address: 0x402f08
```
name_input_transfer = name_input;
name_input_length = strlen(name_input);
*appended_filename = strncat(
tmp,
name_input_transfer,
name_input_length);
file_pointer = strtok(*appended_filename, "\n");
*stream = fopen(file_pointer, "wb");
write = fwrite(key_input, 1uLL, 0x12CuLL, *stream);
stream_transfer = *stream;
v355 = write;
v48 = fclose(stream_transfer);
appended_filename_transfer = *appended_filename;
v354 = v48;
v50 = fopen(appended_filename_transfer, "rb");
```

So we can see here some manipulation going on with our two inputs. First it takes `name_input` (which because of a previous check should be `.starcraft`)  and appends it to the end of `/tmp/` (look at it's value in gdb). Proceeding that, it strips a newline character from the appended filename. After that it opens up the appended string as a writeable file, then writes 0x12c bytes of `key_input` to it (it will write more bytes ). Later on it opens the same file as a readable file. 

tl;dr If the name you input is `.starcraft` it will create the file `/tmp/.starcraft` and write the input you gave it as a key to it (plus the difference from the length of the input to 0x12c). It ends off with opening the file you created as readable,.

So the file it created is probably read later on in the code. We see in the imports that the function fread is in the code. Let's run the binary in gdb and set a breakpoint for `fread` so we can see where our input is read:

```
gdb-peda$ b *fread
Breakpoint 1 at 0x400b30
gdb-peda$ r
Starting program: /Hackery/csaw17/prophecy/prophecy 
----------------------------------------------
|PROPHECY PROPHECY PROPHECY PROPHECY PROPHECY| 
----------------------------------------------
[*]Give me the secret name
>>.starcraft
[*]Give me the key to unlock the prophecy
>>15935728
[*]Interpreting the secret....

[----------------------------------registers-----------------------------------]
RAX: 0x4 
RBX: 0x0 
RCX: 0x619c20 --> 0xfbad2488 
RDX: 0x4 
RSI: 0x1 
RDI: 0x7fffffffd3c0 --> 0x3c2700 ('')
RBP: 0x7fffffffdee0 --> 0x7fffffffdf60 --> 0x406380 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffd268 --> 0x403197 (<_Z6parserv+8455>:	mov    r8d,0x1cd65a05)
RIP: 0x7ffff71d73d0 (<__GI__IO_fread>:	push   r13)
R8 : 0xced24a00 
R9 : 0xced24a01 
R10: 0x634 
R11: 0x7ffff71d73d0 (<__GI__IO_fread>:	push   r13)
R12: 0x400f01 (<_GLOBAL__sub_I_prophecy.cpp+273>:	add    ecx,esi)
R13: 0x7fffffffe001 --> 0x0 
R14: 0xffffffff 
R15: 0xffffff01
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x7ffff71d73c4 <__GI__IO_fputs+388>:	mov    rdi,rsi
   0x7ffff71d73c7 <__GI__IO_fputs+391>:	call   0x7ffff71886f0 <_Unwind_Resume>
   0x7ffff71d73cc:	nop    DWORD PTR [rax+0x0]
=> 0x7ffff71d73d0 <__GI__IO_fread>:	push   r13
   0x7ffff71d73d2 <__GI__IO_fread+2>:	push   r12
   0x7ffff71d73d4 <__GI__IO_fread+4>:	push   rbp
   0x7ffff71d73d5 <__GI__IO_fread+5>:	push   rbx
   0x7ffff71d73d6 <__GI__IO_fread+6>:	mov    rbx,rsi
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffd268 --> 0x403197 (<_Z6parserv+8455>:	mov    r8d,0x1cd65a05)
0008| 0x7fffffffd270 --> 0x0 
0016| 0x7fffffffd278 --> 0x0 
0024| 0x7fffffffd280 --> 0x0 
0032| 0x7fffffffd288 --> 0x0 
0040| 0x7fffffffd290 --> 0x0 
0048| 0x7fffffffd298 --> 0x0 
0056| 0x7fffffffd2a0 --> 0x0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 1, __GI__IO_fread (buf=0x7fffffffd3c0, size=0x1, count=0x4, fp=0x619c20) at iofread.c:31
31	iofread.c: No such file or directory.

```

So we can see from the stack section of the output from gdb, that there is a call to fread at `0x403197`. Note that this is the only fread call we get. When we go to the section of code in ida, we see the following:

address:	0x403197
```
v59 = fread(input:0, 1uLL, 4uLL, *v540);
v60 = 0x1CD65A05;
*(_DWORD *)input:0:trans = *(_DWORD *)input:0;
check:0 = *(_DWORD *)input:0:trans == 0x17202508;
```

So we can see here that it will read 4 bytes of data from the file `/tmp/.starcraft` and then creates a bool `check:0` that is true if the 4 bytes of data it scans in is equal to the hex string `0x17202508`. We can continue where we left off in gdb to see exactly what data it's scanning in:

```
gdb-peda$ finish
```

after the fread call finishes, set a breakpoint for the cmp instruction for the bool:

```
0x0000000000403197 in parser() ()
Value returned is $1 = 0x4
gdb-peda$ b *0x4031c1
Breakpoint 2 at 0x4031c1
gdb-peda$ c
Continuing.
```

and once we reach the compare

```
Breakpoint 2, 0x00000000004031c1 in parser() ()
gdb-peda$ x/x $rcx
0x7fffffffd3a0:	0x0000000033393531
```

So we can see that the values it's compare against the hex string `0x17202508` are `1593` which are the fircst four characters we inputted. Sonow that we know that the first four characters So with this, we now know what we need to input to pass the first check.

Now this isn't the only check the binary does.  It does six more checks, so these are all of the checks:

```
0x4031c1:	input = 0x17202508
0x4034eb:	input = 0x4b
0x403cb4:	input = 0x3
0x404296:	input = 0xe4ea93
0x40461d:	input = "LUTAREX"
0x4049bc:	input = 0x444556415300
0x404d60:	input = 0x4c4c4100
``` 

So there are a couple of formatting errors you have to worry about, but once you put it all together you get this:

```
#First import pwntools
from pwn import *

#Establish the target, either remote connection or local process
target = process('./prophecy')
#target = remote("reversing.chal.csaw.io", 7668)

#Attach gdb
gdb.attach(target)

#Print out the starting menu, prompt for input from user, then send filename
print target.recvuntil(">>")
raw_input()
target.sendline(".starcraft")

#Prompt for user input to pause
raw_input()

#Form the data to pass the check, then send it
check0 = "\x08\x25\x20\x17"
check1 = "\x4b"*4 + "\x00"  +  "\x4b"*4
check2 = "\x03"*1
check3 = "\x93\xea\xe4\x00"
check4 = "\x5a\x45\x52\x41\x54\x55\x4c"
check5 = "\x00\x53\x41\x56\x45\x44"
check6 = "\x00\x41\x4c\x4c"
target.send(check0 + check1 + check2 + check3 + check4 + check5 + check6)

#Drop to an interactive shell
target.interactive()
```

and when we run it against the server:

```
$	python solve.py 
[+] Opening connection to reversing.chal.csaw.io on port 7668: Done
----------------------------------------------
|PROPHECY PROPHECY PROPHECY PROPHECY PROPHECY| 
----------------------------------------------
[*]Give me the secret name
>>
give me
the flag
[*] Switching to interactive mode
[*]Give me the key to unlock the prophecy
>>[*]Interpreting the secret....
[*]Waiting....
[*]I do not join. I lead!
[*]You'll see that better future Matt. But it 'aint for the likes of us.
[*]The xel'naga, who forged the stars,Will transcend their creation....
[*]Yet, the Fallen One shall remain,Destined to cover the Void in shadow...
[*]Before the stars wake from their Celestial courses,
[*]He shall break the cycle of the gods,Devouring all light and hope.
[*]It begins with the Great Hungerer. It ends in utter darkness.
==========================================================================================================
[*]ZERATUL:flag{N0w_th3_x3l_naga_that_f0rg3d_us_a11_ar3_r3turn1ng_But d0_th3y_c0m3_to_sav3_0r_t0_d3str0y?}
==========================================================================================================
[*]Prophecy has disappered into the Void....
[*] Got EOF while reading in interactive
$ 
[*] Interrupted
[*] Closed connection to reversing.chal.csaw.io port 7668
```

Just like theat, we captured the flag!
