# Plaid Party Planning III 

Full warning, I solved this using the unintended / cheesy solution. With that let's take a look at the binary:

```
$	file pppiii-b73804b431586f8ecd4a0e8c0daf3ba6 
pppiii-b73804b431586f8ecd4a0e8c0daf3ba6: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/l, for GNU/Linux 3.2.0, BuildID[sha1]=8190b786e8260d7cb6e6d183a1f9f182a96f86d6, stripped
$	./pppiii-b73804b431586f8ecd4a0e8c0daf3ba6 
Alphabetical it is, I guess.
Simulating the dinner...

cai: Thank you guys all for helping out. Great job on another Plaid CTF well done!
strikeskids: I got someone to figure out our seating arrangement for us. Hopefully you're
	seated near to dishes you like.
zwad3: Guys, can you please be careful to not get any gluten in the food?
zwad3: *grabs the basmati rice*
strikeskids: *grabs the samosas*
awesie: *grabs the garlic naan*
susie: *grabs the basmati rice*
tylerni7: *grabs the matar methi malai*
jarsp: *grabs the plain naan*
ubuntor: I've saved some of my best ones for tonight!
ubuntor: *grabs the kashmiri naan*
cai: *grabs the samosas*
waituck: *grabs the samosas*
erye: *grabs the mango lassi*
ricky: This looks delicious!
ricky: *grabs the samosa chaat*
strikeskids: *grabs the mango lassi*
zwad3: *grabs the dal makhani*
waituck: *puts the samosas back*
zaratec: *grabs the samosas*
jarsp: *puts the plain naan back*
ricky: *grabs the chaas*
panda: *grabs the plain naan*
strikeskids: *puts the mango lassi back*
zwad3: *grabs the mango lassi*
ricky: *puts the samosa chaat back*
jarsp: *grabs the pakoras*
zwad3: *puts the basmati rice back*
strikeskids: *puts the samosas back*
awesie: *grabs the basmati rice*
jarsp: *puts the pakoras back*
Aborted (core dumped)
``` 

So we are dealing with a 64 bit binary, that crashes when we run it.

### Reversing

When we look at the main function, we see this:
```
signed __int64 __fastcall main(int arg_count, char **argv, char **a3)
{
  int first_arg; // [sp+1Ch] [bp-14h]@1
  signed int i; // [sp+20h] [bp-10h]@2
  signed int j; // [sp+24h] [bp-Ch]@8
  signed int k; // [sp+28h] [bp-8h]@12
  signed int current_placement; // [sp+2Ch] [bp-4h]@9

  setup_((__int64)&x, (__int64)&y);
  first_arg = 1;
  if ( arg_count == 1 )
  {
    puts("Alphabetical it is, I guess.");
    for ( i = 0; i <= 14; ++i )
      placement[8 * i] = i;
  }
  else
  {
    if ( arg_count != 17 )
      abort();
    first_arg = atoi(argv[1]);
    for ( j = 0; j <= 14; ++j )
    {
      placement[8 * j] = atoi(argv[j + 2LL]) - 1;
      current_placement = placement[8 * j];
      if ( current_placement < 0 || current_placement > 14 )
        abort();
      for ( k = 0; k < j; ++k )
      {
        if ( current_placement == placement[8 * k] )
          abort();
      }
    }
  }
  if ( first_arg == 1 )
  {
    puts("Simulating the dinner...\n");
    simulatingDinner((__int64)&x, (__int64)&y);
  }
  else
  {
    puts("Checking the dinner...\n");
    if ( first_arg != 2 )
      abort();
    if ( (unsigned __int8)checkingDinner((__int64)&x, (__int64)&y) ^ 1 )
    {
      printf("Your dinner arrangement was unacceptable. We might never finish :(", &y, argv);
      return 1LL;
    }
  }
  return 0LL;
}
```

Looking at this, we can see that it takes in input via arguments. Depending on the arguments it will either fill the bss section `placement` (at offset `0x2086b0`) with certain values, or exit with `abort`. If we input no arguments, then it will fill in `placament` with values `0-14` in ascending order. If we input `16` arguments (excluding the file name) it will take the first argument and save it in the `first_arg` variable. The last `15` arguments are then saved in the `placement` array (assuming that the arguments are between `0-14` and not repeated, if so the program aborts). Also if we don't either give the program `15` or no arguments (excluding file name) the program aborts.

Also with the setup function, we see that it sets `x` to be a pointer to various strings and function addresses, and sets `y` to be equal to a pointer to various strings and integers. Essentially we are giving the places for people to sit, ranging from `0-14`.

Then it decides to either simulate or check the dinner. This is based upon the value `first_arg` (initialized to `1`). If it is `1` then it simulates it, `2` for checking. If it is a value other than those two then the program aborts. At the moment the `simulatingDinner` function is of more interest to use because we can see that the flag is printed in that function:

```
  custom_print(&v38, (__int64)"It's a flag!", v21, v22, v23, v24, v25);
  tv_thing((__int64)&v38, 5uLL);
  ptr = genFlag(x);
  custom_print(
    (_QWORD *)(x + 256),
    (__int64)"Let me take a look. It seems to say\n\tPCTF{%s}.",
    (__int64)ptr,
    x + 256,
    v27,
    v28,
    v29);
```

However before that happens, we see that this code runs around `0x1829`:

```
  for ( i = 0; i <= 14; ++i )
  {
    if ( pthread_create((pthread_t *)&th[i], 0LL, (void *(*)(void *))start_routine, (void *)(x + 32LL * i)) )
      abort();
  }
  for ( j = 0; j <= 14; ++j )
  {
    if ( pthread_join(th[j], 0LL) )
      abort();
  }
```

What that block does is it takes the functions stored in `x`, and executes them in different threads. In one of those functions somewhere, the program is aborting. After a bit of reversing we find this section of code at `0x3288` in the function at `0x314e`:

```
    if ( strstr(*((const char **)v2 + 1), "paneer") )
      abort();
```

Depending on the order of spots we give, a different string gets compared here. To get past this, I just changed around the spots a bit until I got past that check. Then I ran into another problem where due to the `pthread_join(th[j], 0LL)` calls, the code hangs to the point where we won't get the flag:

```
$	./pppiii-b73804b431586f8ecd4a0e8c0daf3ba6 1 12 13 14 15 1 2 3 4 5 6 7 8 9 10 11
Simulating the dinner...

cai: Thank you guys all for helping out. Great job on another Plaid CTF well done!
strikeskids: I got someone to figure out our seating arrangement for us. Hopefully you're
	seated near to dishes you like.
strikeskids: *grabs the pakoras*
zwad3: Guys, can you please be careful to not get any gluten in the food?
zwad3: *grabs the basmati rice*
zwad3: *grabs the matar methi malai*
tylerni7: *grabs the palak paneer*
erye: *grabs the mango lassi*
awesie: *grabs the kashmiri naan*
cai: *grabs the samosas*
ricky: This looks delicious!
f0xtrot: *grabs the roti*
jarsp: *grabs the garlic naan*
susie: *grabs the basmati rice*
ubuntor: I've saved some of my best ones for tonight!
ubuntor: *grabs the plain naan*
waituck: *grabs the samosas*
strikeskids: *grabs the chaas*
zwad3: *grabs the mango lassi*
waituck: *puts the samosas back*
jarsp: *puts the garlic naan back*
zaratec: *grabs the samosas*
strikeskids: *puts the chaas back*
panda: *grabs the garlic naan*
jarsp: *grabs the samosas*
zwad3: *puts the basmati rice back*
strikeskids: *puts the pakoras back*
awesie: *grabs the basmati rice*
ricky: *grabs the pakoras*
zwad3: *puts the mango lassi back*
ricky: *grabs the mango lassi*
zaratec: *grabs the mango lassi*
awesie: *puts the kashmiri naan back*
jarsp: *puts the samosas back*
ricky: *puts the pakoras back*
zwad3: *puts the matar methi malai back*
strikeskids: *grabs the pakoras*
zaratec: *puts the samosas back*
waituck: *grabs the samosas*
jarsp: *grabs the dal makhani*
erye: *grabs the matar methi malai*
erye: *puts the mango lassi back*
strikeskids: *puts the pakoras back*
ricky: Do I see any cheese in there? Actually, I think I'm good.
zwad3: Hey! Aren't we missing someone?
jarsp: *grabs the mango lassi*
```

However we don't need to figure out how to get past that wall to get the flag. Turns out there is an unintentional solution where we can just jump past this section, and it will print the flag. For this I would set a breakpoint for the `pthread_join` call, then jump to right past the for loop with the `pthread_join` call at `0x18e7`:

First set the breakpoints and run it:
```
ef➤  pie b *0x18be
gef➤  pie b *0x18e7
gef➤  pie run 1 12 13 14 15 1 2 3 4 5 6 7 8 9 10 11
Stopped due to shared library event (no libraries added or removed)
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Simulating the dinner...

.	.	.
```

Then we once we get to the `pthread_join` call, we can just jump past it. We will need to add it's offset to the pie base `0x0000555555554000` since pie is enabled:

```
gef➤  vmmap
Start              End                Offset             Perm Path
0x0000555555554000 0x000055555555c000 0x0000000000000000 r-x /Hackery/plaid19/planning/pppiii-b73804b431586f8ecd4a0e8c0daf3ba6
0x000055555575b000 0x000055555575c000 0x0000000000007000 r-- /Hackery/plaid19/planning/pppiii-b73804b431586f8ecd4a0e8c0daf3ba6
0x000055555575c000 0x000055555575d000 0x0000000000008000 rw- /Hackery/plaid19/planning/pppiii-b73804b431586f8ecd4a0e8c0daf3ba6
0x000055555575d000 0x000055555577e000 0x0000000000000000 rw- [heap]
0x00007fffeffb6000 0x00007fffeffb7000 0x0000000000000000 --- 
0x00007fffeffb7000 0x00007ffff07b7000 0x0000000000000000 rw- 
0x00007ffff07b7000 0x00007ffff07b8000 0x0000000000000000 --- 
0x00007ffff07b8000 0x00007ffff0fb8000 0x0000000000000000 rw- 
0x00007ffff0fb8000 0x00007ffff0fb9000 0x0000000000000000 --- 
0x00007ffff0fb9000 0x00007ffff17b9000 0x0000000000000000 rw- 
0x00007ffff17b9000 0x00007ffff17ba000 0x0000000000000000 --- 
0x00007ffff17ba000 0x00007ffff1fba000 0x0000000000000000 rw- 
0x00007ffff1fba000 0x00007ffff1fbb000 0x0000000000000000 --- 
0x00007ffff1fbb000 0x00007ffff27bb000 0x0000000000000000 rw- 
0x00007ffff27bb000 0x00007ffff27bc000 0x0000000000000000 --- 
0x00007ffff27bc000 0x00007ffff2fbc000 0x0000000000000000 rw- 
0x00007ffff2fbc000 0x00007ffff2fbd000 0x0000000000000000 --- 
0x00007ffff2fbd000 0x00007ffff37bd000 0x0000000000000000 rw- 
0x00007ffff37bd000 0x00007ffff37be000 0x0000000000000000 --- 
0x00007ffff37be000 0x00007ffff3fbe000 0x0000000000000000 rw- 
0x00007ffff3fbe000 0x00007ffff3fbf000 0x0000000000000000 --- 
0x00007ffff3fbf000 0x00007ffff47bf000 0x0000000000000000 rw- 
0x00007ffff47bf000 0x00007ffff47c0000 0x0000000000000000 --- 
0x00007ffff47c0000 0x00007ffff4fc0000 0x0000000000000000 rw- 
0x00007ffff4fc0000 0x00007ffff4fc1000 0x0000000000000000 --- 
0x00007ffff4fc1000 0x00007ffff57c1000 0x0000000000000000 rw- 
0x00007ffff57c1000 0x00007ffff57c2000 0x0000000000000000 --- 
0x00007ffff57c2000 0x00007ffff5fc2000 0x0000000000000000 rw- 
0x00007ffff5fc2000 0x00007ffff5fc3000 0x0000000000000000 --- 
0x00007ffff5fc3000 0x00007ffff67c3000 0x0000000000000000 rw- 
0x00007ffff67c3000 0x00007ffff67c4000 0x0000000000000000 --- 
0x00007ffff67c4000 0x00007ffff6fc4000 0x0000000000000000 rw- 
0x00007ffff6fc4000 0x00007ffff6fc5000 0x0000000000000000 --- 
0x00007ffff6fc5000 0x00007ffff77c5000 0x0000000000000000 rw- 
0x00007ffff77c5000 0x00007ffff79ac000 0x0000000000000000 r-x /lib/x86_64-linux-gnu/libc-2.27.so
0x00007ffff79ac000 0x00007ffff7bac000 0x00000000001e7000 --- /lib/x86_64-linux-gnu/libc-2.27.so
0x00007ffff7bac000 0x00007ffff7bb0000 0x00000000001e7000 r-- /lib/x86_64-linux-gnu/libc-2.27.so
0x00007ffff7bb0000 0x00007ffff7bb2000 0x00000000001eb000 rw- /lib/x86_64-linux-gnu/libc-2.27.so
0x00007ffff7bb2000 0x00007ffff7bb6000 0x0000000000000000 rw- 
0x00007ffff7bb6000 0x00007ffff7bd0000 0x0000000000000000 r-x /lib/x86_64-linux-gnu/libpthread-2.27.so
0x00007ffff7bd0000 0x00007ffff7dcf000 0x000000000001a000 --- /lib/x86_64-linux-gnu/libpthread-2.27.so
0x00007ffff7dcf000 0x00007ffff7dd0000 0x0000000000019000 r-- /lib/x86_64-linux-gnu/libpthread-2.27.so
0x00007ffff7dd0000 0x00007ffff7dd1000 0x000000000001a000 rw- /lib/x86_64-linux-gnu/libpthread-2.27.so
0x00007ffff7dd1000 0x00007ffff7dd5000 0x0000000000000000 rw- 
0x00007ffff7dd5000 0x00007ffff7dfc000 0x0000000000000000 r-x /lib/x86_64-linux-gnu/ld-2.27.so
0x00007ffff7fd8000 0x00007ffff7fdd000 0x0000000000000000 rw- 
0x00007ffff7ff7000 0x00007ffff7ffa000 0x0000000000000000 r-- [vvar]
0x00007ffff7ffa000 0x00007ffff7ffc000 0x0000000000000000 r-x [vdso]
0x00007ffff7ffc000 0x00007ffff7ffd000 0x0000000000027000 r-- /lib/x86_64-linux-gnu/ld-2.27.so
0x00007ffff7ffd000 0x00007ffff7ffe000 0x0000000000028000 rw- /lib/x86_64-linux-gnu/ld-2.27.so
0x00007ffff7ffe000 0x00007ffff7fff000 0x0000000000000000 rw- 
0x00007ffffffde000 0x00007ffffffff000 0x0000000000000000 rw- [stack]
0xffffffffff600000 0xffffffffff601000 0x0000000000000000 r-x [vsyscall]
gef➤  j *0x5555555558e7
Continuing at 0x5555555558e7.
f0xtrot: *grabs the roti*
erye: *grabs the mango lassi*
cai: *grabs the samosas*
awesie: *grabs the kashmiri naan*
jarsp: *grabs the garlic naan*
ricky: This looks delicious!
ricky: *grabs the pakoras*
ubuntor: I've saved some of my best ones for tonight!
ubuntor: *grabs the plain naan*
strikeskids: I got someone to figure out our seating arrangement for us. Hopefully you're
	seated near to dishes you like.
waituck: *grabs the samosas*
susie: *grabs the basmati rice*
tylerni7: *grabs the palak paneer*
zwad3: Guys, can you please be careful to not get any gluten in the food?
zwad3: *grabs the basmati rice*

```

Then when we hit the final breakpoint, we can just continue and we will get the flag:

```
Thread 1 "pppiii-b73804b4" hit Breakpoint 2, 0x00005555555558e7 in ?? ()
gef➤  c
Continuing.
erye: *grabs the matar methi malai*
jarsp: *puts the garlic naan back*
panda: *grabs the garlic naan*
ricky: *grabs the mango lassi*
waituck: *puts the samosas back*
zaratec: *grabs the samosas*
ricky: *puts the pakoras back*
jarsp: *grabs the samosas*
zaratec: *grabs the mango lassi*
erye: *puts the mango lassi back*
strikeskids: *grabs the pakoras*
strikeskids: *grabs the chaas*
ricky: Do I see any cheese in there? Actually, I think I'm good.
ricky: *grabs the dal makhani*
zaratec: *puts the samosas back*
erye: *grabs the mango lassi*
waituck: *grabs the samosas*
jarsp: *puts the samosas back*
erye: *puts the mango lassi back*
strikeskids: *puts the chaas back*
ricky: *puts the dal makhani back*
jarsp: *grabs the dal makhani*
strikeskids: *puts the pakoras back*
ricky: *puts the mango lassi back*
jarsp: *grabs the mango lassi*
bluepichu: Sorry we're late. There wasn't enough meat here, so I decided to go
	make some spaghetti with alfredo sauce, mushrooms, and chicken at home.
strikeskids: *grabs the pakoras*
mserrano: I decided to tag along because, as you know, cheese is very desirable.
strikeskids: *puts the pakoras back*
bluepichu: And I bought a ton of extra parmesan!
mserrano: Anyway, we brought you guys a gift.
bluepichu: It's a flag!
strikeskids: Let me take a look. It seems to say
	PCTF{1 l1v3 1n th3 1nt3rs3ct1on of CSP and s3cur1ty and parti3s!}.
strikeskids: Hopefully that's useful to someone.
[Thread 0x7ffff07b6700 (LWP 13635) exited]
[Thread 0x7ffff0fb7700 (LWP 13634) exited]
[Thread 0x7ffff17b8700 (LWP 13633) exited]
[Thread 0x7ffff1fb9700 (LWP 13632) exited]
[Thread 0x7ffff27ba700 (LWP 13631) exited]
[Thread 0x7ffff2fbb700 (LWP 13630) exited]
[Thread 0x7ffff47be700 (LWP 13627) exited]
[Thread 0x7ffff37bc700 (LWP 13629) exited]
[Thread 0x7ffff4fbf700 (LWP 13626) exited]
[Thread 0x7ffff57c0700 (LWP 13625) exited]
[Thread 0x7ffff5fc1700 (LWP 13624) exited]
[Thread 0x7ffff67c2700 (LWP 13623) exited]
[Thread 0x7ffff6fc3700 (LWP 13622) exited]
[Thread 0x7ffff77c4700 (LWP 13621) exited]
[Thread 0x7ffff7fd8740 (LWP 13617) exited]
[Inferior 1 (process 13617) exited normally]
```

Just like that we got the flag `PCTF{1 l1v3 1n th3 1nt3rs3ct1on of CSP and s3cur1ty and parti3s!}`.
