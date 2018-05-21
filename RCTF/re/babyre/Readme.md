# babyre

This is a Reversing challenge from RCTF 2018. So for this challenge we are given two files in our zip. Let's see what they are:

```
$	file babyre 
babyre: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=809e8a49ddb6f593c8e2082edec06f963518faea, stripped
$	file out 
out: ASCII text, with CRLF line terminators
$	cat out 
B80C91FE70573EFE
BEED92AE7F7A8193
7390C17B90347C6C
AA7A15DFAA7A15DF
526BA076153F1A32
545C15AD7D8AA463
526BA076FBCB7AA0
7D8AA4639C513266
526BA0766D7DF3E1
AA7A15DF9C513266
1EDC38649323BC07
7D8AA463FBCB7AA0
153F1A32526BA076
F5650025AA7A15DF
1EDC3864B13AD888
$	./babyre 
15
15
your input:try again15935728
526ba076
7f08e077
545c15ad
a1e10430
7f08e077
20067e4b
ae4c822d
28def57e
b8c4f788
b8c4f788
b8c4f788
b8c4f788
b8c4f788
b8c4f788
b8c4f788
b8c4f788
b8c4f788
b8c4f788
b8c4f788
b8c4f788
b8c4f788
b8c4f788
b8c4f788
b8c4f788
b8c4f788
b8c4f788
b8c4f788
b8c4f788
b8c4f788
b8c4f788
your input:try again
```

So we can see that we are given an ASCII file with what appears to be a lot of hex strings. We can see that we also have an elf which takes input three times, and outputs a lot of hex strings. When we look at the hex strings we have, we can see that they are about half the lenght (eight characters) when compared to the hex strings in the ASCII file (sixteen characters). Also we can see that the elf produces twice the amount of hex strings. So what we probably will need to do is figure out how to get the elf to output the contents of the `out` file. Let's take a look at the elf in a decompiler:

Main Function:
```
int __cdecl main()
{
  int result; // eax@7
  int v1; // ecx@7
  unsigned int seed; // [sp+18h] [bp-80h]@1
  int v3; // [sp+1Ch] [bp-7Ch]@1
  int v4; // [sp+20h] [bp-78h]@7
  char v5; // [sp+24h] [bp-74h]@7
  char v6; // [sp+4Ch] [bp-4Ch]@7
  char s; // [sp+6Ch] [bp-2Ch]@1
  int v8; // [sp+8Ch] [bp-Ch]@1

  v8 = *MK_FP(__GS__, 20);
  v3 = 0x25DB3;
  memset(&s, 0, 0x20u);
  scanf("%s", &s);
  scanf("%d", &seed);
  if ( (signed int)seed <= 9 )
  {
    puts("needmorestrings");
    exit(0);
  }
  if ( (signed int)seed > 32 )
  {
    puts("stringsaretoolong");
    exit(0);
  }
  srand(seed);
  seed ^= v4 + (v4 ^ seed);
  v3 = (unsigned __int8)v4;
  v4 = (unsigned __int8)v4 << 8;
  first_and_fifth_check();
  sub_8048A41((int)&v5);
  important_func(&v6, 0xA72BE4C1, 0x1D082C23, seed, v4, v3);
  sub_8048980(&s);
  first_and_fifth_check();
  putchar(10);
  result = 0;
  v1 = *MK_FP(__GS__, 20) ^ v8;
  return result;
}
```

So we can see a lot of interesting things here. First we can see that the first input it prompts us for is scanned into the `s` char array, however it doesn't specify how much so we have a buffer overflow bug (not important to the challenge, but I thought it was funny for it to be in an RE chall). Proceeding that our second input an integer to the int `seed` which needs to be between 10-31 otherwise the program will exit. After that `seed` is used as a seedfor the `srand` function. Proceeding that we can see that it assigns values to `seed`, `v3`, and `v4` however we don't have any control over that. For `seed` this is because it ends up zoring it by itself so no matter what we put it is going to end up zero, and for the two our input doesn't influence their value. Let's look at the function `first_and_fifth_check()`:

```
int first_and_fifth_check()
{
  int result; // eax@1
  __int32 random_int; // edx@3
  int v2; // ecx@11
  signed int i0; // [sp+0h] [bp-48h]@1
  signed int i1; // [sp+4h] [bp-44h]@4
  int v5[3]; // [sp+8h] [bp-40h]@6
  int storage_int_array[10]; // [sp+14h] [bp-34h]@3
  int v7; // [sp+3Ch] [bp-Ch]@1

  v7 = *MK_FP(__GS__, 20);
  result = 0;
  for ( i0 = 0; i0 <= 9; ++i0 )
  {
    random_int = random();
    result = i0;
    storage_int_array[i0] = random_int;
  }
  for ( i1 = 0; i1 <= 2; ++i1 )
  {
    printf("your input:");
    alarm(0xAu);
    result = storage_int_array[i1 + 2];
    if ( v5[i1] != result )
    {
      result = printf("try again");
      break;
    }
    if ( i1 != 2 )
      result = puts("go on!");
  }
  v2 = *MK_FP(__GS__, 20) ^ v7;
  return result;
}
```

So for this function, we can see that in order for it to print out the string `go on`, and not to get the string `try again` we will have to get the `random` function to output a value of 0 with a seed between 10-31. The reason for this is the if then statement which decides that checks to see if the output of the random function (stored in the `storage_int_array` and transferred to the `result` int) is equivalent to the corresponding value of the `v5` array, which is zero since it was never assigned. To see if this was possible, I wrote a quick C program just to output the first value of the `random` function using all of our possible seeds here:

```
$	cat random.c
int first_and_fifth_check()
{
  int result; // eax@1
  __int32 random_int; // edx@3
  int v2; // ecx@11
  signed int i0; // [sp+0h] [bp-48h]@1
  signed int i1; // [sp+4h] [bp-44h]@4
  int v5[3]; // [sp+8h] [bp-40h]@6
  int storage_int_array[10]; // [sp+14h] [bp-34h]@3
  int v7; // [sp+3Ch] [bp-Ch]@1

  v7 = *MK_FP(__GS__, 20);
  result = 0;
  for ( i0 = 0; i0 <= 9; ++i0 )
  {
    random_int = random();
    result = i0;
    storage_int_array[i0] = random_int;
  }
  for ( i1 = 0; i1 <= 2; ++i1 )
  {
    printf("your input:");
    alarm(0xAu);
    result = storage_int_array[i1 + 2];
    if ( v5[i1] != result )
    {
      result = printf("try again");
      break;
    }
    if ( i1 != 2 )
      result = puts("go on!");
  }
  v2 = *MK_FP(__GS__, 20) ^ v7;
  return result;
}
$	/random 
0x486c7c6f
0x76927bbf
0x648e8cd0
0x50fa73aa
0x7fef911b
0x2d6fc2d5
0x1b93747c
0x49308bb9
0x76ebdb56
0x25265e19
0x130c47c7
0x40c15130
0x6eb933c2
0x5d21660e
0xb3a3849
0x783cd2dd
0x65d471b5
0x54756825
0x42322373
0x70206b77
0x1d6f8fa5
0x4bca8e48
```

As you can see with our given constraints it isn't possible to pass that check. However that doesn't matter since the only thing that happens if the check passes is it will print an unimportant string and continue the loop. So in the end we really don't care about that function. When we look at the second function called in main which is `sub_8048A41` we find a similar situation. This is because our input doesn't effect that function in any way. The argument that is passed to it `v5` we don't get to influence it's value at all, and looking at what the function does we can see that it doesn't prompt us for more input or use any of our existing input. Then that brings us to the next function it calls which is `important_func`:


important_func
```
int __cdecl important_func(void *input, int a2, int a3, int a4, int a5, int a6)
{
  unsigned int v6; // ST4C_4@3
  signed int i; // [sp+1Ch] [bp-1Ch]@1

  memset(input, 0, 0x20u);
  scanf("%s", input);
  for ( i = 0; i <= 29; ++i )
  {
    v6 = process_input(*((_BYTE *)input + i), __PAIR__(a3, a2), a4, a6, a5);
    printf("%lx\n", v6);
  }
  return i;
}
```

So here we can see it prompts us for our third input which is stored in `input`. In addition to that we can see that it runs each character of our input (plus some other arguments) through the `process_input` function, then prints the result of that. This is where we get the output that we think needs to match the contents of the `out` file. When we look at what `process_input` does, we see it runs it through an algorithm however there is an easier way of figuring out how to get the output we need:

```
$	./babyre 
25
25
your input:try again000000000000000000000000000000
c567b6b6
c567b6b6
c567b6b6
c567b6b6
c567b6b6
c567b6b6
c567b6b6
c567b6b6
c567b6b6
c567b6b6
c567b6b6
c567b6b6
c567b6b6
c567b6b6
c567b6b6
c567b6b6
c567b6b6
c567b6b6
c567b6b6
c567b6b6
c567b6b6
c567b6b6
c567b6b6
c567b6b6
c567b6b6
c567b6b6
c567b6b6
c567b6b6
c567b6b6
c567b6b6
your input:try again
$	./babyre 
eyes
10
your input:try again000000000000000000000000000000
c567b6b6
c567b6b6
c567b6b6
c567b6b6
c567b6b6
c567b6b6
c567b6b6
c567b6b6
c567b6b6
c567b6b6
c567b6b6
c567b6b6
c567b6b6
c567b6b6
c567b6b6
c567b6b6
c567b6b6
c567b6b6
c567b6b6
c567b6b6
c567b6b6
c567b6b6
c567b6b6
c567b6b6
c567b6b6
c567b6b6
c567b6b6
c567b6b6
c567b6b6
c567b6b6
your input:try again
```

So when we ran the program twice, we can see two things. The first thing is that the first two inputs we gave doesn't affect the hex strings it outputs. The second is that the hex string it outputs is independent of it's position in the for loop, meaning that if we input the same character in the first and last (or any) iteration of the loop, we will get the same output. With this we don't need to reverse the `process_input` function anymore, we can just run ASCII characters through the function, record the outputs, and correlate them to the contents of the `out` file, and use that to figure out what the flag is. With that, we get the following ranges needed to get the flag:

```
a:	0x9c513266
b:	0x30a3769a
c:	0xaa8afbba
d:	0x1edc3864
e:	0xaa7a15df
f:	0x6c1194bf
g:	0xeade7bf1
h:	0x115f3801
i:	0x42bafa35
j:	0xa5a30516
k:	0x4e032f9f
l:	0x121ee8ab
m:	0xe75d55e4
n:	0x7f543d62
o:	0x153f1a32
p:	0x6d076b18
q:	0xf3857621
r:	0x6d7df3e1
s:	0xfbcb7aa0
t:	0x36b897bd
u:	0x82c974fc
v:	0xf5650025
w:	0x90f77ba1
x:	0xf9b8d92b
y:	0x9323bc07
z:	0xa5c88e2

0:	0xc567b6b6
1:	0x526ba076
2:	0xae4c822d
3:	0xa1e10430
4:	0xc3f2de73
5:	0x7f08e077
6:	0x7240b7ba
7:	0x20067e4b
8:	0x28def57e
9:	0x545c15ad
!:	0xb8a6ee10
@:	0x3e968078
#:	0xf1b1602
$:	0x2571a420
%:	0x805feee3
^:	0xa8f27e12
&:	0x958b0534
*:	0xee152dad
(:	0x45c66c5a
):	0xcda47499
-:	0x7386bd6a
_:	0x7d8aa463
=:	0x6958d9df
+:	0x77591917

K:	0x90347C6C
```

With that we can figure out that the flag is `RCTF{Kee1o9_1s_a1ready_so1ved}`. Just like that, we captured the flag!
