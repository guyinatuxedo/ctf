# rev_rev_rev

Let's take a look at the binary:

```
$    file rev_rev_rev-a0b0d214b4aeb9b5dd24ffc971bd391494b9f82e2e60b4afc20e9465f336089f
rev_rev_rev-a0b0d214b4aeb9b5dd24ffc971bd391494b9f82e2e60b4afc20e9465f336089f: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=e33eb178391bae637823f4645d63d63eac3a8d07, stripped
```

So we can see that it is a 32 bit linux binary. Let's try to run it:

```
$    ./rev_rev_rev-a0b0d214b4aeb9b5dd24ffc971bd391494b9f82e2e60b4afc20e9465f336089f
Rev! Rev! Rev!
Your input: gimme that flag
Invalid!
```

So it asks for input, and it told us it was invalid. My guess is that this program takes input, alters it, and compares it against a string. Let's take a look at the main function:

```
int __cdecl main()
{
  int result; // eax@7
  int v1; // edx@7
  char input_buf; // [sp+1Bh] [bp-2Dh]@1
  int v3; // [sp+3Ch] [bp-Ch]@1

  v3 = *MK_FP(__GS__, 20);
  puts("Rev! Rev! Rev!");
  printf("Your input: ");
  if ( !fgets(&input_buf, 33, stdin) )
  {
    puts("Input Error.");
    exit(0);
  }
  str_func(&input_buf);
  rev_func(&input_buf);
  enc_func(&input_buf);
  not_func(&input_buf);
  if ( !strcmp(&input_buf, desired_output) )
    puts("Correct!");
  else
    puts("Invalid!");
  result = 0;
  v1 = *MK_FP(__GS__, 20) ^ v3;
  return result;
}
```

So we can see that this function scans in input into `input_buf`, then runs it through four different functions (`str_func`, `rev_func`, `enc_func`, and `not_func`). Then it compares `input_buf` against the hex string `desired_output`. So essentially it scans in input, alters it, and compares it against a predefined string. Let's take a look at `str_func`:

```
char *__cdecl str_func(char *input)
{
  char *newline; // eax@1

  newline = strchr(input, 0xA);
  *newline = 0;
  return newline;
}
```

Looking at this function, we can see that it first looks for the character `0xa`, which is a newline character. Then it set's that equal to `0x0`. So essentially it replaces the newline character with a null byte. Let's take a look at `rev_func`:

```
char *__cdecl rev_func(char *input)
{
  char x; // ST17_1@2
  char *result; // eax@3
  char *input_ptr; // [sp+8h] [bp-10h]@1
  char *i; // [sp+Ch] [bp-Ch]@1

  input_ptr = input;
  for ( i = &input[strlen(input) - 1]; ; --i )
  {
    result = input_ptr;
    if ( input_ptr >= i )
      break;
    x = *input_ptr;
    *input_ptr = *i;
    *i = x;
    ++input_ptr;
  }
  return result;
}
```

This code essentially takes our input (which has had the newline character stripped) and just reverses it. For instance if we gave the program `1234`, it would reverse it to `4321`. Now let's look at `enc_func`.

```
int __cdecl enc_func(char *input)
{
  char x; // ST0B_1@2
  unsigned __int8 y; // ST0B_1@2
  int result; // eax@3
  char *input_ptr; // [sp+Ch] [bp-4h]@1

  for ( input_ptr = input; ; ++input_ptr )
  {
    result = (unsigned __int8)*input_ptr;
    if ( !(_BYTE)result )
      break;
    x = 2 * (*input_ptr & 0x55) | (*input_ptr >> 1) & 0x55;
    y = 4 * (x & 0x33) | (x >> 2) & 0x33;
    *input_ptr = 16 * y | (y >> 4);
  }
  return result;
}
```

This function alters the input, by performing various binary operations on our input (and in one case, multiplying it). We can see that it is a for loop, that will run once per each character of our input. It will take the hex value of each character of our input and alter it, however it will only take the first 8 bits worth of data (so the least significant bit). This code effectively translates to the following python:

```
def enc(input):
    output = ""
    for c in input:
        c = ord(c)
        x = (2 * (c & 0x55)) | ((c >> 1) & 0x55)
        print "x is: " + hex(x)
        y = (4 * (x & 0x33)) | ((x >> 2) & 0x33)
        print "y is: " + hex(y)
        z = (16 * y) | ( y >> 4)
        print "z is: " + hex(z)
        output = hex(z).replace("0x", "")[-2:] + output
    return output

input = "xut"
out = enc(input)  
print "output: 0x" + out
```

Keep in mind, the input for that python script needs to be reversed. So now that we know what the `enc_func` does, we can take a look at the final function:

```
int __cdecl not_func(_BYTE *input)
{
  int result; // eax@3
  _BYTE *i; // [sp+Ch] [bp-4h]@1

  for ( i = input; ; ++i )
  {
    result = *i;
    if ( !(_BYTE)result )
      break;
    *i = ~*i;
  }
  return result;
}
```

So like the previous function, this runs a loop that iterates for each character of the input. However this time it alters each character by performing a binary not (which it's operator in c is `~`). Essentially it takes the binary value of the character, and converts the zeroes to ones and ones to zeroes. For instance:

```
0:    0x30:    00110000
NOT 0:        11001111 = 0xcf
```

it essentially performs the same function as this python script:

```
def not_inp(inp):
    output = 0x0
    result = ""
    string = bin(inp).replace("0b", "")
    print "Binary string is: " + string
    for s in string:
        if s == "0":
            result += "1"
        if s == "1":
            result += "0"
    print "Binary inverse is: " + result
    output = int(result, 2)
    return output
```

So we understand what the four functions do. We could of also figured out what some of the functions do by using gdb, and looking at the value of `input_buf` changes (it's how I figured out what the first two functions did):

Set the breakpoints before each of the four functions is called, and the final strcmp:
```
gdb-peda$ b *0x0804862b
Breakpoint 1 at 0x804862b
gdb-peda$ b *0x0804863a
Breakpoint 2 at 0x804863a
gdb-peda$ b *0x08048649
Breakpoint 3 at 0x8048649
gdb-peda$ b *0x08048658
Breakpoint 4 at 0x8048658
gdb-peda$ b *0x0804866d
Breakpoint 5 at 0x804866d
gdb-peda$ r
Starting program: /Hackery/west/rev/rev_rev_rev-a0b0d214b4aeb9b5dd24ffc971bd391494b9f82e2e60b4afc20e9465f336089f
Rev! Rev! Rev!
Your input: tux

```

Before `str_func` is called:
```
Breakpoint 1, 0x0804862b in ?? ()
gdb-peda$ x/s $eax
0xffffd07b:    "tux\n"
gdb-peda$ c
Continuing.
```

After `str_func`, before `rev_func`:
```
Breakpoint 2, 0x0804863a in ?? ()
gdb-peda$ x/s $eax
0xffffd07b:    "tux"
gdb-peda$ c
Continuing.
```

After `rev_func`, before `enc_func`:

```
Breakpoint 3, 0x08048649 in ?? ()
gdb-peda$ x/s $eax
0xffffd07b:    "xut"
gdb-peda$ c
Continuing.
```

After `enc_func`, before `not_func`:
```
Breakpoint 4, 0x08048658 in ?? ()
gdb-peda$ x/x $eax
0xffffd07b:    0x1e
gdb-peda$ x/w $eax
0xffffd07b:    0x002eae1e
gdb-peda$ x/s $eax
0xffffd07b:    "\036\256."
gdb-peda$ c
Continuing.
```

After `not_func`, before `strcmp`:
```
Breakpoint 5, 0x0804866d in ?? ()
gdb-peda$ x/x $eax
0xffffd07b:    0xe1
gdb-peda$ x/w $eax
0xffffd07b:    0x00d151e1
```

So we can see the text altered as it is passed through the function. Now that we know what happens to the text, we just need to know what it needs to be after all of it. When we see what value `desired_output` holds, we see this:

```
.rodata:08048870 desired_output_storage db  41h ; A      ; DATA XREF: .data:desired_outputo
.rodata:08048871                 db  29h ; )
.rodata:08048872                 db 0D9h ; +
.rodata:08048873                 db  65h ; e
.rodata:08048874                 db 0A1h ; í
.rodata:08048875                 db 0F1h ; ±
.rodata:08048876                 db 0E1h ; ß
.rodata:08048877                 db 0C9h ; +
.rodata:08048878                 db  19h
.rodata:08048879                 db    9
.rodata:0804887A                 db  93h ; ô
.rodata:0804887B                 db  13h
.rodata:0804887C                 db 0A1h ; í
.rodata:0804887D                 db    9
.rodata:0804887E                 db 0B9h ; ¦
.rodata:0804887F                 db  49h ; I
.rodata:08048880                 db 0B9h ; ¦
.rodata:08048881                 db  89h ; ë
.rodata:08048882                 db 0DDh ; ¦
.rodata:08048883                 db  61h ; a
.rodata:08048884                 db  31h ; 1
.rodata:08048885                 db  69h ; i
.rodata:08048886                 db 0A1h ; í
.rodata:08048887                 db 0F1h ; ±
.rodata:08048888                 db  71h ; q
.rodata:08048889                 db  21h ; !
.rodata:0804888A                 db  9Dh ; ¥
.rodata:0804888B                 db 0D5h ; +
.rodata:0804888C                 db  3Dh ; =
.rodata:0804888D                 db  15h
.rodata:0804888E                 db 0D5h ; +
.rodata:0804888F                 db    0
```

So we can see that it is equal to a hex string starting with `0x41` and ending with `0x0`. So now that we know what it needs to be equal to we can use the solver z3. Essentially once we define what happens to the input, z3 will tell us what input we need to meet the desired output.

 I made two scripts, one to undo the binar not, and one to figure out the input needed to get the desired output out of `enc_func`. Also to account for `rev_func` I just inputted the hex string backwards. Now for the script to undo the binary not:
 
```
#Establish the flag after the binary not
flag = [ 0xd5, 0x15, 0x3d, 0xd5, 0x9d, 0x21, 0x71, 0xf1, 0xa1, 0x69, 0x31, 0x61, 0xdd, 0x89, 0xb9, 0x49, 0xb9, 0x09, 0xa1, 0x13, 0x93, 0x09, 0x19, 0xc9, 0xe1, 0xf1, 0xa1, 0x65, 0xd9, 0x29, 0x41]

#Establish the function to execute the binary not
def not_inp(inp):
    output = 0x0
    result = ""
    string = bin(inp).replace("0b", "")
    #Check if there are less than 8 bits, and if so add zeroes to the front to get 8 bits
    if len(string) < 8:
        diff = 8 - len(string)
        string = diff*"0" + string
    print "Binary string is:  " + string
    
    #Swap the ones with zeroes, and vice versa
    for s in string:
        if s == "0":
            result += "1"
        if s == "1":
            result += "0"
    print "Binary inverse is: " + result
    
    #Convert the binary string to an int, and return it
    output = int(result, 2)
    return output

#Establish the array which will hold the output
out = []
#Iterate through each character of the flag, and undo the binary not
for i in flag:
    x = not_inp(i)
    out.append(x)
    print hex(x)

#Print the flag before the binary not
print "alt_flag = " + str(out)

```

when we run the script, we see that the hex string before the binary not happens is equal to this:

```
alt_flag = [42, 234, 194, 42, 98, 222, 142, 14, 94, 150, 206, 158, 34, 118, 70, 182, 70, 246, 94, 236, 108, 246, 230, 54, 30, 14, 94, 154, 38, 214, 190]
```

With this info, we can just use z3 to figure out the input needed for `enc_func` to output that:

```
#Import z3
from z3 import *

#Establish the hex array of what the end result should be before the binary not
alt_flag = [42, 234, 194, 42, 98, 222, 142, 14, 94, 150, 206, 158, 34, 118, 70, 182, 70, 246, 94, 236, 108, 246, 230, 54, 30, 14, 94, 154, 38, 214, 190]

#Establish the solving function
def solve(alt_flag):    
    #Establish the solver
    zolv = Solver()

    #Establish the array which will hold all of the integers which we will input
    inp = []
    for i in range(0, len(alt_flag)):
        b = BitVec("%d" % i, 16)
        inp.append(b)

    #Run the same text altering function as enc_func
    for i in range(0, len(alt_flag)):
        x = (2 * (inp[i] & 0x55)) | ((inp[i] >> 1) & 0x55)
        y = (4 * (x & 0x33)) | ((x >> 2) & 0x33)
        z = (16 * y) | ( y >> 4)
        #We need to and it by 0xff, that way we only get the last 8 bits
        z = z & 0xff
        #Add the condition to z3 that we need to end value to be equal to it's corresponding alt_flag value
        zolv.add( z == alt_flag[i])

    #Check if the problem is solvable by z3
    if zolv.check() == sat:
        print "The condition is satisfied, would still recommend crying: " + str(zolv.check())
        #The problem is solvable, model it and print the solution
        solution = zolv.model()
        flag = ""
        for i in range(0, len(alt_flag)):
            flag += chr(int(str(solution[inp[i]])))
        print flag

    #The problem is not solvable by z3    
    if zolv.check() == unsat:
        print "The condition is not satisfied, would recommend crying: " + str(zolv.check())


solve(alt_flag)
```

let's run it!

```
$    python solve.py
The condition is satisfied, would still recommend crying: sat
TWCTF{qpzisyDnbmboz76oglxpzYdk}
```

Just like that, we captured the flag!
