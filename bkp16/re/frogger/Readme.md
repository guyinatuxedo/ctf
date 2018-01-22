# frog-fraction-2

This is based off of these writeups:

```
https://github.com/ByteBandits/writeups/tree/master/bostonkeyparty-2016/reverse/Alewife/sudhackar
https://github.com/p4-team/ctf/tree/master/2016-03-06-bkpctf/re_5_Frog_Fractions_2
```

Let's take a look at the binary:

```
$	file frog 
frog: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=a4d814d0167c1c0732e8fdf0e25c368c61d6b27d, not stripped
$	./frog 
15935728
Nope!  You need to practice your fractions!
```

So we are dealing with an x64 program that scans in input, then checks it. Looking at the code in IDA, we can see that it use the `gmp` library (official website: https://gmplib.org/ useful documentation: http://web.mit.edu/gnu/doc/html/gmp_4.html). This is a library that is designed to hand really large numbers in C. Before we start looking at the code in IDA, I'm just going to review some of the functions from the `gmp` library which we will be deailing with:

All of this is coming from the wonderful documentation at: http://web.mit.edu/gnu/doc/html/gmp_4.html
```c
gmpz_init( MP_INT *integer)
```
This takes a pointer to a struct and initializes it be an integer which gmp can use, with the initial value of 0. 

```c
gmpz_set_ui(MP_INT *integer, unsigned long int initial_value)
```
This function will change the value of `integer` to whatever `initial_value` is.

```c
mpz_pow_ui(MP_INT *res, MP_INT *base, unsigned long int exp)
```

This function takes sets `res` equal to `based` raised to the `exp` power. 

```c
mpz_mul(MP_INT *product, MP_INT *multiplicator, MP_INT *multiplicand)
```

This function sets `product` equal to `multiplicator * multiplicand`

```c
mpz_sscanf(char *input_string, char *format_string, char *storage_string)
```

This is like the typical scanf function, it will scan in `input_string` into `storage_int` using `format_string` for formatting (from: http://van.prooyen.com/reversing/2016/03/11/Frog-Fractions-2.html)

```c
mpz_div(MP_INT * quotient, MP_INT *dividend, MP_INT *divisor)
```

This sets `quotient` equal to `dividend / divisor`

```c
mpz_divisible(MP_INT *dividend, MP_INT *divisor)
```

This returnns a `true/flase` value depending on if `dividend/divisor` does not have a remainder.

also this is the strut of an `MP_INT`
```c
// 16 bytes total
int size; //This is the amount of DWORDS which the number takes up 4 bytes
int ?; // idk what this does, but it takes up four bytes
int * //This is a pointer to the actual integer itself is stored in memory
```

and now let's look at the first section of code:

```
  __gmpz_init((__int64)&gmp_int_0, (__int64)argv, (__int64)envp);
  __gmpz_init((__int64)&gmp_int_1, (__int64)argv, v3);
  __gmpz_set_ui(&gmp_int_0, 0x3FBLL);
  size = 0xACLL;
  input = (char *)malloc(0xACuLL);
  size_pointer = &size;
  bytes_allocated = getline(&input, &size, _bss_start);
  input[bytes_allocated - 1] = 0;
```

When we look at the C pseudocode, we see something wierd. `gmpz_init()` is given three arguments when it should be given one. Looking at the assembly code for those two calls gives us the truth:

```
.text:0000000000400CDD                 lea     rax, [rbp+gmp_int_0]
.text:0000000000400CE1                 mov     rdi, rax
.text:0000000000400CE4                 call    ___gmpz_init
.text:0000000000400CE9                 lea     rax, [rbp+gmp_int_1]
.text:0000000000400CED                 mov     rdi, rax
.text:0000000000400CF0                 call    ___gmpz_init
```

Looking here we can see that the two calls only take one argument. Hex-Rays doesn't always get things write on the first try, and this is one of those cases. So it starts off by initializing the two MP_INTS `gmp_int_0` and `gmp_int_1`, and then sets the value of `gmp_int_0` to `0x3fb`.  After that we can see it mallocs `0xac` bytes worth of data in heap, and then scans in that much data into that space, and then null terminates it. It stores the amount of bytes allocated in `bytes_allocated`, which will be one fore every character plus the newline. Let's look at the next block:

```c
  for ( i = 0; ; ++i )
  {
    i_transfer = (double)i;
    if ( fmin((double)bytes_allocated, 84.0) <= i_transfer )// This will break once i > len(input + '\n')
      break;
    __gmpz_set_ui(&gmp_int_1, primes[i]);
    __gmpz_pow_ui(&gmp_int_1, &gmp_int_1, input[i]);
    size_pointer = (size_t *)&gmp_int_0;
    __gmpz_mul(&gmp_int_0, &gmp_int_0, &gmp_int_1);
  }
```

So here we can see that we have a for loop, that will run once for each character of input plus one (because of the newline character `getline()` appends to the end), or when there are 84 iterations (whichever one comes first). For each loop we can see that `gmp_int_1` is set equal to whatever `primes[i]` is equal to, then set equal to `gmp_int_1 ^ input[i]`. Let's take a look at `primes`:

```
.rodata:000000000040D9E0 ; int primes[]
.rodata:000000000040D9E0 primes          dd 2                    ; DATA XREF: factor_print+66r
.rodata:000000000040D9E0                                         ; factor_print+8Br ...
.rodata:000000000040D9E4                 db    3
.rodata:000000000040D9E5                 db    0
.rodata:000000000040D9E6                 db    0
.rodata:000000000040D9E7                 db    0
.rodata:000000000040D9E8                 db    5
.rodata:000000000040D9E9                 db    0
.rodata:000000000040D9EA                 db    0
.rodata:000000000040D9EB                 db    0
.rodata:000000000040D9EC                 db    7
.rodata:000000000040D9ED                 db    0
.rodata:000000000040D9EE                 db    0
.rodata:000000000040D9EF                 db    0
.rodata:000000000040D9F0                 db  0Bh
.rodata:000000000040D9F1                 db    0
.rodata:000000000040D9F2                 db    0
.rodata:000000000040D9F3                 db    0
.rodata:000000000040D9F4                 db  0Dh
.rodata:000000000040D9F5                 db    0
.rodata:000000000040D9F6                 db    0
.rodata:000000000040D9F7                 db    0
.rodata:000000000040D9F8                 db  11h
continued...
```

So we can see that `primes` is an array of a servies of prime integers in the read only data segment, starting with 2. Continuing on with the code we see that `gmp_int_1` is multiplied with `gmp_int0`, and the value is stored in `gmp_int0`.

So tl;dr `gmp_int_0` is set equal to `prime[I] ^ input[i]` and `gmp_int_1` is set equal to `gmp_int_0 * gmp_int_1` for each character in input.

```c
  __gmpz_init((__int64)&mp_int_2, (__int64)size_pointer, v6);
  __gmpz_init((__int64)&mp_int_3, (__int64)size_pointer, v7);
```

looking at the next segment of code, we can see that two more `MP_INTS` are initialized (again look at the assembly code to see that there is only one argument to those functions).

Let's look at the next block of code:

```
  do
  {
    break_condition = 0;
    for ( j = 0; ; ++j )
    {
      j_transfer = j;
      if ( j_transfer >= length((__int64)program) )// lenght(program) = 0x1a7 = 423
        break;
      __gmp_sscanf(program[2 * j], &format_string, &mp_int_2);// formatstring = %Zi which is a signed decimal integer that length is size_t
      __gmp_sscanf(program_0[2 * j], &format_string, &mp_int_3);
      __gmpz_set(&gmp_int_1, &gmp_int_0);       // gmp_int_1 = gmp_int_0
      __gmpz_mul(&gmp_int_1, &gmp_int_1, &mp_int_2);// gmp_int_1 = gmp_int_1 * mp_int_2
      if ( __gmpz_divisible_p(&gmp_int_1, &mp_int_3) )// executes if gmp_int_1 / mp_int_3 has no remainder
      {
        __gmpz_tdiv_q(&gmp_int_0, &gmp_int_1, &mp_int_3);// gmp_intz_0 = gmp_int_1 / mp_int_3
        break_condition = 1;                    // exits the loop
        break;
      }
    }
  }
  while ( break_condition );
  factor_print((__int64)&gmp_int_0);
```

So looking at this, we see that we have a while statement for an int (the check to change the int and stop the loop happens later). Within that we have a for loop, which should run 423 times. Each time that loop runs, a string is scanned in as an integer to `mp_int_2` and `mp_int_3` from `program[2 * j]` and `program_0[2 * j]` (they both point to the same sequence of numbers, but they are off by eight bytes). Proceeding that it sets `gmp_int_1` equal to `gmp_int_0`, and `gmp_int_1` equal to `gmp_int_1 * mp_int_2`. 

After that, it checks to see if `gmp_int_1/mp_int_3` yeilds a remainder of `0`, and if it does then `gmp_int_0` is set equal to `gmp_int_1/mp_int_3` and the break_condition is set equal to one, so the next time the while loop conditional is evaluated it will stop running. Proceeding that `gmp_int_0` is passed as an argument to `factor_print`. Looking at the `factor_print()` function, it appear to take the argument, alter it, then prints out the output. So the message the is printed is directly influnced by it's argument `gmp_int_0`. 

##Factoring

This section is based off of: https://github.com/ByteBandits/writeups/tree/master/bostonkeyparty-2016/reverse/Alewife/sudhackar

Now when the check to see if `gmp_int_1 % mp_int_3 == 0` happens, `gmp_int_1 = gmp_int_0 * mp_int_2 `, and both of the `mp_int`s are qual to values from `program`. If we can find factors of the values in `program`, we could use thsi to help us with this check. Here is the code for it (from the writeup):

```
#Code is from: https://github.com/ByteBandits/writeups/tree/master/bostonkeyparty-2016/reverse/Alewife/sudhackar

#Import libraries
from sympy.ntheory import factorint

#Establish the arrays for primes and programs
primes = [ 0x2, 0x3, 0x5, 0x7, 0x0B, 0x0D, 0x11, 0x13, 0x17, 0x1D, 0x1F, 0x25, 0x29, 0x2B, 0x2F, 0x35, 0x3B, 0x3D, 0x43, 0x47, 0x49, 0x4F, 0x53, 0x59, 0x61, 0x65, 0x67, 0x6B, 0x6D, 0x71, 0x7F, 0x83, 0x89, 0x8B, 0x95, 0x97, 0x9D, 0x0A3, 0x0A7, 0x0AD, 0x0B3, 0x0B5, 0x0BF, 0x0C1, 0x0C5, 0x0C7, 0x0D3, 0x0DF, 0x0E3, 0x0E5, 0x0E9, 0x0EF, 0x0F1, 0x0FB, 0x101, 0x107, 0x10D, 0x10F, 0x115, 0x119, 0x11B, 0x125, 0x133, 0x137, 0x139, 0x13D, 0x14B, 0x151, 0x15B, 0x15D, 0x161, 0x167, 0x16F, 0x175, 0x17B, 0x17F, 0x185, 0x18D, 0x191, 0x199, 0x1A3, 0x1A5, 0x1AF, 0x1B1, 0x1B7, 0x1BB, 0x1C1, 0x1C9, 0x1CD, 0x1CF, 0x1D3, 0x1DF, 0x1E7, 0x1EB, 0x1F3, 0x1F7, 0x1FD, 0x209, 0x20B, 0x21D, 0x223, 0x22D, 0x233, 0x239, 0x23B, 0x241, 0x24B, 0x251, 0x257, 0x259, 0x25F, 0x265, 0x269, 0x26B, 0x277, 0x281, 0x283, 0x287, 0x28D, 0x293, 0x295, 0x2A1, 0x2A5, 0x2AB, 0x2B3, 0x2BD, 0x2C5, 0x2CF, 0x2D7, 0x2DD, 0x2E3, 0x2E7, 0x2EF, 0x2F5, 0x2F9, 0x301, 0x305, 0x313, 0x31D, 0x329, 0x32B, 0x335, 0x337, 0x33B, 0x33D, 0x347, 0x355, 0x359, 0x35B, 0x35F, 0x36D, 0x371, 0x373, 0x377, 0x38B, 0x38F, 0x397, 0x3A1, 0x3A9, 0x3AD, 0x3B3, 0x3B9, 0x3C7, 0x3CB, 0x3D1, 0x3D7, 0x3DF, 0x3E5, 0x3F1, 0x3F5, 0x3FB, 0x3FD ]

program=[] #Check github for script with full values

#Establish all of the values mp_int_2 & mp_int_3 will have
mp_int_2 = [program[(2 * i)] for i in xrange(len(program)/2)]
mp_int_3 = [program[1 + (2 * i)] for i in xrange(len(program)/2)]

#Factor all of them
factor_mp_int_2 = [factorint(i) for i in mp_int_2]
factor_mp_int_3 = [factorint(i) for i in mp_int_3]

#Print out the factors
print "Factors for mp_int_2: "
print factor_mp_int_2
print "Factors for mp_int_3: "
print factor_mp_int_3
```

When we run the python code:

```
$	python factor.py 
Factors for mp_int_2: 
[{1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {1009: 1}, {997: 1}, {2: 78, 3: 111, 5: 112, 7: 101, 137: 32, 11: 33, 13: 32, 17: 32, 19: 89, 149: 114, 23: 111, 29: 117, 31: 32, 163: 116, 37: 110, 167: 105, 41: 101, 43: 101, 173: 111, 47: 100, 179: 110, 53: 32, 59: 116, 151: 97, 61: 111, 181: 115, 67: 32, 71: 112, 73: 114, 79: 97, 83: 99, 139: 102, 89: 116, 97: 105, 131: 114, 101: 99, 103: 101, 107: 32, 109: 121, 157: 99, 113: 111, 191: 33, 127: 117}, {2: 67, 3: 111, 5: 110, 7: 103, 137: 32, 11: 114, 13: 97, 17: 116, 19: 117, 149: 111, 23: 108, 29: 97, 31: 116, 163: 111, 37: 105, 167: 109, 41: 111, 43: 110, 173: 101, 47: 115, 179: 32, 53: 33, 59: 32, 151: 32, 61: 32, 181: 100, 193: 114, 67: 84, 197: 105, 71: 114, 73: 101, 79: 97, 83: 116, 139: 116, 89: 32, 199: 97, 223: 115, 97: 121, 227: 33, 131: 102, 101: 111, 103: 117, 107: 114, 109: 115, 157: 115, 113: 101, 211: 110, 191: 117, 127: 108}, {997: 1}, {1019: 1}, {997: 1}, {1021: 1, 439: 1}, {997: 1}, {997: 1}, {443: 1, 1021: 1}, {997: 1}, {997: 1}, {449: 1, 1021: 1}, {997: 1}, {997: 1}, {457: 1, 1021: 1}, {997: 1}, {997: 1}, {461: 1, 1021: 1}, {997: 1}, {997: 1}, {1021: 1, 463: 1}, {997: 1}, {997: 1}, {467: 1, 1021: 1}, {997: 1}, {997: 1}, {1021: 1, 479: 1}, {997: 1}, {997: 1}, {1021: 1, 487: 1}, {997: 1}, {997: 1}, {491: 1, 1021: 1}, {997: 1}, {997: 1}, {499: 1, 1021: 1}, {997: 1}, {997: 1}, {1021: 1, 503: 1}, {997: 1}, {997: 1}, {509: 1, 1021: 1}, {997: 1}, {997: 1}, {521: 1, 1021: 1}, {997: 1}, {997: 1}, {523: 1, 1021: 1}, {997: 1}, {997: 1}, {541: 1, 1021: 1}, {997: 1}, {997: 1}, {547: 1, 1021: 1}, {997: 1}, {997: 1}, {557: 1, 1021: 1}, {997: 1}, {997: 1}, {563: 1, 1021: 1}, {997: 1}, {997: 1}, {569: 1, 1021: 1}, {997: 1}, {997: 1}, {571: 1, 1021: 1}, {997: 1}, {997: 1}, {577: 1, 1021: 1}, {997: 1}, {997: 1}, {587: 1, 1021: 1}, {997: 1}, {997: 1}, {593: 1, 1021: 1}, {997: 1}, {997: 1}, {1021: 1, 599: 1}, {997: 1}, {997: 1}, {601: 1, 1021: 1}, {997: 1}, {997: 1}, {1021: 1, 607: 1}, {997: 1}, {997: 1}, {613: 1, 1021: 1}, {997: 1}, {997: 1}, {617: 1, 1021: 1}, {997: 1}, {997: 1}, {619: 1, 1021: 1}, {997: 1}, {997: 1}, {1021: 1, 631: 1}, {997: 1}, {997: 1}, {641: 1, 1021: 1}, {997: 1}, {997: 1}, {643: 1, 1021: 1}, {997: 1}, {997: 1}, {1021: 1, 647: 1}, {997: 1}, {997: 1}, {653: 1, 1021: 1}, {997: 1}, {997: 1}, {659: 1, 1021: 1}, {997: 1}, {997: 1}, {661: 1, 1021: 1}, {997: 1}, {997: 1}, {673: 1, 1021: 1}, {997: 1}, {997: 1}, {677: 1, 1021: 1}, {997: 1}, {997: 1}, {683: 1, 1021: 1}, {997: 1}, {997: 1}, {691: 1, 1021: 1}, {997: 1}, {997: 1}, {701: 1, 1021: 1}, {997: 1}, {997: 1}, {709: 1, 1021: 1}, {997: 1}, {997: 1}, {1021: 1, 719: 1}, {997: 1}, {997: 1}, {1021: 1, 727: 1}, {997: 1}, {997: 1}, {733: 1, 1021: 1}, {997: 1}, {997: 1}, {739: 1, 1021: 1}, {997: 1}, {997: 1}, {1021: 1, 743: 1}, {997: 1}, {997: 1}, {1021: 1, 751: 1}, {997: 1}, {997: 1}, {757: 1, 1021: 1}, {997: 1}, {997: 1}, {761: 1, 1021: 1}, {997: 1}, {997: 1}, {769: 1, 1021: 1}, {997: 1}, {997: 1}, {773: 1, 1021: 1}, {997: 1}, {997: 1}, {787: 1, 1021: 1}, {997: 1}, {997: 1}, {797: 1, 1021: 1}, {997: 1}, {997: 1}, {809: 1, 1021: 1}, {997: 1}, {997: 1}, {811: 1, 1021: 1}, {997: 1}, {997: 1}, {821: 1, 1021: 1}, {997: 1}, {997: 1}, {1021: 1, 823: 1}, {997: 1}, {997: 1}, {827: 1, 1021: 1}, {997: 1}, {997: 1}, {829: 1, 1021: 1}, {997: 1}, {997: 1}, {1021: 1, 839: 1}, {997: 1}, {997: 1}, {853: 1, 1021: 1}, {997: 1}, {997: 1}, {857: 1, 1021: 1}, {997: 1}, {997: 1}, {859: 1, 1021: 1}, {997: 1}, {997: 1}, {1021: 1, 863: 1}, {997: 1}, {997: 1}, {877: 1, 1021: 1}, {997: 1}, {997: 1}, {881: 1, 1021: 1}, {997: 1}, {997: 1}, {883: 1, 1021: 1}, {997: 1}, {997: 1}, {1021: 1, 887: 1}, {997: 1}, {997: 1}, {907: 1, 1021: 1}, {997: 1}, {997: 1}, {1021: 1, 911: 1}, {997: 1}, {997: 1}, {1021: 1, 919: 1}, {997: 1}, {997: 1}, {929: 1, 1021: 1}, {997: 1}, {997: 1}, {937: 1, 1021: 1}, {997: 1}, {997: 1}, {941: 1, 1021: 1}, {997: 1}, {997: 1}, {947: 1, 1021: 1}, {997: 1}, {997: 1}, {953: 1, 1021: 1}, {997: 1}, {997: 1}, {1021: 1, 967: 1}, {997: 1}, {997: 1}, {971: 1, 1021: 1}, {997: 1}, {997: 1}, {977: 1, 1021: 1}, {997: 1}, {997: 1}, {1021: 1, 983: 1}, {997: 1}, {997: 1}, {1021: 1, 991: 1}, {997: 1}, {997: 1}, {1013: 1}]
Factors for mp_int_3: 
[{2: 1, 997: 1}, {997: 1, 439: 1}, {3: 1, 997: 1}, {443: 1, 997: 1}, {5: 1, 997: 1}, {449: 1, 997: 1}, {997: 1, 7: 1}, {457: 1, 997: 1}, {11: 1, 997: 1}, {461: 1, 997: 1}, {13: 1, 997: 1}, {997: 1, 463: 1}, {17: 1, 997: 1}, {467: 1, 997: 1}, {19: 1, 997: 1}, {997: 1, 479: 1}, {997: 1, 23: 1}, {997: 1, 487: 1}, {29: 1, 997: 1}, {491: 1, 997: 1}, {997: 1, 31: 1}, {499: 1, 997: 1}, {37: 1, 997: 1}, {997: 1, 503: 1}, {41: 1, 997: 1}, {509: 1, 997: 1}, {43: 1, 997: 1}, {521: 1, 997: 1}, {997: 1, 47: 1}, {523: 1, 997: 1}, {53: 1, 997: 1}, {541: 1, 997: 1}, {59: 1, 997: 1}, {547: 1, 997: 1}, {61: 1, 997: 1}, {557: 1, 997: 1}, {67: 1, 997: 1}, {563: 1, 997: 1}, {997: 1, 71: 1}, {569: 1, 997: 1}, {73: 1, 997: 1}, {571: 1, 997: 1}, {997: 1, 79: 1}, {577: 1, 997: 1}, {83: 1, 997: 1}, {587: 1, 997: 1}, {89: 1, 997: 1}, {593: 1, 997: 1}, {97: 1, 997: 1}, {997: 1, 599: 1}, {101: 1, 997: 1}, {601: 1, 997: 1}, {997: 1, 103: 1}, {997: 1, 607: 1}, {107: 1, 997: 1}, {613: 1, 997: 1}, {109: 1, 997: 1}, {617: 1, 997: 1}, {113: 1, 997: 1}, {619: 1, 997: 1}, {997: 1, 127: 1}, {997: 1, 631: 1}, {131: 1, 997: 1}, {641: 1, 997: 1}, {137: 1, 997: 1}, {643: 1, 997: 1}, {139: 1, 997: 1}, {997: 1, 647: 1}, {149: 1, 997: 1}, {653: 1, 997: 1}, {997: 1, 151: 1}, {659: 1, 997: 1}, {157: 1, 997: 1}, {661: 1, 997: 1}, {163: 1, 997: 1}, {673: 1, 997: 1}, {997: 1, 167: 1}, {677: 1, 997: 1}, {173: 1, 997: 1}, {683: 1, 997: 1}, {179: 1, 997: 1}, {691: 1, 997: 1}, {181: 1, 997: 1}, {701: 1, 997: 1}, {997: 1, 191: 1}, {709: 1, 997: 1}, {193: 1, 997: 1}, {997: 1, 719: 1}, {197: 1, 997: 1}, {997: 1, 727: 1}, {997: 1, 199: 1}, {733: 1, 997: 1}, {211: 1, 997: 1}, {739: 1, 997: 1}, {997: 1, 223: 1}, {997: 1, 743: 1}, {227: 1, 997: 1}, {997: 1, 751: 1}, {229: 1, 997: 1}, {757: 1, 997: 1}, {233: 1, 997: 1}, {761: 1, 997: 1}, {997: 1, 239: 1}, {769: 1, 997: 1}, {241: 1, 997: 1}, {773: 1, 997: 1}, {251: 1, 997: 1}, {787: 1, 997: 1}, {257: 1, 997: 1}, {797: 1, 997: 1}, {997: 1, 263: 1}, {809: 1, 997: 1}, {269: 1, 997: 1}, {811: 1, 997: 1}, {997: 1, 271: 1}, {821: 1, 997: 1}, {277: 1, 997: 1}, {997: 1, 823: 1}, {281: 1, 997: 1}, {827: 1, 997: 1}, {283: 1, 997: 1}, {829: 1, 997: 1}, {293: 1, 997: 1}, {997: 1, 839: 1}, {307: 1, 997: 1}, {853: 1, 997: 1}, {997: 1, 311: 1}, {857: 1, 997: 1}, {313: 1, 997: 1}, {859: 1, 997: 1}, {317: 1, 997: 1}, {997: 1, 863: 1}, {331: 1, 997: 1}, {877: 1, 997: 1}, {337: 1, 997: 1}, {881: 1, 997: 1}, {347: 1, 997: 1}, {883: 1, 997: 1}, {349: 1, 997: 1}, {997: 1, 887: 1}, {353: 1, 997: 1}, {907: 1, 997: 1}, {997: 1, 359: 1}, {997: 1, 911: 1}, {997: 1, 367: 1}, {997: 1, 919: 1}, {373: 1, 997: 1}, {929: 1, 997: 1}, {379: 1, 997: 1}, {937: 1, 997: 1}, {997: 1, 383: 1}, {941: 1, 997: 1}, {389: 1, 997: 1}, {947: 1, 997: 1}, {397: 1, 997: 1}, {953: 1, 997: 1}, {401: 1, 997: 1}, {997: 1, 967: 1}, {409: 1, 997: 1}, {971: 1, 997: 1}, {419: 1, 997: 1}, {977: 1, 997: 1}, {421: 1, 997: 1}, {997: 1, 983: 1}, {997: 1, 431: 1}, {997: 1, 991: 1}, {433: 1, 997: 1}, {1009: 1}, {997: 1}, {641: 1, 619: 1, 797: 1, 773: 1, 929: 1, 577: 1, 521: 1, 523: 1, 653: 1, 941: 1, 911: 1, 823: 1, 947: 1, 643: 1, 739: 1, 661: 1, 953: 1, 857: 1, 883: 1, 541: 1, 673: 1, 977: 1, 547: 1, 811: 1, 677: 1, 809: 1, 647: 1, 557: 1, 827: 1, 743: 1, 683: 1, 563: 1, 821: 1, 919: 1, 439: 1, 631: 1, 569: 1, 607: 1, 571: 1, 769: 1, 701: 1, 1013: 1, 449: 1, 863: 1, 907: 1, 709: 1, 991: 1, 839: 1, 457: 1, 859: 1, 587: 1, 937: 1, 461: 1, 727: 1, 463: 1, 593: 1, 467: 1, 659: 1, 853: 1, 983: 1, 599: 1, 787: 1, 601: 1, 829: 1, 719: 1, 733: 1, 479: 1, 887: 1, 443: 1, 613: 1, 487: 1, 617: 1, 691: 1, 491: 1, 877: 1, 971: 1, 751: 1, 881: 1, 499: 1, 757: 1, 967: 1, 503: 1, 761: 1, 509: 1}, {1013: 1}, {1021: 1}, {2: 76, 1019: 1}, {2: 75, 1019: 1}, {2: 1, 1019: 1}, {3: 70, 1019: 1}, {3: 69, 1019: 1}, {3: 1, 1019: 1}, {1019: 1, 5: 90}, {1019: 1, 5: 89}, {1019: 1, 5: 1}, {1019: 1, 7: 124}, {1019: 1, 7: 123}, {1019: 1, 7: 1}, {11: 41, 1019: 1}, {11: 40, 1019: 1}, {11: 1, 1019: 1}, {1019: 1, 13: 67}, {1019: 1, 13: 66}, {1019: 1, 13: 1}, {17: 122, 1019: 1}, {17: 121, 1019: 1}, {17: 1, 1019: 1}, {19: 33, 1019: 1}, {19: 32, 1019: 1}, {19: 1, 1019: 1}, {1019: 1, 23: 117}, {1019: 1, 23: 116}, {1019: 1, 23: 1}, {1019: 1, 29: 105}, {1019: 1, 29: 104}, {1019: 1, 29: 1}, {1019: 1, 31: 102}, {1019: 1, 31: 101}, {1019: 1, 31: 1}, {1019: 1, 37: 33}, {1019: 1, 37: 32}, {1019: 1, 37: 1}, {41: 120, 1019: 1}, {41: 119, 1019: 1}, {41: 1, 1019: 1}, {43: 98, 1019: 1}, {43: 97, 1019: 1}, {43: 1, 1019: 1}, {1019: 1, 47: 122}, {1019: 1, 47: 121}, {1019: 1, 47: 1}, {1019: 1, 53: 45}, {1019: 1, 53: 44}, {1019: 1, 53: 1}, {59: 33, 1019: 1}, {59: 32, 1019: 1}, {59: 1, 1019: 1}, {1019: 1, 61: 117}, {1019: 1, 61: 116}, {1019: 1, 61: 1}, {67: 105, 1019: 1}, {67: 104, 1019: 1}, {67: 1, 1019: 1}, {1019: 1, 71: 106}, {1019: 1, 71: 105}, {1019: 1, 71: 1}, {73: 116, 1019: 1}, {73: 115, 1019: 1}, {73: 1, 1019: 1}, {1019: 1, 79: 33}, {1019: 1, 79: 32}, {1019: 1, 79: 1}, {83: 100, 1019: 1}, {83: 99, 1019: 1}, {83: 1, 1019: 1}, {89: 105, 1019: 1}, {89: 104, 1019: 1}, {89: 1, 1019: 1}, {97: 98, 1019: 1}, {97: 97, 1019: 1}, {97: 1, 1019: 1}, {1019: 1, 101: 109}, {1019: 1, 101: 108}, {1019: 1, 101: 1}, {1019: 1, 103: 109}, {1019: 1, 103: 108}, {1019: 1, 103: 1}, {107: 102, 1019: 1}, {107: 101, 1019: 1}, {107: 1, 1019: 1}, {1019: 1, 109: 111}, {1019: 1, 109: 110}, {1019: 1, 109: 1}, {113: 104, 1019: 1}, {113: 103, 1019: 1}, {113: 1, 1019: 1}, {1019: 1, 127: 102}, {1019: 1, 127: 101}, {1019: 1, 127: 1}, {131: 33, 1019: 1}, {131: 32, 1019: 1}, {131: 1, 1019: 1}, {137: 120, 1019: 1}, {137: 119, 1019: 1}, {137: 1, 1019: 1}, {139: 112, 1019: 1}, {139: 111, 1019: 1}, {139: 1, 1019: 1}, {1019: 1, 149: 118}, {1019: 1, 149: 117}, {1019: 1, 149: 1}, {1019: 1, 151: 109}, {1019: 1, 151: 108}, {1019: 1, 151: 1}, {1019: 1, 157: 101}, {1019: 1, 157: 100}, {1019: 1, 157: 1}, {163: 33, 1019: 1}, {163: 32, 1019: 1}, {163: 1, 1019: 1}, {1019: 1, 167: 99}, {1019: 1, 167: 98}, {1019: 1, 167: 1}, {1019: 1, 173: 102}, {1019: 1, 173: 101}, {1019: 1, 173: 1}, {179: 33, 1019: 1}, {179: 32, 1019: 1}, {179: 1, 1019: 1}, {1019: 1, 181: 110}, {1019: 1, 181: 109}, {1019: 1, 181: 1}, {1019: 1, 191: 118}, {1019: 1, 191: 117}, {1019: 1, 191: 1}, {193: 100, 1019: 1}, {193: 99, 1019: 1}, {193: 1, 1019: 1}, {1019: 1, 197: 105}, {1019: 1, 197: 104}, {1019: 1, 197: 1}, {1019: 1, 199: 33}, {1019: 1, 199: 32}, {1019: 1, 199: 1}, {211: 102, 1019: 1}, {211: 101, 1019: 1}, {211: 1, 1019: 1}, {1019: 1, 223: 98}, {1019: 1, 223: 97}, {1019: 1, 223: 1}, {227: 116, 1019: 1}, {227: 115, 1019: 1}, {227: 1, 1019: 1}, {1019: 1, 229: 106}, {1019: 1, 229: 105}, {1019: 1, 229: 1}, {233: 102, 1019: 1}, {233: 101, 1019: 1}, {233: 1, 1019: 1}, {1019: 1, 239: 115}, {1019: 1, 239: 114}, {1019: 1, 239: 1}, {241: 33, 1019: 1}, {241: 32, 1019: 1}, {241: 1, 1019: 1}, {251: 120, 1019: 1}, {251: 119, 1019: 1}, {251: 1, 1019: 1}, {257: 106, 1019: 1}, {257: 105, 1019: 1}, {257: 1, 1019: 1}, {1019: 1, 263: 117}, {1019: 1, 263: 116}, {1019: 1, 263: 1}, {1019: 1, 269: 105}, {1019: 1, 269: 104}, {1019: 1, 269: 1}, {1019: 1, 271: 33}, {1019: 1, 271: 32}, {1019: 1, 271: 1}, {1019: 1, 277: 98}, {1019: 1, 277: 97}, {1019: 1, 277: 1}, {281: 33, 1019: 1}, {281: 32, 1019: 1}, {281: 1, 1019: 1}, {283: 100, 1019: 1}, {283: 99, 1019: 1}, {283: 1, 1019: 1}, {1019: 1, 293: 122}, {1019: 1, 293: 121}, {1019: 1, 293: 1}, {307: 99, 1019: 1}, {307: 98, 1019: 1}, {307: 1, 1019: 1}, {1019: 1, 311: 102}, {1019: 1, 311: 101}, {1019: 1, 311: 1}, {313: 115, 1019: 1}, {313: 114, 1019: 1}, {313: 1, 1019: 1}, {1019: 1, 317: 111}, {1019: 1, 317: 110}, {1019: 1, 317: 1}, {331: 102, 1019: 1}, {331: 101, 1019: 1}, {331: 1, 1019: 1}, {337: 117, 1019: 1}, {337: 116, 1019: 1}, {337: 1, 1019: 1}, {347: 106, 1019: 1}, {347: 105, 1019: 1}, {347: 1, 1019: 1}, {1019: 1, 349: 100}, {1019: 1, 349: 99}, {1019: 1, 349: 1}, {353: 33, 1019: 1}, {353: 32, 1019: 1}, {353: 1, 1019: 1}, {1019: 1, 359: 103}, {1019: 1, 359: 102}, {1019: 1, 359: 1}, {1019: 1, 367: 115}, {1019: 1, 367: 114}, {1019: 1, 367: 1}, {1019: 1, 373: 112}, {1019: 1, 373: 111}, {1019: 1, 373: 1}, {379: 104, 1019: 1}, {379: 103, 1019: 1}, {379: 1, 1019: 1}, {1019: 1, 383: 33}, {1019: 1, 383: 32}, {1019: 1, 383: 1}, {1019: 1, 389: 99}, {1019: 1, 389: 98}, {1019: 1, 389: 1}, {1019: 1, 397: 115}, {1019: 1, 397: 114}, {1019: 1, 397: 1}, {401: 98, 1019: 1}, {401: 97, 1019: 1}, {401: 1, 1019: 1}, {409: 106, 1019: 1}, {409: 105, 1019: 1}, {409: 1, 1019: 1}, {419: 111, 1019: 1}, {419: 110, 1019: 1}, {419: 1, 1019: 1}, {1019: 1, 421: 42}, {1019: 1, 421: 41}, {1019: 1, 421: 1}, {1019: 1, 431: 126}, {1019: 1, 431: 125}, {1019: 1, 431: 1}, {433: 1}, {1019: 1}]
```

Now looking at this, we can see something interesting. From the output of `mp_int_3` and starting with `76`, we can see a series of integers that are within the ascii range. When we convert them over to ascii and reorder them, it reveals something interesting:

```
>>> ascii_values = [ 76, 75, 70, 69, 90, 89, 124, 123, 41, 40, 67, 66, 122, 121, 33, 32, 117, 116, 105, 104, 102, 101, 33, 32, 120, 119, 98, 97, 122, 121, 45, 44, 33, 32, 117, 116, 105, 104, 106, 105, 116, 115, 33, 32, 100, 99, 105, 104, 98, 97, 109, 108, 109, 108, 102, 101, 111, 110, 104, 103, 102, 101, 33, 32, 120, 119, 112, 111, 118, 117, 109, 108, 101, 100, 33, 32, 99, 98, 102, 101, 33, 32, 110, 109, 118, 117, 100, 99, 105, 104, 33, 32, 102, 101, 98, 97, 116, 115, 106, 105, 102, 101, 115, 114, 33, 32, 120, 119, 106, 105, 117, 116, 105, 104, 33, 32, 98, 97, 33, 32, 100, 99, 122, 121, 99, 98, 102, 101, 115, 114, 111, 110, 102, 101, 117, 116, 106, 105, 100, 99, 33, 32, 103, 102, 115, 114, 112, 111, 104, 103, 33, 32, 99, 98, 115, 114, 98, 97, 106, 105, 111, 110, 42, 41, 126, 125 ]
>>> ''.join(chr(ascii_values[(i)]) for i in xrange(len(ascii_values)))
'LKFEZY|{)(CBzy! utihfe! xwbazy-,! utihjits! dcihbamlmlfeonhgfe! xwpovumled! cbfe! nmvudcih! febatsjifesr! xwjiutih! ba! dczycbfesronfeutjidc! gfsrpohg! cbsrbajion*)~}'
```

Here we can see that when we convert it over to ascii, we see characters that we would expect to see in the flag such as `B,K,E,Y,C,{,}`.  When we look at how the values from `program` are used by the program, it is every second one for both, which are off by one. Sorting the ascii values this way reveals something cool:

```
>>> ''.join(chr(ascii_values[(i*2)]) for i in xrange(len(ascii_values)/2))
'LFZ|)Cz!uif!xbz-!uijt!dibmmfohf!xpvme!cf!nvdi!fbtjfs!xjui!b!dzcfsofujd!gsph!csbjo*~'
>>> ''.join(chr(ascii_values[1+(i*2)]) for i in xrange(len(ascii_values)/2))
'KEY{(By the way, this challenge would be much easier with a cybernetic frog brain)}'
```

Just like that, we got the flag!

##reusing putchar

This is another solution to this challenge from: https://github.com/p4-team/ctf/tree/master/2016-03-06-bkpctf/re_5_Frog_Fractions_2

Looking at the value for `gmp_int_0` as it is passed as an argument to `factor_print` reveals something interesting:

```
gdb-peda$ b *0x400ef2
Breakpoint 1 at 0x400ef2
gdb-peda$ r
Starting program: /Hackery/bkp16/frogger/frog 
15935728

[----------------------------------registers-----------------------------------]
RAX: 0x7fffffffdf40 --> 0x16a0000016a 
RBX: 0x1a7 
RCX: 0x36 ('6')
RDX: 0x1a70 
RSI: 0x0 
RDI: 0x7fffffffdf40 --> 0x16a0000016a 
RBP: 0x7fffffffdf70 --> 0x400f10 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffdef0 --> 0x1 
RIP: 0x400ef2 (<main+542>:	call   0x400bfd <factor_print>)
R8 : 0x1b40000000000000 
R9 : 0x1ad7271048b9af1a 
R10: 0xbc53696b5be57a99 
R11: 0x159 
R12: 0x400ad0 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe050 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x400eea <main+534>:	nop
   0x400eeb <main+535>:	lea    rax,[rbp-0x30]
   0x400eef <main+539>:	mov    rdi,rax
=> 0x400ef2 <main+542>:	call   0x400bfd <factor_print>
   0x400ef7 <main+547>:	mov    eax,0x0
   0x400efc <main+552>:	add    rsp,0x78
   0x400f00 <main+556>:	pop    rbx
   0x400f01 <main+557>:	pop    rbp
Guessed arguments:
arg[0]: 0x7fffffffdf40 --> 0x16a0000016a 
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffdef0 --> 0x1 
0008| 0x7fffffffdef8 --> 0x4022000000000000 ('')
0016| 0x7fffffffdf00 --> 0x100000013 
0024| 0x7fffffffdf08 --> 0x6121d0 --> 0x3fb 
0032| 0x7fffffffdf10 --> 0x1000001b7 
0040| 0x7fffffffdf18 --> 0x611410 --> 0x3f5 
0048| 0x7fffffffdf20 --> 0x610050 ("15935728")
0056| 0x7fffffffdf28 --> 0xac 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 1, 0x0000000000400ef2 in main ()
gdb-peda$ x/2x $rdi
0x7fffffffdf40:	0x0000016a0000016a	0x0000000000610760
gdb-peda$ x/362x 0x610760
0x610760:	0x0000000000000000	0x00aa754fc8bbc000
0x610770:	0x93860f7c518556a1	0x7d705d2c77f23096
0x610780:	0x8583864f85357d2f	0x6278451a507a137f
0x610790:	0xf63a95734c8a2bc5	0x6cd04c1f70936de4
0x6107a0:	0x273bcb730b463ced	0x64e2606432d87aa2
0x6107b0:	0xa7cf0bca8dfa4d6a	0xa6be56fcf4b3b81d
0x6107c0:	0xd63b86c20ad41f9b	0x90adb04855dc1325
0x6107d0:	0x27d81371c50096ab	0x2e8924cb6f3ac280
0x6107e0:	0x8701a48bf624b815	0x68e13c25b375cb12
0x6107f0:	0xfd78a81c1f293241	0xfcc0719f745481b1
0x610800:	0xc1b690025dc93390	0x08cb5d99f74a81ef
0x610810:	0x1c6f4cdaf8b30ab2	0x80115c9823b8ddcd
0x610820:	0xc9ee966bb9cb783e	0xf3a04f14e7f397ac
0x610830:	0x26e0b280a2025e3a	0x2dd364fda5045445
0x610840:	0x3666cccbbea27550	0x49a76396d24989d4
0x610850:	0xe04d195be06c1f4d	0xed8fad6f55e20f76
0x610860:	0x25d2dfc2b4b2a0df	0x172b808621f31b84
0x610870:	0x6eb88967afc929cb	0x4ffb4a2d7f525694
0x610880:	0x5cd86e474142986d	0x90970c08224e4c6d
0x610890:	0xe47a2768d6d965ec	0xcb2c9186fe1a942e
0x6108a0:	0x6aad3c0a49e455a4	0xab35eb7310103973
0x6108b0:	0xcb9f57639f95e69c	0x9a2376eeefbb4a74
0x6108c0:	0x9a1e87630d1c19ad	0xc69875e811136218
0x6108d0:	0x2dd7cc425e7df388	0x46f209adbc570fc3
0x6108e0:	0xe90be9901358dfb9	0x87a11c4e95453c66
0x6108f0:	0x0678e86f7a6d943e	0xd6cb9da8cbdfc48c
0x610900:	0x31d055afda672e79	0x8e54a5f7735b13a3
0x610910:	0xd1b1540d3be87096	0x441bb3ac07e97768
0x610920:	0x37bf1af0b7997db4	0xba890e5043129bda
0x610930:	0x38304a5b43cce4f7	0x4a3eb642e6ef393a
0x610940:	0x971f9103ebbbc39c	0xfbd3b14d343b38ee
0x610950:	0x00b6bee8a1986de3	0x6a2e6b26bdfe12ae
0x610960:	0x3dda4814c57772e2	0x778d20ff2140e0e5
0x610970:	0xfcf777b707e8b792	0x1d99dcc7982726fa
0x610980:	0x95f93267f57952b6	0xbc285ed9c5817cce
0x610990:	0x44da94d6685ab75d	0xe7b0d2d032c836ac
0x6109a0:	0x2914166a70551e6b	0x52553655c9c59f54
0x6109b0:	0x6dc13c0afd8e0767	0x32f3c2eb4cd56bd7
0x6109c0:	0x74e755ab19d68466	0xfa29f49324c3758d
0x6109d0:	0x383ce64f7ecbf203	0x488db370eaafa71e
0x6109e0:	0x486355da476cdb64	0x9433e23096a376f9
0x6109f0:	0x43c847acf67e1d7f	0xb5f2509ad7bea572
0x610a00:	0x7ac54d62c3da3b19	0x43b91794d0c61415
0x610a10:	0xca4319d2fc43450e	0x19ddffe2cda3ca37
0x610a20:	0x7077597e33cccbd2	0xc23d14227820e8b1
0x610a30:	0xdef009583a18bd03	0x211a91f90e58fcd7
0x610a40:	0xfd280d8e204fbe5b	0xfcb8286ea1bf3ee2
0x610a50:	0x0c0a565a79b99c5d	0x22795f8f8a39989b
0x610a60:	0xd426153ee313cd65	0xe66a8c5fb1927467
0x610a70:	0x9376e8b10d5266e2	0xad5345d8606a06ef
0x610a80:	0xdfb190e81816962e	0x14a9383f8146c72b
0x610a90:	0x9d398a6bf197e44f	0xb543af3863f068ba
0x610aa0:	0xd485534bdd794910	0x7254acffcacfbe78
0x610ab0:	0x16b31fc5d03573ff	0xd83be2b6bea95626
0x610ac0:	0xd13356bb73389c90	0x585645bac4bd838b
0x610ad0:	0x1596188348c05447	0x3da20fe195366f0d
0x610ae0:	0x77ab06bd27a16701	0x3128f993fbd106bf
0x610af0:	0x2d5dee0a14922fe4	0xe6e2491740676065
0x610b00:	0x9178fc024ec07080	0x1f74284bca7fce68
0x610b10:	0x49b57d419ec8eddb	0x5ca7a9529c8fe83b
0x610b20:	0xfa939406eab68f1c	0x2b7c35fd0f4e3a23
0x610b30:	0x6382b06a081e1e7a	0xbabf6c6669b81c87
0x610b40:	0x7a50581781390a48	0x0fb897b635844f14
0x610b50:	0x79d027fc4ce26fb9	0x717f1b19d20125cb
0x610b60:	0x09b75aba805a580f	0x2dbab0f1c3cbbf04
0x610b70:	0x197223eb77a908f2	0x7c7b62ca6380824a
0x610b80:	0xabe7d4bb0a297f2d	0xecf670ed60e801dc
0x610b90:	0xbf3917940315b789	0xf679633195bc9515
0x610ba0:	0xc7eb52e38868044e	0xd50efcbbec3b3c7f
0x610bb0:	0xf8976121bdc4fa52	0x99e768b479966890
0x610bc0:	0x3e5e725a227ba68e	0x6ef0fd3a8b3dd35f
0x610bd0:	0x24be63e62dba6642	0xcb6f8eccae9e6569
0x610be0:	0xd45e026a51ef450a	0x5bd1806363aa31ab
0x610bf0:	0x708e7b2289f4d27f	0x25f4e0ec70912e2b
0x610c00:	0xfc34da7c3731cdbd	0x6ad82570b95c393c
0x610c10:	0xb54fda837a65a33a	0x48fbb5a602238b7f
0x610c20:	0xd3806b2cc3d79dd2	0x3f32d19deb3e7733
0x610c30:	0x6f9c4bfec575562c	0x00e13a27e4dce99f
0x610c40:	0x49ac1ffe1ce68d0a	0xc15bf64717609e93
0x610c50:	0xe5f4d41930aad0d9	0x0ea6ec3ef9833ca0
0x610c60:	0x0123009d3dab8c02	0x1a0744f8f3477a9c
0x610c70:	0x2dc3229512fa68b2	0xf8fbed68545d2d25
0x610c80:	0x07900d8e6e82db38	0x48c1e1c902d93f09
0x610c90:	0x442ef66309797e3a	0xa3a85c73b2667aa8
0x610ca0:	0xcd483249bb74fd75	0x53fc138f24631fb6
0x610cb0:	0xc90d08cfaccb7fe0	0x771654d492d61d66
0x610cc0:	0xf20885de2d295234	0x319cdc9907adda20
0x610cd0:	0x482bdbadc94228a9	0xf47f9152e3ddd4ac
0x610ce0:	0x18660e6ba4f86d6a	0x6d74d0a96f84ccd6
0x610cf0:	0xacdc92615c1796d7	0x6ed6e45315d6188c
0x610d00:	0x06101f21059f87f0	0xfaef881fd755ec93
0x610d10:	0xe5727fc1b2dcf95e	0x8fe0651a62dde88d
0x610d20:	0xb5e29fc36458ce21	0xfafc3c38e7f0dbb7
0x610d30:	0x054e4a280fb733e6	0xaefc010437d678c9
0x610d40:	0x1bc9cef8a93837ab	0x01868211565ffe10
0x610d50:	0x05d0703616686bc0	0x40739b05d80b8215
0x610d60:	0xd7a7c9c8b710b110	0x55e28ce46d7fe419
0x610d70:	0xa1d65b9476e23c5f	0xa1055f488310ae77
0x610d80:	0x7d3673ca6f1b59f2	0xa498a798566ce0f6
0x610d90:	0x225feb1106c78fbc	0x2e5de02a6463484c
0x610da0:	0x6e84cb508742f86c	0x12eac3e646d64147
0x610db0:	0xc7086a16b6e03e6e	0xd621db72859c3457
0x610dc0:	0xbde756a7dbc8b61c	0xcb2f692bf9c393fc
0x610dd0:	0xa88a82c582cfc7c4	0x4522d2089ce23b4c
0x610de0:	0xaf3ec0614ee51182	0x87fa6d1f8641c1fb
0x610df0:	0x713425299893f527	0xd91a1bea3eb18702
0x610e00:	0x56c7263bbb2c5bd5	0xb68e2d20e19b0575
0x610e10:	0xf512d79fd2bc1f8e	0xd9089fd14d14c8ba
0x610e20:	0xec8e8a202ae9a62a	0xa0da36ff8ab7ad70
0x610e30:	0x1bbbbae496ddcbeb	0x48f4dfa5ee48f475
0x610e40:	0x0ea214a185a29fdf	0x2f935de0e42017ff
0x610e50:	0x47fea01394c4a338	0xa15416434a914efc
0x610e60:	0xd0aea1a1f16fa5ea	0x4ee8b68e7c5ee44d
0x610e70:	0x5b54e0de9968e89d	0xd52bb76fb9597d4b
0x610e80:	0xf7052b4bfa58c8c1	0x83b7c3d3b0f74011
0x610e90:	0x1e001fcbb3f9b31d	0x0098f0ddb08ab7f0
0x610ea0:	0x1a79d2ba8687015e	0xb35f5f1d2c10271e
0x610eb0:	0x408263172a340039	0xfb3ff053b5c9e862
0x610ec0:	0xc6451c29487ea897	0xd8cc60b852242b48
0x610ed0:	0xa74b1c741e053f84	0x5ab9a73f498e1b5c
0x610ee0:	0x857c32c0cc764d56	0x1fa53e4ed64841f0
0x610ef0:	0xc4d8b83d009519c9	0x9441f710ab26798d
0x610f00:	0x5f9a645f8471a3d3	0x38c7bf777bc198f7
0x610f10:	0xb8efc017ac25572c	0xdacf010f61faade0
0x610f20:	0xe17f845f7e193bd1	0x58a2463d8d982b02
0x610f30:	0x82eeadc96771e304	0x8ec4810925c7395d
0x610f40:	0x89b737b85869c5f4	0x872eb2619c50c732
0x610f50:	0x03aec071bc60a6cf	0xcd8316675efa9129
0x610f60:	0x7c0bf4ec1a1f9033	0x1d53fbecf54d77bb
0x610f70:	0x257f34a1341b29ee	0xf69e1c5c98ed863d
0x610f80:	0x7165b363378549b2	0x3811feb74cf57dd8
0x610f90:	0x57cf112290f02f32	0x7b9abde41c337228
0x610fa0:	0xe69f7b81264b5e5a	0x6c1323cebbaefab0
0x610fb0:	0xc8b4ee8fb73968e7	0xa34ba166ae3bfaa1
0x610fc0:	0xc0d1123e53249de8	0xf96c887b3f4c0865
0x610fd0:	0xe6bcc18fa738bf1c	0xe4ee92cfdf9e819f
0x610fe0:	0x7e5c31589de598e7	0xbac1375883488c1c
0x610ff0:	0x7e687c9fa4254aaf	0x36ddca4220239d34
0x611000:	0x62f21d019c544ea6	0x26825ae3725cd45a
0x611010:	0x393f95cdbf45169f	0x59a524ccab3447b1
0x611020:	0x253cc2a3bb519f24	0xc6939bed7aad67f5
0x611030:	0xe4cb6bd35fc55fa3	0xf88f6389db8030db
0x611040:	0xe0bc460b69ff3364	0x6c97b68c9be9adc8
0x611050:	0xaf8cf98a803f0ab8	0xad028f55ae5e3536
0x611060:	0xe5d68e0a7f12cce1	0x7729a418aa56a922
0x611070:	0x297c39714549d82b	0x568f39492b8f08ae
0x611080:	0x93edc441148aa004	0x1aa4c0f18bf2f444
0x611090:	0x9b99361dcdcc82ac	0x60f7b50c873ba1aa
0x6110a0:	0x117d0f0697ef08f4	0x1e92775c2aecc43d
0x6110b0:	0x8663b1b641f5c32f	0x38a3884a2669942b
0x6110c0:	0xa5b04f36644cb6de	0xd2612ab374273dbb
0x6110d0:	0x10706783e6d4aa5b	0xbb064d2e53772030
0x6110e0:	0x37d8ccd39357500c	0x8a6e0d8a16a8f80d
0x6110f0:	0x063662d6a42641ed	0x5def9ec42bb04821
0x611100:	0x1600aae4ace22334	0xf9ab4e2828c9b062
0x611110:	0x780838ba6e53c7a8	0xe7e0ea65e5c08d05
0x611120:	0x6e678fd651cdb853	0xbda851aaa377cab5
0x611130:	0x718c08a9b914d9a2	0xe866bcb192904cdf
0x611140:	0x8c92b05e68096e6e	0xb0d53c03423fb156
0x611150:	0x0490b8960d6c55a5	0x1cff91111a141db1
0x611160:	0xc2998d8805643540	0xbf7a4f426b8801b8
0x611170:	0x404edbd9adc80685	0xf1bcad3da3fc4ae8
0x611180:	0x6a75e207ab0bdf9f	0x5297d5254417a290
0x611190:	0xcb6f401ccfbe0846	0x1e40b3d6898def16
0x6111a0:	0x907501b796e8423b	0x442158d390ae8b4a
0x6111b0:	0x484c63a036ef778c	0xc315f9c0047b5c45
0x6111c0:	0x7506bf54e950e32f	0x6d508a6b630f277b
0x6111d0:	0x000cd75c7d10972b	0x86c5ffdf061051f4
0x6111e0:	0x9228a6f35e0447a6	0x0cacbcada689c6c9
0x6111f0:	0xe184ba1a420e6634	0xc623e29a25e87207
0x611200:	0xc585a74eda4d1a1e	0x17f038968ee2a09e
0x611210:	0xc63cbfd60f57ec9e	0x78a993bf4d625da7
0x611220:	0x6f9e12e0e3d3a238	0x5e6d847f9c75b789
0x611230:	0x75f9615fb2111085	0x3f7787f6910e00aa
0x611240:	0x4142d0bb47327867	0x90e974d4084626dd
0x611250:	0x142bfc3210b598ce	0x4fa9946a012e84d1
0x611260:	0x7e86e6a195a92204	0xf3a2a03b70298d6f
0x611270:	0x54aeaef3df99b47c	0x5d8a3528b5f96933
0x611280:	0x24a18c8f0d783e19	0xe43ee880e0bcda74
0x611290:	0x77d41b246005a56d	0x7744734d51100234
0x6112a0:	0xe08aadc0b403d804	0x000000000000f722
```

When we run the program with different inputs, we always get the same output which is this massive integer. This is made even more interesting because when we look at the strings of this program, we see two strings that are noticeably larger than everything else. The first one starts with `628342186020279030208477` (is 6960 characters long) and the second one is `5020973558043690795` (is 8428 characters long). This get's interesting because when we convert the first string to hex (as an integer, using python's `hex()`) we get a hex string which is the same thing that we saw as the argument which is passed to `factor_print` when we passed it any input (the hex string dtarts with `0xf722e08aadc0b403d804`. 

Since we know how the algorithm works for generating the argument for `factor_print()` let's try to write a python script to generate the input which will set the argument to `factor_print()` equal to the second massive integer we saw that was a string, and see if that solves the challenge. Luckily enough just with trial and error, we find that if we input the int which will print out the success message, it will print out the flag for us:

```
#This code is from: https://github.com/p4-team/ctf/tree/master/2016-03-06-bkpctf/re_5_Frog_Fractions_2

#On my github, there is code with these values plugged in
primes = []
program = []
success = 5020973558043690795...

#Establish the factor_print function in python
def factor_print(inp):
	output = ''
	for i in xrange(0xab):
		c = 0x0
		while ( inp % primes[i] == 0):
			inp = inp/primes[i]
			c = c + 1
		if (c != 0):
			output += chr(c)
	print output

#Establish the python code which will do the equivalent of the second algorithm which deals with our input
def second_part(inp):
	i = 0
	while (i < len(program)/2):
		x = program[i*2]
		y = program[i*2+1]

		z = inp * y
		if ( z % x == 0):
			inp = z / x
			i = 0
		else:
			i = i + 1
	factor_print(inp)

#Run the success integer through the code
second_part(success)
```

and when we run it:

```
$	python putchar.py 
KEY{(By the way, this challenge would be much easier with a cybernetic frog brain)}
```

Just like that, we got the flag!

 
