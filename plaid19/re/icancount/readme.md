# icancount

This writeup is based off of: https://github.com/elklepo/pwn/blob/master/PlaidCTF_2019/i_can_count/exploit.py

When we look at the binary:

```
$	file i_can_count_8484ceff57cb99e3bdb3017f8c8a2467 
i_can_count_8484ceff57cb99e3bdb3017f8c8a2467: ELF 32-bit LSB shared object, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-, for GNU/Linux 2.6.32, BuildID[sha1]=e75719f2cd90c042f04af29a0cd1263bb72c7417, not stripped
$	pwn checksec i_can_count_8484ceff57cb99e3bdb3017f8c8a2467 
[*] '/Hackery/plaid19/icancount/i_can_count_8484ceff57cb99e3bdb3017f8c8a2467'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
$	./i_can_count_8484ceff57cb99e3bdb3017f8c8a2467 
We're going to count numbers, starting from one and
counting all the way up to the flag!
Are you ready? Go!
> 1
Yep!
> 2
Yep!
> 3
Yes!
> 5
No, the correct number is 4.
But I believe in you. Let's try again sometime!
```

We see that it is a `64` bit binary with PIE enabled. When we run it, we see that it prompts us for numbers that increment by `1` starting at `1`.

### Reversing

When we take a look at the main function, we see this:

```
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  int v3; // esi@0
  unsigned int seed; // eax@1
  char *compliment; // eax@8
  char input[38]; // [sp+0h] [bp-26h]@1

  *(_DWORD *)&input[34] = &argc;
  seed = time(0);
  srand(seed);
  puts("We're going to count numbers, starting from one and");
  puts("counting all the way up to the flag!");
  puts("Are you ready? Go!");
  while ( 1 )
  {
    incr_flag();
    printf("> ");
    fflush(stdout);
    fgets(input, 30, stdin);
    if ( input[0] && input[strlen(input) - 1] <= 31 )
      input[strlen(input) - 1] = 0;
    if ( strcmp(input, flag_buf) )
    {
      printf("No, the correct number is %s.\n", flag_buf);
      puts("But I believe in you. Let's try again sometime!");
      exit(1);
    }
    compliment = get_compliment();
    puts(compliment);
    check_flag(v3);
  }
}
```

So we can see that it starts off by using time as a seed, and printing out some text. Then it proceeds to enter into an infinite loop. For each iteration of the loop, it will first run the `incr_flag` function which increments the value stored in `flag_buf`. It then compares our input to `flag_buf` and if they aren't equivalent then the program exits. One thing to note the value stored in `flag_buf` is in ascii, so instead of it being `0x01` it would be `0x31`. If we pass the check then it generates and prints a random compliment with `get_compliment()` and `puts()`. Then it runs the `check_flag()` function.

Looking at the `incr_flag` function tells us a bit about what the bianry expects as input:
```
size_t incr_flag()
{
  size_t result; // eax@4
  signed __int32 v1; // eax@5
  size_t i; // [sp+Ch] [bp-Ch]@1

  for ( i = strlen(flag_buf); ; flag_buf[i] = 48 )
  {
    v1 = i--;
    if ( v1 <= 0 )
      break;
    if ( flag_buf[i] != '9' )
    {
      result = (size_t)&flag_buf[i];
      ++flag_buf[i];
      return result;
    }
  }
  if ( strlen(flag_buf) == 19 )
    exit(2);
  result = strlen(flag_buf);
  flag_buf[result] = '0';
  flag_buf[0] = '1';
  return result;
}
```

A couple of things from this, first if we weren't sure before we can see that `flag_bug` is only filled with the bytes between `0x30-0x39` (ASCII `0`-`9`). In addition to that since if the length of `flag_buf` exceeds `19` the program exits, our input is probably `19` characters long.

When we take a look at the `check_flag()` function we see this:
```
int __usercall check_flag@<eax>(int argument@<esi>)
{
  int argumentCpy; // esi@1
  char a; // STFB_1@2
  __int64 b; // STF0_8@2
  __int64 c; // STE8_8@2
  __int64 d; // STE0_8@2
  __int64 e; // rax@2
  __int64 f; // STD8_8@2
  __int64 g; // rax@2
  __int64 h; // STD0_8@2
  __int64 j; // rax@2
  __int64 k; // STC8_8@2
  __int64 l; // STC0_8@2
  __int64 m; // rax@2
  __int64 n; // STD8_8@2
  __int64 o; // rax@2
  __int64 p; // STD0_8@2
  __int64 q; // rax@2
  __int64 r; // STC0_8@2
  __int64 s; // rax@2
  __int64 t; // STD8_8@2
  __int64 u; // rax@2
  __int64 v; // STC8_8@2
  __int64 w; // rax@2
  unsigned __int64 x; // STB8_8@2
  unsigned __int64 y; // STB8_8@2
  int result; // eax@2
  signed int i; // [sp+ECh] [bp-1Ch]@1

  _x86_get_pc_thunk_si();
  argumentCpy = argument + 9642;
  for ( i = 0; ; ++i )
  {
    if ( i > 19 )
    {
      printf(&aPctfS[argumentCpy - 12288], &flag_buf[argumentCpy - 12288]);
      exit(0);
    }
    a = *(&flag_buf[argumentCpy - 12288] + i);
    b = a & 3;
    c = (a >> 2) & 3;
    d = (a >> 4) & 0xF;
    LODWORD(e) = rol(b + 0xA55AA55AA559LL, 2);
    f = e;
    LODWORD(g) = rol(c - e + 0xA55AA55AA559LL, 13);
    h = g;
    LODWORD(j) = rol(d - g + 0xA55AA55AA559LL, 17);
    k = j;
    l = h ^ j ^ f;
    LODWORD(m) = rol((h & ~(h ^ j ^ f) | j & (h ^ j ^ f)) + f + d + 0xFF01F83C6LL, 3);
    n = m;
    LODWORD(o) = rol((k & ~m | l & m) + h + b + 68453106630LL, 11);
    p = o;
    LODWORD(q) = rol((n & ~k | o & k) + l + c + 68453106630LL, 19);
    r = q;
    LODWORD(s) = rol((p ^ k ^ q) + n + c + 0xB744867B8CA6LL, 5);
    t = s;
    LODWORD(u) = rol((r ^ s ^ p) + k + b + 0xB744867B8CA6LL, 7);
    v = u;
    LODWORD(w) = rol((t ^ p ^ u) + r + d + 0xB744867B8CA6LL, 23);
    x = (unsigned int)((unsigned __int64)(v + w + t + p) >> 32) ^ (unsigned __int64)(v + w + t + p);
    y = (x >> 16) ^ x;
    result = (unsigned __int8)(BYTE1(y) ^ y);
    if ( (*(_BYTE **)((char *)&check_buf + argumentCpy - 12288))[i] != (BYTE1(y) ^ (unsigned __int8)y) )
      break;
  }
  return result;
}
```

Looking at this, we can see that it checks the input one byte at a time. We know this because when we set a breakpoint in a debugger and see what `a` is set equal to, we see that it is set to a byte of our input starting with the first one. We see that it takes `a` and uses it to perform a long series of calculations. Then it runs an if then statement at the end, and if it fails then the loop ends. We can also see that if the loop runs `19` times, then the flag is printed (we can tell that with the printf statement in the for loop the address `&aPctfS[argumentCpy - 12288]` points to `PCTF{%s}`). Due to the structure of this program, we can use Angr to solve this problem.

### Angr Script

This portion of the writeup is based off of: https://github.com/elklepo/pwn/blob/master/PlaidCTF_2019/i_can_count/exploit.py

So with our knowledge of what the binary expects as input, and how it evaluates that input, we can just use angr to figure out what input it would expect to print the flag:

```
# This script is based off of: https://github.com/elklepo/pwn/blob/master/PlaidCTF_2019/i_can_count/exploit.py

# Import angr & Claripy

import angr
import claripy

# Establish the target
target = angr.Project('i_can_count_8484ceff57cb99e3bdb3017f8c8a2467', auto_load_libs=False)

# Establish the entry state to be the start of the check_flag function
state = target.factory.blank_state(addr = target.loader.find_symbol('check_flag').rebased_addr)

# Establish the input angr has control over, as a array with nineteen bytes, values between ASCII 0 - 9 (0x30 - 0x39)
flag_input = claripy.BVS('flag', 8*19)
for i in flag_input.chop(8):
  state.solver.add(state.solver.And(i >= '0', i <= '9'))

# Set the area of memory in the binary where our input is set 
state.memory.store(target.loader.find_symbol('flag_buf').rebased_addr, flag_input)

# Establish the simulation
simulation = target.factory.simulation_manager(state)

# Establish the addresses wh
success = 0xf87 + target.loader.main_object.min_addr
failure = 0xfae + target.loader.main_object.min_addr

# Setup the simulation
simulation.use_technique(angr.exploration_techniques.Explorer(find = success, avoid= failure))

# Run the simulation
print simulation.run()

# Parse out the solution, in integer form
flag_integer = simulation.found[0].solver.eval(flag_input)

# Go through and convert the solution to a string
flag = ""
for i in xrange(19):
  flag = chr(flag_integer & 0xff) + flag
  flag_integer = flag_integer >> 8

# Print the flag
print "flag: PCTF{" + flag + "}" 
```

When we run the script (it takes a minute to run):
```
$   python rev.py 
WARNING | 2019-04-21 18:34:38,815 | angr.analyses.disassembly_utils | Your version of capstone does not support MIPS instruction groups.
WARNING | 2019-04-21 18:34:38,862 | cle.loader | The main binary is a position-independent executable. It is being loaded with a base address of 0x400000.
<SimulationManager with 1 found, 19 avoid>
flag: PCTF{2052419606511006177}
```

Just like that we get the flag `PCTF{2052419606511006177}`.
