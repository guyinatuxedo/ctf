# fairlight

This writeup is based off of: https://github.com/angr/angr-doc/tree/master/examples/securityfest_fairlight

Let's take a look at the binary:
```
$	file fairlight 
fairlight: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/l, for GNU/Linux 2.6.24, BuildID[sha1]=382cac0a89b47b48f6e24cdad066e1ac605bd3e5, not stripped
$	./fairlight 
useage: ./keygen code
$	./fairlight 15935728
NOPE - ACCESS DENIED!
```

So we are given a `64` bit binary that prompts us for a code as an argument.

### Reversing

Looking at the IDA psuedo code for the main function, we see this:

```
int __cdecl main(int argc, const char **codeArg, const char **envp)
{
  const char *v3; // rsi@6
  int result; // eax@6
  __int64 v5; // rbx@6
  const char **argCpy; // [sp+0h] [bp-1C0h]@1
  char s[8]; // [sp+10h] [bp-1B0h]@1
  char v8; // [sp+18h] [bp-1A8h]@1
  __int64 stackCanary; // [sp+1A8h] [bp-18h]@1

  argCpy = codeArg;
  stackCanary = *MK_FP(__FS__, 40LL);
  *(_QWORD *)s = 0LL;
  memset(&v8, 0, 0x188uLL);
  if ( argc <= 1 )
  {
    puts("useage: ./keygen code");
    exit(0);
  }
  if ( strlen(codeArg[1]) != 14 )
    denied_access();
  v3 = codeArg[1];
  strncpy(&code, v3, 0x28uLL);
  check_0((__int64)&code, (__int64)v3);
  check_1();
  check_2();
  check_3();
  check_4();
  check_5();
  check_6();
  check_7();
  check_8();
  check_9();
  check_10();
  check_11();
  check_12();
  check_13();
  sprintf(s, success, &code, argCpy);
  printf("%s", s);
  result = 0;
  v5 = *MK_FP(__FS__, 40LL) ^ stackCanary;
  return result;
}
```

So we can see it first checks that our input is `14` characters, then runs 14 different checks on our input. When we look at the checks, we see that they each perform checks on our input. If either the checks in the `check_x` or the initial input length checks fail, then the `denied_access` function is called which exits the code.


Now we could go through and reverse all of the checks to figure out how to pass all of them and get the correct input. On the other hand, we could just use Angr (can be found here: https://github.com/angr/angr). Angr is a binary analysis framework, that will allow us to write a simple script in which we tell it what address we want to go to, and which one we don't want it to end up at (in addition to that what input we have control over). Then angr will figure what input is needed to get to the desired address, while avoiding the undesired address.

### Angr

To use angr, we need to specify three things. The address we want to end up at, the address we don't want to end up at, and our input. We could also specify an address that we start at, however in this situation it really wouldn't help us that much.

For the address we want to end up at, the `printf` victory call at `0x401a73` seems as good as any (since we should only end up here if we give the correct input):

```
  401a5a:       e8 d1 eb ff ff          call   400630 <sprintf@plt>
  401a5f:       48 8d 85 50 fe ff ff    lea    rax,[rbp-0x1b0]
  401a66:       48 89 c6                mov    rsi,rax
  401a69:       bf 24 1b 40 00          mov    edi,0x401b24
  401a6e:       b8 00 00 00 00          mov    eax,0x0
  401a73:       e8 88 eb ff ff          call   400600 <printf@plt>
```

For the address we don't want to end up at, I choose `0x40074d` the start of the `denied_access` function. This is because whenever this function is executed, we didn't give the correct input:

```
000000000040074d <denied_access>:
  40074d:       55                      push   rbp
  40074e:       48 89 e5                mov    rbp,rsp
  400751:       be a0 30 60 00          mov    esi,0x6030a0
  400756:       bf 24 1b 40 00          mov    edi,0x401b24
  40075b:       b8 00 00 00 00          mov    eax,0x0
  400760:       e8 9b fe ff ff          call   400600 <printf@plt>
  400765:       bf 00 00 00 00          mov    edi,0x0
  40076a:       e8 d1 fe ff ff          call   400640 <exit@plt>
```

As for the input size, our input is `14` characters. Since a character takes up one byte, that gives us `14 * 8 = 112` bits for our input. We will just use claripy (angr's solver engine) to establish a bit vector with `112` bits, and use that as input.

With those three componets, we can write the solution script:
```
# This script is based off of: https://github.com/angr/angr-doc

# Import angr and claripy
import angr
import claripy

# Establish the angr project
target = angr.Project('./fairlight', load_options={"auto_load_libs": False})

# Establish the input as a 14*8 = 112 bit vector for 14 characters
inp_argv1 = claripy.BVS("inp_argv1", 0xe * 8)

# Establish the entry state as the binary running with our input as argv1
entry_state = target.factory.entry_state(args=["./fairlight", inp_argv1])

# Establish the simulation
simulation = target.factory.simulation_manager(entry_state)

# Symbolically execute the binary until find / avoid conditions met 
simulation.explore(find = 0x401a73, avoid = 0x40074d)

# Parse in the correct input
solution = simulation.found[0]

# Print the correct input
print solution.solver.eval(inp_argv1, cast_to=bytes)
```

When we run it, we can see the flag:
```
$	python rev.py 
WARNING | 2019-04-11 14:01:28,616 | angr.analyses.disassembly_utils | Your version of capstone does not support MIPS instruction groups.
WARNING | 2019-04-11 14:01:35,862 | angr.state_plugins.symbolic_memory | Concretizing symbolic length. Much sad; think about implementing.
4ngrman4gem3nt
$	./fairlight 4ngrman4gem3nt
OK - ACCESS GRANTED: CODE{4ngrman4gem3nt}
```

Just like that, we solved the challenge.
