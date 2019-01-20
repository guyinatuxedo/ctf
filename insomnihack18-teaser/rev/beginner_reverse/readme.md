# Insomnihack 2018 beginner reverse

Let's take a look at the binary, and run it:
```
beginner_reverse-466bdf23cf344b8ee734a8ae86620ac72a37bb81a950b30eae6709f185c3b247: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=0f81b8fd8f6542e92e7e98c809bd2fd532e52c79, with debug_info, not stripped
$	./beginner_reverse-466bdf23cf344b8ee734a8ae86620ac72a37bb81a950b30eae6709f185c3b247 
15935728
```

So we can see that it is a 64 bit binary. When we run it, it appears to just scan in input and process it somehow. When we look at it in Binja, it becomes apparant that this was written in Rust. When we look at the main function, we see this:
```
main:
push    rax {var_8}
mov     rax, rsi
movsxd  rdx, edi
lea     rcx, [rel beginer_reverse::main::h80fa15281f646bc1]
mov     qword [rsp {var_8}], rcx  {beginer_reverse::main::h80fa15281f646bc1}
lea     rsi, [rel anon.0e239fffff9ba82fdff...fcd948ac0.0.llvm.15443791065720472637]
mov     rdi, rsp {var_8}
mov     rcx, rax
call    std::rt::lang_start_internal::had9505969b8e20a2
pop     rcx {var_8}
retn     {__return_addr}
```

Since I haven't reversed Rust much, I just looked for where our input was scanned in, and what used out input after it. When we step through the function, we see that our input is scanned in in the function which is called right before the main function returns, so that sub function is probably what's important and we can just ignore everything else in the main function.

When we first look at the sub function `lang_start_internal::had9505969b8e20a2`, it might look a bit overwhelming at first. However when we step through it, we can see that our input is scanned in at `0xee11` with this line:

```
call    __rust_maybe_catch_panic
```

I spent a lot of time looking for what happens to our input after this function is called, however after vetting out the rest of the function I decided to look closer at the `__rust_maybe_catch_panic` call (what happens after this function doesn't matter, we can step through the rest of it and see that our input really isn't messed with in any way of importance to us). When we take a look at the `__rust_maybe_catch_panic` we see this:

```
__rust_maybe_catch_panic:
push    rbp {var_8}
push    r15 {var_10}
push    r14 {var_18}
push    rbx {var_20}
sub     rsp, 0x18
mov     r14, rcx
mov     rbx, rdx
mov     rax, rdi
xor     ebp, ebp
mov     rdi, rsi
call    rax
{ Falls through into sub_2153a }
```

Stepping through this function, we can see again that our input isn't scanned in untill the function which is called at the end. That leads us to `beginer_reverse::main::h80fa15281f646bc1` (I just looked at what function we end up after the jump there in gdb). Looking at this function we can see where our input is scanned into memory with `read_line` at `0x6769`

```
call    std::io::stdio::Stdin::read_line::h85c3421ca914511e
```

After that we can see a compare and jump statement immediately following the `read_line` call. I figured out through accidental trial and error to solve a check later on, that this check here essentially just makes sure your input is all in UTF-8 characters:

```
cmp     qword [rsp+0x58 {var_60}], 0x1
je      0x6aaf
```

After that (down the branch that passes the last check) we see a long chain of compare statements. Looking at the one of the checks, it becomes apparant that we won't be able to pass all of these checks:

```
je      0x6aaf
mov     ebx, esi
and     bl, 0xc0
cmp     bl, 0x80
jne     0x680d
```

looking at this, a character from our input end up in `bl`, which gets anded by `0xc0` and then get's compared to `0x80`. In order to pass this check we will need to insert a character that when it get's anded by `0xc0` it ends up as `0x80`. Due to how anding works, the only value we can actually give here top pass this check is `0x80`. However that is not a UTF-8 character, so we won't pass the check up above so we wouldn't ever be able to reach this check if we gave it that character. As a result, passing some of these checks just isn't pheasible.

So after this I just looked throughout the rest of the function for where the code actually prints output, which I found the segment of code which prints the victory message starting at `0x69b6`:

```
lea     rax, [rel data_64f00]
mov     qword [rsp+0x58 {var_60}], rax  {data_64f00}
mov     qword [rsp+0x60 {var_58}], 0x1
mov     qword [rsp+0x68 {var_58+0x8}], 0x0
lea     rax, [rel data_510c8]  {"src/main.rsError reading input: …"}
mov     qword [rsp+0x78 {var_40_1}], rax  {data_510c8, "src/main.rsError reading input: …"}
mov     qword [rsp+0x80 {var_38_1}], 0x0
lea     rdi, [rsp+0x58 {var_60}]
call    std::io::stdio::_print::h77f73d11755d3bb8
```

When we jump to that block of code in a debugger, it prints out a victory message, so it becomes clear that we need to reach that block of code in order to solve the challenge. Directly above that you can see a loop that appears to be checking input, which depending on the checks it can either run the victory block or skip it. I made sure with just normal input we can reach the block, then I just stepped through it untill I saw how our input was used. That is when I found this code:

```
mov     edi, dword [r15+rsi*4]
sar     edi, 0x2
xor     edi, 0xa
xor     eax, eax
cmp     edi, dword [r14+rsi*4]
```

What this code segment does here is it moves a character of the encrypted flag out of memory into `edi`, decrypts it, then compares it to a character of our own input. We can see an example of that here:
```

```

So we can see here that it moves an encrypted value into the `edi` register, then it shifts it over by two bits (bits one the right fall off instead of getting shifted to the left most side). Proceeding that it xors it by `0xa`, and then we have the unencrypted character

we can actually see the full encrypted flag here:
```
Breakpoint 10, 0x000055555555a985 in beginer_reverse::main ()
b-peda$ x/18g $r15+$rsi*4
0x7ffff6c2a000:	0x000001120000010e	0x000001c600000166
0x7ffff6c2a010:	0x000000ea000001ce	0x000001e2000001fe
0x7ffff6c2a020:	0x000001ae00000156	0x000001e200000156
0x7ffff6c2a030:	0x000001ae000000e6	0x00000156000000ee
0x7ffff6c2a040:	0x000000fa0000018a	0x000001ba000001e2
0x7ffff6c2a050:	0x000000ea000001a6	0x000000e6000001e2
0x7ffff6c2a060:	0x000001e200000156	0x000001f2000000e6
0x7ffff6c2a070:	0x000001e2000000e6	0x000000e6000001e6
0x7ffff6c2a080:	0x000001de000001e2	0x0000000000000000
```

and we can see the unencrypted flag character here:

```
Breakpoint 8, 0x000055555555a991 in beginer_reverse::main ()
gdb-peda$ p $edi
$165 = 0x49
```

so we have two options now to solve this. We can either rerun the program 34 times (once per character) and see what flag character it is looking for, add it, and then rerun it. Or we can just write a quick pythons script to decode it for us (keep in mind that the encrypted flag is stored in least endian, so we need to reverse their order):

```
$	cat rev.py 
encFlag = [0x10e, 0x112, 0x166, 0x1c6, 0x1ce, 0xea, 0x1fe, 0x1e2, 0x156, 0x1ae, 0x156, 0x1e2, 0xe6, 0x1ae, 0xee, 0x156, 0x18a, 0xfa, 0x1e2, 0x1ba, 0x1a6, 0xea, 0x1e2, 0xe6, 0x156, 0x1e2, 0xe6, 0x1f2, 0xe6, 0x1e2, 0x1e6, 0xe6, 0x1e2, 0x1de]

flag = ""
x = 0
for i in encFlag:
    x = i >> 2
    x = x ^ 0xa
    flag += chr(x)

print "the flag is: " + flag
```

and when we run the script:

```
$	python rev.py 
the flag is: INS{y0ur_a_r3a1_h4rdc0r3_r3v3rs3r}
```

So we got the flag, and when we try it out:

```
$	./beginner_reverse-466bdf23cf344b8ee734a8ae86620ac72a37bb81a950b30eae6709f185c3b247 
INS{y0ur_a_r3a1_h4rdc0r3_r3v3rs3r}
Submit this and get you'r points!
```

Just like that, we solved the challenge!
