# Rev 100 A tour of x86 pt 2

```
Open stage2 in a disassembler, and figure out how to jump to the rest of the code!

-Elyk
```

Now for this challenge, we have to compile and run a binary (which we will need nasm and qemu installed to do). You can compile it like this:
```
$	ls
Makefile  stage-1.asm  stage-2.bin
$	make
nasm -Wall -D NUM_SECTORS=8 -f bin -o stage-1.bin stage-1.asm
stage-1.asm:240: warning: uninitialized space declared in .text section: zeroing
dd bs=512        if=stage-1.bin of=tacOS.bin
1+0 records in
1+0 records out
512 bytes copied, 0.000172661 s, 3.0 MB/s
dd bs=512 seek=1 if=stage-2.bin of=tacOS.bin
0+1 records in
0+1 records out
470 bytes copied, 8.6686e-05 s, 5.4 MB/s
```

You can run the binary like this (or you can just look in the Makefile and see the qemu command to run it):
```
$	make run
Binary is 4 KB long
qemu-system-x86_64 -serial stdio -d guest_errors -drive format=raw,file=tacOS.bin
```

When we run it, we see a screen that comes up and prints some text. It doesn't look like anything important yet. So we take a quick look again through `stage-1.asm` and we see this on line `224`

```
load_second_stage:
  ; this bit calls another interrupt that uses a file-descriptor-like thing, a daps, to find a load a file from disk.
  ; load the rest of the bootloader
  mov si, daps ; disk packet address
  mov ah, 0x42 ; al unused
  mov dl, 0x80 ; what to copy
  int 0x13     ; do it (the interrupt takes care of the file loading)
```

This coupled with the fact that we are on stage 2, we can reasonably assume that the code in `stage-2.bin` is being ran. Let's take a quick look at the source code:

```
00000000 <.data>:
   0:   f4                      hlt
   1:   e4 92                   in     al,0x92
   3:   0c 02                   or     al,0x2
   5:   e6 92                   out    0x92,al
   7:   31 c0                   xor    eax,eax
   9:   8e d0                   mov    ss,eax
```

We see that there is a `hlt` instruction on the first line. This would stop the rest of the code in here from running. We can simply patch a NOP instruction (the code for it is `0x90`), which has code execution continue with the next instruction. You can do this with any hex editor, I just used Binja (just replace the `0xf4` with `0x90`). After that, just delete `tacOS.bin` and recompile it, then run the new binary.

When we run it again, we can see that after it gets past the point where it stopped before we patched it, there is a blue screen that pops up with the flag `flag{0ne_sm411_JMP_for_x86_on3_m4ss1ve_1eap_4_Y0U}`. Just like that, we solved the challenge!
