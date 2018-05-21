# movuscated1

This challenge is from, and this writeup is based off of https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html

Let's check out the elf:

```
$	file movfuscated1 
movfuscated1: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, stripped
$	./movfuscated1 
M/o/Vfuscator 2.0a // domas // @xoreaxeaxeax
Enter the key: key_pls
Nope.
```

So we can see that it is a 32 bit elf, that prompts us for a key, and it probably checks it and tells us if it is write or wrong. The special thing about this program is it was compiled with `M/o/Vfuscator` (checkout the github page: https://github.com/xoreaxeaxeax/movfuscator), which essentially is a compiler that only uses `mov` instructions. As you can imagine it will be a pain to reverse this (here is a piece of the assembly code):
```
.text:0804AE68                 mov     dl, byte_8063BD0[eax+ebx]
.text:0804AE6F                 mov     dh, byte_8063DE0[eax+ebx]
.text:0804AE76                 mov     al, byte_8063BD0[edx+ecx]
.text:0804AE7D                 mov     byte ptr unk_80D5C99, al
.text:0804AE82                 mov     al, byte_8063DE0[edx+ecx]
.text:0804AE89                 mov     byte ptr dword_80D5C9C, al
.text:0804AE8E                 mov     al, byte ptr dword_80D5C90+2
.text:0804AE93                 mov     bl, byte ptr dword_80D5C94+2
.text:0804AE99                 mov     cl, byte ptr dword_80D5C9C
.text:0804AE9F                 mov     dl, byte_8063BD0[eax+ebx]
.text:0804AEA6                 mov     dh, byte_8063DE0[eax+ebx]
.text:0804AEAD                 mov     al, byte_8063BD0[edx+ecx]
.text:0804AEB4                 mov     byte_80D5C9A, al
.text:0804AEB9                 mov     al, byte_8063DE0[edx+ecx]
.text:0804AEC0                 mov     byte ptr dword_80D5C9C, al
.text:0804AEC5                 mov     al, byte ptr dword_80D5C90+3
.text:0804AECA                 mov     bl, byte ptr dword_80D5C94+3
.text:0804AED0                 mov     cl, byte ptr dword_80D5C9C
.text:0804AED6                 mov     dl, byte_8063BD0[eax+ebx]
.text:0804AEDD                 mov     dh, byte_8063DE0[eax+ebx]
.text:0804AEE4                 mov     al, byte_8063BD0[edx+ecx]
.text:0804AEEB                 mov     byte_80D5C9B, al
.text:0804AEF0                 mov     al, byte_8063DE0[edx+ecx]
.text:0804AEF7                 mov     byte ptr dword_80D5C9C, al
.text:0804AEFC                 mov     eax, dword ptr byte_80D5C98
.text:0804AF01                 mov     edi, eax
.text:0804AF03                 mov     eax, 0FFFFFFFCh
.text:0804AF08                 mov     edx, off_81D5DB4
.text:0804AF0E                 mov     dword_80D5C90, eax
.text:0804AF13                 mov     dword_80D5C94, edx
```

However if this code checks the input one character at a time and then immediately exits upon reaching an incorrect character (like many other CTF challenges) then it would be possible to perform a Side-Channel Attack. For this we would essentially count the number of instructions that the program runs, and go with whatever character input yields the most instructions ran. This is because if there is a character that is correct, it will go on to check the next character which should run through more instructions than immediately exiting which is what we assume a wrong character will do. 

For this we can use the performance annalyzer `perf` to count the number of instructions ran (we can also count other events such as the `cpu-clock` or `branches`). Here are some examples

Count the number of instructions:
```
$	perf stat -e instructions ./movfuscated1 
M/o/Vfuscator 2.0a // domas // @xoreaxeaxeax
Enter the key: 15935728
Nope.

 Performance counter stats for './movfuscated1':

           804,200      instructions                                                

       2.940768967 seconds time elapsed
```

We can also format the output of `perf` to make it easier to parse:

```
$	perf stat -x : -e instructions ./movfuscated1 
M/o/Vfuscator 2.0a // domas // @xoreaxeaxeax
Enter the key: 15935728
Nope.
803653::instructions:857080:100.00::::
```

Also we can specify what privilege level we want to view the events (so count the number of instructions that run at the user level `:u` or the kernel level `:k`, or the user level `k`):

```
$	sudo perf stat -x : -e instructions:u ./movfuscated1 
M/o/Vfuscator 2.0a // domas // @xoreaxeaxeax
Enter the key: 15935728 
Nope.
261507::instructions:u:790421:100.00::::
```

We will want to use `u`, since the instructions we want to count are being ran with user level privileges.

So we can see that the number of instructions is the first thing it gives us with this form of output. Now with this, we can write a python program based off of the earlier mentined writeup which will simply iterate through all printable characters for each slot, choose the character which has the most instructions ran, and move on to the next character.

```
#Import the libraries
from subprocess import *
import string
import sys

#Establish the command to count the number of instructions, pipe output of command to /dev/null
command = "perf stat -x : -e instructions:u " + sys.argv[1] + " 1>/dev/null" 

#Establish the empty flag
flag = ''


while True:
	#Reset the highest instruction value and corresponding character 
	ins_count = 0
	count_chr = ''
	#Iteratethrough all printable chatacyers
	for i in string.printable:
		#Start a new process for the new character
		target = Popen(command, stdout=PIPE, stdin=PIPE, stderr=STDOUT, shell=True)
		#Give the program the new input to test, and grab the store the output of perf-stat in target_output
		target_output, _ = target.communicate(input='%s\n'%(flag + i))
		#Filter out the instruction count
		instructions = int(target_output.split(':')[0])
		#Check if the new character has the highest instruction count, and if so record the instruction count and corresponding character
		if instructions > ins_count:
			count_chr = i
			ins_count = instructions
	#Add the character with the highest instruction count to flag, print it, and restart
	flag += count_chr
	print flag
```

and when we run it:

```
$	python reverent.py ./movfuscated1 
{
{R
{RE
{REc
{REco
{REcoN
{REcoN2
{REcoN20
{REcoN201
{REcoN2016
{REcoN2016}
{REcoN2016}f
{REcoN2016}f1
{REcoN2016}f1t
{REcoN2016}f1t$
{REcoN2016}f1t$2
{REcoN2016}f1t$2F
```

The script will loop on forever, so it will continue to try and figure out characters even after it already has the key (which is probably `{REcoN2016}`). Let's try it!

```
$	./movfuscated1 
M/o/Vfuscator 2.0a // domas // @xoreaxeaxeax
Enter the key: {REcoN2016}   
YES!
```

Just like that, we solved the challenge!
