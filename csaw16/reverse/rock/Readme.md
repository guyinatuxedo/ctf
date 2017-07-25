Let's take a look at the elf:

```
$	file rock 
rock: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=1b8a37b6db38689354df86ec86fab729c1a54afb, stripped
```

So we can see that it is a 64 bit elf, let's try running it:

```
$	./rock 
try
-------------------------------------------
Quote from people's champ
-------------------------------------------
*My goal was never to be the loudest or the craziest. It was to be the most entertaining.
*Wrestling was like stand-up comedy for me.
*I like to use the hard times in the past to motivate me today.
-------------------------------------------
Checking....
Too short or too long
```

So we are prompted for input (which apparantly isn't the right length). It is probably being checked against something. Looking at the code in IDA, we can see that the code is C++. Either looking at the string `FLAG23456912365453475897834567` or the function `sub_4015dc` leads us to the following code:

```
int __fastcall input_prep(__int64 char_heap_struct, const std::string *input)
{
  char return_char; // [sp+1Fh] [bp-11h]@1

  check_sub_0((_QWORD *)char_heap_struct);
  *(_QWORD *)char_heap_struct = &off_401BF0;
  *(_DWORD *)(char_heap_struct + 12) = 0;
  std::string::string((std::string *)(char_heap_struct + 16), input);
  std::string::string((std::string *)(char_heap_struct + 24), input);
  std::allocator<char>::allocator(&return_char, input);
  std::string::string(char_heap_struct + 32, "FLAG23456912365453475897834567", &return_char);
  return std::allocator<char>::~allocator(&return_char);
}
```

So we can see here, that it is essentially moving our input and the string `FLAG23456912365453475897834567` and moving it into `char_heap_struct` So it is probably formatting our input and the flag string for later use:

```
  input_prep((__int64)&check_output_char, (const std::string *)&input);
```

Here is the function being called, and we can see the arguments that it is passed. Moving on we can see where the encryption part takes place with this function call:

```
  input_encrypt((__int64)&check_output_char);
```

and onto the code for function `sub_4016ba`

```
bool __fastcall input_encrypt(__int64 char_heap_struct)
{
  __int64 print; // rax@2
  _BYTE *current_char_open_0; // rax@5
  _BYTE *current_char_write; // rbx@5
  _BYTE *current_char_logic_0; // rax@5
  _BYTE *current_char_open_1; // rax@8
  _BYTE *current_char_write_1; // rbx@8
  _BYTE *current_char_logic_1; // rax@8
  bool return_value; // al@9
  int i; // [sp+18h] [bp-18h]@4
  int i2; // [sp+1Ch] [bp-14h]@7

  if ( std::string::length((std::string *)(char_heap_struct + 16)) != 30LL )
  {
    LODWORD(print) = std::operator<<<std::char_traits<char>>(&std::cout, "Too short or too long");
    std::ostream::operator<<(print, &std::endl<char,std::char_traits<char>>);
    exit(-1);
  }
  for ( i = 0; (unsigned __int64)i <= std::string::length((std::string *)(char_heap_struct + 16)); ++i )
  {
    LODWORD(current_char_open_0) = std::string::operator[](char_heap_struct + 16, i);
    current_char_write = current_char_open_0;
    LODWORD(current_char_logic_0) = std::string::operator[](char_heap_struct + 16, i);
    *current_char_write = (*current_char_logic_0 ^ 0x50) + 20;
  }
  for ( i2 = 0; ; ++i2 )
  {
    return_value = (unsigned __int64)i2 <= std::string::length((std::string *)(char_heap_struct + 16));
    if ( !return_value )
      break;
    LODWORD(current_char_open_1) = std::string::operator[](char_heap_struct + 16, i2);
    current_char_write_1 = current_char_open_1;
    LODWORD(current_char_logic_1) = std::string::operator[](char_heap_struct + 16, i2);
    *current_char_write_1 = (*current_char_logic_1 ^ 0x10) + 9;
  }
  return return_value;
}
```

Corresponding to where our input was stored in `input_prep`, we can see that our input is being ran through two seperate loops that are changing the values of the strings byte by byte. Also we can see that we need to submit a string that is 30 characters long. It essentially translates to the following python code:

```
if len(input) == 30:
	out = ""
	for i in input:
		x = ord(i)
		x = ord(i)
		x = x ^ 0x50
		x = x + 20
		x = x ^ 0x10
		x = x + 9
		out += chr(x)
	print out
```

So as we can see, it takes each character, xors it by 0x50 then adds 20 to it, then xors it by 0x10 and then adds 9. Moving on we can see where it performs the check on the input with the following line:

```
  if ( (unsigned int)input_check((__int64)&char_heap_struct) == 0 ) 
```

and now onto the code for `sub_4017ff`

```
__int64 __fastcall real_input_check(__int64 char_heap_struct)
{
  char *flagstring_scan; // rax@2
  char flagstring_scan_transfer; // bl@2
  _BYTE *input_scan; // rax@2
  __int64 pass_print0; // rax@3
  __int64 pass_print1; // rax@3
  __int64 fail_print0; // rax@4
  __int64 fail_print1; // rax@4
  unsigned int i; // [sp+1Ch] [bp-14h]@1

  for ( i = 0; (unsigned __int64)(signed int)i < std::string::length((std::string *)(char_heap_struct + 16)); ++i )
  {
    LODWORD(flagstring_scan) = std::string::operator[](char_heap_struct + 32, (signed int)i);
    flagstring_scan_transfer = *flagstring_scan;
    LODWORD(input_scan) = std::string::operator[](char_heap_struct + 16, (signed int)i);
    if ( flagstring_scan_transfer != *input_scan )
    {
      LODWORD(fail_print0) = std::operator<<<std::char_traits<char>>(&std::cout, "You did not pass ");
      LODWORD(fail_print1) = std::ostream::operator<<(fail_print0, i);
      std::ostream::operator<<(fail_print1, &std::endl<char,std::char_traits<char>>);
      *(_DWORD *)(char_heap_struct + 12) = 1;
      return *(_DWORD *)(char_heap_struct + 12);
    }
    LODWORD(pass_print0) = std::operator<<<std::char_traits<char>>(&std::cout, "Pass ");
    LODWORD(pass_print1) = std::ostream::operator<<(pass_print0, i);
    std::ostream::operator<<(pass_print1, &std::endl<char,std::char_traits<char>>);
  }
  return *(_DWORD *)(char_heap_struct + 12);
}
```

So we can see here, that it is essentially scanning in the output of our modified and input and comparing each character to that of the flag string `FLAG23456912365453475897834567`. If it success, it prints our that we passed along with the iteration count and continues to the next check. If it fails, then the for loop stops and it prints that we have failed along with the iteration count. 

So essentially this program scans in our input, runs it through an algorithm, then compares the output to the string `FLAG23456912365453475897834567`. good news for us is all the logic that was performed on our input (xor and addition) is all reversible. And since we know what the output is, we can just take that string and reverse the logic on it to get the desired input. We can do that with the following python code:

```
#Designate the string which we need the output of the encryption to be
string = "FLAG23456912365453475897834567"

#Specify the output string
out = ""

#Run the loop which will reverse the encryption logic, and add each byte to the output string
for i in string:
	x = ord(i)
	x = ord(i)
	x = x - 9
	x = x ^ 0x10
	x = x - 20
	x = x ^ 0x50
	out += chr(x)

#Print the result
print out
```

Let's see it in action!

```
$	python solve.py 
IoDJuvwxy\tuvyxwxvwzx{\z{vwxyz
$	./rock 
IoDJuvwxy\tuvyxwxvwzx{\z{vwxyz
-------------------------------------------
Quote from people's champ
-------------------------------------------
*My goal was never to be the loudest or the craziest. It was to be the most entertaining.
*Wrestling was like stand-up comedy for me.
*I like to use the hard times in the past to motivate me today.
-------------------------------------------
Checking....
Pass 0
Pass 1
Pass 2
Pass 3
Pass 4
Pass 5
Pass 6
Pass 7
Pass 8
Pass 9
Pass 10
Pass 11
Pass 12
Pass 13
Pass 14
Pass 15
Pass 16
Pass 17
Pass 18
Pass 19
Pass 20
Pass 21
Pass 22
Pass 23
Pass 24
Pass 25
Pass 26
Pass 27
Pass 28
Pass 29
/////////////////////////////////
Do not be angry. Happy Hacking :)
/////////////////////////////////
Flag{IoDJuvwxy\tuvyxwxvwzx{\z{vwxyz}
```

Just like that, we got the flag!
