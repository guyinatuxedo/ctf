This writeup is based off of this other writeup:
```
http://ohaithe.re/post/129657401392/csaw-quals-2015-reversing-500-wyvern
```

Let's take a look at the elf:
```
$	file wyvern_c85f1be480808a9da350faaa6104a19b 
wyvern_c85f1be480808a9da350faaa6104a19b: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=45f9b5b50d013fe43405dc5c7fe651c91a7a7ee8, not stripped
```

So it is a 64 bit elf. When we run it, we see that it prompts us for a certain unknown string. So it is probably looking for a string that we can find by reversing the elf, then when we enter it and it passed the check we will get the flag. Let's take a look at the main function in IDA.

```
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v3; // ST24_4@1
  __int64 v4; // rdx@1
  char v6; // [sp+80h] [bp-140h]@2
  char v7; // [sp+88h] [bp-138h]@1
  char v8; // [sp+A0h] [bp-120h]@1
  char v9; // [sp+A8h] [bp-118h]@1
  char input_char; // [sp+B0h] [bp-110h]@1
  int v11; // [sp+1BCh] [bp-4h]@1

  v11 = 0;
  std::operator<<<std::char_traits<char>>(&std::cout, (unsigned int)"+-----------------------+\n", envp);
  std::operator<<<std::char_traits<char>>(
    &std::cout,
    (unsigned int)"|    Welcome Hero       |\n",
    "|    Welcome Hero       |\n");
  std::operator<<<std::char_traits<char>>(
    &std::cout,
    (unsigned int)"+-----------------------+\n\n",
    "+-----------------------+\n\n");
  std::operator<<<std::char_traits<char>>(
    &std::cout,
    (unsigned int)"[!] Quest: there is a dragon prowling the domain.\n",
    "[!] Quest: there is a dragon prowling the domain.\n");
  std::operator<<<std::char_traits<char>>(
    &std::cout,
    (unsigned int)"\tbrute strength and magic is our only hope. Test your skill.\n\n",
    "\tbrute strength and magic is our only hope. Test your skill.\n\n");
  std::operator<<<std::char_traits<char>>(
    &std::cout,
    (unsigned int)"Enter the dragon's secret: ",
    "Enter the dragon's secret: ");
  fgets(&input_char, 257, stdin);
  std::allocator<char>::allocator((__int64)&v8, 257LL);
  std::string::string((__int64)&v9, (__int64)&input_char, (__int64)&v8);
  std::allocator<char>::~allocator(&v8);
  std::string::string((std::string *)&v7, (const std::string *)&v9);
  v3 = start_quest((std::string *)&v7);
  std::string::~string((std::string *)&v7);
  if ( v3 == 0x1337 )
  {
    std::string::string((std::string *)&v6, (const std::string *)&v9);
    reward_strength((std::string *)&v6);
    std::string::~string((std::string *)&v6);
  }
  else
  {
    std::operator<<<std::char_traits<char>>(
      &std::cout,
      (unsigned int)"\n[-] You have failed. The dragon's power, speed and intelligence was greater.\n",
      v4);
  }
  v11 = 0;
  std::string::~string((std::string *)&v9);
  return v11;
}
```

Ater looking through it, this is the piece that we are interested in:

```
  fgets(&input_char, 257, stdin);
  std::allocator<char>::allocator((__int64)&v8, 257LL);
  std::string::string((__int64)&v9, (__int64)&input_char, (__int64)&v8);
  std::allocator<char>::~allocator(&v8);
  std::string::string((std::string *)&v7, (const std::string *)&v9);
  output = start_quest((std::string *)&v7);
  std::string::~string((std::string *)&v7);
  if ( output == 0x1337 )
  {
    std::string::string((std::string *)&v6, (const std::string *)&v9);
    reward_strength((std::string *)&v6);
    std::string::~string((std::string *)&v6);
  }
  else
  {
    std::operator<<<std::char_traits<char>>(
      &std::cout,
      (unsigned int)"\n[-] You have failed. The dragon's power, speed and intelligence was greater.\n",
      v4);
  }
```

This has some garbage, but essentially what it is doing, is it is scanning in input securely with fgets, passing that as an argument to the `start_quest` function, then if the output is equal to the hex string `0x1337` we will get a reward. Let's take a look at the `start_quest` function.

When we look at the start quest function, we see a lot of if then statments resembling these two:

```
      if ( y26 < 10 || (((_BYTE)x25 - 1) * (_BYTE)x25 & 1) == 0 )
        break;
```

```
    if ( y26 >= 10 && (((_BYTE)x25 - 1) * (_BYTE)x25 & 1) != 0 )
      goto LABEL_15;
```

When we look to see where the variable being evaluated `y26` is called by examining the XREFS, we see that it is only read, never written to (the only type is `r` which means read). Since the variable is never written to, it is probably zero initiated. In addition to that, we can see that they are located in the bss (Basic Service Set) which hosts data values that are zero initialized. As a result of that, these if then statments can become really simple.

```
      if ( y26 < 10 || (((_BYTE)x25 - 1) * (_BYTE)x25 & 1) == 0 )
        break;
```

This will always result in true. This is because `y26 < 10` will always be true, since `0 < 10`. In addition to that `True or False = True` and `True or True = True`.


```
    if ( y26 >= 10 && (((_BYTE)x25 - 1) * (_BYTE)x25 & 1) != 0 )
      goto LABEL_15;
```

Since zero is less than 10, this will always evaluate to be false (and the fact that that `False and True = False` and `False and False = False`). So we can see that this binary was compiled to have essentially a lot of extra garbage in it, which we can clean up. This is what the `start_quest` after we cut out all of the unimportant pieces, and rename the variables:

```
__int64 __fastcall start_quest(std::string *argument)
{
  __int64 v2; // [sp+0h] [bp-90h]@2
  unsigned int return_value; // [sp+34h] [bp-5Ch]@11
  int sanitize_output; // [sp+48h] [bp-48h]@9
  bool len_check; // [sp+4Fh] [bp-41h]@2
  std::string *sanitize_input; // [sp+50h] [bp-40h]@2
  int *transfer; // [sp+58h] [bp-38h]@2
  std::string *argument_transfer; // [sp+70h] [bp-20h]@1

  argument_transfer = argument;
  transfer = (int *)(&v2 - 2);
  sanitize_input = (std::string *)(&v2 - 2);
  
  std::vector<int,std::allocator<int>>::push_back(&hero, &secret_100);
  std::vector<int,std::allocator<int>>::push_back(&hero, &secret_214);
  std::vector<int,std::allocator<int>>::push_back(&hero, &secret_266);
  std::vector<int,std::allocator<int>>::push_back(&hero, &secret_369);
  std::vector<int,std::allocator<int>>::push_back(&hero, &secret_417);
  std::vector<int,std::allocator<int>>::push_back(&hero, &secret_527);
  std::vector<int,std::allocator<int>>::push_back(&hero, &secret_622);
  std::vector<int,std::allocator<int>>::push_back(&hero, &secret_733);
  std::vector<int,std::allocator<int>>::push_back(&hero, &secret_847);
  std::vector<int,std::allocator<int>>::push_back(&hero, &secret_942);
  std::vector<int,std::allocator<int>>::push_back(&hero, &secret_1054);
  std::vector<int,std::allocator<int>>::push_back(&hero, &secret_1106);
  std::vector<int,std::allocator<int>>::push_back(&hero, &secret_1222);
  std::vector<int,std::allocator<int>>::push_back(&hero, &secret_1336);
  std::vector<int,std::allocator<int>>::push_back(&hero, &secret_1441);
  std::vector<int,std::allocator<int>>::push_back(&hero, &secret_1540);
  std::vector<int,std::allocator<int>>::push_back(&hero, &secret_1589);
  std::vector<int,std::allocator<int>>::push_back(&hero, &secret_1686);
  std::vector<int,std::allocator<int>>::push_back(&hero, &secret_1796);
  std::vector<int,std::allocator<int>>::push_back(&hero, &secret_1891);
  std::vector<int,std::allocator<int>>::push_back(&hero, &secret_1996);
  std::vector<int,std::allocator<int>>::push_back(&hero, &secret_2112);
  std::vector<int,std::allocator<int>>::push_back(&hero, &secret_2165);
  std::vector<int,std::allocator<int>>::push_back(&hero, &secret_2260);
  std::vector<int,std::allocator<int>>::push_back(&hero, &secret_2336);
  std::vector<int,std::allocator<int>>::push_back(&hero, &secret_2412);
  std::vector<int,std::allocator<int>>::push_back(&hero, &secret_2498);
  std::vector<int,std::allocator<int>>::push_back(&hero, &secret_2575);
  
  len_check = std::string::length(argument_transfer) - 1LL != set_int >> 2;

  if ( len_check )
  {
      *transfer = set_int >> 2;  
  }

  else
  {
      std::string::string(sanitize_input, argument_transfer);  
      sanitize_output = sanitize_input(sanitize_input);
      *transfer = sanitize_output;
      std::string::~string(sanitize_input);   
  }

  return_value = *transfer;
  return return_value;
}
```

So we can see here, it is essentially checking the length of the input string, and if it matches the correct length, it runs the `sanitize_input()` function. In addition to that, we can see that it is copying 28 positive integers over to the `hero` array with lines like these:

```
 std::vector<int,std::allocator<int>>::push_back(&hero, &secret_100);
```

 We can see the length check with this line:

```
len_check = std::string::length(argument_transfer) - 1LL != set_int >> 2;
```

This will set the bool `len_check` equal to false if the length of our argument isn't equal to the value of `set_int` when shifted to the right by 2. We can see what `set_int` is equal to in IDA:

```
.data:0000000000610138                 public set_int
.data:0000000000610138 set_int         dd 73h                  ; DATA XREF: sanitize_input(std::string)+20Er
```

Here we can see that `set_int` is equal to the hex string 0x73. When 0x73 is shifted to the right by two, we are left with 0x1c, so our password has to be 28 characters (same amount as the integers copied to hero). Let's look at the `sanitize_input()` function:

When we look at it, we can see that it has a lot of if then statements like the `start_quest` function. Here are the regex lines I used to find all of those statements.

```
y18 < 10 \|\| .*
y4 >= 10 \&\& .*
y18 >= 10 \&\& .*
y4 < 10 \|\| .*
```

Just like the `start_quest`, there is a lot of unnecissary code here that just makes it harder to read. This is our code after the cleanup:

Just like the `start_quest`, there is a lot of unnecissary code here that just makes it harder to read. This is our code after the cleanup:

```
__int64 __fastcall sanitize_input(std::string *argument)
{
  _BYTE *input_transfer_0; // rax@11
  int *custom_check_transfer_0; // rdx@18
  int *custom_check_transfer_2; // rax@23
  int *hero; // rax@27
  __int64 iteration_transfer_2; // rsi@41
  _DWORD *current_hero_character; // rax@42
  __int64 success_var; // rax@62
  __int64 init_int; // [sp+0h] [bp-180h]@4
  unsigned int return_value; // [sp+44h] [bp-13Ch]@65
  bool custom_check_test_1; // [sp+56h] [bp-12Ah]@46
  _DWORD *current_hero_character_transfer; // [sp+80h] [bp-100h]@42
  __int64 iteration_transfer_3; // [sp+88h] [bp-F8h]@41
  int custom_check_transfer_3; // [sp+90h] [bp-F0h]@41
  bool equal_check; // [sp+97h] [bp-E9h]@35
  int transform_input_value; // [sp+98h] [bp-E8h]@34
  int hero_transfer_1; // [sp+A0h] [bp-E0h]@29
  int *hero_transfer_0; // [sp+A8h] [bp-D8h]@27
  __int64 iteration_transfer_1; // [sp+B0h] [bp-D0h]@26
  bool custom_check_test_0; // [sp+BEh] [bp-C2h]@23
  unsigned __int64 input_length; // [sp+C0h] [bp-C0h]@20
  __int64 custom_check_transfer_1; // [sp+D0h] [bp-B0h]@18
  _BYTE *input_transfer_1; // [sp+E0h] [bp-A0h]@11
  __int64 iteration_transfer_0; // [sp+F0h] [bp-90h]@8
  bool len_check; // [sp+FFh] [bp-81h]@5
  __int64 *input_transfer_4; // [sp+100h] [bp-80h]@4
  int *custom_check; // [sp+108h] [bp-78h]@4
  __int64 *input_transfer_2; // [sp+120h] [bp-60h]@4
  int *i; // [sp+128h] [bp-58h]@4
  __int64 *input_transfer_3; // [sp+130h] [bp-50h]@4
  int *pass_return_value; // [sp+138h] [bp-48h]@4
  std::string *input; // [sp+150h] [bp-30h]@1

  input = argument;  

  pass_return_value = (int *)(&init_int - 2);
  input_transfer_3 = &init_int - 4;
  i = (int *)(&init_int - 2);
  input_transfer_2 = &init_int - 2;
  custom_check = (int *)(&init_int - 2);
  input_transfer_4 = &init_int - 4;
  std::vector<int,std::allocator<int>>::vector(&init_int - 4);
  *i = 0;
  while ( 1 )
  { 
    len_check = *i < set_int >> 2;
    if ( !len_check )
    {
      do
      LODWORD(success_var) = std::operator<<<std::char_traits<char>>(
                      &std::cout,
                      (unsigned int)"success\n",
                      (unsigned int)(x17 - 1));
        *pass_return_value = 4919;
      goto LABEL_END;
    }
    iteration_transfer_0 = *i;       
  
    LODWORD(input_transfer_0) = std::string::operator[](input, iteration_transfer_0);
    input_transfer_1 = input_transfer_0;
    *(_DWORD *)input_transfer_2 = *input_transfer_1;
    std::vector<int,std::allocator<int>>::push_back(input_transfer_3, input_transfer_2);
  
    custom_check_transfer_0 = custom_check;
    *custom_check = *i;
    custom_check_transfer_1 = *custom_check_transfer_0;custom_check_transfer_1
    input_length = std::string::length(input);
    custom_check_transfer_2 = custom_check;
    *custom_check = (input_length >> 40) & custom_check_transfer_1 | 0x1C;
    custom_check_test_0 = *custom_check_transfer_2 != 0;
   
    if ( custom_check_test_0 )
    {
      iteration_transfer_1 = *i;
      LODWORD(hero) = std::vector<int,std::allocator<int>>::operator[]((unsigned int)&hero, iteration_transfer_1);
      hero_transfer_0 = hero;
      hero_transfer_1 = *hero_transfer_0;
      std::vector<int,std::allocator<int>>::vector(input_transfer_4, input_transfer_3);
      transform_input_value = transform_input((__int64)input_transfer_4);
      equal_check = hero_transfer_1 == transform_input_value;
      std::vector<int,std::allocator<int>>::~vector(input_transfer_4);
      if ( equal_check )
      {
          iteration_transfer_2 = *i;
          custom_check_transfer_3 = *custom_check;
          iteration_transfer_3 = iteration_transfer_2;
      }

      LODWORD(current_hero_character) = std::vector<int,std::allocator<int>>::operator[]((unsigned int)&hero, iteration_transfer_3);
      current_hero_character_transfer = current_hero_character;
      *custom_check = (*current_hero_character_transfer & custom_check_transfer_3) < 0;
      
      custom_check_test_1 = *custom_check != 0;
    }
    
    if ( custom_check_test_1 )
    {
        break;
    }
    
    ++*i;
  
  }

    *pass_return_value = ((unsigned __int16)*i << 8) & 0x147;

LABEL_END:
    std::vector<int,std::allocator<int>>::~vector(input_transfer_3);
    return_value = *pass_return_value;

  return return_value;
}
```

So we know that we need this function to output 0x1337. We can see that that hex string is written to `pass_return_value`, which whatever is in there will get outputted if this if then statement is executed.

```
    len_check = *i < set_int >> 2;
    if ( !len_check )
    {
      do
      LODWORD(success_var) = std::operator<<<std::char_traits<char>>(
                      &std::cout,
                      (unsigned int)"success\n",
                      (unsigned int)(x17 - 1));
        *pass_return_value = 4919;
      goto LABEL_END;
    }
```

So we can see here that if the iteration count `i`, which starts at 0 and is incremented by one each time the loop runs, is equal to or greater than `set_int >> 2` ( 0x73 >> 2 = 28) or 28. In addition to that, it will jump to `LABEL_END` and safely output the value we need. Since even after our clean up this code is still unnecissaryily complicated, let's go through it block by block:

```
    iteration_transfer_0 = *i;       
  
    LODWORD(input_transfer_0) = std::string::operator[](input, iteration_transfer_0);
    input_transfer_1 = input_transfer_0;
    *(_DWORD *)input_transfer_2 = *input_transfer_1;
    std::vector<int,std::allocator<int>>::push_back(input_transfer_3, input_transfer_2);
```

This essentially just grabs the current input character that corresponds to the current iteration (so first character for first iteration, second for second, etc.)

```
    custom_check_transfer_0 = custom_check;
    *custom_check = *i;
    custom_check_transfer_1 = *custom_check_transfer_0;custom_check_transfer_1
    input_length = std::string::length(input);
    custom_check_transfer_2 = custom_check;
    *custom_check = (input_length >> 40) & custom_check_transfer_1 | 0x1C;
    custom_check_test_0 = *custom_check_transfer_2 != 0;
```

Here we can see it establishes the variable `custom_check`, and see's if it is equal to zero, and then stores the result of that in `custom_check_test_0`. We can see that `custom_check` has an initial value of 0x1C writtent to it, so it will pass the first check. We see that later on, the only time it is ever written to again is when it is xored with the current character of hero.  Remember that in that case, we will be xoring a postivie int with a positive int, so we can't get anything less than 0. 

```
    if ( custom_check_test_0 )
    {
      iteration_transfer_1 = *i;
      LODWORD(hero) = std::vector<int,std::allocator<int>>::operator[]((unsigned int)&hero, iteration_transfer_1);
      hero_transfer_0 = hero;
      hero_transfer_1 = *hero_transfer_0;
```

Here we can see the first part of the main if then statement. We can see here that it is essentially just grabbing the current hero character.

```
      std::vector<int,std::allocator<int>>::vector(input_transfer_4, input_transfer_3);
      transform_input_value = transform_input((__int64)input_transfer_4);
```

Here we can see that it is grabbing the current character from our input, and running it through the `transform_input()` function. We need to look into that later.

```
      equal_check = hero_transfer_1 == transform_input_value;
      std::vector<int,std::allocator<int>>::~vector(input_transfer_4);
      if ( equal_check )
      {
          iteration_transfer_2 = *i;
          custom_check_transfer_3 = *custom_check;
          iteration_transfer_3 = iteration_transfer_2;
      }
```

Here we can see that it is checking to see if the output from `transform_input()` is the same as the current hero character. If it is, it set's certain variables equal to the iteration count and the custom check, which later on we can see we need (so we can influence the curstom_check).

```
      LODWORD(current_hero_character) = std::vector<int,std::allocator<int>>::operator[]((unsigned int)&hero, iteration_transfer_3);
      current_hero_character_transfer = current_hero_character;
      *custom_check = (*current_hero_character_transfer & custom_check_transfer_3) < 0;
      
      custom_check_test_1 = *custom_check != 0;
    }
        
    if ( custom_check_test_1 )
    {
        break;
    }
    
    ++*i;
  
  }
```

Here we can see why the previous block is important. We can see that it is using variables only established if the previous if then statement executes to xor `current_hero_character_transfer` with `custom_check_transfer_3` to set it equal to zero, and store it in `custom_check`. This is important because if `cutom_check` isn't equal to zero, then the if then statement there will execute and the function will break and we will fail the check. If that doesn't happen, then the iteration count is incremented.

```
  }

    *pass_return_value = ((unsigned __int16)*i << 8) & 0x147;

LABEL_END:
    std::vector<int,std::allocator<int>>::~vector(input_transfer_3);
    return_value = *pass_return_value;

  return return_value;
}
```

Here we can see is the rest of the function, and where the code jumps when the iteration count gets to 28. It essentially just outputs the `return_value`. So with all of this info, we can refine the code even more.

```
while (true)
{
	int i = 0;
	int *check;
	int result;

	if (i >= 28)
	{
		result = 0x1337
	}

	if (hero[i] == transform_input(inpit[i]))
	{
		check = hero[i] & *check;
	}
	else
	{
		break
	}

	i = i + 1;
}

return result;
```

So we can see that it is essentially checking to see if the output of the `transform_input` function is equal to the values in the hero array, and if not the code stops, Let's see what is in the `transform_input()` function.

Regex used to clean it up:
```
y2 >= 10 \&\& .*
y12 < 10 \|\| .*
y12 >= 10 \&\& .*
y2 < 10 \|\| .*
```

```
__int64 __fastcall transform_input(__int64 argument)
{
  _DWORD *current_input_character; // rax@12
  __int64 init_int; // [sp+0h] [bp-50h]@4
  unsigned int return_value; // [sp+14h] [bp-3Ch]@20
  bool len_check; // [sp+1Fh] [bp-31h]@7
  __int64 *i; // [sp+28h] [bp-28h]@4
  __int64 *pass_return_value; // [sp+30h] [bp-20h]@4
  __int64 input; // [sp+40h] [bp-10h]@1

  input = argument;
  while ( 1 )
  {
    *((_DWORD *)&init_int - 4) = 0;
    *((_DWORD *)&init_int - 4) = 0;
    pass_return_value = &init_int - 2;
    i = &init_int - 2;
    
    LODWORD(input_length) = std::vector<int,std::allocator<int>>::size(input);
    len_check = i < input_length;
    
    if ( len_check )
    {
      LODWORD(current_input_character) = std::vector<int,std::allocator<int>>::operator[](input, *(_DWORD *)i);
      *(_DWORD *)pass_return_value += *current_input_character;
    }
      
    ++*(_DWORD *)i;
    return_value = *(_DWORD *)pass_return_value;
    return return_value;
    }
}
```

So we can see here, this will run as a loop as long as the iteration count `i` does not exceed the number of characters given in our input. But once it verifies that it hasn't essentially all it is doing is it is cumulatively adding the characters of our input, in the order that they were given to the `pass_retunr_value`, then returning the sum of all characters given. We know we need the value that this function returns to be equal to the value of hero, so we should be able to set it equal to that. Let's take a look at the values that hero was set to back in the `start_quest()` function:

```
.data:000000000061013C                 public secret_100
.data:000000000061013C secret_100      db  64h ; d             ; DATA XREF: start_quest(std::string)+5Eo
.data:000000000061013C                                         ; start_quest(std::string)+8CDo
.data:000000000061013D                 db    0
.data:000000000061013E                 db    0
.data:000000000061013F                 db    0
.data:0000000000610140                 public secret_214
.data:0000000000610140 secret_214      db 0D6h ; +             ; DATA XREF: start_quest(std::string)+AFo
.data:0000000000610140                                         ; start_quest(std::string)+8E6o
.data:0000000000610141                 db    0
.data:0000000000610142                 db    0
.data:0000000000610143                 db    0
.data:0000000000610144                 public secret_266
.data:0000000000610144 secret_266      dw 10Ah                 ; DATA XREF: start_quest(std::string)+C8o
.data:0000000000610144                                         ; start_quest(std::string)+8FFo
.data:0000000000610146                 db    0
.data:0000000000610147                 db    0
.data:0000000000610148                 public secret_369
.data:0000000000610148 secret_369      dw 171h                 ; DATA XREF: start_quest(std::string)+E1o
.data:0000000000610148                                         ; start_quest(std::string)+918o
.data:000000000061014A                 db    0
.data:000000000061014B                 db    0
```

So we can see that the first 4 values are 0x64, 0xD6, 0x10A, and 0x1A1 (had to convert the last two to words). We can see that they are each larger than the previous value. We see that it starts off with 0x64, which is an ascii character however the rest of the hex stringsdon't convert over to ascii. However since the `transform_input` function is returning the interger value of the sum of all characters to that point, we should be able to use ascii characters corresponding to the differences in the hex strings to get to that point.

```
>>> chr(0x64 - 0)
'd'
>>> chr(0xD6 - 0x64)
'r'
>>> chr(0x10A - 0xD6)
'4'
>>> chr(0x171 - 0x10A)
'g'
```

As you can see, that does give us ascii characters. So we will just use ascii characters to reach the same values as the hero array. Here is a python script which automates the process of calculating the differences and converting them to ascii:

```
#Establish the values we got from Hero
diff = [ 0x0, 0x64, 0xD6, 0x10A, 0x171, 0x1A1, 0x20F, 0x26E, 0x2DD, 0x34F, 0x3AE, 0x41E, 0x452, 0x4C6, 0x538, 0x5A1, 0x604, 0x635, 0x696, 0x704, 0x763, 0x7CC, 0x840, 0x875, 0x8D4, 0x920, 0x96C, 0x9C2, 0x0A0F]

#Establish the list, and the string which will hold the secret
secret_list = [-1]*29 
secret = ""

#For loop to calculate the differences, convert them to ASCII, and store them in the list
for i in xrange(1, 29):
    secret_list[i] = chr(diff[i] - diff[i - 1])

#Consolidate the list into the string, and print it
secret = secret.join(secret_list[1:])
print secret
```

Let's try it:

```
$	python solve.py 
dr4g0n_or_p4tric1an_it5_LLVM
$	./wyvern_c85f1be480808a9da350faaa6104a19b 
+-----------------------+
|    Welcome Hero       |
+-----------------------+

[!] Quest: there is a dragon prowling the domain.
	brute strength and magic is our only hope. Test your skill.

Enter the dragon's secret: dr4g0n_or_p4tric1an_it5_LLVM
success

[+] A great success! Here is a flag{dr4g0n_or_p4tric1an_it5_LLVM}

```

Just like that, we slayed the dragon!




