Let's take a look at the binary:

```
$	file key.exe
key.exe: PE32 executable (console) Intel 80386, for MS Windows
```

So we can see that it is a 32 bit Windows exectuable. When we run it, it just prints out the string `?W?h?a?t h?a?p?p?e?n?` and exits. When we look at the strings in ida, we see `Congrats You got it!`. Following either string brings us to the function `sub_401100` which I renamed to `check`. Near the top we can see this code:

```
  i = 0;
  zero_3 = 1684630885;
  LOWORD(fifteen_1) = 97;
  *(_OWORD *)repeat_string_transfer = repeat_string;
  oneone83 = 0x2E3C;
  zero_4 = 0;
  specialstring_transfer = specialstring;
  do
  {
    pass((int)&pass_output, 1u, (*((_BYTE *)repeat_string_transfer + i) ^ *((_BYTE *)&specialstring_transfer + i)) + 22);
    ++i;
  }
```

Looking at it, we can see that the while loop will run 18 times, Each time it runs it will run the `pass` function. Looking at the third argument, it appears to be the output of xoring  the characters corresponding to the iteration count of two seperate arrays, then adding the decimal 22 to that. let's take a look at the first array `repeat_string`:

```
.rdata:0040528C repeat_string   xmmword 68746164696D6568746164696D656874h
.rdata:0040528C                                         ; DATA XREF: check+64r
.rdata:0040529C dword_40529C    dd 64696D65h            ; DATA XREF: check+5Fr
.rdata:004052A0 word_4052A0     dw 61h                  ; DATA XREF: check+6Er
.rdata:004052A2                 align 4
```

So we can see that the array has the string `themidathemidathemida` stored in it as hex. Since we are only xoring the first 18 characters, the string as far as we're concerned is `themidathemidathem`. Now onto `specialstring`:

```
.rdata:004052A4 specialstring   xmmword 3C3C3C2E2E2E2E2B2B2B2B2D2D2D2D3Eh
.rdata:004052A4                                         ; DATA XREF: check+88r
.rdata:004052B4 word_4052B4     dw 2E3Ch                ; DATA XREF: check+79r
.rdata:004052B6 byte_4052B6     db 0                    ; DATA XREF: check+8Fr
.rdata:004052B7                 align 4
```

Looking here we can see the string `>----++++....<<<<.` stored in ascii, which is exactly 18 characters long. Looking at the code for the `pass` function, it doesn't appear to be chaning the value of the third argument, just storing it. Looking directly after this we can see another call to `pass`:

```
i2 = 0;
  fifteen_1 = 15;
  zero_3 = 0;
  LOBYTE(repeat_string_transfer[0]) = 0;
  LOBYTE(v48) = 2;
  fifteen_3 = fifteen_2;
  pass_output_transfer_1 = (void **)pass_output;
  do
  {
    pass_output_transfer = &pass_output;
    if ( fifteen_3 >= 0x10 )
      pass_output_transfer = pass_output_transfer_1;
    pass((int)repeat_string_transfer, 1u, *((_BYTE *)pass_output_transfer + i2++) + 9);
  }
  while ( i2 < 18 );
```

Here we can see that instead of xoring, it is simply adding 9 to each object from the output of the previous `pass` call. Just like the last instance, this while loop will run 18 times. Unlike the previous segment, it will store the output in `repeat_string_transfer` and only draw input from `pass_output_transfer`.

So so far the encoding process translates to this python code:
```
x0 = "themidathemidathem"
x1 = ">----++++....<<<<."

a = [0]*18

i = 0
for i in xrange(18):
    x = ord(x0[i])
    y = ord(x1[i])
    z = x ^ y
    a[i] = z + 22
#print a

b ="" 

for i in xrange(18):
    b += chr(a[i] + 9)
#    print chr(b[i])
print b
```

Looking forward we can see that the output of the previous segment `repeat_string_transfer`, and any values that are assigned it's values, are only ever used in the function sub_DD220C0. Looking in that function, it appears that it doesn't edit the value, just evaluates it so it is probably checking it. Here is the code for it (renamed it to `check_function`):

```
signed int __thiscall check_function(int this, int arg0, unsigned int arg1, int encoded, unsigned int arg3)
{
  unsigned int arg1_transfer; // edi@1
  unsigned int arg3_transfer; // edx@5
  int encoded_transfer; // esi@8
  unsigned int arg3_minus4; // edx@8
  bool bool_0; // cf@12
  unsigned __int8 v10; // al@14
  unsigned __int8 v11; // al@16
  unsigned __int8 v12; // al@18
  signed int return_value; // eax@19

  arg1_transfer = arg1;
  if ( *(_DWORD *)(this + 16) < arg1 )
    arg1_transfer = *(_DWORD *)(this + 16);
  if ( *(_DWORD *)(this + 20) >= 0x10u )
    this = *(_DWORD *)this;
  arg3_transfer = arg3;
  if ( arg1_transfer < arg3 )
    arg3_transfer = arg1_transfer;
  if ( arg3_transfer )
  {
    encoded_transfer = encoded;
    bool_0 = arg3_transfer < 4;
    arg3_minus4 = arg3_transfer - 4;
    if ( bool_0 )
    {
LABEL_11:
      if ( arg3_minus4 == -4 )
        goto LABEL_20;
    }
    else
    {
      while ( *(_DWORD *)this == *(_DWORD *)encoded_transfer )
      {
        this += 4;
        encoded_transfer += 4;
        bool_0 = arg3_minus4 < 4;
        arg3_minus4 -= 4;
        if ( bool_0 )
          goto LABEL_11;
      }
    }
    bool_0 = *(_BYTE *)this < *(_BYTE *)encoded_transfer;
    if ( *(_BYTE *)this != *(_BYTE *)encoded_transfer
      || arg3_minus4 != -3
      && ((v10 = *(_BYTE *)(this + 1),
           bool_0 = v10 < *(_BYTE *)(encoded_transfer + 1),
           v10 != *(_BYTE *)(encoded_transfer + 1))
       || arg3_minus4 != -2
       && ((v11 = *(_BYTE *)(this + 2),
            bool_0 = v11 < *(_BYTE *)(encoded_transfer + 2),
            v11 != *(_BYTE *)(encoded_transfer + 2))
        || arg3_minus4 != -1
        && (v12 = *(_BYTE *)(this + 3),
            bool_0 = v12 < *(_BYTE *)(encoded_transfer + 3),
            v12 != *(_BYTE *)(encoded_transfer + 3)))) )
    {
      return_value = -bool_0 | 1;
      goto LABEL_21;
    }
LABEL_20:
    return_value = 0;
LABEL_21:
    if ( return_value )
      return return_value;
  }
  if ( arg1_transfer >= arg3 )
    return_value = arg1_transfer != arg3;
  else
    return_value = -1;
  return return_value;
}
```

Because the encoded values are never missed with again, we should be able to simply generate the key by working though the logic on our own, since we have all of the inputs and steps. I did this with the python script earlier:

```
$	python solve.py 
idg_cni~bjbfi|gsxb
```

Running the python script from earlier gives us the key to the file, and also the flag. Just like that we revresed the challenge!

 