This writeup is based off of this writeup:
```
https://www.incertia.net/blog/csaw-quals-2016-tar-tar-binks-400/
```

So we see that we have two files, a tar file`flag.tar` and a dynamic link file `libarchive.dylib`. Let's take a look at them.

```
$	tar -xvf flag.tar 
tar: This does not look like a tar archive
tar: Skipping to next header
flag.txt
tar: Exiting with failure status due to previous errors
$	ls
flag.tar  flag.txt  libarchive.dylib
$	cat flag.txt 
F5D1,4D6B,ED6A,08A6,38DD,F7FA,609E,EBC4,E55F,E6D1,7C89,ED5B,0871,1A69,5D58,72DE,224B,3AA6,0845,7DD6,58FB,E9CC,0A2D,76B8,ED60,251A,1F6B,32CC,E78D,12FA,201A,E889,2D25,922A,4BC5,F5FF,F8E5,C79B,3A77,4BDB,EA11,5941,58BD,3A95,F5C9,A225,AD40,F8BD,095D,70B6,458C,E7A9,EA68,252F,094B,5E41,0969,6015,5ED5,F6E5,59B9,7CAF,66DF,265B,7837,57B4,7CAF,AED9,F707,6A3C,F8E5,F509,7C8B,0915,2235,336F,33E9,2D14,7C91,5804,83E5,E78D,F4EA,0874,ED6B,4B35,E839,57B4,E77C,EA68,2525,AD41,ED6F,3A4A,4BCC,6015,F440,0858,3AA6,7809,671D,0874,EA77,63AF,2E91,5845,F6C4,086D,7795,3939,57B4,7C89,82DC,32ED,B994,C7AF,9135,0E65,1B66,ED5B,3235,6577,5A80,3AD3,E776,1EE5,AD41,ED59,864C,70B4,3876,ED67,64D6,F8E5,F505,EAD9,7C9C,32ED,B994,B4EF,0C6C,F665,F5F5,9047,521A,E99E,EA68,252F,9D09,76B7,E776,1ED0,095D,0D4D,5D5A,087B,2005,1526,7E76,85AD,78B9,E8B6,782C,251C,32ED,7F68,EBE3,EA41,57FD,ED59,846D,7A05,B994,BB78,ED6A,08A6,38DD,3B5D,7E45,E839,738C,E9CC,0A2D,764A,609E,E8B6,EA68,2524,E6BB,7C9C,639F,3A95,0895,F40F,8328,EA69,7EE5,F8BD,7F7D,0D6D,70B6,458C,E8B6,EA68,251C,6065,B35F,C789,5845,7F7D,6D89,4C6E,A20E,60B5,7E45,ED59,F707,69EF,922A,4BC5,F6EF,8635,F4B9,57B4,7CF8,ED60,2510,095D,20AF,3545,F40F,8328,EA41,58A4,225D,7E7C,4BDB,F8BD,082C,EAE7,5D57,5D50,0914,E7C7,8624,7CF8,ED60,2511,7C8E,7159,8416,7EF9,E7E5,774A,3895,1EC9,7C90,09B9,58BD,5FF5,E99E,EA68,250A,224C,EA3D,73F5,7C89,53A6,3190,3B5D,1526,7DD5,666A,0919,225F,CDEF,79E1,7E7B,7E6B,082C,A277,E885,E8BB,E775,5FF7,EA68,251B,7FDF,589D,7A05,779A,8A5A,7C91,5D5C,32ED,F628,2195,F49A,0C77,EAE1,59B9,58BD,E570,E99E,EA3D,73F9,13AD,2BF5,225D,7F7D,70B6,4A9C,337A,1EC9,4D05,7E75,2578,ED59,38E5,1ECA,A210,3B5D,779A,8A6F,C790,2518,4B41,7C89,5D49,4D05,152D,73C5,79F9,4BED,913C,37C9,5D4D,53C8,0941,7C97,5D5B,346A,82D8,5F36,801F,C800,
$	file libarchive.dylib libarchive.dylib: Mach-O 64-bit x86_64 dynamically linked shared library, flags:<NOUNDEFS|DYLDLINK|TWOLEVEL|NO_REEXPORTED_DYLIBS>
```

So we see that the tar file just held a file called `flag.txt` which holds what appears to be fourc character segments of hex code, followed by a comma. We can also see that the dynamic library is 64 bit. Let's see if there is anything in the dynamic library which might print out something like this with strings.

```
$	strings libarchive.dylib | grep X,
%04X,
```

So we can see the string `%04X,` which should print out four hex characters followed by a comma, which is exactly what how the data in `flag.txt` is formatted. 

```
    set_output_array(bof1, argument_3_transfer);
    bof2 = (char *)malloc(0x2710uLL);
    __memset_chk(bof1, 0LL, 10000LL, -1LL);
    __memset_chk(bof2, 0LL, 0x2710LL, -1LL);
    for ( i = 0; i < posi; ++i )
    {
      bof2_len = strlen(bof2);
      __sprintf_chk(&bof2[bof2_len], 0, 0xFFFFFFFFFFFFFFFFLL, "%04X,", output[(unsigned __int64)i]);
    }
```

So we can see that this is the only time the string `%04x` is used, in `sub_7b720`. We see here that it is essentially looping through all of the values of the `output` array (originally anmed sub_101) and printing them to `bof2`. We see that a lot else happens with `bof2`, however right now we're only interrested in how the 4 character hex segments are made (since that is what `flag.txt` is comprised of). We see that there is only one other xreference to the `output` array, which lies in this function:

```
_DWORD *__fastcall encrypt(__int64 argument_struct)
{
  _DWORD *result; // rax@1
  int current_int; // ST04_4@1
  unsigned int index; // esi@1

  result = output;
  current_int = *(_DWORD *)argument_struct
              + 40 * *(_DWORD *)(argument_struct + 4)
              + 1600 * *(_DWORD *)(argument_struct + 8);
  index = posi++;
  output[(unsigned __int64)index] = current_int;
  return result;
}
```

So we see here that the function is essentially being handed three integers `x`, `y`, and `z`, then setting an object in output equal to `(x * 1600) + (y * 40) + z`. This seems like a function that is looped for the entirety of the input string, so let's see where it is called:

```
__int64 __fastcall set_output_array(_BYTE *argument_0, int atgument_1_int)
{
  int argument1_transfer2; // eax@2
  _BYTE *argument0_transfer1; // rax@3
  int argument0_transfer2; // [sp+4h] [bp-2Ch]@3
  signed int three; // [sp+8h] [bp-28h]@1
  int argument_1_int_transfer; // [sp+Ch] [bp-24h]@1
  _BYTE *argument0_transfer; // [sp+10h] [bp-20h]@1
  int get_position_output[3]; // [sp+1Ch] [bp-14h]@5
  __int64 stack_canary; // [sp+28h] [bp-8h]@1

  stack_canary = *(_QWORD *)__stack_chk_guard_ptr;
  argument0_transfer = argument_0;
  argument_1_int_transfer = atgument_1_int;
  three = 3;
  while ( 1 )
  {
    argument1_transfer2 = argument_1_int_transfer--;
    if ( !argument1_transfer2 )
      break;
    argument0_transfer1 = argument0_transfer++;
    argument0_transfer2 = *argument0_transfer1;
    pending = 1;
    while ( pending )
    {
      get_position_output[--three] = get_position(argument0_transfer2);
      if ( !three )
      {
        encrypt((__int64)get_position_output);
        three = 3;
      }
    }
  }
  if ( three != 3 )
  {
    while ( three != -1 )
      get_position_output[--three] = 0;
    encrypt((__int64)get_position_output);
  }
  return *(_QWORD *)__stack_chk_guard_ptr;
}
```

So we can see here that the `encryption` function is called twice in this function. In addition to that, we can see that this function is called prior to the `sprintf` call with the `%04X` format (so this definately runs). Looking over the conditions for it to be called, there should be nothing stopping it from running. We can see that the input for it is the output of the `get_position` function. Let's take a look at that function:

```
__int64 __fastcall get_position(int argument)
{
  int transfer_return; // ST04_4@2
  int i; // [sp+0h] [bp-Ch]@5
  int input; // [sp+4h] [bp-8h]@1
  signed int return_value; // [sp+8h] [bp-4h]@2

  input = argument;
  if ( data_input == -1 )
  {
    if ( argument == 126 )
      input = 0;
    for ( i = 0; i < 39; ++i )
    {
      if ( ctable[i] == input )
      {
        pending = 0;
        return (unsigned int)i;
      }
      if ( ctable[i + 39] == input )
      {
        pending = 1;
        data_input = i;
        return 39;
      }
    }
    pending = 0;
    return_value = 37;
  }
  else
  {
    transfer_return = data_input;
    data_input = -1;
    pending = 0;
    return_value = transfer_return;
  }
  return (unsigned int)return_value;
}
```

So we can see here that it is checking to see if it's input is equal to a value in `ctable`. If it is, and it is stored in the first 39 characters, then it just returns `i`. If it is stored after the first 39 characters, it returns the integer `39` followed by `i`. Let's see what values are stored in the `ctable` array:

```
__data:00000000000D8840 ; _BYTE ctable[80]
__data:00000000000D8840 _ctable         db 0, 61h, 62h, 63h, 64h, 65h, 66h, 67h, 68h, 69h, 6Ah
__data:00000000000D8840                                         ; DATA XREF: get_position+5Eo
__data:00000000000D8840                                         ; get_position:loc_7B29Bo
__data:00000000000D8840                 db 6Bh, 6Ch, 6Dh, 6Eh, 6Fh, 70h, 71h, 72h, 73h, 74h, 75h
__data:00000000000D8840                 db 76h, 77h, 78h, 79h, 7Ah, 30h, 31h, 32h, 33h, 34h, 35h
__data:00000000000D8840                 db 36h, 37h, 38h, 39h, 20h, 0Ah, 0, 41h, 42h, 43h, 44h
__data:00000000000D8840                 db 45h, 46h, 47h, 48h, 49h, 4Ah, 4Bh, 4Ch, 4Dh, 4Eh, 4Fh
__data:00000000000D8840                 db 50h, 51h, 52h, 53h, 54h, 55h, 56h, 57h, 58h, 59h, 5Ah
__data:00000000000D8840                 db 28h, 21h, 40h, 23h, 2Ch, 2Eh, 3Fh, 2Fh, 2Ah, 29h, 3Ch
__data:00000000000D8840                 db 3Eh, 2 dup(0)
```

So we can see here, that there are 79 bytes worth of hex strings, with the exception of two null bytes and a newline character all of them convert to ascii. Here is the ascii conversion:
```
ctable = "\x00abcdefghijklmnopqrstuvwxyz0123456789 \n\x00ABCDEFGHIJKLMNOPQRSTUVWXYZ(!@#,.?/*)<>\x00"
```

So as far as the encryption goes,  it will first determine it's location in the ctable char array (for instance `d` would be 4). It then takes it's position and stores it in an array. if it's location is greater than 39, it will store both 39 and `i - 39` in the array with i being it's location. It will then run the `encrypt` function which grabs three intergers from the array generate in the last step `x`, `y`, and `z` (it will loop through all of the integers in the array). It will generate an object in a new array equal to `(x * 1600) + (y * 40) + z`. It translates to this python code:

```
#Establish the ctable strung
ctable = "\x00abcdefghijklmnopqrstuvwxyz0123456789 \n\x00ABCDEFGHIJKLMNOPQRSTUVWXYZ(!@#,.?/*)<>\x00"

#Establsih the function which will map characters to their position in ctable
def cipher(cleartext):
    print "Ciphering: " + cleartext
    y = [0]*1036  
    i = 0
    for j in cleartext:
        x = 0
        for k in ctable:            
            if j == k:
#Check to see if the current letter is beyond the 39 limit, if it isn't just store i, if it is store 39 and i - 39
                if x > 39:
                    y[i] += 39
                    i += 1
                    y[i] += x - 39
                    i += 1
                if x <= 39:
                    y[i] += x
                    i += 1
            x += 1
    return y

#Establish the function which will take the output of cipher and encrypt it
def sum(ciphertext):
#Establish the variables and array needed
    enctext = [0]*346
    x = 0
    y = 0
    z = 0
    i = 0
    j = 0
#Use a for loop to do the math
    for k in xrange(346):
#We have to check if we are on the last object in ciphertext, since 346 % 3 = 1, and the last encryption will just be enctext[345] = x * 1600      
        if j < 345:
            x = ciphertext[i]
            x = x * 1600
            y = ciphertext[i + 1]
            y = y * 40
            z = ciphertext[i + 2]
            enctext[j] = [x + y + z]
            i += 3
            j += 1
        if j == 345:
            x = ciphertext[i]
            x = x * 1600  
            enctext[j] = x
            i += 1
            j += 1
    return enctext

#Prompt the user for a string to encrypt
cleartext = raw_input("What do you want to be ciphered? ")

#Find the position of each character inputted by the user in the ctable
ciphertext = [0]*(len(cleartext) + 1)
ciphertext = cipher(cleartext)
#print "Output of step one: " + str(ciphertext)

#Run the encryption on the poisitions of the input on ctable
sumtext = [0]*346
sumtext = sum(ciphertext)
for i in xrange(len(sumtext)):
    p = str(sumtext[i])
    p = int(p.replace("]", "").replace("[", ""))
    print hex(p)
```

So to decrypt `flag.txt`Just take it's contents and apply the reverse process to it. To reverse the three integers part we can just apply this math to it:

```
c = some contants under 40
x = c0 * 1600
y = c1 * 40
z = c2 
int = x + y + z

int = (c0 * 1600) + (c1 * 40) + (c2)

for x:
(int/1600) = c0 + (c1/40) + (c2/1600)
apply integer division (ignore remainders, and the fact that c1 & c2 are less than 40 means they become zero)
(int/1600) =  c0

for y:
(int/40) = c0*40 + c1 + (c2/40)
apply integer division
((int/40) % 40) = (c0*40 + c1) % 40
Since c1 is a constant less than 40, it's not affected by the mod. Since c0 is multiplied by 40, the mod 40 effictively turns it to zero.
((int/40) % 40) = c1

for z:
int = c0*1600 + c1*40 + c2
(int) % 40 = ((c0 * 1600) + (c1*40) + (c2)) % 40
Since 1600 % 40 = 0, and 40 % 40 = 0, c0 and c1 are turned to zero, and sice c2 < 40 it is unaffected by the mod.
(int % 40) = c2
```
For the rest of it, we can just kepp on applying the same logic that was used to encrypt the data reversed. Also we will need to ensure that we skip the null bytes in the final part, since they will mess up the hash.  here is the python code for it:

```
#Establish the encrypted flag.txt data
flag = [0xF5D1, 0x4D6B, 0xED6A, 0x08A6, 0x38DD, 0xF7FA, 0x609E, 0xEBC4, 0xE55F, 0xE6D1, 0x7C89, 0xED5B, 0x0871, 0x1A69, 0x5D58, 0x72DE, 0x224B, 0x3AA6, 0x0845, 0x7DD6, 0x58FB, 0xE9CC, 0x0A2D, 0x76B8, 0xED60, 0x251A, 0x1F6B, 0x32CC, 0xE78D, 0x12FA, 0x201A, 0xE889, 0x2D25, 0x922A, 0x4BC5, 0xF5FF, 0xF8E5, 0xC79B, 0x3A77, 0x4BDB, 0xEA11, 0x5941, 0x58BD, 0x3A95, 0xF5C9, 0xA225, 0xAD40, 0xF8BD, 0x095D, 0x70B6, 0x458C, 0xE7A9, 0xEA68, 0x252F, 0x094B, 0x5E41, 0x0969, 0x6015, 0x5ED5, 0xF6E5, 0x59B9, 0x7CAF, 0x66DF, 0x265B, 0x7837, 0x57B4, 0x7CAF, 0xAED9, 0xF707, 0x6A3C, 0xF8E5, 0xF509, 0x7C8B, 0x0915, 0x2235, 0x336F, 0x33E9, 0x2D14, 0x7C91, 0x5804, 0x83E5, 0xE78D, 0xF4EA, 0x0874, 0xED6B, 0x4B35, 0xE839, 0x57B4, 0xE77C, 0xEA68, 0x2525, 0xAD41, 0xED6F, 0x3A4A, 0x4BCC, 0x6015, 0xF440, 0x0858, 0x3AA6, 0x7809, 0x671D, 0x0874, 0xEA77, 0x63AF, 0x2E91, 0x5845, 0xF6C4, 0x086D, 0x7795, 0x3939, 0x57B4, 0x7C89, 0x82DC, 0x32ED, 0xB994, 0xC7AF, 0x9135, 0x0E65, 0x1B66, 0xED5B, 0x3235, 0x6577, 0x5A80, 0x3AD3, 0xE776, 0x1EE5, 0xAD41, 0xED59, 0x864C, 0x70B4, 0x3876, 0xED67, 0x64D6, 0xF8E5, 0xF505, 0xEAD9, 0x7C9C, 0x32ED, 0xB994, 0xB4EF, 0x0C6C, 0xF665, 0xF5F5, 0x9047, 0x521A, 0xE99E, 0xEA68, 0x252F, 0x9D09, 0x76B7, 0xE776, 0x1ED0, 0x095D, 0x0D4D, 0x5D5A, 0x087B, 0x2005, 0x1526, 0x7E76, 0x85AD, 0x78B9, 0xE8B6, 0x782C, 0x251C, 0x32ED, 0x7F68, 0xEBE3, 0xEA41, 0x57FD, 0xED59, 0x846D, 0x7A05, 0xB994, 0xBB78, 0xED6A, 0x08A6, 0x38DD, 0x3B5D, 0x7E45, 0xE839, 0x738C, 0xE9CC, 0x0A2D, 0x764A, 0x609E, 0xE8B6, 0xEA68, 0x2524, 0xE6BB, 0x7C9C, 0x639F, 0x3A95, 0x0895, 0xF40F, 0x8328, 0xEA69, 0x7EE5, 0xF8BD, 0x7F7D, 0x0D6D, 0x70B6, 0x458C, 0xE8B6, 0xEA68, 0x251C, 0x6065, 0xB35F, 0xC789, 0x5845, 0x7F7D, 0x6D89, 0x4C6E, 0xA20E, 0x60B5, 0x7E45, 0xED59, 0xF707, 0x69EF, 0x922A, 0x4BC5, 0xF6EF, 0x8635, 0xF4B9, 0x57B4, 0x7CF8, 0xED60, 0x2510, 0x095D, 0x20AF, 0x3545, 0xF40F, 0x8328, 0xEA41, 0x58A4, 0x225D, 0x7E7C, 0x4BDB, 0xF8BD, 0x082C, 0xEAE7, 0x5D57, 0x5D50, 0x0914, 0xE7C7, 0x8624, 0x7CF8, 0xED60, 0x2511, 0x7C8E, 0x7159, 0x8416, 0x7EF9, 0xE7E5, 0x774A, 0x3895, 0x1EC9, 0x7C90, 0x09B9, 0x58BD, 0x5FF5, 0xE99E, 0xEA68, 0x250A, 0x224C, 0xEA3D, 0x73F5, 0x7C89, 0x53A6, 0x3190, 0x3B5D, 0x1526, 0x7DD5, 0x666A, 0x0919, 0x225F, 0xCDEF, 0x79E1, 0x7E7B, 0x7E6B, 0x082C, 0xA277, 0xE885, 0xE8BB, 0xE775, 0x5FF7, 0xEA68, 0x251B, 0x7FDF, 0x589D, 0x7A05, 0x779A, 0x8A5A, 0x7C91, 0x5D5C, 0x32ED, 0xF628, 0x2195, 0xF49A, 0x0C77, 0xEAE1, 0x59B9, 0x58BD, 0xE570, 0xE99E, 0xEA3D, 0x73F9, 0x13AD, 0x2BF5, 0x225D, 0x7F7D, 0x70B6, 0x4A9C, 0x337A, 0x1EC9, 0x4D05, 0x7E75, 0x2578, 0xED59, 0x38E5, 0x1ECA, 0xA210, 0x3B5D, 0x779A, 0x8A6F, 0xC790, 0x2518, 0x4B41, 0x7C89, 0x5D49, 0x4D05, 0x152D, 0x73C5, 0x79F9, 0x4BED, 0x913C, 0x37C9, 0x5D4D, 0x53C8, 0x0941, 0x7C97, 0x5D5B, 0x346A, 0x82D8, 0x5F36, 0x801F, 0xC800]

#Establish the ctable
ctable = "\x00abcdefghijklmnopqrstuvwxyz0123456789 \n\x00ABCDEFGHIJKLMNOPQRSTUVWXYZ(!@#,.?/*)<>\x00"

#Establish the decrypt function, which essentially splits the 4 character hex strings into the original three integers
def decrypt():
     dectext = []
     for j in flag:
          x = (j/1600) 
          y = (j/40) % 40
          z = j % 40
          dectext += [x,y,z]
     return dectext

#Establish the regroup function, which takes the integers over 39, and readds the (39 + (i - 39)) so the remapping can go smoothly
def regroup(dectext):
     postext = []
     i = 0
     while i < len(dectext):
          if dectext[i] == 39:
               postext += [39 + dectext[i + 1]]
               i += 2
          else:
               postext += [dectext[i]]
               i += 1
     return postext

#Established the remap function, which takes the integers from the reqroup function, and outputs the corresponding characters from ctable
def remap(postext):
     maptext = ""
     for i in xrange(len(postext)):
          x = postext[i]
          if ctable[x] != "\x00":
               maptext += ctable[x]
     return maptext

#Runs the decrypt function
dectext = []
dectext += decrypt()
#print dectext

#Takes the output from decrypt, and pipes it into the regroup function
postext = []
postext = regroup(dectext)
#print postext

#Takes the output from the regroup function, pipes it into the remap function, then prints out the unecrpyted flag.txt data
maptext = ""
maptext = remap(postext)
print maptext
```

Let's try it out!

```
$	python solve.py 
Milos Raonic (born 1990) is a Canadian professional tennis player. He reached a career high world No. 4 singles ranking in May 2015, as ranked by the Association of Tennis Professionals (ATP). His career highlights include a Grand Slam final at the 2016 Wimbledon Championships and two Grand Slam semifinals at the 2014 Wimbledon Championships and 2016 Australian Open. He was the 2011 ATP Newcomer of the Year, and has been ranked continuously inside the top 20 since August 2012. Raonic is the first player born in the 1990s to win an ATP title, to be ranked in the top 10, and to qualify for the ATP World Tour Finals. He has eight ATP singles titles, all won on hard courts. He is frequently described as having one of the best serves among his contemporaries. Statistically, he is among the strongest servers in the Open Era, winning 91p of service games to rank third all time. Aided by his serve, he plays an all court style with an emphasis on short points.
$	python solve.py | md5sum
2c8cd31daeba8753815851f13e6370b3  -
```

The hash is indeed `2c8cd31daeba8753815851f13e6370b3`. Just like that we reversed the challenge!