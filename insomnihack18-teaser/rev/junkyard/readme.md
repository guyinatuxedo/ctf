# Junkyard

This writeup is based off of: https://github.com/perfectblue/ctf-writeups/tree/master/insomnihack-teaser-2019/junkyard

When we look at the binary, we see this:

```
$	file junkyard 
junkyard: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=d71e8a4cc04049bb70a75a1988ea6a5f1a3ebd10, stripped
$	./junkyard 
Usage: ./chall user pass
$	./junkyard 1 2
I don't like your name
```

So we can see that it is a 64 bit binary, that prompts us for two arguments. When we take a look at the main function, we see this:

```
void __fastcall __noreturn main(int argc, char **argv, char **a3)
{
  char s; // [sp+40h] [bp-810h]@9
  __int64 v6; // [sp+848h] [bp-8h]@1

  v6 = *MK_FP(__FS__, 40LL);
  if ( argc != 3 )
    error(8u, 0xFFFFFFFF);
  if ( !lenCheck(argv[1]) )
    error(0, 0xFFFFFFFF);
  sub_1384();
  if ( !lenCheck(argv[2]) )
    error(1u, 0xFFFFFFFF);
  sub_1B85(69LL);
  sub_2AF8(7, off_8C18, &s);
  puts(&s);
  sub_1B40(331572LL, 0LL, "am5kiTLdN02ypeAQQZqKIFLwNXG09j", 0LL, 0LL);
  memset(&s, 0, 0x800uLL);
  decryptCheck(argv[1], argv[2]);
}
```

So we can see that our input is only referenced in four places. The first is when they check that argc is three (so we provide two arguments). The next two just check that the length of the two arguments are greater than `0xf` and less than `0x40` with the `lenCheck` function. Finally if we pass those three checks both of our arguments are passed to `decryptCheck` . There other code that is executed here, however it really doesn't effect anything we do. After that we have the `decryptCheck` function.

```
void __fastcall __noreturn decryptCheck(const char *arg0, const char *arg1)
{
  size_t arg0Len; // rax@1
  size_t arg1Len; // rax@3
  unsigned __int64 length; // rsi@3
  int v6; // ebx@7
  __int64 v7; // STC0_8@7
  int aplhabetOffset; // ST8C_4@24
  signed int index0; // eax@24
  signed int index1; // eax@28
  __int64 hashInputLength; // rax@33
  size_t hashLen; // rax@33
  char *arg1Trsf; // [sp+0h] [bp-11D0h]@1
  char k; // [sp+1Fh] [bp-11B1h]@30
  signed int keyLength; // [sp+7Ch] [bp-1154h]@19
  unsigned int v17; // [sp+80h] [bp-1150h]@34
  unsigned int v18; // [sp+84h] [bp-114Ch]@34
  int v19; // [sp+88h] [bp-1148h]@19
  __int64 v20; // [sp+90h] [bp-1140h]@10
  unsigned __int64 j; // [sp+98h] [bp-1138h]@10
  signed __int64 x; // [sp+A0h] [bp-1130h]@19
  signed __int64 y; // [sp+A0h] [bp-1130h]@23
  unsigned __int64 i; // [sp+A8h] [bp-1128h]@7
  char *input0; // [sp+B0h] [bp-1120h]@1
  char *input1; // [sp+B8h] [bp-1118h]@1
  __int64 v27; // [sp+C0h] [bp-1110h]@7
  char hashInput[5]; // [sp+CBh] [bp-1105h]@31
  __int64 v29; // [sp+D0h] [bp-1100h]@1
  __int64 v30; // [sp+D8h] [bp-10F8h]@1
  __int16 v31; // [sp+E0h] [bp-10F0h]@1
  char v32; // [sp+E2h] [bp-10EEh]@1
  char charSet[19]; // [sp+F0h] [bp-10E0h]@19
  __int64 v34; // [sp+110h] [bp-10C0h]@3
  __int64 v35; // [sp+118h] [bp-10B8h]@3
  int v36; // [sp+120h] [bp-10B0h]@3
  __int16 v37; // [sp+124h] [bp-10ACh]@3
  char v38; // [sp+126h] [bp-10AAh]@3
  char md5Output; // [sp+150h] [bp-1080h]@33
  char hashAscii; // [sp+180h] [bp-1050h]@33
  char key[2048]; // [sp+1B0h] [bp-1020h]@19
  char v42[2056]; // [sp+9B0h] [bp-820h]@30
  __int64 v43; // [sp+11B8h] [bp-18h]@1

  arg1Trsf = (char *)arg1;
  v43 = *MK_FP(__FS__, 40LL);
  v29 = 8672370769196829778LL;
  v30 = 7588358910211810867LL;
  v31 = 25210;
  v32 = 97;
  input0 = (char *)malloc(0x40uLL);
  input1 = (char *)malloc(0x40uLL);
  arg0Len = strlen(arg0);
  strncpy(input0, arg0, arg0Len);
  arg1Len = strlen(arg1);
  strncpy(input1, arg1, arg1Len);
  v34 = 'P0djmaMC';
  v35 = 'ct3k7vxh';
  v36 = 'l6zU';
  v37 = 'TF';
  v38 = 'O';
  length = 220206LL;
  sub_1D9E(0LL, 220206LL, 490509LL, 103LL, 105LL, 426840LL);
  if ( strlen(arg0) <= 0x3F )                   // two repeated checks here to make sure argument lengths are less than 64 (0x40)
  {
    length = strlen(arg0);
    extendCopy(input0, length, 0x40uLL);
  }
  if ( strlen(arg1Trsf) <= 0x3F )
  {
    length = strlen(arg1Trsf);
    extendCopy(input1, length, 0x40uLL);
  }
  v6 = input1[sub_369D(input1, length)] - 48;
  v7 = v6 + *(_DWORD *)&aU[4 * input1[(signed int)sub_379A()]] + 634;
  v27 = sub_303E((__int64)input0, (__int64)input0) + v7;
  for ( i = 0LL; i <= 0x28E; ++i )
    *(_DWORD *)&aU[4 * i] += v27;
  v20 = 0LL;
  for ( j = 0LL; j <= 0x28E; ++j )
  {
    if ( !(*(_DWORD *)&aU[4 * j] % 23) )
      v20 += *(_DWORD *)&aU[4 * j];
    if ( !(*(_DWORD *)&aU[4 * j] % 300) )
      v20 -= *(_DWORD *)&aU[4 * j];
    if ( v20 < 0 )
      v20 = -v20;
  }
  x = *(_DWORD *)&aU[4 * (155LL - *input1)];
  snprintf(key, 0x13uLL, "%lu", x, arg1Trsf);
  sub_1E12();
  charSet[0] = 'A';                             // These characters are the only ones used when building the key
  charSet[1] = 'B';
  charSet[2] = 'C';
  charSet[3] = 'D';
  charSet[4] = 'E';
  charSet[5] = 'F';
  charSet[6] = 'G';
  charSet[7] = 'H';
  charSet[8] = 'I';
  charSet[9] = 'J';
  charSet[10] = 'K';
  charSet[11] = 'L';
  charSet[12] = 'M';
  charSet[13] = 'N';
  charSet[14] = 'O';
  charSet[15] = 'P';
  charSet[16] = 'Q';
  charSet[17] = 'R';
  charSet[18] = 'S';
  keyLength = 0;
  v19 = x;
  while ( x && keyLength <= 15 )                // These next three loops build the key
  {                                             // This will increment keyLength to take into account the keylength before it enters these loops
    x = ((signed __int64)((unsigned __int128)(0x6666666666666667LL * x) >> 64) >> 2) - (x >> 63);
    ++keyLength;
  }
  y = v19;
  while ( y && keyLength <= 15 )
  {                                             // This will append characters rangin from 'A-K', which correlate to the first part of the key
    aplhabetOffset = y - 10 * (((signed __int64)((unsigned __int128)(0x6666666666666667LL * y) >> 64) >> 2) - (y >> 63));
    y = ((signed __int64)((unsigned __int128)(0x6666666666666667LL * y) >> 64) >> 2) - (y >> 63);
    index0 = keyLength++;
    key[index0] = charSet[aplhabetOffset];
  }
  while ( keyLength <= 15 )
  {                                             // This adds 'a's to the end of the key, untill the length is 16
    index1 = keyLength++;
    key[index1] = 'a';
  }
  convertToChars((__int64)key, (__int64)v42, 0x10uLL);
  notImportant();
  for ( k = 5; (unsigned __int8)k <= 8u; ++k )
    hashInput[(signed __int64)((unsigned __int8)k - 5)] = v42[(unsigned __int8)k];
  hashInputLength = strlen(hashInput);
  MD5((__int64)hashInput, hashInputLength, (__int64)&md5Output);
  convertToChars((__int64)&md5Output, (__int64)&hashAscii, 0x10uLL);
  notImportant();
  hashLen = strlen(md5Hash7303);
  if ( !strncmp(md5Hash7303, &hashAscii, hashLen) )
  {
    v17 = 3;
    v18 = 0xFFFFFAC7;
    decrypt((__int64)key);                      // The decryption happens in here
  }
  else
  {
    v17 = 4;
    v18 = -101;
  }
  free(input0);
  free(input1);
  error(v17, v18);
}
```

We see that it again checks the length of the first two arguments. 

Proceeding that, we can see that it starts to build the key (after a block of code). The key is built with three different loops (in addition to some work done earlier), that do the following:

```
0:  Initial portion of key is generated from input before the three loops, only contains digits 0 - 9
1:  The  first loop will essentially increment `keyLength` by one for every character already in the key `key` (doesn't write to the key)
2:  This will increment characters from charSet to the key, using the values from the first part of the key as an index
3:  The last part will just append "a"s to the last part of the key, until the length of the key is 16 bytes 
```

So from this, we know that the second and third parts of the key can be correlated to the first key. In addition to that, we know that the first part of the key is only made from characters `0-9`. The second part is only made up of characters ranging from "A-J". To verify this, we can just look at various different keys generated with gdb.

After that there is a check performed on the key. It takes out a part of the key, hashes it with MD5, then compares it against a different MD5 hash. However to solve the challenge, we don't need to reverse this. Later on (if this check is passed) we see that the `decrypt` function is called, which from it we can see that the flag is encrypted, and how we can just brute force the flag:

```
__int64 __fastcall decrypt(__int64 key)
{
  __int64 v1; // rax@1
  void *ptr; // [sp+20h] [bp-140h]@1
  __int64 v4; // [sp+28h] [bp-138h]@1
  char v5; // [sp+40h] [bp-120h]@1
  char v6; // [sp+41h] [bp-11Fh]@1
  char v7; // [sp+42h] [bp-11Eh]@1
  char v8; // [sp+43h] [bp-11Dh]@1
  char v9; // [sp+44h] [bp-11Ch]@1
  char v10; // [sp+45h] [bp-11Bh]@1
  char v11; // [sp+46h] [bp-11Ah]@1
  char v12; // [sp+47h] [bp-119h]@1
  char v13; // [sp+48h] [bp-118h]@1
  char v14; // [sp+49h] [bp-117h]@1
  char v15; // [sp+4Ah] [bp-116h]@1
  char v16; // [sp+4Bh] [bp-115h]@1
  char v17; // [sp+4Ch] [bp-114h]@1
  char v18; // [sp+4Dh] [bp-113h]@1
  char v19; // [sp+4Eh] [bp-112h]@1
  char v20; // [sp+4Fh] [bp-111h]@1
  char s[128]; // [sp+50h] [bp-110h]@1
  __int64 v22; // [sp+D0h] [bp-90h]@1
  __int64 v23; // [sp+D8h] [bp-88h]@1
  __int64 v24; // [sp+E0h] [bp-80h]@1
  __int64 v25; // [sp+E8h] [bp-78h]@1
  __int64 v26; // [sp+F0h] [bp-70h]@1
  __int64 v27; // [sp+F8h] [bp-68h]@1
  __int64 v28; // [sp+100h] [bp-60h]@1
  __int64 v29; // [sp+108h] [bp-58h]@1
  __int64 v30; // [sp+110h] [bp-50h]@1
  __int64 v31; // [sp+118h] [bp-48h]@1
  __int64 v32; // [sp+120h] [bp-40h]@1
  __int64 v33; // [sp+128h] [bp-38h]@1
  __int64 v34; // [sp+130h] [bp-30h]@1
  __int64 v35; // [sp+138h] [bp-28h]@1
  __int64 v36; // [sp+140h] [bp-20h]@1
  __int64 v37; // [sp+148h] [bp-18h]@1
  char v38; // [sp+150h] [bp-10h]@1
  __int64 v39; // [sp+158h] [bp-8h]@1

  v39 = *MK_FP(__FS__, 40LL);
  v22 = 3702632019011973218LL;
  v23 = 4049922657938323301LL;
  v24 = 7090407685554909235LL;
  v25 = 3630575546785804343LL;
  v26 = 7291720546628481074LL;
  v27 = 3545519526314586928LL;
  v28 = 3545008424334078819LL;
  v29 = 3847026491731949364LL;
  v30 = 4062871611462018361LL;
  v31 = 3904680475597431396LL;
  v32 = 4135204065421440563LL;
  v33 = 3918471666251937591LL;
  v34 = 3631648863407990073LL;
  v35 = 3617856386911265634LL;
  v36 = 3774405927021129830LL;
  v37 = 3689916171301315129LL;
  v38 = 0;
  v5 = '1';
  v6 = '2';
  v7 = '3';
  v8 = '4';
  v9 = '1';
  v10 = '2';
  v11 = '3';
  v12 = '4';
  v13 = '1';
  v14 = '2';
  v15 = '3';
  v16 = '4';
  v17 = '1';
  v18 = '2';
  v19 = '3';
  v20 = '4';
  LODWORD(v1) = sub_2312(&v22, &ptr);
  v4 = v1;
  sub_1B85(104LL);
  s[(signed int)AESDecryptFunc((__int64)ptr, v4, key, (__int64)&v5, (__int64)s)] = 0;
  puts(s);
  free(ptr);
  return *MK_FP(__FS__, 40LL) ^ v39;
}
```

In here, we see that the only place our key is used is for an argument to `AESDecryptFunc`. Here we can see that there are four function calls that tell us about how the data is encrypted 

```
  LODWORD(v6) = EVP_aes_128_cbc();
  if ( EVP_DecryptInit_ex(v20, v6, 0LL, keyPtrTrsf, IV) != 1 )
```

```
  if ( EVP_DecryptUpdate(v20, v11, &v15, cipherText, a2) != 1 )
```

```
  if ( EVP_DecryptFinal_ex(v20, (signed int)v15 + v11, (__int64)&v15) != 1 )
```

From this, we know that the encryption we are dealing with here is 128 bit AES CBC (`128` bit because we can see that the key is `16` characters long, so it's 16 bytes). Also we can see that the IV and Ciphertext are both in the program. We can just use gdb to find these two things:

First the IV, which we can get by setting a breakpoint for the `EVP_DecryptInit_ex` call:

```
[----------------------------------registers-----------------------------------]
RAX: 0x55555555e820 --> 0x0 
RBX: 0x1 
RCX: 0x7fffffffc690 ("910915FBJABJaaaa")
RDX: 0x0 
RSI: 0x7ffff7a12080 --> 0x10000001a3 
RDI: 0x55555555e820 --> 0x0 
RBP: 0x7fffffffc360 --> 0x7fffffffc4d0 --> 0x7fffffffd6b0 --> 0x7fffffffdf10 --> 0x5555555587b0 (endbr64)
RSP: 0x7fffffffc2d0 --> 0x7fffffffdff0 --> 0x3 
RIP: 0x5555555560d8 (call   0x5555555550b0 <EVP_DecryptInit_ex@plt>)
R8 : 0x7fffffffc3b0 ("1234123412341234")
R9 : 0x0 
R10: 0x7 
R11: 0x7ffff7700010 (<EVP_aes_128_cbc>:	lea    rax,[rip+0x336d59]        # 0x7ffff7a36d70)
R12: 0x5555555551c0 (endbr64)
R13: 0x7fffffffdff0 --> 0x3 
R14: 0x0 
R15: 0x0
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x5555555560cd:	mov    rcx,rdx
   0x5555555560d0:	mov    edx,0x0
   0x5555555560d5:	mov    rdi,rax
=> 0x5555555560d8:	call   0x5555555550b0 <EVP_DecryptInit_ex@plt>
   0x5555555560dd:	cmp    eax,0x1
   0x5555555560e0:	je     0x5555555560e7
   0x5555555560e2:	call   0x555555555eee
   0x5555555560e7:	mov    edi,0x63
Guessed arguments:
arg[0]: 0x55555555e820 --> 0x0 
arg[1]: 0x7ffff7a12080 --> 0x10000001a3 
arg[2]: 0x0 
arg[3]: 0x7fffffffc690 ("910915FBJABJaaaa")
arg[4]: 0x7fffffffc3b0 ("1234123412341234")
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffc2d0 --> 0x7fffffffdff0 --> 0x3 
0008| 0x7fffffffc2d8 --> 0x7fffffffc3c0 --> 0x7342e00000000 
0016| 0x7fffffffc2e0 --> 0x7fffffffc3b0 ("1234123412341234")
0024| 0x7fffffffc2e8 --> 0x7fffffffc690 ("910915FBJABJaaaa")
0032| 0x7fffffffc2f0 --> 0x4055559620 
0040| 0x7fffffffc2f8 --> 0x55555555e7d0 --> 0x483782e7b34d23b0 
0048| 0x7fffffffc300 --> 0x18ec5ffffc336 
0056| 0x7fffffffc308 --> 0x1100005e30f 
[------------------------------------------------------------------------------]
```

Here we can see that the IV is `1234123412341234`. Next we can get the Ciphertext by setting a breakpoint for `EVP_DecryptUpdate`.

```
[----------------------------------registers-----------------------------------]
RAX: 0x55555555e820 --> 0x7ffff7a12080 --> 0x10000001a3 
RBX: 0x1 
RCX: 0x55555555e7d0 --> 0x483782e7b34d23b0 
RDX: 0x7fffffffc300 --> 0x18ec5ffffc336 
RSI: 0x7fffffffc3c0 --> 0x7342e00000000 
RDI: 0x55555555e820 --> 0x7ffff7a12080 --> 0x10000001a3 
RBP: 0x7fffffffc360 --> 0x7fffffffc4d0 --> 0x7fffffffd6b0 --> 0x7fffffffdf10 --> 0x5555555587b0 (endbr64)
RSP: 0x7fffffffc2d0 --> 0x7fffffffdff0 --> 0x3 
RIP: 0x555555556140 (call   0x555555555180 <EVP_DecryptUpdate@plt>)
R8 : 0x40 ('@')
R9 : 0x7ffff733c1b0 (<__memcpy_ssse3+6752>:	mov    r11,QWORD PTR [rsi-0x10])
R10: 0x0 
R11: 0x3433323134333231 ('12341234')
R12: 0x5555555551c0 (endbr64)
R13: 0x7fffffffdff0 --> 0x3 
R14: 0x0 
R15: 0x0
EFLAGS: 0x213 (CARRY parity ADJUST zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x555555556136:	mov    rax,QWORD PTR [rbp-0x48]
   0x55555555613a:	mov    r8d,edi
   0x55555555613d:	mov    rdi,rax
=> 0x555555556140:	call   0x555555555180 <EVP_DecryptUpdate@plt>
   0x555555556145:	cmp    eax,0x1
   0x555555556148:	je     0x55555555614f
   0x55555555614a:	call   0x555555555eee
   0x55555555614f:	mov    edi,0x56
Guessed arguments:
arg[0]: 0x55555555e820 --> 0x7ffff7a12080 --> 0x10000001a3 
arg[1]: 0x7fffffffc3c0 --> 0x7342e00000000 
arg[2]: 0x7fffffffc300 --> 0x18ec5ffffc336 
arg[3]: 0x55555555e7d0 --> 0x483782e7b34d23b0 
arg[4]: 0x40 ('@')
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffc2d0 --> 0x7fffffffdff0 --> 0x3 
0008| 0x7fffffffc2d8 --> 0x7fffffffc3c0 --> 0x7342e00000000 
0016| 0x7fffffffc2e0 --> 0x7fffffffc3b0 ("1234123412341234")
0024| 0x7fffffffc2e8 --> 0x7fffffffc690 ("910915FBJABJaaaa")
0032| 0x7fffffffc2f0 --> 0x4055559620 
0040| 0x7fffffffc2f8 --> 0x55555555e7d0 --> 0x483782e7b34d23b0 
0048| 0x7fffffffc300 --> 0x18ec5ffffc336 
0056| 0x7fffffffc308 --> 0x1100005e30f 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 7, 0x0000555555556140 in ?? ()
gdb-peda$ x/9g 0x55555555e7d0
0x55555555e7d0:	0x483782e7b34d23b0	0xb29ecd70fb903230
0x55555555e7e0:	0x41971f031e4e5720	0xc56b394721af32c3
0x55555555e7f0:	0x0646cedbb8486a9e	0xa685a177c9022136
0x55555555e800:	0x527596bcf2f5bd9e	0x5357b19ba41b9ff0
0x55555555e810:	0x0000000000000000
``` 

So we can see the ciphertext here. So we know the encryption type, Ciphertext, IV, and some things about the Key. Since we already know a lot about what the key should contain, and everything else, we can write a script to brute force it.

### Solution Script

```
# This is based off of: https://github.com/perfectblue/ctf-writeups/tree/master/insomnihack-teaser-2019/junkyard

from Crypto.Cipher import AES

# Establish the IV, charSet, and CipherText
IV = "1234123412341234"
cipherText = "b0234db3e7823748303290fb70cd9eb220574e1e031f9741c332af2147396bc59e6a48b8dbce4606362102c977a185a69ebdf5f2bc967552f09f1ba49bb15753".decode('hex')
charSet = "ABCDEFGHIJKLMNOPQRS"

# This is a function which will generate the second and third portions from the first part
def numConvert(value):
    output = str(value)
    while value:
        output += charSet[value%10]
        value = value / 10
    output += "a"*(16 - len(output))
    return output

# Brute force the key, try values between 0 - 9999999999 for first part of the key 
for i in xrange(9999999999):
    # First part of the key is i
    key = numConvert(i)

    # Try to decrypt the ciphertext
    cipher = AES.new(key, AES.MODE_CBC, IV)
    decrypted = cipher.decrypt(cipherText)

    # Check if the text contains "INS" (which for this ctf the flag format is INS{flag_here})
    if "INS" in decrypted:
        print "decrypted: " + decrypted
        print "using key: " + key

```

and when we run it:
```
$ python rev.py 
decrypted: f�)  S���עd���#�~��m3��u�j��)�j_0E�m]nr��>O�cU"y>IN��1
using key: 67653DFGHGaaaaaa
decrypted: ���e+<��1Hy'�s�ܕ��,i�E���$INS��5�rz�rT�O^1؝�/��CI^x>�
using key: 414158IFBEBEaaaa
decrypted: ��]��>����_��h@��)H����_�INS-����Azk�<`�)i������(�*�8�����E
using key: 765418IBEFGHaaaa
decrypted: INS{Ev3ryb0dy_go0d?PleNty_oF_sl4v3s_FoR_My_r0bot_Col0ny?}
using key: 917087HIAHBJaaaa
��Uw�V!Z�p�ԉY)Io������W)�Ϧ$x0#��!�ǳj��?���dINS����t
using key: 1109484EIEJABBaa
```

With that, we can see that we were able to correctly decrypt the flag `INS{Ev3ryb0dy_go0d?PleNty_oF_sl4v3s_FoR_My_r0bot_Col0ny?}` with the key `917087HIAHBJaaaa`.
