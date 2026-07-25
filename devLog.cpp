Whole investigation:

1.  Its logical to think that the game has an active word list

                ZombieManager
                {
                    std::vector<Word> ActiveWordList;
                }

but there could be multiple variations of this

                ZombieManager
                {
                    std::vector<Word*> ActiveWordList;
                }

                ZombieManager
                {
                    Word** ActiveWordList;
                }

regardless, our goal is to find the address of that ActiveWordList


2.  since we on windows, the raw address of your game changes everytime you launch the game 
(ASLR - windows randomizes where things load)

However this exe is from December 2000, which is before ASLR existed. ASLR arrived around 2007
a binary that old was never compiled with /DYNAMICBASE
So ASLR doesnt apply to it.


The tod_e.exe is around 2MB

thats the default image base for 32-bit EXEs.

                0x00400000


and guess what, when you run the program to print out their addresses
they are at these addresses
        
                module base : 0x00400000
                image range : 0x00400000 - 0x00A43000 (size 0x643000)



3.  Go into a game. I went inside Drill Mode Speed 1.
I see a on-screen word. Its logical to think that the game has pointers pointing to a static word list
especially considering it has a folder called word/

so during the game, in real time, I first do a memory scan of that word 
the game starts from 0x00400000
so an example dump would be like:

                module base : 0x00400000
                image range : 0x00400000 - 0x00A43000 (size 0x643000)
                Turtle
                STRING "Turtle" at 0x0083CC30
                  2 pointer(s) point at it:
                    pointer stored at 0x0083A644 (STATIC, base+0x43A644)
                    pointer stored at 0x08DC6E80 (heap, base+0x89C6E80)
                Feeder
                STRING "Feeder" at 0x0083D270
                  2 pointer(s) point at it:
                    pointer stored at 0x0083AB00 (STATIC, base+0x43AB00)
                    pointer stored at 0x08DC74D0 (heap, base+0x89C74D0)
                Turtle
                STRING "Turtle" at 0x0083CC30
                  1 pointer(s) point at it:
                    pointer stored at 0x0083A644 (STATIC, base+0x43A644)


you see two pointers, one will be static, the other is heap.
the heap pointer is the key for us. Its pointing to the static word data.


4.  in the examples above, we see the heap pointers is stored at 0x08DC6E80, 0x08DC74D0
The current thinking is that, it might look something like 



                ZombieManager
                {
                    std::vector<Word> ActiveWordList;
                    {
                        WordStruct entry 0

                            char* word pointer


                        WordStruct entry 1

                            char* word pointer


                        WordStruct entry 2

                            char* word pointer

                        ...
                        ...
                    }
                }

so the idea is that lets do a memory dump around that field, so we can reverse engineer the struct layout
DumpAround revealed the (Claude figured this out for us)
    
as we do the Memory Dump, we also want to annotate the memory 


                // ---- struct-discovery instrumentation (Stage A of the struct-walk approach) ----
                // Dump 4-byte words around an address, classifying each as static/heap pointer or
                // int, with an ASCII view and a peek at any pointer's target text. Reveals an
                // on-screen word struct's layout: where the word sits and which field links onward.
                void DumpAround(HANDLE hProcess, uint32_t center, int before, int after,
                                uintptr_t imgBase, uintptr_t imgEnd)
                {
                    for (int off = -before; off <= after; off += 4) {
                        uint32_t a = center + off;
                        uint8_t raw[4] = {0};
                        SIZE_T got = 0;
                        if (!ReadProcessMemory(hProcess, (LPCVOID)(uintptr_t)a, raw, 4, &got) || got < 4) 
                        {
                            printf("  %+5d 0x%08X : <unreadable>\n", off, a);
                            continue;
                        }
                        uint32_t v; memcpy(&v, raw, 4);
                        char ascii[5];
                        for (int k = 0; k < 4; ++k)
                            ascii[k] = (raw[k] >= 0x20 && raw[k] <= 0x7E) ? (char)raw[k] : '.';
                        ascii[4] = '\0';

                        const char* kind = "int?";
                        if (v >= imgBase && v < imgEnd)     
                            kind = "STATIC ptr";
                        else if (v >= imgEnd && v < 0x7FFFFFFF) 
                            kind = "heap ptr";
                        else if (v < 0x10000)                    
                            kind = "int";

                        char peek[28] = "";
                        if (v >= 0x10000 && v < 0x7FFFFFFF) 
                        {   
                            // if it looks like a pointer, peek at its text
                            std::string t = ReadWordStrict(hProcess, v, 20);
                            if (!t.empty()) 
                            {
                                snprintf(peek, sizeof(peek), " -> \"%s\"", t.c_str());
                            }
                        }
                        printf("  %+5d 0x%08X : %08X  |%s|  %-11s%s\n", off, a, v, ascii, kind, peek);
                    }
                }


See the comments we have:

-   we grab 4 bytes, we want to check if its a keyboard typable character 
    we more or less do this check with ascii code comparisons:
                
                (raw[k] >= 0x20 && raw[k] <= 0x7E)

-   we check if its static

                v >= imgBase && v < imgEnd

-   check if its heap

                v >= imgEnd && v < 0x7FFFFFFF                

    this is a very loose check. Its just "above the main .exe's image." 
    In this process: base = 0x00400000, imgEnd = 0x00A43000, and the word structs lives at ~0x0C9xxxxx — which is inde the range of [imgEnd ~ 0x7FFFFFFF] 


5.  Here is an example:

                in here
                Hello to Typing of the dead Bot
                Process ID: 2060
                Is Wow64 Process: Yes
                module base : 0x00400000
                image range : 0x00400000 - 0x00A43000 (size 0x643000)

                on-screen word to inspect> Mimosa
                "Mimosa": dict string at 0x0083D3F0 (1 copies)
                  2 pointer(s) to it, 1 on the heap
                  first heap pointer field at 0x0C960B50 - struct dump:
                    -96 0x0C960AF0 : FFFFFD30  |0...|  int?       
                    -92 0x0C960AF4 : 0C960980  |....|  heap ptr   
                    -88 0x0C960AF8 : 0C961050  |P...|  heap ptr   
                    -84 0x0C960AFC : 0C5C1550  |P.\.|  heap ptr    -> " "
                    -80 0x0C960B00 : 004B2A30  |0*K.|  STATIC ptr 
                    -76 0x0C960B04 : 00000000  |....|  int        
                    -72 0x0C960B08 : 0001007E  |~...|  int?       
                    -68 0x0C960B0C : 00000001  |....|  int        
                    -64 0x0C960B10 : 00000000  |....|  int        
                    -60 0x0C960B14 : 00000000  |....|  int        
                    -56 0x0C960B18 : 00000000  |....|  int        
                    -52 0x0C960B1C : 00000000  |....|  int        
                    -48 0x0C960B20 : 0C965810  |.X..|  heap ptr    -> "`$D"                 "
                    -44 0x0C960B24 : 00000000  |....|  int        
                    -40 0x0C960B28 : 00000000  |....|  int        
                    -36 0x0C960B2C : 0C960B00  |....|  heap ptr    -> "0*K"                 "
                    -32 0x0C960B30 : 00000000  |....|  int        
                    -28 0x0C960B34 : 41743850  |P8tA|  heap ptr   
                    -24 0x0C960B38 : 3FEF095D  |]..?|  heap ptr   
                    -20 0x0C960B3C : C2B2F026  |&...|  int?       
                    -16 0x0C960B40 : 3F800000  |...?|  heap ptr   
                    -12 0x0C960B44 : 3EE66666  |ff.>|  heap ptr   
                     -8 0x0C960B48 : 3F800000  |...?|  heap ptr   
                     -4 0x0C960B4C : 00000000  |....|  int        
                     +0 0x0C960B50 : 0083D3F0  |....|  STATIC ptr  -> "Mimosa"              "
                     +4 0x0C960B54 : 0083D3F8  |....|  STATIC ptr 
                     +8 0x0C960B58 : 4F4D494D  |MIMO|  heap ptr   
                    +12 0x0C960B5C : 00004153  |SA..|  int        
                    +16 0x0C960B60 : 00000000  |....|  int        
                    +20 0x0C960B64 : 00000000  |....|  int        
                    +24 0x0C960B68 : 00000000  |....|  int        
                    +28 0x0C960B6C : 00000000  |....|  int        
                    +32 0x0C960B70 : 00000000  |....|  int        
                    +36 0x0C960B74 : 00000000  |....|  int        
                    +40 0x0C960B78 : 00000000  |....|  int        
                    +44 0x0C960B7C : 00000000  |....|  int        
                    +48 0x0C960B80 : 00000000  |....|  int        
                    +52 0x0C960B84 : 00000000  |....|  int        
                    +56 0x0C960B88 : 00000000  |....|  int        
                    +60 0x0C960B8C : 00000000  |....|  int        
                    +64 0x0C960B90 : 00000000  |....|  int        
                    +68 0x0C960B94 : 00000000  |....|  int        
                    +72 0x0C960B98 : 00000006  |....|  int        
                    +76 0x0C960B9C : 00180000  |....|  int?       
                    +80 0x0C960BA0 : 00000000  |....|  int        
                    +84 0x0C960BA4 : 00000007  |....|  int        
                    +88 0x0C960BA8 : 00000000  |....|  int        
                    +92 0x0C960BAC : 00000000  |....|  int        
                    +96 0x0C960BB0 : 00000000  |....|  int        
                  pointers landing near this struct:
                    ref at 0x008395C4 (STATIC) -> 0x0C960B00 (word-80)
                    ref at 0x0C960B2C (heap  ) -> 0x0C960B00 (word-80)
                    ref at 0x0C960DC4 (heap  ) -> 0x0C960AF0 (word-96)
                    ref at 0x0C965834 (heap  ) -> 0x0C960B00 (word-80)

                on-screen word to inspect> Chirp
                "Chirp": dict string at 0x0083C8E0 (1 copies)
                  2 pointer(s) to it, 1 on the heap
                  first heap pointer field at 0x0C928E90 - struct dump:
                    -96 0x0C928E30 : FFFFFD30  |0...|  int?       
                    -92 0x0C928E34 : 0C927A10  |.z..|  heap ptr   
                    -88 0x0C928E38 : 0C9612A0  |....|  heap ptr   
                    -84 0x0C928E3C : 0C5C1550  |P.\.|  heap ptr    -> " "
                    -80 0x0C928E40 : 004B2A30  |0*K.|  STATIC ptr 
                    -76 0x0C928E44 : 00000000  |....|  int        
                    -72 0x0C928E48 : 00010080  |....|  int?       
                    -68 0x0C928E4C : 00000001  |....|  int        
                    -64 0x0C928E50 : 00000000  |....|  int        
                    -60 0x0C928E54 : 00000000  |....|  int        
                    -56 0x0C928E58 : 00000000  |....|  int        
                    -52 0x0C928E5C : 00000000  |....|  int        
                    -48 0x0C928E60 : 0C927A20  | z..|  heap ptr    -> "`$D"                 "
                    -44 0x0C928E64 : 00000000  |....|  int        
                    -40 0x0C928E68 : 00000000  |....|  int        
                    -36 0x0C928E6C : 0C928E40  |@...|  heap ptr    -> "0*K"                 "
                    -32 0x0C928E70 : 00000000  |....|  int        
                    -28 0x0C928E74 : C0C05C2C  |,\..|  int?       
                    -24 0x0C928E78 : C129C1A2  |..).|  int?       
                    -20 0x0C928E7C : C2B3B17A  |z...|  int?       
                    -16 0x0C928E80 : 3F800000  |...?|  heap ptr   
                    -12 0x0C928E84 : 3EE66666  |ff.>|  heap ptr   
                     -8 0x0C928E88 : 3F800000  |...?|  heap ptr   
                     -4 0x0C928E8C : 00000000  |....|  int        
                     +0 0x0C928E90 : 0083C8E0  |....|  STATIC ptr  -> "Chirp"               "
                     +4 0x0C928E94 : 0083C8E8  |....|  STATIC ptr 
                     +8 0x0C928E98 : 52494843  |CHIR|  heap ptr   
                    +12 0x0C928E9C : 00000050  |P...|  int        
                    +16 0x0C928EA0 : 00000000  |....|  int        
                    +20 0x0C928EA4 : 00000000  |....|  int        
                    +24 0x0C928EA8 : 00000000  |....|  int        
                    +28 0x0C928EAC : 00000000  |....|  int        
                    +32 0x0C928EB0 : 00000000  |....|  int        
                    +36 0x0C928EB4 : 00000000  |....|  int        
                    +40 0x0C928EB8 : 00000000  |....|  int        
                    +44 0x0C928EBC : 00000000  |....|  int        
                    +48 0x0C928EC0 : 00000000  |....|  int        
                    +52 0x0C928EC4 : 00000000  |....|  int        
                    +56 0x0C928EC8 : 00000000  |....|  int        
                    +60 0x0C928ECC : 00000000  |....|  int        
                    +64 0x0C928ED0 : 00000000  |....|  int        
                    +68 0x0C928ED4 : 00000000  |....|  int        
                    +72 0x0C928ED8 : 00000005  |....|  int        
                    +76 0x0C928EDC : 00160000  |....|  int?       
                    +80 0x0C928EE0 : 00000000  |....|  int        
                    +84 0x0C928EE4 : 00000006  |....|  int        
                    +88 0x0C928EE8 : 00000000  |....|  int        
                    +92 0x0C928EEC : 00000000  |....|  int        
                    +96 0x0C928EF0 : 00000000  |....|  int        
                  pointers landing near this struct:
                    ref at 0x008395C8 (STATIC) -> 0x0C928E40 (word-80)
                    ref at 0x0C927A44 (heap  ) -> 0x0C928E40 (word-80)
                    ref at 0x0C928E6C (heap  ) -> 0x0C928E40 (word-80)
                    ref at 0x0C929104 (heap  ) -> 0x0C928E30 (word-96)


6.  Then the next step is to call

                // 4) who references this struct? clustered heap refs = the active-word manager
                printf("  pointers landing near this struct:\n");
                FindReferrers(hProcess, pf - 0x100, pf + 0x10, pf, base, imgEnd);


Because we want to look for sceanrios of 

                ZombieManager
                {
                    Word* ActiveWordList;       ----->
                    {
                        WordStruct entry 0

                            char* word pointer


                        WordStruct entry 1

                            char* word pointer


                        WordStruct entry 2

                            char* word pointer

                        ...
                        ...
                    }
                }

where ActiveWordList is a pointer.


The function is:

                // Find every 4-byte value in the target that points into [lo, hi]; print where it's
                // stored (static vs heap) and its offset from `anchor`. Used to locate the manager
                // array / linked list that holds on-screen word structs, and any static anchor to it.
                void FindReferrers(HANDLE hProcess, uint32_t lo, uint32_t hi, uint32_t anchor,
                                   uintptr_t imgBase, uintptr_t imgEnd)
                {
                    SYSTEM_INFO si; GetSystemInfo(&si);
                    uint8_t* addr = (uint8_t*)si.lpMinimumApplicationAddress;
                    uint8_t* maxAddr = (uint8_t*)0x7FFFFFFF;
                    MEMORY_BASIC_INFORMATION mbi;
                    std::vector<uint8_t> buf;
                    int shown = 0;
                    while (addr < maxAddr) {
                        if (VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi)) != sizeof(mbi)) {
                            addr += si.dwPageSize; continue;
                        }
                        const DWORD mask = PAGE_READONLY|PAGE_READWRITE|PAGE_WRITECOPY|
                            PAGE_EXECUTE_READ|PAGE_EXECUTE_READWRITE|PAGE_EXECUTE_WRITECOPY;
                        bool readable = (mbi.State==MEM_COMMIT) && (mbi.Protect & mask) &&
                                        !(mbi.Protect & PAGE_GUARD);
                        if (readable) {
                            buf.resize(mbi.RegionSize);
                            SIZE_T got = 0;
                            if (ReadProcessMemory(hProcess, mbi.BaseAddress, buf.data(),
                                                  mbi.RegionSize, &got) && got >= 4) {
                                for (SIZE_T i = 0; i + 4 <= got; i += 4) {
                                    uint32_t v; memcpy(&v, &buf[i], 4);
                                    if (v >= lo && v <= hi) {
                                        uint32_t at = (uint32_t)((uintptr_t)mbi.BaseAddress + i);
                                        bool inImage = (at >= imgBase && at < imgEnd);
                                        printf("    ref at 0x%08X (%-6s) -> 0x%08X (word%+d)\n",
                                               at, inImage ? "STATIC" : "heap", v, (int)(v - anchor));
                                        if (++shown >= 64) { printf("    ...(64+ refs, truncated)\n"); return; }
                                    }
                                }
                            }
                        }
                        addr = (uint8_t*)mbi.BaseAddress + mbi.RegionSize;
                    }
                }


7.  So a sample result is

                  pointers landing near this struct:
                    ref at 0x008395C4 (STATIC) -> 0x0C960B00 (word-80)
                    ref at 0x0C960B2C (heap  ) -> 0x0C960B00 (word-80)
                    ref at 0x0C960DC4 (heap  ) -> 0x0C960AF0 (word-96)
                    ref at 0x0C965834 (heap  ) -> 0x0C960B00 (word-80)


So from the FindReferrers output, you can see that we got three pointers pointing at 0x0C960B00, one static, two heap
That implies that the code code references an object by its start address, not some field in its middle. 

When multiple pointers in random addresses point to the same address, its very likely thats the beginnning of an Object




8.  if you look further inside at address 0x0C960B00


                on-screen word to inspect> Mimosa
                "Mimosa": dict string at 0x0083D3F0 (1 copies)
                  2 pointer(s) to it, 1 on the heap
                  first heap pointer field at 0x0C960B50 - struct dump:
                    -96 0x0C960AF0 : FFFFFD30  |0...|  int?       
                    -92 0x0C960AF4 : 0C960980  |....|  heap ptr   
                    -88 0x0C960AF8 : 0C961050  |P...|  heap ptr   
                    -84 0x0C960AFC : 0C5C1550  |P.\.|  heap ptr    -> " "
    ----------->    -80 0x0C960B00 : 004B2A30  |0*K.|  STATIC ptr 

it is a static ptr.
The value at 0x0C960B00 is 0x004B2A30, which is into the module image (0x00400000–0x00A43000), 
the read-only region where code and vtables live, not into the heap.


A heap object whose very first 4 bytes point into the images code/data is the 
classic signature of a C++ polymorphic object. 
The compiler puts the vtable pointer as the hidden first member, at offset 0. 


the same thing is confirmed for the 2nd word

                on-screen word to inspect> Chirp
                "Chirp": dict string at 0x0083C8E0 (1 copies)
                  2 pointer(s) to it, 1 on the heap
                  first heap pointer field at 0x0C928E90 - struct dump:
                    -96 0x0C928E30 : FFFFFD30  |0...|  int?       
                    -92 0x0C928E34 : 0C927A10  |.z..|  heap ptr   
                    -88 0x0C928E38 : 0C9612A0  |....|  heap ptr   
                    -84 0x0C928E3C : 0C5C1550  |P.\.|  heap ptr    -> " "
                    -80 0x0C928E40 : 004B2A30  |0*K.|  STATIC ptr 
                    -76 0x0C928E44 : 00000000  |....|  int        



so the vtable address is 
                
                0x004B2A30

the base of our image is 

                0x00400000

so we have

                static const uint32_t WORD_VTABLE_RVA = 0xB2A30;    // 0x004B2A30 - base


9.  Another thing u realized is that the address of the pointer itself is also in the heap


    ------->    -80 0x0C960B00 : 004B2A30  |0*K.|  STATIC ptr 
                -76 0x0C960B04 : 00000000  |....|  int        
                -72 0x0C960B08 : 0001007E  |~...|  int?       
                -68 0x0C960B0C : 00000001  |....|  int        
                -64 0x0C960B10 : 00000000  |....|  int        
                -60 0x0C960B14 : 00000000  |....|  int        
                -56 0x0C960B18 : 00000000  |....|  int        
                -52 0x0C960B1C : 00000000  |....|  int        
                -48 0x0C960B20 : 0C965810  |.X..|  heap ptr    -> "`$D"                 "
                -44 0x0C960B24 : 00000000  |....|  int        
                -40 0x0C960B28 : 00000000  |....|  int        
                -36 0x0C960B2C : 0C960B00  |....|  heap ptr    -> "0*K"                 "
                -32 0x0C960B30 : 00000000  |....|  int        
                -28 0x0C960B34 : 41743850  |P8tA|  heap ptr   
                -24 0x0C960B38 : 3FEF095D  |]..?|  heap ptr   
                -20 0x0C960B3C : C2B2F026  |&...|  int?       
                -16 0x0C960B40 : 3F800000  |...?|  heap ptr   
                -12 0x0C960B44 : 3EE66666  |ff.>|  heap ptr   
                 -8 0x0C960B48 : 3F800000  |...?|  heap ptr   
                 -4 0x0C960B4C : 00000000  |....|  int        
                 +0 0x0C960B50 : 0083D3F0  |....|  STATIC ptr  -> "Mimosa"              "


   ------->     -80 0x0C928E40 : 004B2A30  |0*K.|  STATIC ptr 
                -76 0x0C928E44 : 00000000  |....|  int        
                -72 0x0C928E48 : 00010080  |....|  int?       
                -68 0x0C928E4C : 00000001  |....|  int        
                -64 0x0C928E50 : 00000000  |....|  int        
                -60 0x0C928E54 : 00000000  |....|  int        
                -56 0x0C928E58 : 00000000  |....|  int        
                -52 0x0C928E5C : 00000000  |....|  int        
                -48 0x0C928E60 : 0C927A20  | z..|  heap ptr    -> "`$D"                 "
                -44 0x0C928E64 : 00000000  |....|  int        
                -40 0x0C928E68 : 00000000  |....|  int        
                -36 0x0C928E6C : 0C928E40  |@...|  heap ptr    -> "0*K"                 "
                -32 0x0C928E70 : 00000000  |....|  int        
                -28 0x0C928E74 : C0C05C2C  |,\..|  int?       
                -24 0x0C928E78 : C129C1A2  |..).|  int?       
                -20 0x0C928E7C : C2B3B17A  |z...|  int?       
                -16 0x0C928E80 : 3F800000  |...?|  heap ptr   
                -12 0x0C928E84 : 3EE66666  |ff.>|  heap ptr   
                 -8 0x0C928E88 : 3F800000  |...?|  heap ptr   
                 -4 0x0C928E8C : 00000000  |....|  int        
                 +0 0x0C928E90 : 0083C8E0  |....|  STATIC ptr  -> "Chirp"               "

and you can see that the two pointers are very far apart. 
                
                Mimosa struct @ 0x0C960B00
                Chirp  struct @ 0x0C928E40
                             difference ≈ 0x37CC0  ≈ 228 KB apart

Meaning we have an array of WordStruct*
Which confirms that we have something like

                ZombieManager
                {
                    Word** ActiveWordList;
                }

or

                ZombieManager
                {
                    Word*[] ActiveWordList;
                }


an array of Word*


11. and if you notice the first line and the last line in my snippet below

                    -80 0x0C960B00 : 004B2A30  |0*K.|  STATIC ptr 
                    -76 0x0C960B04 : 00000000  |....|  int        
                    -72 0x0C960B08 : 0001007E  |~...|  int?       
                    -68 0x0C960B0C : 00000001  |....|  int        
                    -64 0x0C960B10 : 00000000  |....|  int        
                    -60 0x0C960B14 : 00000000  |....|  int        
                    -56 0x0C960B18 : 00000000  |....|  int        
                    -52 0x0C960B1C : 00000000  |....|  int        
                    -48 0x0C960B20 : 0C965810  |.X..|  heap ptr    -> "`$D"                 "
                    -44 0x0C960B24 : 00000000  |....|  int        
                    -40 0x0C960B28 : 00000000  |....|  int        
                    -36 0x0C960B2C : 0C960B00  |....|  heap ptr    -> "0*K"                 "
                    -32 0x0C960B30 : 00000000  |....|  int        
                    -28 0x0C960B34 : 41743850  |P8tA|  heap ptr   
                    -24 0x0C960B38 : 3FEF095D  |]..?|  heap ptr   
                    -20 0x0C960B3C : C2B2F026  |&...|  int?       
                    -16 0x0C960B40 : 3F800000  |...?|  heap ptr   
                    -12 0x0C960B44 : 3EE66666  |ff.>|  heap ptr   
                     -8 0x0C960B48 : 3F800000  |...?|  heap ptr   
                     -4 0x0C960B4C : 00000000  |....|  int        
                     +0 0x0C960B50 : 0083D3F0  |....|  STATIC ptr  -> "Mimosa"              "

its exactly 50 lines. 
so +50 is where the word pointer is at.

hence we get:

                static const uint32_t WORD_PTR_OFF    = 0x50;       // struct -> dict string pointer

do note that 80 is 0x50 in hex. therefore we see the -80 becomes 0x50



12. also the acitve word list pointer is at 0x008395C4
    hence we have the following log for the first word "Mimosa"

                  pointers landing near this struct:
                    ref at 0x008395C4 (STATIC) -> 0x0C960B00 (word-80)
                    ref at 0x0C960B2C (heap  ) -> 0x0C960B00 (word-80)
                    ref at 0x0C960DC4 (heap  ) -> 0x0C960AF0 (word-96)
                    ref at 0x0C965834 (heap  ) -> 0x0C960B00 (word-80)

with 
                0x008395C4 - 0x00400000

we get
                
                static const uint32_t WORD_ARRAY_RVA  = 0x4395C4;   // static active-word pointer array


do note that:

                .text — code
                .rdata — read-only data (string literals, vtables)
                .data — initialized globals/statics
                .bss — zero-initialized globals/statics

Global and static variables are compiled into .data/.bss, 
which are part of that image range. 
The heap, by contrast, is memory the OS hands out at runtime from separate regions mapped outside the image, at higher addresses. 

so we know that this array is inside:

                .data — initialized globals/statics
                .bss — zero-initialized globals/statics


13. finally the shape we sort of have is:

                ZombieManager
                {
                    Word*[] ActiveWordList;
                }


    and

                        WordStruct entry 0
                0x00        vtable
                0x50        char* wordPointer
                0x58        inline text


                        WordStruct entry 1
                0x00        vtable
                0x50        char* wordPointer
                0x58        inline text


                        WordStruct entry 2
                0x00        vtable
                0x50        char* wordPointer
                0x58        inline text


14. Then lets see how we gather the entire Word Array
                


                std::vector<std::string> WalkWordArray(HANDLE hProcess, uint32_t arrStart, int slots,
                        uint32_t vtable, uintptr_t imgBase, uintptr_t imgEnd)
                {
                    std::vector<std::string> words;
                    for (int i = 0; i < slots; ++i) {
                        uint32_t sp = 0; SIZE_T g = 0;
                        if (!ReadProcessMemory(hProcess, (LPCVOID)(uintptr_t)(arrStart + i * 4), &sp, 4, &g) || g != 4)
                            continue;
                        std::string w = WordFromStruct(hProcess, sp, vtable, imgBase, imgEnd);
                        if (!w.empty()) words.push_back(w);
                    }
                    return words;
                }

notice the pointer math: (arrStart + i * 4)
Word* is 32 bit since this is a 32 bit process.

Hence we get our word detection



15. Numbers are encoded completely differently 
heres an example dump:

                on screen: [$][B][J]
                on screen: (none)
                ---- raw active-word array ----
                  slot[ 8] struct=0x0C76A100 vt=0x004B2A30* wp=0x005958F4 (image) raw=|J...H...G...F...|  ints=0000004A 00000048 00000047
                  slot[ 9] struct=0x0C76B7F0 vt=0x004B2A30* wp=0x0059590C (image) raw=|B...9...8...7...|  ints=00000042 00000039 00000038
                  slot[10] struct=0x0C76CEE0 vt=0x004B2A30* wp=0x0059588C (image) raw=|$...'... ...%...|  ints=00000024 00000027 00000020                               '
                  slot[11] struct=0x0C76E5D0 vt=0x004B2A30* wp=0x005EAA54 (image) raw=|.W.......V......|  ints=00005782 000000A9 00005682
                      ^ NOT read as a word - full struct 0x0C76E5D0:
                     +0 0x0C76E5D0 : 004B2A30  |0*K.|  STATIC ptr 
                     +4 0x0C76E5D4 : 00000000  |....|  int        
                     +8 0x0C76E5D8 : 00013F6C  |l?..|  int?       
                    +12 0x0C76E5DC : 00000001  |....|  int        
                    +16 0x0C76E5E0 : 00000000  |....|  int        
                    +20 0x0C76E5E4 : 00000000  |....|  int        
                    +24 0x0C76E5E8 : 00000000  |....|  int        
                    +28 0x0C76E5EC : 00000000  |....|  int        
                    +32 0x0C76E5F0 : 0C76D1B0  |..v.|  heap ptr   
                    +36 0x0C76E5F4 : 00000000  |....|  int        
                    +40 0x0C76E5F8 : 00000000  |....|  int        
                    +44 0x0C76E5FC : 0C76E5D0  |..v.|  heap ptr    -> "0*K"                                                                                             "
                    +48 0x0C76E600 : 00000000  |....|  int        
                    +52 0x0C76E604 : C05E2917  |.)^.|  int?       
                    +56 0x0C76E608 : C0A014C6  |....|  int?       
                    +60 0x0C76E60C : C23EF340  |@.>.|  int?       
                    +64 0x0C76E610 : 3F800000  |...?|  heap ptr   
                    +68 0x0C76E614 : 3EE66666  |ff.>|  heap ptr   
                    +72 0x0C76E618 : 3F523F47  |G?R?|  heap ptr   
                    +76 0x0C76E61C : 00000000  |....|  int        
                    +80 0x0C76E620 : 005EAA54  |T.^.|  STATIC ptr 
                    +84 0x0C76E624 : 005EAA50  |P.^.|  STATIC ptr 
                    +88 0x0C76E628 : 00000038  |8...|  int        
                    +92 0x0C76E62C : 00000000  |....|  int        
                    +96 0x0C76E630 : 00000000  |....|  int        
                  slot[12] struct=0x0C76FCC0 vt=0x004B2A30* wp=0x005EAA6C (image) raw=|.T.......S......|  ints=00005482 000000A6 00005382
                      ^ NOT read as a word - full struct 0x0C76FCC0:
                     +0 0x0C76FCC0 : 004B2A30  |0*K.|  STATIC ptr 
                     +4 0x0C76FCC4 : 00000000  |....|  int        
                     +8 0x0C76FCC8 : 00013F6E  |n?..|  int?       
                    +12 0x0C76FCCC : 00000001  |....|  int        
                    +16 0x0C76FCD0 : 00000000  |....|  int        
                    +20 0x0C76FCD4 : 00000000  |....|  int        
                    +24 0x0C76FCD8 : 00000000  |....|  int        
                    +28 0x0C76FCDC : 00000000  |....|  int        
                    +32 0x0C76FCE0 : 0C76E8A0  |..v.|  heap ptr   
                    +36 0x0C76FCE4 : 00000000  |....|  int        
                    +40 0x0C76FCE8 : 00000000  |....|  int        
                    +44 0x0C76FCEC : 0C76FCC0  |..v.|  heap ptr    -> "0*K"                                                                                             "
                    +48 0x0C76FCF0 : 00000000  |....|  int        
                    +52 0x0C76FCF4 : 40310D2E  |..1@|  heap ptr   
                    +56 0x0C76FCF8 : C09AE2B9  |....|  int?       
                    +60 0x0C76FCFC : C2702898  |.(p.|  int?       
                    +64 0x0C76FD00 : 3F800000  |...?|  heap ptr   
                    +68 0x0C76FD04 : 3EE66666  |ff.>|  heap ptr   
                    +72 0x0C76FD08 : 3F800000  |...?|  heap ptr   
                    +76 0x0C76FD0C : 00000000  |....|  int        
                    +80 0x0C76FD10 : 005EAA6C  |l.^.|  STATIC ptr 
                    +84 0x0C76FD14 : 005EAA68  |h.^.|  STATIC ptr 
                    +88 0x0C76FD18 : 00000035  |5...|  int        
                    +92 0x0C76FD1C : 00000000  |....|  int        
                    +96 0x0C76FD20 : 00000000  |....|  int        
                -------------------------------

  why we are suppose to also have he words "8" and "5"



so we first detected [R][W][X]

                0x0000004A is J 
                0x00000042 is B 
                0x00000024 is $ 

but we have no idea what 

                0x00005782
                0x00005482

is. Its definitly not ASCII. Low byte is 0x82, not a digit.


16. if we look deeply, we see whats going on


                +88 0x0C76E628 : 00000038  |8...|  int    


                +88 0x0C76FD18 : 00000035  |5...|  int     

so at +88 (0x58 in hex) offset, we see the actual numbers




17. Tracking down the current progress on the word

So we also want to track down the currently typed word and our progress.

the way we do that is also looking at memory dump

we assume that the progress of the word is tracked on the WordStruct itself
so we examine bytes on the wordstruct, to see if any bytes have changed

-   start monitoring 
-   examine memory snapshot 1
-   type a letter
-   examine memory snapshot 2
-   check if theres any difference



                on screen: [Random]
                === WATCH ON  struct=0x0A8183B0 - type slowly; changed fields print below ===
                  +0x4C: 00000000 -> 000000A0
                  +0x98: 00000006 -> 00000106
                  +0xA0: 00000000 -> 00000004
                  +0xA0: 00000004 -> 00000009
                  +0xA0: 00000009 -> 0000000F
                  +0x48: 3B8CF400 -> 00000000
                  ...
                  ...
                  +0x98: 00000106 -> 00000206
                  ...
                === WATCH OFF ===


and you can see that at 

                  +0x98: 00000006 -> 00000106
                  ...
                  ...
                  +0x98: 00000106 -> 00000206


06 is the length of the word Random

then 01, 02 is the current progress
current letters typed


essentially you have the mask of 

                chars typed = (value >> 8)
                word length = (value & 0xFF)


hence we have:

                static const uint32_t WORD_PROGRESS_OFF = 0x98;     // packs (charsTyped << 8) | wordLength



18. Also encoutered sync bug, as the bot was typing already typed words.
The reason is because the bot is doing one single read and then typing the whole the word in burst.

but if the keystroke gets dropped or the read is slightly delayed, you get a desync.

so the solution is to do a read everytime before u type, and only typing 1 character at a time.
this is needed because Typing a key with SendInput is asynchronous. 
The keystroke goes into the OS queue, and the game only processes it a frame or two later, then bumps its progress counter at +0x98.


After the 2nd loop, we just move on after 15 attempts and re read and re type that character?

The edge case is that, you might get into permenant stall. If the character genuinely cant land, the bot retries it forever and never moves on. 
so human intervention is needed then

