#include <iostream>
#include <windows.h>
#include <cstdint>
#include <cwchar>
#include <cstring>
#include <vector>
#include <algorithm>

// Windows tool help library
#include <tlhelp32.h>
#include <psapi.h>          // link against psapi/Kernel32

// Note don't use Process32Next, Process32First
uint32_t FindProcessIdByName(const wchar_t* processName)
{
    uint32_t processId = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32W pe;
        pe.dwSize = sizeof(PROCESSENTRY32W);
        std::cout << "in here" << std::endl;

        if (Process32FirstW(hSnapshot, &pe))
        {
            do
            {
                // std::wcout << "pe.szExeFile" << pe.szExeFile << std::endl;
                if (_wcsicmp(pe.szExeFile, processName) == 0)
                {
                    processId = pe.th32ProcessID;
                    break;
                }
            } while (Process32NextW(hSnapshot, &pe));
        }
        else
        {
            std::wcerr << L"Process32FirstW failed. Error: "
                    << GetLastError()
                    << std::endl;
        }


        CloseHandle(hSnapshot);
    }
    return processId;
}


struct Pattern
{
    std::vector<uint8_t> bytes;
    bool IsUnicode;
};

// the idea is that i need to convert word into a byte array
// if its Unicode/wide, then each character is 2 bytes (i need to add one byte of 00 padding)
// so 
//      48 45 4c 4F 
// becomes 
//      48 00 45 00 4c 00 4f 00
// if its ASCI, its just 1 byte (pretty much just copying from word)

// for string little/big endian doesn't matter
// matters for more integer
Pattern MakePattern(const char* word, bool wide)
{
    Pattern pattern;
    pattern.IsUnicode = wide;

    // bool wide
    for(const char*c = word; *c != '\0'; c++)
    {
        // we do static cast to silence warnings about narrowing conversion from char to uint8_t
        // char is usually signed, uint8_t is unsigned.
        // for memory comparison, we want to treat the bytes as unsigned, so we use uint8_t
        if(wide)
        {
            pattern.bytes.push_back(static_cast<uint8_t>(*c));
            pattern.bytes.push_back(0x00); // padding for UTF-16
        }
        else
        {
            pattern.bytes.push_back(static_cast<uint8_t>(*c));
        }
    }
    return pattern;
}


std::vector<uintptr_t> ScanForPattern(HANDLE hProcess, const Pattern& pattern)
{
    std::vector<uintptr_t> hits;
    if (pattern.bytes.empty()) return hits;

    SYSTEM_INFO si;
    GetSystemInfo(&si);
    uint8_t* addr = static_cast<uint8_t*>(si.lpMinimumApplicationAddress);
    // 32-bit target: nothing lives above 2GB, so cap the scan there for speed.
    uint8_t* maxAddr = reinterpret_cast<uint8_t*>(0x7FFFFFFF);
    MEMORY_BASIC_INFORMATION mbi;
    std::vector<uint8_t> buffer;
    while (addr < maxAddr)
    {
        if (VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi)) != sizeof(mbi)) {
            addr += si.dwPageSize;
            continue;
        }
        const DWORD readableMask = PAGE_READONLY | PAGE_READWRITE |
            PAGE_WRITECOPY | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
            PAGE_EXECUTE_WRITECOPY;
        bool readable = (mbi.State == MEM_COMMIT) &&
                        (mbi.Protect & readableMask) &&
                        !(mbi.Protect & PAGE_GUARD);
        if (readable)
        {
            buffer.resize(mbi.RegionSize);
            SIZE_T bytesRead = 0;
            if (ReadProcessMemory(hProcess, mbi.BaseAddress, buffer.data(),
                                mbi.RegionSize, &bytesRead) && bytesRead > 0)
            {
                auto begin = buffer.begin();
                auto end   = buffer.begin() + bytesRead;
                auto it = begin;
                while ((it = std::search(it, end,
                        pattern.bytes.begin(), pattern.bytes.end())) != end)
                {
                    uintptr_t base = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
                    hits.push_back(base + (it - begin));
                    ++it;   // keep finding overlapping/later matches
                }
            }
        }

        addr = static_cast<uint8_t*>(mbi.BaseAddress) + mbi.RegionSize;
    }
    return hits;
}

  // Search the game's memory for a 4-byte value (e.g. a pointer/address).
// Bytes are laid out little-endian, matching how x86 stores a uint32_t.
std::vector<uintptr_t> ScanForValue(HANDLE hProcess, uint32_t value)
{
    Pattern p;
    p.IsUnicode = false;
    p.bytes = {
        (uint8_t)( value        & 0xFF),   // lowest byte first
        (uint8_t)((value >>  8) & 0xFF),
        (uint8_t)((value >> 16) & 0xFF),
        (uint8_t)((value >> 24) & 0xFF),   // highest byte last
    };
    return ScanForPattern(hProcess, p);
}



// #pragma comment(lib, "psapi.lib")   // if using MSVC and it doesn't auto-link
uintptr_t GetModuleBase(HANDLE hProcess)
{
    HMODULE hMods[1024];
    DWORD needed = 0;
    // LIST_MODULES_ALL so a 64-bit tool can see a 32-bit target's modules
    if (EnumProcessModulesEx(hProcess, hMods, sizeof(hMods), &needed, LIST_MODULES_ALL))
    {
        // hMods[0] is ALWAYS the process's own .exe — no name matching needed.
        return reinterpret_cast<uintptr_t>(hMods[0]);
    }
    return 0;
}


std::string ReadWordAt(HANDLE hProcess, uintptr_t address, bool wide, size_t maxLen = 63)
{
    std::string result;
    for (size_t i = 0; i < maxLen; ++i) {
        uintptr_t at = address + i * (wide ? 2 : 1);
        uint8_t buf[2] = {0, 0};
        SIZE_T got = 0;
        if (!ReadProcessMemory(hProcess, (LPCVOID)at, buf, wide ? 2 : 1, &got) || got == 0)
            break;
        char ch = static_cast<char>(buf[0]);
        if (ch == '\0') break;
        result.push_back(ch);
    }
    return result;
}

void DebugBaseAddress(const HANDLE& hProcess, uintptr_t& base, uintptr_t& imgEnd)
{
  base = 0, imgEnd = 0;
  {
      HMODULE hMod; DWORD needed;
      if (EnumProcessModulesEx(hProcess, &hMod, sizeof(hMod), &needed, LIST_MODULES_ALL)) {
          MODULEINFO mi = {};
          GetModuleInformation(hProcess, hMod, &mi, sizeof(mi));
          base   = (uintptr_t)mi.lpBaseOfDll;
          imgEnd = base + mi.SizeOfImage;
      }
  }
  printf("module base : 0x%08X\n", (unsigned)base);
  printf("image range : 0x%08X - 0x%08X (size 0x%X)\n",
         (unsigned)base, (unsigned)imgEnd, (unsigned)(imgEnd - base));
}








void SendKey(WORD scanCode)
{
    INPUT in[2] = {};
    in[0].type       = INPUT_KEYBOARD;
    in[0].ki.wScan   = scanCode;
    in[0].ki.dwFlags = KEYEVENTF_SCANCODE;            // key down
    in[1]            = in[0];
    in[1].ki.dwFlags = KEYEVENTF_SCANCODE | KEYEVENTF_KEYUP;  // key up
    SendInput(1, &in[0], sizeof(INPUT));
    Sleep(15);                       // brief hold
    SendInput(1, &in[1], sizeof(INPUT));
}

void TypeWord(const std::string& word)                 // scan-code version (ACTIVE - game reads scan codes)
{
    const WORD SHIFT_SCAN = 0x2A;                      // left-shift scan code
    for (char c : word) {
        SHORT vk = VkKeyScanA(c);                      // char -> virtual key + shift state
        if (vk == -1) continue;                        // char not typeable on this layout
        BYTE  vkey  = (BYTE)(vk & 0xFF);               // low byte  = virtual key
        bool  shift = ((vk >> 8) & 1) != 0;            // high byte bit0 = Shift required
        WORD  scan  = (WORD)MapVirtualKey(vkey, MAPVK_VK_TO_VSC);  // VK -> scan code

        if (shift) {                                   // hold Shift for ! @ ~ uppercase etc.
            INPUT s = {}; s.type = INPUT_KEYBOARD;
            s.ki.wScan = SHIFT_SCAN; s.ki.dwFlags = KEYEVENTF_SCANCODE;
            SendInput(1, &s, sizeof(INPUT));
        }

        SendKey(scan);                                 // press + release the key itself

        if (shift) {                                   // release Shift
            INPUT s = {}; s.type = INPUT_KEYBOARD;
            s.ki.wScan = SHIFT_SCAN;
            s.ki.dwFlags = KEYEVENTF_SCANCODE | KEYEVENTF_KEYUP;
            SendInput(1, &s, sizeof(INPUT));
        }

        if (word.size() > 1)
            Sleep(10);                                 // gap between keystrokes (multi-char calls only)
    }
}

// Inject a single character straight into the focused window as Unicode. This bypasses
// scan codes, keyboard layout, and Shift entirely, so letters, DIGITS, and symbols are
// all delivered identically - which the scan-code path did not manage for digits.
void SendUnicodeChar(wchar_t ch)
{
    INPUT in[2] = {};
    in[0].type       = INPUT_KEYBOARD;
    in[0].ki.wScan   = ch;                               // the UTF-16 code unit
    in[0].ki.dwFlags = KEYEVENTF_UNICODE;                // key down
    in[1]            = in[0];
    in[1].ki.dwFlags = KEYEVENTF_UNICODE | KEYEVENTF_KEYUP;
    SendInput(1, &in[0], sizeof(INPUT));
    Sleep(15);
    SendInput(1, &in[1], sizeof(INPUT));
}

// Unicode-injection version. UNUSED for this game: it delivers WM_CHAR, which this
// title (DirectInput / raw scan codes) ignores, so nothing types. Kept for reference /
// games that read character input.
void TypeWordUnicode(const std::string& word)
{
    for (char c : word) {
        SendUnicodeChar((wchar_t)(uint8_t)c);            // treat each byte as ASCII/Latin-1
        Sleep(20);                                       // gap between keystrokes
    }
}



  
std::string ReadWordStrict(HANDLE hProcess, uint32_t addr, size_t maxLen = 63)
{
    char buf[64] = {};
    SIZE_T got = 0;
    if (!ReadProcessMemory(hProcess, (LPCVOID)(uintptr_t)addr, buf, maxLen, &got) || got == 0)
        return "";
    std::string s;
    for (SIZE_T i = 0; i < got; ++i) {
        uint8_t c = (uint8_t)buf[i];
        if (c == 0)                  return s;   // clean end
        // 0x20-0x7E is printable ASCII == every key typeable on the keyboard
        // (space through '~'). Anything outside is binary/garbage, so a byte
        // here means this pointer target isn't a real word -> reject the whole run.
        if (c < 0x20 || c > 0x7E)    return "";  // non-printable -> reject
        s.push_back((char)c);
    }
    return "";                                   // no terminator -> reject
}



// Scan HEAP for pointers into the dictionary band; return the words they hit.
std::vector<std::string> FindOnScreenWords(HANDLE hProcess,
        uintptr_t imgEnd, uint32_t dictLo, uint32_t dictHi)
{
    std::vector<std::string> words;
    SYSTEM_INFO si; GetSystemInfo(&si);
    uint8_t* addr = (uint8_t*)si.lpMinimumApplicationAddress;
    uint8_t* maxAddr = (uint8_t*)0x7FFFFFFF;
    MEMORY_BASIC_INFORMATION mbi;
    std::vector<uint8_t> buf;
    while (addr < maxAddr) {
        if (VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi)) != sizeof(mbi)) {
            addr += si.dwPageSize; 
            continue;
        }
        const DWORD mask = PAGE_READONLY|PAGE_READWRITE|PAGE_WRITECOPY|
            PAGE_EXECUTE_READ|PAGE_EXECUTE_READWRITE|PAGE_EXECUTE_WRITECOPY;
        bool readable = (mbi.State==MEM_COMMIT) && (mbi.Protect & mask) &&
                        !(mbi.Protect & PAGE_GUARD);
        bool isHeap   = (uintptr_t)mbi.BaseAddress >= imgEnd;  // skip static image
        if (readable && isHeap) {
            buf.resize(mbi.RegionSize);
            SIZE_T got = 0;
            if (ReadProcessMemory(hProcess, mbi.BaseAddress, buf.data(),
                                mbi.RegionSize, &got) && got >= 4) {
                for (SIZE_T i = 0; i + 4 <= got; i += 4) {     // 4-byte aligned
                    uint32_t v; memcpy(&v, &buf[i], 4);
                    if (v > dictLo && v < dictHi) {            // points into dict
                        // #2: real dictionary entries are null-terminated, so the byte
                        // just before a valid entry start must be 0x00. Rejects pointers
                        // that land in the middle of a string (a big garbage source).
                        uint8_t prev = 0xFF; SIZE_T pg = 0;
                        if (!ReadProcessMemory(hProcess, (LPCVOID)(uintptr_t)(v - 1),
                                               &prev, 1, &pg) || pg == 0 || prev != 0x00)
                            continue;
                        std::string w = ReadWordStrict(hProcess, v);
                        if (w.size() >= 1) words.push_back(w);  // keep single-char prompts like ! or #
                    }
                }
            }
        }
        addr = (uint8_t*)mbi.BaseAddress + mbi.RegionSize;
    }
    return words;
}


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
        else if (v >= imgEnd  && v < 0x7FFFFFFF) 
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


// A word struct: vtable at +0, a text pointer at +0x50, and an INLINE copy of the current
// text at +0x58 (e.g. "MIMOSA", or a single "8"). Constants are image-relative -> add base.
static const uint32_t WORD_VTABLE_RVA   = 0xB2A30;  // 0x004B2A30 - base
static const uint32_t WORD_PTR_OFF      = 0x50;     // struct -> text pointer (letters/words)
static const uint32_t WORD_INLINE_OFF   = 0x58;     // struct -> inline text (digits & words)
static const uint32_t WORD_PROGRESS_OFF = 0x98;     // packs (charsTyped << 8) | wordLength
static const uint32_t WORD_ARRAY_RVA    = 0x4395C4; // static active-word pointer array

// Resolve one word-struct pointer -> its dictionary word ("" if not a valid word struct).
std::string WordFromStruct(HANDLE hProcess, uint32_t structPtr, uint32_t vtable,
                           uintptr_t imgBase, uintptr_t imgEnd)
{
    if (structPtr < imgEnd) return "";                   // must be a heap object
    SIZE_T bytesRead = 0;
    uint32_t vtableValue = 0, wordPtr = 0;
    if (!ReadProcessMemory(hProcess, (LPCVOID)(uintptr_t)structPtr, &vtableValue, 4, &bytesRead)
        || bytesRead != 4 || vtableValue != vtable)
        return "";                                       // wrong/absent vtable -> not a word struct

    // Primary: follow the +0x50 pointer into the image (letters, symbols, dictionary words).
    if (ReadProcessMemory(hProcess, (LPCVOID)(uintptr_t)(structPtr + WORD_PTR_OFF), &wordPtr, 4, &bytesRead)
        && bytesRead == 4 && wordPtr >= imgBase && wordPtr < imgEnd)
    {
        std::string word = ReadWordStrict(hProcess, wordPtr);
        if (!word.empty()) return word;
    }
    // Fallback: number prompts store the digit INLINE at +0x58 (their +0x50 points at
    // non-text data). Reading inline here also works for words stored in place.
    return ReadWordStrict(hProcess, structPtr + WORD_INLINE_OFF);
}

// AUTHORITATIVE: read the game's static active-word pointer array; each valid slot -> word.
std::vector<std::string> WalkWordArray(HANDLE hProcess, uint32_t arrStart, int slots,
        uint32_t vtable, uintptr_t imgBase, uintptr_t imgEnd)
{
    std::vector<std::string> words;
    for (int slot = 0; slot < slots; ++slot)
    {
        uint32_t structPtr = 0;
        SIZE_T bytesRead = 0;
        if (!ReadProcessMemory(hProcess, (LPCVOID)(uintptr_t)(arrStart + slot * 4), &structPtr, 4, &bytesRead) || bytesRead != 4)
            continue;
        std::string word = WordFromStruct(hProcess, structPtr, vtable, imgBase, imgEnd);
        if (!word.empty()) words.push_back(word);
    }
    return words;
}

// One live on-screen word: its struct, text, and typing progress read from +0x98.
struct LiveWord
{
    uint32_t structPtr;
    std::string text;
    int typed;
    int len;
};

// Like WalkWordArray, but also reads each word's progress (+0x98 = (typed<<8)|length)
// and returns the struct pointer. Deduplicated by struct so a word appears once.
std::vector<LiveWord> WalkWordArrayFull(HANDLE hProcess, uint32_t arrStart, int slots,
        uint32_t vtable, uintptr_t imgBase, uintptr_t imgEnd)
{
    std::vector<LiveWord> liveWords;
    for (int slot = 0; slot < slots; ++slot)
    {
        uint32_t structPtr = 0;
        SIZE_T bytesRead = 0;
        if (!ReadProcessMemory(hProcess, (LPCVOID)(uintptr_t)(arrStart + slot * 4), &structPtr, 4, &bytesRead) || bytesRead != 4)
            continue;
        std::string word = WordFromStruct(hProcess, structPtr, vtable, imgBase, imgEnd);
        if (word.empty()) continue;
        bool alreadySeen = false;
        for (const LiveWord& existing : liveWords)
        {
            if (existing.structPtr == structPtr)
            {
                alreadySeen = true;
                break;
            }
        }
        if (alreadySeen) continue;
        uint32_t progress = 0;
        ReadProcessMemory(hProcess, (LPCVOID)(uintptr_t)(structPtr + WORD_PROGRESS_OFF), &progress, 4, &bytesRead);
        int charsTyped = (int)((progress >> 8) & 0xFF);
        int wordLength = (int)(progress & 0xFF);
        liveWords.push_back({ structPtr, word, charsTyped, wordLength });
    }
    return liveWords;
}

// CROSS-CHECK: scan the whole heap for objects carrying the word vtable, read each word.
std::vector<std::string> EnumWordsByVtable(HANDLE hProcess, uint32_t vtable,
        uintptr_t imgBase, uintptr_t imgEnd)
{
    std::vector<std::string> words;
    SYSTEM_INFO si; GetSystemInfo(&si);
    uint8_t* addr = (uint8_t*)si.lpMinimumApplicationAddress;
    uint8_t* maxAddr = (uint8_t*)0x7FFFFFFF;
    MEMORY_BASIC_INFORMATION mbi;
    std::vector<uint8_t> buf;
    while (addr < maxAddr) {
        if (VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi)) != sizeof(mbi)) {
            addr += si.dwPageSize; continue;
        }
        const DWORD mask = PAGE_READONLY|PAGE_READWRITE|PAGE_WRITECOPY|
            PAGE_EXECUTE_READ|PAGE_EXECUTE_READWRITE|PAGE_EXECUTE_WRITECOPY;
        bool readable = (mbi.State==MEM_COMMIT) && (mbi.Protect & mask) &&
                        !(mbi.Protect & PAGE_GUARD);
        bool isHeap   = (uintptr_t)mbi.BaseAddress >= imgEnd;
        if (readable && isHeap) {
            buf.resize(mbi.RegionSize);
            SIZE_T got = 0;
            if (ReadProcessMemory(hProcess, mbi.BaseAddress, buf.data(),
                                  mbi.RegionSize, &got) && got >= 4) {
                for (SIZE_T i = 0; i + 4 <= got; i += 4) {
                    uint32_t v; memcpy(&v, &buf[i], 4);
                    if (v == vtable) {                   // object base carrying the word vtable
                        uint32_t b = (uint32_t)((uintptr_t)mbi.BaseAddress + i);
                        std::string w = WordFromStruct(hProcess, b, vtable, imgBase, imgEnd);
                        if (!w.empty()) words.push_back(w);
                    }
                }
            }
        }
        addr = (uint8_t*)mbi.BaseAddress + mbi.RegionSize;
    }
    return words;
}


// Diagnostic: dump every populated slot of the active-word array WITHOUT the vtable /
// image-range / printable filters, so we can see why some prompts (e.g. digits) don't
// show up - wrong vtable? word pointer into the heap instead of the image? odd bytes?
void DumpArrayRaw(HANDLE hProcess, uint32_t arrStart, int slots,
                  uint32_t vtable, uintptr_t imgBase, uintptr_t imgEnd)
{
    printf("---- raw active-word array ----\n");
    for (int i = 0; i < slots; ++i)
    {
        uint32_t sp = 0; SIZE_T g = 0;
        if (!ReadProcessMemory(hProcess, (LPCVOID)(uintptr_t)(arrStart + i * 4), &sp, 4, &g) || g != 4)
            continue;
        if (sp < imgEnd) continue;                       // only slots pointing at heap objects
        uint32_t vt = 0, wp = 0;
        ReadProcessMemory(hProcess, (LPCVOID)(uintptr_t)sp, &vt, 4, &g);
        ReadProcessMemory(hProcess, (LPCVOID)(uintptr_t)(sp + WORD_PTR_OFF), &wp, 4, &g);
        const char* loc = (wp >= imgBase && wp < imgEnd) ? "image"
                        : (wp >= imgEnd)                 ? "heap "
                        :                                  "low  ";
        char raw[24] = {0}; SIZE_T got = 0;              // raw bytes at the word pointer
        ReadProcessMemory(hProcess, (LPCVOID)(uintptr_t)wp, raw, 16, &got);
        char view[17];
        for (int k = 0; k < 16; ++k) view[k] = (raw[k] >= 0x20 && raw[k] <= 0x7E) ? raw[k] : '.';
        view[16] = '\0';
        uint32_t i0 = 0, i1 = 0, i2 = 0;                 // first three 4-byte values, in hex
        memcpy(&i0, raw, 4); memcpy(&i1, raw + 4, 4); memcpy(&i2, raw + 8, 4);
        printf("  slot[%2d] struct=0x%08X vt=0x%08X%s wp=0x%08X (%s) raw=|%s|  ints=%08X %08X %08X\n",
               i, sp, vt, (vt == vtable) ? "*" : " ", wp, loc, view, i0, i1, i2);

        // if we can't read a word from this slot, dump its whole struct so we can find
        // where the value (e.g. a digit) actually lives for these odd prompts.
        if (WordFromStruct(hProcess, sp, vtable, imgBase, imgEnd).empty()) {
            printf("      ^ NOT read as a word - full struct 0x%08X:\n", sp);
            DumpAround(hProcess, sp, 0, 0x60, imgBase, imgEnd);
        }
    }
    printf("-------------------------------\n");
}

// ---- small helpers used by the main loop ----
void dedup(std::vector<std::string>& words)
{
    std::sort(words.begin(), words.end());
    words.erase(std::unique(words.begin(), words.end()), words.end());
}

// scan the active-word array and return the deduplicated on-screen words
std::vector<std::string> scanWords(HANDLE hProcess, uint32_t arrStart, uint32_t vtable,
                                   uintptr_t base, uintptr_t imgEnd)
{
    std::vector<std::string> words = WalkWordArray(hProcess, arrStart - 0x20, 64, vtable, base, imgEnd);
    dedup(words);
    return words;
}

// render a word list as "[a][b][c]" for display / change-detection
std::string joined(const std::vector<std::string>& words)
{
    std::string result;
    for (const std::string& word : words)
    {
        result += '[';
        result += word;
        result += ']';
    }
    return result;
}

// address of the first on-screen word struct (heap pointer), 0 if none
uint32_t firstLiveStruct(HANDLE hProcess, uint32_t arrStart, uint32_t vtable,
                         uintptr_t base, uintptr_t imgEnd)
{
    for (int slot = 0; slot < 64; ++slot)
    {
        uint32_t structPtr = 0;
        SIZE_T bytesRead = 0;
        if (ReadProcessMemory(hProcess, (LPCVOID)(uintptr_t)((arrStart - 0x20) + slot * 4), &structPtr, 4, &bytesRead)
            && bytesRead == 4 && !WordFromStruct(hProcess, structPtr, vtable, base, imgEnd).empty())
            return structPtr;
    }
    return 0;
}

// rising-edge key detector: true only on the frame a key transitions up -> down
bool KeyEdge(int vk, bool& prev)
{
    bool down = (GetAsyncKeyState(vk) & 0x8000) != 0;
    bool edge = down && !prev;
    prev = down;
    return edge;
}

// F8: toggle the bot on/off
void ProcessF8BotToggle(bool& botOn, bool& prevTog)
{
    if (KeyEdge(VK_F8, prevTog))
    {
        botOn = !botOn;
        printf("=== bot %s ===\n", botOn ? "ON" : "OFF");
    }
}

// F10: returns true on the frame quit is requested
bool ProcessF10QuitGame(bool& prevQuit)
{
    return KeyEdge(VK_F10, prevQuit);
}

// F9: dump the raw active-word array (diagnostic)
void ProcessF9RawDump(bool& prevDump, HANDLE hProcess, uint32_t arrStart,
                      uint32_t vtable, uintptr_t base, uintptr_t imgEnd)
{
    if (KeyEdge(VK_F9, prevDump))
        DumpArrayRaw(hProcess, arrStart - 0x20, 64, vtable, base, imgEnd);
}

// Print struct fields that changed since the previous poll, skipping animation floats
// (position/scale). Updates `previous` to the current snapshot. Used by F7 watch mode.
void ReportWatchChanges(HANDLE hProcess, uint32_t watchPtr, std::vector<uint8_t>& previous,
                        int watchBytes, uintptr_t base, uintptr_t imgEnd)
{
    std::vector<uint8_t> current(watchBytes, 0);
    SIZE_T bytesRead = 0;
    if (!ReadProcessMemory(hProcess, (LPCVOID)(uintptr_t)watchPtr, current.data(), watchBytes, &bytesRead)
        || (int)bytesRead < watchBytes)
        return;

    for (int off = 0; off + 4 <= watchBytes; off += 4)
    {
        uint32_t oldValue = 0, newValue = 0;
        memcpy(&oldValue, &previous[off], 4);
        memcpy(&newValue, &current[off], 4);
        if (oldValue == newValue)
            continue;
        // keep small ints and image pointers - that's where a counter or text cursor lives.
        bool interesting = (newValue < 0x10000) || (oldValue < 0x10000)
                        || (newValue >= base && newValue < imgEnd)
                        || (oldValue >= base && oldValue < imgEnd);
        if (interesting)
            printf("  +0x%02X: %08X -> %08X\n", off, oldValue, newValue);
    }
    previous = current;
}

int main()
{
    const wchar_t* exeName = L"Tod_e.exe";

    
    uint32_t processId = FindProcessIdByName(exeName);

    std::cout << "Hello to Typing of the dead Bot" << std::endl;
    std::wcout << L"Process ID: " << processId << std::endl;

    HANDLE hProcess = OpenProcess(
        PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, 
        FALSE, 
        processId);

    if(hProcess == NULL)
    {
        std::cerr << "Failed to open process. Error: " << GetLastError() << std::endl;
        return 1;
    }

    // wow = windows 32-bit on windows 64-bit
    BOOL isWow64Process = FALSE;
    if (!IsWow64Process(hProcess, &isWow64Process))
    {
        std::wcerr << L"Failed to determine if process is running under WOW64. Error: " << GetLastError() << std::endl; 
    }
    else
    {
        std::wcout << L"Is Wow64 Process: " << (isWow64Process ? L"Yes" : L"No") << std::endl;
    }

    uintptr_t base = 0, imgEnd = 0;
    DebugBaseAddress(hProcess, base, imgEnd);

/*
    uint32_t wordField = 0x0C805408;   // this run's struct base + 0x58
    while (true) {
        char buf[64] = {};
        SIZE_T got = 0;
        ReadProcessMemory(hProcess, (LPCVOID)(uintptr_t)wordField, buf, 63, &got);
        printf("current word: \"%s\"\n", buf);
        Sleep(200);
    }
*/

    /* ---- STRING + pointer scanner (kept, commented out) ----
    
    while (true)
    {
        char word[256];
        if (scanf(" %255[^\n]", word) != 1) 
        {
            break;
        }

        // ---- find the STRING ----
        auto ascii = ScanForPattern(hProcess, MakePattern(word, false));
        auto wide  = ScanForPattern(hProcess, MakePattern(word, true));
        bool useWide = ascii.empty();
        auto strHits = useWide ? wide : ascii;
        if (strHits.empty()) 
        { 
            printf("string not found\n"); 
            continue; 
        }
    
        uint32_t strAddr = (uint32_t)strHits[0];
        printf("STRING \"%s\" at 0x%08X\n", word, strAddr);
        
        // ---- find POINTERS to that string ----
        auto ptrs = ScanForValue(hProcess, strAddr);
        printf("  %zu pointer(s) point at it:\n", ptrs.size());
        for (auto p : ptrs) {
            bool inImage = (p >= base && p < imgEnd);
            printf("    pointer stored at 0x%08X (%s, base+0x%X)\n",
                    (unsigned)p, inImage ? "STATIC" : "heap",
                    (unsigned)(p - base));
        }
    }
    */
    /* ---- on-screen word scanner (heap-pointer version, kept, commented out) ----
    // ---- on-screen word scanner (active) ----
    uint32_t dictLo = 0x0083C000, dictHi = 0x0083F000;  // #1 tight dictionary band (observed 0x0083Cxxx-0x0083Exxx)
    while (true) {
        auto words = FindOnScreenWords(hProcess, imgEnd, dictLo, dictHi);
        
        std::sort(words.begin(), words.end());
        words.erase(std::unique(words.begin(), words.end()), words.end());
        
        printf("on screen: ");
        for (auto& w : words) 
        {
            printf("[%s] ", w.c_str());
        }

        printf("\n");
        Sleep(200);
    }
    */

    /* ---- Stage A: struct discovery (kept, commented out) ----
    // ---- Stage A: discover the on-screen word struct (active) ----
    // The word text lives ONCE, in the static dictionary; on-screen structs reference
    // it by pointer. So: find the dict string, find heap fields that point AT it (those
    // sit inside the live structs), dump the struct, and see what references the struct.
    while (true) {
        char probe[256];
        printf("\non-screen word to inspect> ");
        if (scanf(" %255[^\n]", probe) != 1) break;

        // 1) locate the dictionary string (prefer the static-image copy)
        auto hits = ScanForPattern(hProcess, MakePattern(probe, false));
        uint32_t strAddr = 0;
        for (auto h : hits) if (h >= base && h < imgEnd) { strAddr = (uint32_t)h; break; }
        if (!strAddr && !hits.empty()) strAddr = (uint32_t)hits[0];
        if (!strAddr) { printf("  \"%s\" not found in memory\n", probe); continue; }
        printf("\"%s\": dict string at 0x%08X (%zu copies)\n", probe, strAddr, hits.size());

        // 2) heap fields that POINT at the string -> these live inside on-screen structs
        auto ptrs = ScanForValue(hProcess, strAddr);
        std::vector<uint32_t> heapPtrs;
        for (auto p : ptrs) if ((uintptr_t)p >= imgEnd) heapPtrs.push_back((uint32_t)p);
        printf("  %zu pointer(s) to it, %zu on the heap\n", ptrs.size(), heapPtrs.size());
        if (heapPtrs.empty()) { printf("  no heap pointer - not currently on screen?\n"); continue; }

        // 3) dump the struct around the first heap pointer field (peek shows the word)
        uint32_t pf = heapPtrs[0];
        printf("  first heap pointer field at 0x%08X - struct dump:\n", pf);
        DumpAround(hProcess, pf, 0x60, 0x60, base, imgEnd);

        // 4) who references this struct? clustered heap refs = the active-word manager
        printf("  pointers landing near this struct:\n");
        FindReferrers(hProcess, pf - 0x100, pf + 0x10, pf, base, imgEnd);
    }
    */

    // ---- Stage B/C: enumerate on-screen words + auto-type (active) ----
    // WalkWordArray reads the game's static active-word array (base+0x4395C4) and returns
    // exactly the words on screen. (EnumWordsByVtable stays as a heap-scan cross-check.)
    const uint32_t vtable   = (uint32_t)base + WORD_VTABLE_RVA;
    const uint32_t arrStart = (uint32_t)base + WORD_ARRAY_RVA;


    // F8 = bot on/off;  F7 = watch one struct (finds the progress field);  F9 = raw dump;  F10 = quit.
    // Focus the GAME window: keystrokes go to the foreground app, while F7-F10 are read
    // globally so they still fire while the game has focus.
    bool botOn = false, prevTog = false, prevQuit = false, prevDump = false, prevWatch = false;
    const int WATCH_BYTES = 0xC0;   // watch a wide window - progress fields can sit past +0x60
    bool watching = false; uint32_t watchPtr = 0; std::vector<uint8_t> watchPrev(WATCH_BYTES, 0);
    std::string lastTyped, lastShown;
    printf("\nReady - focus the game.   [F8] bot on/off   [F7] watch struct   [F9] raw dump   [F10] quit\n");

    while (true)
    {
        ProcessF8BotToggle(botOn, prevTog);
        if (ProcessF10QuitGame(prevQuit))
            break;
        ProcessF9RawDump(prevDump, hProcess, arrStart, vtable, base, imgEnd);

        // F7 = lock onto one word struct and report every field that changes as you type.
        // The offset(s) that advance while you type correct letters ARE the progress tracker.
        if (KeyEdge(VK_F7, prevWatch))
        {
            watching = !watching;
            if (watching)
            {
                watchPtr = firstLiveStruct(hProcess, arrStart, vtable, base, imgEnd);
                SIZE_T bytesRead = 0;
                ReadProcessMemory(hProcess, (LPCVOID)(uintptr_t)watchPtr, watchPrev.data(), WATCH_BYTES, &bytesRead);
                printf("=== WATCH ON  struct=0x%08X - type slowly; changed fields print below ===\n", watchPtr);
            }
            else
            {
                printf("=== WATCH OFF ===\n");
            }
        }

        if (watching && watchPtr)
        {
            ReportWatchChanges(hProcess, watchPtr, watchPrev, WATCH_BYTES, base, imgEnd);
            Sleep(80);
            continue;                 // while watching, don't auto-type - you type manually
        }

        std::vector<std::string> words = scanWords(hProcess, arrStart, vtable, base, imgEnd);
        std::string now = joined(words);
        if (now != lastShown)
        {
            printf("on screen: %s\n", now.empty() ? "(none)" : now.c_str()); 
            lastShown = now; 
        }

        if (!botOn)         
        { 
            lastTyped.clear(); 
            Sleep(60); 
            continue; 
        }   // hands off - you type
        
        if (words.empty())  
        { 
            Sleep(60); 
            continue; 
        }

        // Read the live words WITH progress (+0x98 = (typed<<8)|length).
        std::vector<LiveWord> live = WalkWordArrayFull(hProcess, arrStart - 0x20, 64, vtable, base, imgEnd);
        if (live.empty())
        {
            Sleep(60);
            continue;
        }

        // Prefer the word the game is locked onto (started but not finished); otherwise a
        // fresh word (len unknown for single-char/number prompts -> treat as start-from-0).
        const LiveWord* target = nullptr;
        for (const LiveWord& liveWord : live)
        {
            if (liveWord.len > 0 && liveWord.typed > 0 && liveWord.typed < liveWord.len)
            {
                target = &liveWord;
                break;
            }
        }
        if (!target)
        {
            for (const LiveWord& liveWord : live)
            {
                if (liveWord.len <= 0 || liveWord.typed < liveWord.len)
                {
                    target = &liveWord;
                    break;
                }
            }
        }
        if (!target)
        {
            Sleep(60);
            continue;
        }

        // Type ONE character at a time - always the next un-typed one, re-reading progress
        // each pass. This never re-sends an already-typed character, and re-syncs if a
        // keystroke is dropped or the player types part of the word themselves.
        int typed = (target->len > 0 && target->typed > 0) ? target->typed : 0;
        if (typed >= (int)target->text.size())
        {
            Sleep(30);
            continue;
        }
        char nextChar = target->text[typed];
        uint32_t targetStruct = target->structPtr;
        printf("  bot types '%c' (%d/%d)\n", nextChar, typed, target->len);
        TypeWord(std::string(1, nextChar));

        // wait until the game registers the keystroke (progress moves past `typed`) or the
        // word is gone, before reading the next character.
        for (int attempt = 0; attempt < 60; ++attempt)
        {
            std::vector<LiveWord> after = WalkWordArrayFull(hProcess, arrStart - 0x20, 64, vtable, base, imgEnd);
            const LiveWord* stillLive = nullptr;
            for (const LiveWord& liveWord : after)
            {
                if (liveWord.structPtr == targetStruct)
                {
                    stillLive = &liveWord;
                    break;
                }
            }
            if (!stillLive)
                break;                                        // completed and despawned
            if (stillLive->typed > typed)
                break;                                        // our keystroke registered
            Sleep(3);
        }
    }

    std::cout << "closing the program " << std::endl;       
    CloseHandle(hProcess);

    return 0;
}










    /*
    while (true)
    {
        char word[256];
        if (scanf(" %255[^\n]", word) != 1) 
        {
            break;
        }

        // ---- find the STRING ----
        auto ascii = ScanForPattern(hProcess, MakePattern(word, false));
        auto wide  = ScanForPattern(hProcess, MakePattern(word, true));
        bool useWide = ascii.empty();
        auto strHits = useWide ? wide : ascii;
        if (strHits.empty()) 
        { 
            printf("string not found\n"); 
            continue; 
        }
    
        uint32_t strAddr = (uint32_t)strHits[0];
        printf("STRING \"%s\" at 0x%08X\n", word, strAddr);
        
        // ---- find POINTERS to that string ----
        auto ptrs = ScanForValue(hProcess, strAddr);
        printf("  %zu pointer(s) point at it:\n", ptrs.size());
        for (auto p : ptrs) {
            bool inImage = (p >= base && p < imgEnd);
            printf("    pointer stored at 0x%08X (%s, base+0x%X)\n",
                    (unsigned)p, inImage ? "STATIC" : "heap",
                    (unsigned)(p - base));
        }
    }
*/


/*
    std::vector<uintptr_t> memoryAddresses;
    bool useWide = false;
  
    while (true)
    {
        char word[256];
        if (scanf(" %255[^\n]", word) != 1) {
            break;
        }

        if (memoryAddresses.empty()) 
        {
            // FIRST word: full scan to seed candidates.
            auto ascii = ScanForPattern(hProcess, MakePattern(word, false));
            auto wide  = ScanForPattern(hProcess, MakePattern(word, true));
            useWide = ascii.empty();
            memoryAddresses = useWide ? wide : ascii;
            std::cout << "seeded " << memoryAddresses.size() << " candidates\n";
        } 
        else 
        {
          // LATER words: keep only candidates that now hold the new word.
          std::vector<uintptr_t> survivors;
          for (auto a : memoryAddresses)
              if (ReadWordAt(hProcess, a, useWide) == word)
                  survivors.push_back(a);
          memoryAddresses = survivors;
          std::cout << "narrowed to " << memoryAddresses.size() << " candidates\n";
      }
      for (auto a : memoryAddresses)
      {
        bool inImage = (a >= base && a < imgEnd);
        printf("  0x%08X (%s, base+0x%X) -> \"%s\"\n",
                (unsigned)a,
                inImage ? "STATIC" : "heap",
                (unsigned)(a - base),
                ReadWordAt(hProcess, a, useWide).c_str());

      }
    }
*/