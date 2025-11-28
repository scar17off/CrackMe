#include <windows.h>

void CrackTheProgram()
{
    uintptr_t exeBase = (uintptr_t)GetModuleHandleA(NULL);

    /*
       from the disassembler:

       140001349:  75 17          JNZ     140001362   ; "if password length != 9 → Wrong"
       140001357:  75 09          JNZ     140001362   ; "if memcmp != 0 → Wrong"

       both of these are "JE/JNZ" jumps (opcode 75 xx).
       if the condition is true → jump to "Wrong password!" message.
       we want to disable both jumps so the program always goes to "Correct!".

       so weplace 75 xx with 90 90 → two NOPs (No Operation)
       NOP does nothing → CPU just continues to the next instruction → falls into "Correct!"
    */

    // === PATCH 1: Kill the length check (at offset 0x1349) ===
    // original bytes: 75 17  →  JNZ +0x17
    // we turn it into: 90 90 → NOP NOP
    BYTE* lengthCheckJump = (BYTE*)(exeBase + 0x1349);

    DWORD oldProtect;
    VirtualProtect(lengthCheckJump, 2, PAGE_EXECUTE_READWRITE, &oldProtect);
    lengthCheckJump[0] = 0x90; // First NOP
    lengthCheckJump[1] = 0x90; // Second NOP
    VirtualProtect(lengthCheckJump, 2, oldProtect, &oldProtect);

    // === PATCH 2: Kill the actual password comparison check (at offset 0x1357) ===
    // this is the JNZ right after memcmp
    // original: 75 09  →  JNZ +9  (jump to "Wrong" if password is bad)
    // we replace with 90 90 → always continue straight to "Correct!"
    BYTE* passwordCheckJump = (BYTE*)(exeBase + 0x1357);

    VirtualProtect(passwordCheckJump, 2, PAGE_EXECUTE_READWRITE, &oldProtect);
    passwordCheckJump[0] = 0x90;  // NOP
    passwordCheckJump[1] = 0x90;  // NOP
    VirtualProtect(passwordCheckJump, 2, oldProtect, &oldProtect);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hModule);

        CreateThread(
            NULL,
            0,
            (LPTHREAD_START_ROUTINE)CrackTheProgram,
            NULL,
            0,
            NULL
        );
    }
    return TRUE;
}
