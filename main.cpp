#include <windows.h>

bool g_bESPEnabled = false;
bool g_bKeyHandled = false;

// ฟังก์ชันค้นหา Memory Pattern (Pattern Scanning) เพื่อรองรับ SAMP ทุกเวอร์ชัน
BYTE* FindPattern(HMODULE hModule, const char* pattern, const char* mask) {
    MODULEINFO modInfo;
    GetModuleInformation(GetCurrentProcess(), hModule, &modInfo, sizeof(MODULEINFO));
    DWORD base = (DWORD)hModule;
    DWORD size = modInfo.SizeOfImage;
    DWORD patternLength = (DWORD)strlen(mask);

    for (DWORD i = 0; i < size - patternLength; i++) {
        bool found = true;
        for (DWORD j = 0; j < patternLength; j++) {
            found &= mask[j] == '?' || pattern[j] == *(char*)(base + i + j);
        }
        if (found) return (BYTE*)(base + i);
    }
    return nullptr;
}

void ProcessESPName() {
    // เช็คการกดปุ่ม Ctrl + L
    if ((GetAsyncKeyState(VK_CONTROL) & 0x8000) && (GetAsyncKeyState('L') & 0x8000)) {
        if (!g_bKeyHandled) {
            g_bESPEnabled = !g_bESPEnabled;
            g_bKeyHandled = true;
        }
    } else {
        g_bKeyHandled = false;
    }

    HMODULE hSamp = GetModuleHandleA("samp.dll");
    if (!hSamp) return;

    // ค้นหาจุด Render Distance/Line of Sight ของ NameTag ใน samp.dll
    static BYTE* pAddress = nullptr;
    if (!pAddress) {
        pAddress = FindPattern(hSamp, "\x75\x36\x8B\x44\x24\x14", "xxxxxx");
    }

    if (pAddress) {
        DWORD dwOldProtect;
        VirtualProtect(pAddress, 2, PAGE_EXECUTE_READWRITE, &dwOldProtect);
        
        if (g_bESPEnabled) {
            // สั่ง NOP ปิดการเช็คระยะ/สิ่งกีดขวาง (เห็นชื่อ+ID+สีชื่อ ทะลุหมด)
            pAddress[0] = 0x90;
            pAddress[1] = 0x90;
        } else {
            // คืนค่าเดิม
            pAddress[0] = 0x75;
            pAddress[1] = 0x36;
        }
        
        VirtualProtect(pAddress, 2, dwOldProtect, &dwOldProtect);
    }
}

DWORD WINAPI MainThread(LPVOID lpParam) {
    while (true) {
        ProcessESPName();
        Sleep(20);
    }
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        CreateThread(NULL, 0, MainThread, NULL, 0, NULL);
    }
    return TRUE;
}
