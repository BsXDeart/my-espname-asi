#include <windows.h>

bool g_bESPEnabled = false;
bool g_bKeyHandled = false;

// ฟังก์ชันเปิด/ปิด Nametag SAMP (ESP Name + ID + Color)
void ProcessESPName() {
    // เช็คการกด Ctrl + L (VK_CONTROL + 'L')
    if ((GetAsyncKeyState(VK_CONTROL) & 0x8000) && (GetAsyncKeyState('L') & 0x8000)) {
        if (!g_bKeyHandled) {
            g_bESPEnabled = !g_bESPEnabled;
            g_bKeyHandled = true;
        }
    } else {
        g_bKeyHandled = false;
    }

    // Address Memory บังคับวาด Nametag SAMP ทะลุกำแพง (SAMP v0.3.7 R1)
    uintptr_t sampBase = reinterpret_cast<uintptr_t>(GetModuleHandleA("samp.dll"));
    if (!sampBase) return;

    // Offset สำหรับปิด/เปิด Render Distance Check ของ NameTag
    DWORD dwAddress = sampBase + 0x609CD; 

    DWORD dwOldProtect;
    VirtualProtect(reinterpret_cast<LPVOID>(dwAddress), 2, PAGE_EXECUTE_READWRITE, &dwOldProtect);
    
    if (g_bESPEnabled) {
        // NOP สั่งให้เรนเดอร์ชื่อ ID และสีชื่อตลอดเวลา
        *reinterpret_cast<WORD*>(dwAddress) = 0x9090;
    } else {
        // คืนค่า Memory เดิมของ SAMP
        *reinterpret_cast<WORD*>(dwAddress) = 0x3675;
    }
    
    VirtualProtect(reinterpret_cast<LPVOID>(dwAddress), 2, dwOldProtect, &dwOldProtect);
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
