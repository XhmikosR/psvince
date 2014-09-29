#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <tlhelp32.h>
#include <vdmdbg.h>


BOOL WINAPI EnumProcs(char* procname);
BOOL WINAPI EnumProcs2(char* procname);


BOOL APIENTRY DllMain(HANDLE hModule,
                      DWORD  ul_reason_for_call,
                      LPVOID lpReserved
                     )
{
    UNREFERENCED_PARAMETER(hModule);
    UNREFERENCED_PARAMETER(ul_reason_for_call);
    UNREFERENCED_PARAMETER(lpReserved);
    return TRUE;
}

int APIENTRY IsModuleLoaded(char *lpModule)
{
    return EnumProcs(lpModule);
}


BOOL WINAPI EnumProcs(char* procname)
{

    OSVERSIONINFO  osver;
    HINSTANCE      hInstLib;
    LPDWORD        lpdwPIDs;
    DWORD          dwSize, dwSize2, dwIndex;
    HMODULE        hMod;
    HANDLE         hProcess;
    char           szFileName[MAX_PATH];
    char*          szModuleName;
    bool retcode = false;

    // PSAPI Function Pointers.

    BOOL  (WINAPI * lpfEnumProcesses)(DWORD *, DWORD cb, DWORD *);
    BOOL  (WINAPI * lpfEnumProcessModules)(HANDLE, HMODULE *, DWORD, LPDWORD);
    DWORD (WINAPI * lpfGetModuleFileNameEx)(HANDLE, HMODULE, LPTSTR, DWORD);



    // Check to see if were running under Windows NT.

    osver.dwOSVersionInfoSize = sizeof(osver);
    if (!GetVersionEx(&osver)) {
        return FALSE;
    }

    // Convert to lowercase.
    _strlwr(procname);

    if (osver.dwPlatformId == VER_PLATFORM_WIN32_NT) {

        hInstLib = LoadLibraryA("PSAPI.DLL");
        if (hInstLib == nullptr) {
            return FALSE;
        }

        // Get procedure addresses.
        lpfEnumProcesses = (BOOL(WINAPI *)(DWORD *, DWORD, DWORD*)) GetProcAddress(hInstLib, "EnumProcesses");
        lpfEnumProcessModules = (BOOL(WINAPI *)(HANDLE, HMODULE *, DWORD, LPDWORD)) GetProcAddress(hInstLib, "EnumProcessModules");
        lpfGetModuleFileNameEx = (DWORD (WINAPI *)(HANDLE, HMODULE, LPTSTR, DWORD)) GetProcAddress(hInstLib, "GetModuleFileNameExA");

        if (lpfEnumProcesses == nullptr || lpfEnumProcessModules == nullptr ||
                lpfGetModuleFileNameEx == nullptr) { // || lpfVDMEnumTaskWOWEx == nullptr)
            FreeLibrary(hInstLib);
            return FALSE;
        }


        // Call the PSAPI function EnumProcesses to get all of the
        // ProcID's currently in the system.
        // NOTE: In the documentation, the third parameter of
        // EnumProcesses is named cbNeeded, which implies that you
        // can call the function once to find out how much space to
        // allocate for a buffer and again to fill the buffer.
        // This is not the case. The cbNeeded parameter returns
        // the number of PIDs returned, so if your buffer size is
        // zero cbNeeded returns zero.
        // NOTE: The "HeapAlloc" loop here ensures that we
        // actually allocate a buffer large enough for all the
        // PIDs in the system.

        dwSize2 = 256 * sizeof(DWORD);
        lpdwPIDs = nullptr;

        do {

            if (lpdwPIDs) {
                HeapFree(GetProcessHeap(), 0, lpdwPIDs);
                dwSize2 *= 2;
            }

            lpdwPIDs = (LPDWORD)HeapAlloc(GetProcessHeap(), 0, dwSize2);
            if (lpdwPIDs == nullptr) {
                FreeLibrary(hInstLib);
                return FALSE;
            }

            if (!lpfEnumProcesses(lpdwPIDs, dwSize2, &dwSize)) {
                HeapFree(GetProcessHeap(), 0, lpdwPIDs);
                FreeLibrary(hInstLib);
                return FALSE;
            }

        } while (dwSize == dwSize2);

        // How many ProcID's did we get?
        dwSize /= sizeof(DWORD);

        // Loop through each ProcID.
        for (dwIndex = 0; dwIndex < dwSize; dwIndex++) {
            szFileName[0] = 0;

            // Open the process (if we can... security does not
            // permit every process in the system).
            hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, lpdwPIDs[dwIndex]);

            if (hProcess != nullptr) {
                // Here we call EnumProcessModules to get only the
                // first module in the process this is important,
                // because this will be the .EXE module for which we
                // will retrieve the full path name in a second.
                if (lpfEnumProcessModules(hProcess, &hMod, sizeof(hMod), &dwSize2)) {

                    // Get full pathname.
                    if (!lpfGetModuleFileNameEx(hProcess, hMod, szFileName, sizeof(szFileName))) {
                        szFileName[0] = 0;
                    }

                    // Convert to lowercase.
                    _strlwr(szFileName);
                    // Extract the filename.
                    szModuleName = strrchr(szFileName, '\\');
                    if (szModuleName) {
                        szModuleName++;

                        if (strcmp(szModuleName, procname) == 0) {
                            retcode = true;
                        }

                    }

                }

                CloseHandle(hProcess);

            }
        }

        HeapFree(GetProcessHeap(), 0, lpdwPIDs);

    } else {
        return FALSE;
    }

    // Free the library.
    FreeLibrary(hInstLib);

    return (retcode);
}


int APIENTRY IsModuleLoaded2(char *lpModule)
{
    return EnumProcs2(lpModule);
}


BOOL WINAPI EnumProcs2(char* procname)
{
    //MessageBox(nullptr, procname, "msg", MB_OK);
    HANDLE handleToSnapshot;
    PROCESSENTRY32 procEntry;
    procEntry.dwSize = sizeof(PROCESSENTRY32);
    handleToSnapshot = CreateToolhelp32Snapshot(2, 0);

    if (Process32First(handleToSnapshot, &procEntry)) {
        do {
            //MessageBox(nullptr, procEntry.szExeFile, "msg", MB_OK);
            if (strcmp(procname, procEntry.szExeFile) == 0) {
                //delete handleToSnapshot;
                return TRUE;
            }
        } while (Process32Next(handleToSnapshot, &procEntry));
    }
    return FALSE;
}
