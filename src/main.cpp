#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <stdexcept>
#include <string>

#ifndef MAX_PATH
#define MAX_PATH 260
#endif

DWORD get_pID(char const *ProcessName)
{
    HANDLE hPID = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 ProcEntry;
    ProcEntry.dwSize = sizeof(ProcEntry);
    do
    {
        if (!strcmp(ProcEntry.szExeFile, ProcessName))
        {
            DWORD dwPID = ProcEntry.th32ProcessID;
            CloseHandle(hPID);
            return dwPID;
        }
    } while (Process32Next(hPID, &ProcEntry));
}

std::string get_current_path()
{
    static TCHAR szPath[MAX_PATH];
    static std::string path = "";
    if (path.length() > 1)
        return path;
    DWORD len = GetModuleFileName(NULL, szPath, MAX_PATH);
#ifndef UNICODE
    path = szPath;
#else
    std::wstring wpath = szPath;
    path = std::string(wpath.begin(), wpath.end());
#endif
    if (len != path.length())
        throw std::runtime_error("Inequal path length");
    return path;
}

std::string get_last_node(std::string const &p, std::string &output)
{
    unsigned i = p.find_last_of("\\") + 1;          // + 1 because i is the pos of '\' so \aaa.exe
    output = std::string(p.begin(), p.begin() + i); // hopefully there's no trouble here
    return std::string(p.begin() + i, p.end() - 4); // - 4 because .exe
}

enum
{
    PID_NOT_FOUND = 1,
    OPENPROCESS_ERROR,
    LOADLIB_ERROR,
    ALLOC_ERROR,
    WPM_ERROR,
    THREAD_ERROR
};

unsigned long inject_dll(char *pDll, unsigned long pIDID)
{
    void *pProc, *pRemoteThread, *pRemoteBuffer, *pLoadLib;
    if (!pIDID)
        return PID_NOT_FOUND;
    pProc = OpenProcess((PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ), FALSE, pIDID);
    if (!pProc)
        return OPENPROCESS_ERROR;
    pLoadLib = (void *)GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
    if (!pLoadLib)
        return LOADLIB_ERROR;
    pRemoteBuffer = VirtualAllocEx(pProc, NULL, strlen(pDll), (MEM_RESERVE | MEM_COMMIT), PAGE_READWRITE);
    if (!pRemoteBuffer)
        return ALLOC_ERROR;
    if (!WriteProcessMemory(pProc, pRemoteBuffer, pDll, strlen(pDll), NULL))
        return WPM_ERROR;
    pRemoteThread = CreateRemoteThread(pProc, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLib, pRemoteBuffer, 0, NULL);
    if (!pRemoteThread)
        return THREAD_ERROR;
    CloseHandle(pProc);
    return 0;
}

int main()
{
    auto path = get_current_path();
    if (path.find(".exe") == std::string::npos)
        throw std::runtime_error("Only launch as executable(.exe) supported");
    std::string folder;
    auto executable_name = get_last_node(path, folder);
    unsigned long pID;
    char cDLL[MAX_PATH];
    auto dll_path = folder + executable_name + ".dll";
    strncpy(cDLL, dll_path.c_str(), sizeof(cDLL));
    cDLL[sizeof(cDLL) - 1] = 0;
    pID = get_pID("csgo.exe");
    unsigned long failure = inject_dll(cDLL, pID);
    if (failure)
        std::cout << "error code: " << failure << '\n';
    return failure;
}