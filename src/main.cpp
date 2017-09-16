#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <stdexcept>
#include <string>

#ifndef MAX_PATH
#define MAX_PATH 260
#endif

DWORD Process(char const *ProcessName)
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

int main()
{
    auto path = get_current_path();
    std::cout << path << "\n";
    if (path.find(".exe") == std::string::npos)
        throw std::runtime_error("Only launch as executable(.exe) supported");

    std::string folder;
    auto executable_name = get_last_node(path, folder);
    DWORD dwProcess;
    char myDLL[MAX_PATH];
    /* strncpy(myDLL, dll_path.c_str(), sizeof(myDLL));
    myDLL[sizeof(myDLL) - 1] = 0; */
    GetFullPathName(DLL_NAME, MAX_PATH, myDLL, 0);
    dwProcess = Process("csgo.exe");
    HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, dwProcess);
    LPVOID allocatedMem = VirtualAllocEx(hProcess, NULL, sizeof(myDLL), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    WriteProcessMemory(hProcess, allocatedMem, myDLL, sizeof(myDLL), NULL);
    CreateRemoteThread(hProcess, 0, 0, (LPTHREAD_START_ROUTINE)LoadLibrary, allocatedMem, 0, 0);
    CloseHandle(hProcess);
    return 0;
}