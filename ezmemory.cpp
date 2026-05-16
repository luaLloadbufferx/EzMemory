/*
MIT License

Copyright (c) 2026 luaLloadbufferx

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

// https://github.com/luaLloadbufferx/EzMemory

/*
* NOTE: ALL STRUCTURES AND TYPEDEFS ARE FROM https://ntdoc.m417z.com/
*/

#include <string>
#include "include/ezmemory.hpp"
#include <TlHelp32.h>
#include <iostream>

#ifndef InitializeObjectAttributes
#define InitializeObjectAttributes( p, n, a, r, s ) { \
    (p)->Length = sizeof( OBJECT_ATTRIBUTES );          \
    (p)->RootDirectory = r;                             \
    (p)->Attributes = a;                                \
    (p)->ObjectName = n;                                \
    (p)->SecurityDescriptor = s;                        \
    (p)->SecurityQualityOfService = NULL;               \
}
#endif

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWCH Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef const UNICODE_STRING* PCUNICODE_STRING;

typedef LONG KPRIORITY, * PKPRIORITY;

typedef enum _PROCESSINFOCLASS {
    ProcessBasicInformation
    // other fields not needed
} PROCESSINFOCLASS;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    HANDLE SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID EntryInProgress;
    BOOLEAN ShutdownInProgress;
    HANDLE ShutdownThreadId;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    PPEB_LDR_DATA Ldr;
} PEB, * PPEB;

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PCUNICODE_STRING ObjectName;
    ULONG Attributes;
    PSECURITY_DESCRIPTOR SecurityDescriptor;
    PSECURITY_QUALITY_OF_SERVICE SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef struct _PROCESS_BASIC_INFORMATION {
    NTSTATUS ExitStatus;
    PPEB PebBaseAddress;
    KAFFINITY AffinityMask;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION, * PPROCESS_BASIC_INFORMATION;

typedef const OBJECT_ATTRIBUTES* PCOBJECT_ATTRIBUTES;

typedef struct _PS_ATTRIBUTE
{
    ULONG_PTR Attribute;
    SIZE_T Size;
    union
    {
        ULONG_PTR Value;
        PVOID ValuePtr;
    };
    PSIZE_T ReturnLength;
} PS_ATTRIBUTE, * PPS_ATTRIBUTE;

typedef struct _PS_ATTRIBUTE_LIST
{
    SIZE_T TotalLength;
    PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;

typedef NTSTATUS(NTAPI* NtOpenProcess_t)(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    PCOBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID ClientId
);

typedef NTSTATUS(NTAPI* NtReadVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToRead,
    PSIZE_T NumberOfBytesRead
);

typedef NTSTATUS(NTAPI* NtWriteVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten
);

typedef NTSTATUS(NTAPI* NtAllocateVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG PageProtection
);

typedef NTSTATUS(NTAPI* NtFreeVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG FreeType
);

typedef NTSTATUS(NTAPI* NtQueryInformationProcess_t)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

typedef NTSTATUS(NTAPI* NtProtectVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtection,
    PULONG OldProtection
);

typedef NTSTATUS(NTAPI* NtCreateThreadEx_t)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    PCOBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine, // NTAPI functions just expect a pointer so this is acceptable
    PVOID Argument,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PPS_ATTRIBUTE_LIST AttributeList
);

/*
*   HELPER FUNCTIONS
*/

HMODULE GetModuleBase(const wchar_t* moduleName) {
    if (!moduleName) {
        return NULL;
    }
#ifdef _WIN64
    PEB* peb = (PEB*)__readgsqword(0x60);
#else
    PEB* peb = (PEB*)__readfsdword(0x30);
#endif

    if (!peb || !peb->Ldr) {
        return 0;
    }

    LIST_ENTRY* modlist = &peb->Ldr->InMemoryOrderModuleList;
    LIST_ENTRY* currententry = modlist->Flink;

    // loop through the module list
    while (currententry != modlist) {
        LDR_DATA_TABLE_ENTRY* moddata = CONTAINING_RECORD(currententry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

        // check if this is the module we're looking for
        if (moddata->BaseDllName.Buffer && _wcsicmp(moddata->BaseDllName.Buffer, moduleName) == 0) {
            return (HMODULE)moddata->DllBase;
        }
        // if not, increment the current entry
        currententry = currententry->Flink;
    }
    return NULL;
}

DWORD GetPID(const wchar_t* ProcName) {
    DWORD pid = 0;
    // create a snapshot
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W Entry;
        Entry.dwSize = sizeof(Entry);
        if (Process32First(hSnap, &Entry)) {
            // loop through
            do {
                if (wcscmp(Entry.szExeFile, ProcName) == 0) {
                    pid = Entry.th32ProcessID;
                    break;
                }
            } while (Process32NextW(hSnap, &Entry));
        }
        CloseHandle(hSnap);
    }
    return pid;
}

// function defines
NtOpenProcess_t NtOpenProcess;
NtReadVirtualMemory_t NtReadVirtualMemory;
NtWriteVirtualMemory_t NtWriteVirtualMemory;
NtAllocateVirtualMemory_t NtAllocateVirtualMemory;
NtFreeVirtualMemory_t NtFreeVirtualMemory;
NtQueryInformationProcess_t NtQueryInformationProcess;
NtProtectVirtualMemory_t NtProtectVirtualMemory;
NtCreateThreadEx_t NtCreateThreadEx;

HMODULE hNtDll = 0;

void EzMem::Initialize() {
    hNtDll = GetModuleBase(L"ntdll.dll");
    if (!hNtDll) {
        throw std::runtime_error("EzMem::Initialize(): Failed to get ntdll.dll base address");
    }

    NtOpenProcess = (NtOpenProcess_t)GetProcAddress(hNtDll, "NtOpenProcess");
    NtReadVirtualMemory = (NtReadVirtualMemory_t)GetProcAddress(hNtDll, "NtReadVirtualMemory");
    NtWriteVirtualMemory = (NtWriteVirtualMemory_t)GetProcAddress(hNtDll, "NtWriteVirtualMemory");
    NtAllocateVirtualMemory = (NtAllocateVirtualMemory_t)GetProcAddress(hNtDll, "NtAllocateVirtualMemory");
    NtFreeVirtualMemory = (NtFreeVirtualMemory_t)GetProcAddress(hNtDll, "NtFreeVirtualMemory");
    NtQueryInformationProcess = (NtQueryInformationProcess_t)GetProcAddress(hNtDll, "NtQueryInformationProcess");
    NtProtectVirtualMemory = (NtProtectVirtualMemory_t)GetProcAddress(hNtDll, "NtProtectVirtualMemory");
    NtCreateThreadEx = (NtCreateThreadEx_t)GetProcAddress(hNtDll, "NtCreateThreadEx");

    return;
}

/*
*   CORE FUNCTIONALITY
*/

void EzMem::Detach(EzMemProcess& Process, bool FreeMemory) {
    if (FreeMemory) {
        for (uintptr_t address : Process.allocations) {
            PVOID addr = (PVOID)address;
            Process.LastStatus = NtFreeVirtualMemory(Process.hProc, &addr, 0, MEM_RELEASE);
        }
        Process.allocations.clear();
    }
    if (Process.hProc) {
        CloseHandle(Process.hProc);
        Process.hProc = nullptr;
        Process.pid = 0;
    }
}

EzMemProcess EzMem::Attach(const wchar_t* ProcName, DWORD access) {
    EzMemProcess Process{};

    if (!NtOpenProcess || !NtReadVirtualMemory || !NtWriteVirtualMemory ||
        !NtAllocateVirtualMemory || !NtFreeVirtualMemory ||
        !NtQueryInformationProcess || !NtProtectVirtualMemory) {
        return Process;
    }

    CLIENT_ID cid{};
    OBJECT_ATTRIBUTES attr;
    InitializeObjectAttributes(&attr, NULL, 0, NULL, NULL);

    DWORD pid = GetPID(ProcName);
    if (!pid) {
        return Process;
    }
    Process.pid = pid;

    cid.UniqueProcess = (HANDLE)pid;
    cid.UniqueThread = NULL;

    // make a syscall to NtOpenProcess instead of OpenProcess
    Process.LastStatus = NtOpenProcess(&Process.hProc, access, &attr, &cid);
    if (Process.LastStatus != 0x0 || !Process.hProc) {
        Process.hProc = nullptr;
        Process.pid = 0;
        return Process;
    }

    // get the base
    Process.base = EzMem::GetModule(Process, ProcName);

    if (!Process.base) {
        CloseHandle(Process.hProc);
        Process.hProc = nullptr;
        Process.pid = 0;
    }

    return Process;
}

uintptr_t EzMem::GetModule(EzMemProcess& Process, const wchar_t* ModuleName) {
    PROCESS_BASIC_INFORMATION pbi{};
    ULONG length = 0;

    // query the process's information
    Process.LastStatus = NtQueryInformationProcess(Process.hProc, ProcessBasicInformation, &pbi, sizeof(pbi), &length);
    if (Process.LastStatus != 0x0) {
        return 0;
    }
    PEB peb{};
    PEB_LDR_DATA ldr{};

    // read the PEB
    if (!EzMem::ReadEx(Process, (uintptr_t)pbi.PebBaseAddress, &peb, sizeof(peb))) {
        return 0;
    }
    if (!EzMem::ReadEx(Process, (uintptr_t)peb.Ldr, &ldr, sizeof(ldr))) {
        return 0;
    }

    LIST_ENTRY* pListEntry = ldr.InMemoryOrderModuleList.Flink;
    if (!pListEntry) {
        return 0;
    }
    do {
        LDR_DATA_TABLE_ENTRY entry{};
        uintptr_t entryAddr = (uintptr_t)pListEntry - offsetof(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

        // try to read the address
        if (!EzMem::ReadEx(Process, entryAddr, &entry, sizeof(entry))) {
            break;
        }

        wchar_t name[260]{};
        if (entry.BaseDllName.Buffer && entry.BaseDllName.Length > 0) {
            SIZE_T maxBytes = sizeof(name) - sizeof(wchar_t);

            SIZE_T safeLen = entry.BaseDllName.Length;
            if (safeLen > maxBytes) {
                safeLen = maxBytes;
            }

            if (safeLen % 2 != 0) {
                safeLen--;
            }

            if (!EzMem::ReadEx(Process, (uintptr_t)entry.BaseDllName.Buffer, name, safeLen)) {
                return 0;
            }

            name[safeLen / sizeof(wchar_t)] = L'\0';
            if (_wcsicmp(name, ModuleName) == 0) {
                return (uintptr_t)entry.DllBase;
            }
        }
        pListEntry = entry.InMemoryOrderLinks.Flink;
    } while ((uintptr_t)pListEntry != (uintptr_t)ldr.InMemoryOrderModuleList.Flink);

    return 0;
}

DWORD EzMem::Protect(EzMemProcess& Process, uintptr_t address, SIZE_T size, DWORD protection) {
    DWORD oldprotection = 0;
    PVOID addr = (PVOID)address;

    // push a custom protection
    Process.LastStatus = NtProtectVirtualMemory(Process.hProc, &addr, &size, protection, &oldprotection);

    return oldprotection;
}

bool EzMem::ReadEx(EzMemProcess& Process, uintptr_t address, void* buffer, SIZE_T size) {
    Process.LastStatus = NtReadVirtualMemory(Process.hProc, (PVOID)address, buffer, size, &Process.read);
    return (Process.LastStatus == 0x0 && Process.read == size);
}

bool EzMem::WriteEx(EzMemProcess& Process, uintptr_t address, const void* buffer, SIZE_T size) {
    Process.LastStatus = NtWriteVirtualMemory(Process.hProc, (PVOID)address, (void*)buffer, size, &Process.written);
    return (Process.LastStatus == 0x0 && Process.written == size);
}

uintptr_t EzMem::Allocate(EzMemProcess& Process, SIZE_T Size, DWORD Protection) {
    PVOID base = nullptr;
    // allocate a specified amount of memory
    Process.LastStatus = NtAllocateVirtualMemory(Process.hProc, &base, 0, &Size, MEM_COMMIT | MEM_RESERVE, Protection);
    if (Process.LastStatus != 0x0) {
        return 0;
    }
    uintptr_t addr = (uintptr_t)base;

    // push back the allocated address, so we can automatically clean all allocations up
    Process.allocations.push_back(addr);
    return addr;
}

bool EzMem::Free(EzMemProcess& Process, uintptr_t address) {
    // free allocated memory
    Process.LastStatus = NtFreeVirtualMemory(Process.hProc, (PVOID*)&address, 0, MEM_RELEASE);
    if (Process.LastStatus == 0) {
        auto it = std::find(Process.allocations.begin(), Process.allocations.end(), address);
        if (it != Process.allocations.end()) {
            Process.allocations.erase(it);
        }
        return true;
    }
    return false;
}

bool EzMem::LoadLibraryInject(EzMemProcess& Process, const wchar_t* DllPath) {
    PVOID LoadLib = GetProcAddress((HMODULE)EzMem::GetModule(Process, L"kernel32.dll"), "LoadLibraryW");
    if (!LoadLib) {
        return false;
    }
    
    SIZE_T size = (wcslen(DllPath) + 1) * sizeof(wchar_t);
    auto Address = EzMem::Allocate(Process, size);

    EzMem::WriteEx(Process, Address, DllPath, size);

    HANDLE hThread = 0;

    Process.LastStatus = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, Process.hProc, LoadLib, (PVOID)Address, 0, 0, 0, 0, NULL);
    if (Process.LastStatus != 0x0 || !hThread) {
        std::cout << "Failed to create thread!\n";
        EzMem::Free(Process, Address);
        return false;
    }

    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);

    EzMem::Free(Process, Address);

    return true;
}
