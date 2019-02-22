#pragma once
#include <Windows.h>
#include <winternl.h>

/* libc.c */
int
libc_strcmp(const char* s1, const char* s2);
int
libc_wstrcmp(const wchar_t* s1, const wchar_t* s2);
int
libc_wstricmp(const wchar_t* s1, const wchar_t* s2);
wchar_t
libc_wtolower(const wchar_t c);
void
libc_memcpy(void* dst, const void* src, size_t n);
void
libc_memset(void* dst, const unsigned char c, size_t n);

/* dll.c */
typedef struct DLL_LDR_DATA_TABLE_ENTRY
{
  LIST_ENTRY InLoadOrderLinks;
  LIST_ENTRY InMemoryOrderLinks;
  LIST_ENTRY InInitializationOrderLinks;
  PVOID DllBase;
  PVOID EntryPoint;
  ULONG SizeOfImage;
  UNICODE_STRING FullDllName;
  UNICODE_STRING BaseDllName;
  ULONG Flags;
  WORD LoadCount;
  WORD TlsIndex;
  union
  {
    LIST_ENTRY HashLinks;
    struct
    {
      PVOID SectionPointer;
      ULONG CheckSum;
    };
  };
  union
  {
    ULONG TimeDateStamp;
    PVOID LoadedImports;
  };
  void* EntryPointActivationContext;
  PVOID PatchInformation;
  LIST_ENTRY ForwarderLinks;
  LIST_ENTRY ServiceTagLinks;
  LIST_ENTRY StaticLinks;
} DLL_LDR_DATA_TABLE_ENTRY, *DLL_PLDR_DATA_TABLE_ENTRY;

PVOID
get_module_base(PWSTR name);
PVOID
get_export_address(PBYTE module, PSTR name);

typedef DWORD WINAPI
proto_GetModuleFileNameW(HMODULE hModule, LPWSTR lpFilename, DWORD nSize);
typedef BOOL WINAPI
proto_CreateProcessW(LPCWSTR lpApplicationName,
                     LPWSTR lpCommandLine,
                     LPSECURITY_ATTRIBUTES lpProcessAttributes,
                     LPSECURITY_ATTRIBUTES lpThreadAttributes,
                     BOOL bInheritHandles,
                     DWORD dwCreationFlags,
                     LPVOID lpEnvironment,
                     LPCWSTR lpCurrentDirectory,
                     LPSTARTUPINFOW lpStartupInfo,
                     LPPROCESS_INFORMATION lpProcessInformation);
typedef LPWSTR WINAPI
proto_GetCommandLineW(void);
typedef BOOL WINAPI
proto_GetThreadContext(HANDLE hThread, LPCONTEXT lpContext);
typedef BOOL WINAPI
proto_ReadProcessMemory(HANDLE hProcess,
                        LPCVOID lpBaseAddress,
                        LPVOID lpBuffer,
                        SIZE_T nSize,
                        SIZE_T* lpNumberOfBytesRead);
typedef LPVOID WINAPI
proto_VirtualAllocEx(HANDLE hProcess,
                     LPVOID lpAddress,
                     SIZE_T dwSize,
                     DWORD flAllocationType,
                     DWORD flProtect);
typedef BOOL WINAPI
proto_WriteProcessMemory(HANDLE hProcess,
                         LPVOID lpBaseAddress,
                         LPCVOID lpBuffer,
                         SIZE_T nSize,
                         SIZE_T* lpNumberOfBytesWritten);
typedef BOOL WINAPI
proto_SetThreadContext(HANDLE hThread, CONST CONTEXT* lpContext);
typedef DWORD WINAPI
proto_ResumeThread(HANDLE hThread);
typedef BOOL WINAPI
proto_TerminateProcess(HANDLE hProcess, UINT uExitCode);
typedef BOOL WINAPI
proto_CloseHandle(HANDLE hObject);
typedef NTSTATUS NTAPI
proto_ZwUnmapViewOfSection(HANDLE ProcessHandle, PVOID BaseAddress);

struct dll_imports
{
  proto_GetModuleFileNameW* GetModuleFileNameW;
  proto_CreateProcessW* CreateProcessW;
  proto_GetCommandLineW* GetCommandLineW;
  proto_GetThreadContext* GetThreadContext;
  proto_ReadProcessMemory* ReadProcessMemory;
  proto_VirtualAllocEx* VirtualAllocEx;
  proto_WriteProcessMemory* WriteProcessMemory;
  proto_SetThreadContext* SetThreadContext;
  proto_ResumeThread* ResumeThread;
  proto_TerminateProcess* TerminateProcess;
  proto_CloseHandle* CloseHandle;
  proto_ZwUnmapViewOfSection* ZwUnmapViewOfSection;
};

int
resolve_dll_imports(struct dll_imports* imports);

/* runpe.c */
int
runpe(struct dll_imports* imports, PBYTE* pe_image);
