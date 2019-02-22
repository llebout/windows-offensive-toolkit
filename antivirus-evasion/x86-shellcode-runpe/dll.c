#include <Windows.h>
#include <winternl.h>

#include "x86-shellcode-runpe.h"

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
get_export_address(PBYTE module, LPSTR name)
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
get_module_base(LPWSTR name)
{
  PPEB peb;
  DLL_PLDR_DATA_TABLE_ENTRY first_ldr_entry;
  DLL_PLDR_DATA_TABLE_ENTRY ldr_entry;

  /*
    The double word in slot 0x30 is the current process PEB structure
    address.
  */
  peb = (PPEB)__readfsdword(0x30);

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
