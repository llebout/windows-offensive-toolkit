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

  unsigned char data_kernel32_dll[26] = { 0x6B, 0x00, 0x65, 0x00, 0x72, 0x00,
                                          0x6E, 0x00, 0x65, 0x00, 0x6C, 0x00,
                                          0x33, 0x00, 0x32, 0x00, 0x2E, 0x00,
                                          0x64, 0x00, 0x6C, 0x00, 0x6C, 0x00,
                                          0x00, 0x00 };

  unsigned char data_GetModuleFileNameW[19] = { 0x47, 0x65, 0x74, 0x4D, 0x6F,
                                                0x64, 0x75, 0x6C, 0x65, 0x46,
                                                0x69, 0x6C, 0x65, 0x4E, 0x61,
                                                0x6D, 0x65, 0x57, 0x00 };

  imports->GetModuleFileNameW = (PVOID)get_export_address(
    get_module_base(/* L"kernel32.dll" */ (PWSTR)data_kernel32_dll),
    /* "GetModuleFileNameW" */ (PSTR)data_GetModuleFileNameW);
  if (imports->GetModuleFileNameW == NULL) {
    return -1;
  }

  unsigned char data_CreateProcessW[15] = { 0x43, 0x72, 0x65, 0x61, 0x74,
                                            0x65, 0x50, 0x72, 0x6F, 0x63,
                                            0x65, 0x73, 0x73, 0x57, 0x00 };

  imports->CreateProcessW = (PVOID)get_export_address(
    get_module_base(/* L"kernel32.dll" */ (PWSTR)data_kernel32_dll),
    /* "CreateProcessW" */ (PSTR)data_CreateProcessW);
  if (imports->CreateProcessW == NULL) {
    return -2;
  }

  unsigned char data_GetCommandLineW[16] = { 0x47, 0x65, 0x74, 0x43, 0x6F, 0x6D,
                                             0x6D, 0x61, 0x6E, 0x64, 0x4C, 0x69,
                                             0x6E, 0x65, 0x57, 0x00 };

  imports->GetCommandLineW = (PVOID)get_export_address(
    get_module_base(/* L"kernel32.dll" */ (PWSTR)data_kernel32_dll),
    /* "GetCommandLineW" */ (PSTR)data_GetCommandLineW);
  if (imports->GetCommandLineW == NULL) {
    return -3;
  }

  unsigned char data_GetThreadContext[17] = { 0x47, 0x65, 0x74, 0x54, 0x68,
                                              0x72, 0x65, 0x61, 0x64, 0x43,
                                              0x6F, 0x6E, 0x74, 0x65, 0x78,
                                              0x74, 0x00 };

  imports->GetThreadContext = (PVOID)get_export_address(
    get_module_base(/* L"kernel32.dll" */ (PWSTR)data_kernel32_dll),
    /* "GetThreadContext" */ (PSTR)data_GetThreadContext);
  if (imports->GetThreadContext == NULL) {
    return -4;
  }

  unsigned char data_ReadProcessMemory[18] = { 0x52, 0x65, 0x61, 0x64, 0x50,
                                               0x72, 0x6F, 0x63, 0x65, 0x73,
                                               0x73, 0x4D, 0x65, 0x6D, 0x6F,
                                               0x72, 0x79, 0x00 };

  imports->ReadProcessMemory = (PVOID)get_export_address(
    get_module_base(/* L"kernel32.dll" */ (PWSTR)data_kernel32_dll),
    /* "ReadProcessMemory" */ (PSTR)data_ReadProcessMemory);
  if (imports->ReadProcessMemory == NULL) {
    return -5;
  }

  unsigned char data_VirtualAllocEx[15] = { 0x56, 0x69, 0x72, 0x74, 0x75,
                                            0x61, 0x6C, 0x41, 0x6C, 0x6C,
                                            0x6F, 0x63, 0x45, 0x78, 0x00 };

  imports->VirtualAllocEx = (PVOID)get_export_address(
    get_module_base(/* L"kernel32.dll" */ (PWSTR)data_kernel32_dll),
    /* "VirtualAllocEx" */ (PSTR)data_VirtualAllocEx);
  if (imports->VirtualAllocEx == NULL) {
    return -6;
  }

  unsigned char data_WriteProcessMemory[19] = { 0x57, 0x72, 0x69, 0x74, 0x65,
                                                0x50, 0x72, 0x6F, 0x63, 0x65,
                                                0x73, 0x73, 0x4D, 0x65, 0x6D,
                                                0x6F, 0x72, 0x79, 0x00 };

  imports->WriteProcessMemory = (PVOID)get_export_address(
    get_module_base(/* L"kernel32.dll" */ (PWSTR)data_kernel32_dll),
    /* "WriteProcessMemory" */ (PSTR)data_WriteProcessMemory);
  if (imports->WriteProcessMemory == NULL) {
    return -7;
  }

  unsigned char data_SetThreadContext[17] = { 0x53, 0x65, 0x74, 0x54, 0x68,
                                              0x72, 0x65, 0x61, 0x64, 0x43,
                                              0x6F, 0x6E, 0x74, 0x65, 0x78,
                                              0x74, 0x00 };

  imports->SetThreadContext = (PVOID)get_export_address(
    get_module_base(/* L"kernel32.dll" */ (PWSTR)data_kernel32_dll),
    /* "SetThreadContext" */ (PSTR)data_SetThreadContext);
  if (imports->SetThreadContext == NULL) {
    return -8;
  }

  unsigned char data_ResumeThread[13] = { 0x52, 0x65, 0x73, 0x75, 0x6D,
                                          0x65, 0x54, 0x68, 0x72, 0x65,
                                          0x61, 0x64, 0x00 };

  imports->ResumeThread = (PVOID)get_export_address(
    get_module_base(/* L"kernel32.dll" */ (PWSTR)data_kernel32_dll),
    /* "ResumeThread" */ (PSTR)data_ResumeThread);
  if (imports->ResumeThread == NULL) {
    return -9;
  }

  unsigned char data_TerminateProcess[17] = { 0x54, 0x65, 0x72, 0x6D, 0x69,
                                              0x6E, 0x61, 0x74, 0x65, 0x50,
                                              0x72, 0x6F, 0x63, 0x65, 0x73,
                                              0x73, 0x00 };

  imports->TerminateProcess = (PVOID)get_export_address(
    get_module_base(/* L"kernel32.dll" */ (PWSTR)data_kernel32_dll),
    /* "TerminateProcess" */ (PSTR)data_TerminateProcess);
  if (imports->TerminateProcess == NULL) {
    return -10;
  }

  unsigned char data_CloseHandle[12] = { 0x43, 0x6C, 0x6F, 0x73, 0x65, 0x48,
                                         0x61, 0x6E, 0x64, 0x6C, 0x65, 0x00 };

  imports->CloseHandle = (PVOID)get_export_address(
    get_module_base(/* L"kernel32.dll" */ (PWSTR)data_kernel32_dll),
    /* "CloseHandle" */ (PSTR)data_CloseHandle);
  if (imports->CloseHandle == NULL) {
    return -11;
  }

  unsigned char data_ntdll_dll[20] = { 0x6E, 0x00, 0x74, 0x00, 0x64, 0x00, 0x6C,
                                       0x00, 0x6C, 0x00, 0x2E, 0x00, 0x64, 0x00,
                                       0x6C, 0x00, 0x6C, 0x00, 0x00, 0x00 };

  unsigned char data_ZwUnmapViewOfSection[21] = {
    0x5A, 0x77, 0x55, 0x6E, 0x6D, 0x61, 0x70, 0x56, 0x69, 0x65, 0x77,
    0x4F, 0x66, 0x53, 0x65, 0x63, 0x74, 0x69, 0x6F, 0x6E, 0x00
  };

  imports->ZwUnmapViewOfSection = (PVOID)get_export_address(
    get_module_base(/* L"ntdll.dll" */ (PWSTR)data_ntdll_dll),
    /* "ZwUnmapViewOfSection" */ (PSTR)data_ZwUnmapViewOfSection);
  if (imports->ZwUnmapViewOfSection == NULL) {
    return -12;
  }

  return 0;
}
