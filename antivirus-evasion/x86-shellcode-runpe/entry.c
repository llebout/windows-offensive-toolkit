#include <Windows.h>
#include <winternl.h>

#include "x86-shellcode-runpe.h"

int __stdcall entry(PBYTE pe_image, DWORD* proc_id)
{
  struct dll_imports imports;

  if (resolve_dll_imports(&imports) < 0) {
    return -1;
  }

  if (runpe(&imports, pe_image, proc_id) < 0) {
    return -2;
  }

  return 0;
}
