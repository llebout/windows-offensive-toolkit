#include <Windows.h>
#include <winternl.h>

#include "x86-shellcode-runpe.h"

int
entry(PBYTE* pe_image)
{
  /* HACK: Force compiler to store the string on the stack */
  WCHAR kernel32_dll[] = { L'k', L'e', L'r', L'n', L'e', L'l', L'3',
                           L'2', L'.', L'd', L'l', L'l', 0 };

  PVOID kernel32_base = get_module_base(kernel32_dll);

  return 0;
}
