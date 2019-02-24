#pragma once
#include <Windows.h>

/* watchdog.c */
struct watchdog_info
{
  LONG lock;
  ULONGLONG proc_id;
  WCHAR path[MAX_PATH + 1];
};

/* process.c */
#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004