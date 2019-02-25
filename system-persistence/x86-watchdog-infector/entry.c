#include <Windows.h>
#include <winternl.h>

#include "x86-watchdog-infector.h"

int __stdcall entry(PVOID shell_base,
                    SIZE_T shell_size,
                    ULONGLONG proc_id,
                    WCHAR path[MAX_PATH + 1])
{}
