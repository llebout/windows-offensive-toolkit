#include <Windows.h>
#include <stdio.h>

#include "x86-stub-example.h"

/*
  Uninitialized array to enlarge SizeOfImage and reduce
  probability of address conflicts.
*/
static BYTE dummy[0x100000];

void
print_usage(const wchar_t* app_name)
{
  printf("Usage: %ws shellcode pe_file [ watchdog_shellcode ]\n", app_name);
}

int
wmain(int argc, wchar_t* argv[], wchar_t* envp[])
{
  int ret = 0;

  MessageBoxA(NULL,
              "Attach a debugger or click OK to continue.",
              "Information",
              MB_OK | MB_ICONINFORMATION);

  if (argc < 3) {
    print_usage(argv[0]);
    return -1;
  }

  printf("dummy: %p\n", dummy);

  PVOID p_shellcode;
  DWORD size;
  if (read_file_to_mem(argv[1], &p_shellcode, &size, PAGE_EXECUTE_READWRITE) <
      0) {
    printf("Could not read file to memory: %ws\n", argv[1]);
    return -2;
  }

  PVOID p_pe;
  if (read_file_to_mem(argv[2], &p_pe, &size, PAGE_READWRITE) < 0) {
    printf("Could not read file to memory: %ws\n", argv[2]);
    ret = -3;
    goto free_shellcode;
  }

  PVOID p_watchdog = NULL;
  DWORD watchdog_size;
  if (argc > 3) {
    if (read_file_to_mem(
          argv[3], &p_watchdog, &watchdog_size, PAGE_EXECUTE_READWRITE) < 0) {
      printf("Could not read file to memory: %ws\n", argv[3]);
      ret = -4;
      goto free_pe;
    }
  }

  if (IsDebuggerPresent()) {
    DebugBreak();
  }

  shellcode_entry* entry = (shellcode_entry*)p_shellcode;

  DWORD proc_id;
  int s = entry(p_pe, &proc_id);
  if (s < 0) {
    printf("Shellcode's entrypoint returned a negative value: %d\n", s);
    ret = -5;
    goto free_watchdog;
  }

  printf("Success. proc_id: %ld\n", proc_id);

  if (p_watchdog) {
    watchdog_entry* entry_watchdog = (watchdog_entry*)p_watchdog;
    struct shell_param param = {
      ._meta.kind = Shell,
      .shell_base = p_watchdog,
      .shell_size = watchdog_size,
      .proc_id = proc_id,
    };

    lstrcpyW(param.command_line, GetCommandLineW());

    if (!GetModuleFileNameW(NULL, param.path, MAX_PATH)) {
      ret = -6;
      goto free_watchdog;
    }

    entry_watchdog((struct meta_param*)&param);
  }

free_watchdog:
  VirtualFree(p_watchdog, 0, MEM_RELEASE);
free_pe:
  VirtualFree(p_pe, 0, MEM_RELEASE);
free_shellcode:
  VirtualFree(p_shellcode, 0, MEM_RELEASE);
  return ret;
}
