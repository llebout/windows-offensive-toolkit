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
  printf("Usage: %ws shellcode pe_file\n", app_name);
}

int
wmain(int argc, wchar_t* argv[], wchar_t* envp[])
{
  if (argc < 3) {
    print_usage(argv[0]);
    return -1;
  }

  printf("dummy: %p\n", dummy);

  PVOID p_shellcode;
  DWORD size;
  if (read_file_to_mem(argv[1], &p_shellcode, &size, PAGE_EXECUTE_READWRITE) < 0) {
    printf("Could not read file to memory: %ws\n", argv[1]);
    return -2;
  }

  PVOID p_pe;
  if (read_file_to_mem(argv[2], &p_pe, &size, PAGE_READWRITE) < 0) {
    printf("Could not read file to memory: %ws\n", argv[2]);
    return -3;
  }

  shellcode_entry* entry = (shellcode_entry*)p_shellcode;

  int s = entry(p_pe);
  if (s < 0) {
    printf("Shellcode's entrypoint returned a negative value: %d\n", s);
    return -4;
  }

  VirtualFree(p_shellcode, 0, MEM_RELEASE);
  VirtualFree(p_pe, 0, MEM_RELEASE);

  return 0;
}
