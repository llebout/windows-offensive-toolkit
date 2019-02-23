#include <Windows.h>

#include "x86-stub-example.h"

/*
  If the return value is not negative then you must use VirtualFree on *out
*/
int
read_file_to_mem(const wchar_t* filename, PVOID* out, DWORD* size, DWORD prot)
{
  int ret = 0;

  HANDLE file = CreateFileW(
    filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
  if (file == INVALID_HANDLE_VALUE) {
    return -1;
  }

  *size = GetFileSize(file, NULL);
  if (*size == INVALID_FILE_SIZE) {
    ret = -2;
    goto close_file;
  }

  *out = VirtualAlloc(NULL, *size, MEM_COMMIT | MEM_RESERVE, prot);
  if (*out == NULL) {
    ret = -3;
    goto close_file;
  }

  DWORD n_read;
  if (!ReadFile(file, *out, *size, &n_read, NULL)) {
    ret = -4;
    goto free_mem;
  }

free_mem:
  if (ret < 0) {
    VirtualFree(*out, 0, MEM_RELEASE);
  }
close_file:
  CloseHandle(file);

  return ret;
}
