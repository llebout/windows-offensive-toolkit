#include <Windows.h>
#include <stdio.h>

#include "pe-shellcode-extractor.h"

void
print_usage(const wchar_t* app_name)
{
  printf("Usage: %ws pe_file output\n", app_name);
}

int
wmain(int argc, wchar_t* argv[], wchar_t* envp[])
{
  int ret = 0;

  if (argc < 3) {
    print_usage(argv[0]);
    return -1;
  }

  HANDLE file = CreateFileW(
    argv[1], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);

  if (file == INVALID_HANDLE_VALUE) {
    printf("Could not open file: %ws\n", argv[1]);
    return -2;
  }

  HANDLE file_map = CreateFileMappingA(file, NULL, PAGE_READONLY, 0, 0, NULL);
  if (file_map == NULL) {
    printf("Could not create file mapping: %ws\n", argv[1]);
    ret = -3;
    goto close_file;
  }

  PBYTE pe_image = MapViewOfFile(file_map, FILE_MAP_READ, 0, 0, 0);
  if (pe_image == NULL) {
    printf("Could not map view of file: %ws\n", argv[1]);
    ret = -4;
    goto close_map;
  }

  DWORD size, text_va;
  PBYTE text;
  int s;

  s = find_text_section(pe_image, &text, &size, &text_va);
  if (s < 0) {
    printf("Could not find text section: %d\n", s);
    ret = -5;
    goto unmap_file;
  }

  BYTE buf[sizeof(BYTE) + sizeof(DWORD)];

  s = generate_entry_jmp(pe_image, text_va, buf);
  if (s < 0) {
    printf("Could not generate entry jmp: %d\n", s);
    ret = -6;
    goto unmap_file;
  }

  HANDLE out =
    CreateFileW(argv[2], GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
  if (out == INVALID_HANDLE_VALUE) {
    printf("Could not create output file: %ws\n", argv[2]);
    ret = -7;
    goto unmap_file;
  }

  DWORD n_written;
  if (!WriteFile(out, buf, sizeof buf, &n_written, NULL)) {
    printf("Could not write to output file: %ws\n", argv[2]);
    ret = -8;
    goto close_output;
  }

  if (!WriteFile(out, text, size, &n_written, NULL)) {
    printf("Could not write to output file: %ws\n", argv[2]);
    ret = -9;
    goto close_output;
  }

  printf("Success.");

close_output:
  CloseHandle(out);
  if (ret < 0) {
    DeleteFileW(argv[2]);
  }
unmap_file:
  UnmapViewOfFile(pe_image);
close_map:
  CloseHandle(file_map);
close_file:
  CloseHandle(file);

  return ret;
}
