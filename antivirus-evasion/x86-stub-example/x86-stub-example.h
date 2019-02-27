#pragma once

/* main.c */
typedef int __stdcall shellcode_entry(PBYTE pe_image, DWORD* proc_id);

enum meta_param_kind
{
  Shell = 0,
  Watchdog = 1,
};

struct meta_param
{
  int kind;
};

struct shell_param
{
  struct meta_param _meta;
  PVOID shell_base;
  SIZE_T shell_size;
  ULONGLONG proc_id;
  WCHAR path[MAX_PATH + 1];
};

typedef int __stdcall watchdog_entry(struct meta_param *param);

/* file.c */
int
read_file_to_mem(const wchar_t* filename, PVOID* out, DWORD* size, DWORD prot);
