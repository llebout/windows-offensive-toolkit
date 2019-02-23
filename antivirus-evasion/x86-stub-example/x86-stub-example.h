#pragma once

/* main.c */
typedef int __stdcall shellcode_entry(PBYTE pe_image);

/* file.c */
int
read_file_to_mem(const wchar_t* filename, PVOID* out, DWORD* size, DWORD prot);
