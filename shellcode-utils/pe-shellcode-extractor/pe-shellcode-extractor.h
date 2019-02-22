#pragma once

/* main.c */
void
print_usage(const wchar_t* app_name);

/* pe.c */
int
find_text_section(PBYTE pe_image, PBYTE* text, DWORD* size, DWORD* text_va);
int
generate_entry_jmp(PBYTE pe_image,
                   DWORD text_va,
                   BYTE buf[sizeof(BYTE) + sizeof(DWORD)]);