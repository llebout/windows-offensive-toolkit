#include <Windows.h>
#include <string.h>

#include "pe-shellcode-extractor.h"

int
find_text_section(PBYTE pe_image, PBYTE* text, DWORD* size, DWORD* text_va)
{
  PIMAGE_DOS_HEADER p_dos = (PIMAGE_DOS_HEADER)pe_image;
  PIMAGE_NT_HEADERS p_nt = (PIMAGE_NT_HEADERS)(pe_image + p_dos->e_lfanew);

  PIMAGE_SECTION_HEADER p_sections = IMAGE_FIRST_SECTION(p_nt);

  for (size_t n = 0; n < p_nt->FileHeader.NumberOfSections; ++n) {
    if (strncmp((PSTR)p_sections[n].Name, ".text", sizeof p_sections[n].Name) ==
        0) {
      *text = pe_image + p_sections[n].PointerToRawData;
      *size = p_sections[n].SizeOfRawData;
      *text_va = p_sections[n].VirtualAddress;
      return 0;
    }
  }

  return -1;
}

int
generate_entry_jmp(PBYTE pe_image,
                   DWORD text_va,
                   BYTE buf[sizeof(BYTE) + sizeof(DWORD)])
{
  PIMAGE_DOS_HEADER p_dos = (PIMAGE_DOS_HEADER)pe_image;
  PIMAGE_NT_HEADERS p_nt = (PIMAGE_NT_HEADERS)(pe_image + p_dos->e_lfanew);

  /*
    Generating a 32bit relative jump.
    JMP rel32

    see:
    page 1071
    https://software.intel.com/sites/default/files/managed/39/c5/325462-sdm-vol-1-2abcd-3abcd.pdf
  */
  PDWORD displacement = (PDWORD)&buf[1];

  /* Opcode */
  buf[0] = 0xE9;

  /* 32bit relative displacement (little endian) */
  *displacement = p_nt->OptionalHeader.AddressOfEntryPoint - text_va;

  return 0;
}
