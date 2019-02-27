#include "x86-watchdog-infector.h"

size_t
libc_wstrlen(const wchar_t* s)
{
  const wchar_t* s2 = s;
  while (*s2) {
    ++s2;
  }
  return s2 - s;
}

int
libc_strcmp(const char* s1, const char* s2)
{
  while (*s1 == *s2 && *s1 && *s2) {
    ++s1;
    ++s2;
  }
  return *s1 - *s2;
}

int
libc_wstrcmp(const wchar_t* s1, const wchar_t* s2)
{
  while (*s1 == *s2 && *s1 && *s2) {
    ++s1;
    ++s2;
  }
  return *s1 - *s2;
}

wchar_t
libc_wtolower(const wchar_t c)
{
  if (c >= L'A' && c <= L'Z') {
    return c + (L'a' - L'A');
  }
  return c;
}

int
libc_wstricmp(const wchar_t* s1, const wchar_t* s2)
{
  while (libc_wtolower(*s1) == libc_wtolower(*s2) && *s1 && *s2) {
    ++s1;
    ++s2;
  }
  return *s1 - *s2;
}

void
libc_memcpy(void* dst, const void* src, size_t n)
{
  unsigned char* b_dst = dst;
  const unsigned char* b_src = src;

  for (size_t i = 0; i < n; ++i) {
    b_dst[i] = b_src[i];
  }
}

void
libc_memset(void* dst, const unsigned char c, size_t n)
{
  unsigned char* b_dst = dst;

  for (size_t i = 0; i < n; ++i) {
    b_dst[i] = c;
  }
}
