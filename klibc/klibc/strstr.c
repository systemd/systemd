/*
 * strstr.c
 */

#include <string.h>

char *strstr(const char *haystack, const char *needle)
{
  return (char *)memmem(haystack, strlen(haystack), needle, strlen(needle));
}
