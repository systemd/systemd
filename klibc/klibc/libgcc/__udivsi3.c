/*
 * libgcc/__divsi3.c
 */

#include <stdint.h>
#include <stddef.h>

extern uint32_t __udivmodsi4(uint32_t num, uint32_t den, uint32_t *rem);

uint32_t __udivsi3(uint32_t num, uint32_t den)
{
  return __udivmodsi4(num, den, NULL);
}
