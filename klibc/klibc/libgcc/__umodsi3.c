/*
 * libgcc/__umodsi3.c
 */

#include <stdint.h>
#include <stddef.h>

extern uint32_t __udivmodsi4(uint32_t num, uint32_t den, uint32_t *rem);

uint32_t __umodsi3(uint32_t num, uint32_t den)
{
  uint32_t v;

  (void) __udivmodsi4(num, den, &v);
  return v;
}
