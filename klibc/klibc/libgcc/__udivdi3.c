/*
 * arch/i386/libgcc/__divdi3.c
 */

#include <stdint.h>
#include <stddef.h>

extern uint64_t __udivmoddi4(uint64_t num, uint64_t den, uint64_t *rem);

uint64_t __udivdi3(uint64_t num, uint64_t den)
{
  return __udivmoddi4(num, den, NULL);
}
