/*
 * arch/i386/libgcc/__umoddi3.c
 */

#include <stdint.h>
#include <stddef.h>

extern uint64_t __udivmoddi4(uint64_t num, uint64_t den, uint64_t *rem);

uint64_t __umoddi3(uint64_t num, uint64_t den)
{
  uint64_t v;

  (void) __udivmoddi4(num, den, &v);
  return v;
}
