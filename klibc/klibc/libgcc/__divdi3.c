/*
 * arch/i386/libgcc/__divdi3.c
 */

#include <stdint.h>
#include <stddef.h>

extern uint64_t __udivmoddi4(uint64_t num, uint64_t den, uint64_t *rem);

int64_t __divdi3(int64_t num, int64_t den)
{
  int minus = 0;
  int64_t v;

  if ( num < 0 ) {
    num = -num;
    minus = 1;
  }
  if ( den < 0 ) {
    den = -den;
    minus ^= 1;
  }
  
  v = __udivmoddi4(num, den, NULL);
  if ( minus )
    v = -v;

  return v;
}
