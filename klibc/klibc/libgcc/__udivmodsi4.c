#include <klibc/diverr.h>
#include <stdint.h>

uint32_t __udivmodsi4(uint32_t num, uint32_t den, uint32_t *rem_p)
{
  uint32_t quot = 0, qbit = 1;

  if ( den == 0 ) {
    __divide_error();
    return 0;                   /* If trap returns... */
  }

  /* Left-justify denominator and count shift */
  while ( (int32_t)den >= 0 ) {
    den <<= 1;
    qbit <<= 1;
  }

  while ( qbit ) {
    if ( den <= num ) {
      num -= den;
      quot += qbit;
    }
    den >>= 1;
    qbit >>= 1;
  }

  if ( rem_p )
    *rem_p = num;

  return quot;
}
