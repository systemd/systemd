/* Public domain. */

#include "taia.h"

double taia_approx(const struct taia *t)
{
  return tai_approx(&t->sec) + taia_frac(t);
}
