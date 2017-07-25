/* Public domain. */

#include "taia.h"

/* XXX: breaks tai encapsulation */

void taia_uint(struct taia *t,unsigned int s)
{
  t->sec.x = s;
  t->nano = 0;
  t->atto = 0;
}
