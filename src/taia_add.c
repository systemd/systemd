/* Public domain. */

#include "taia.h"

/* XXX: breaks tai encapsulation */

void taia_add(struct taia *t,const struct taia *u,const struct taia *v)
{
  t->sec.x = u->sec.x + v->sec.x;
  t->nano = u->nano + v->nano;
  t->atto = u->atto + v->atto;
  if (t->atto > 999999999UL) {
    t->atto -= 1000000000UL;
    ++t->nano;
  }
  if (t->nano > 999999999UL) {
    t->nano -= 1000000000UL;
    ++t->sec.x;
  }
}
