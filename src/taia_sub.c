/* Public domain. */

#include "taia.h"

/* XXX: breaks tai encapsulation */

void taia_sub(struct taia *t,const struct taia *u,const struct taia *v)
{
  unsigned long unano = u->nano;
  unsigned long uatto = u->atto;
  
  t->sec.x = u->sec.x - v->sec.x;
  t->nano = unano - v->nano;
  t->atto = uatto - v->atto;
  if (t->atto > uatto) {
    t->atto += 1000000000UL;
    --t->nano;
  }
  if (t->nano > unano) {
    t->nano += 1000000000UL;
    --t->sec.x;
  }
}
