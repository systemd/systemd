/* Public domain. */

#include <time.h>
#include "tai.h"

void tai_now(struct tai *t)
{
  tai_unix(t,time((time_t *) 0));
}
