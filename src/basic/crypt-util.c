/***
  Copyright © 2017 Zbigniew Jędrzejewski-Szmek
***/

#if HAVE_LIBCRYPTSETUP
#include "crypt-util.h"
#include "log.h"

void cryptsetup_log_glue(int level, const char *msg, void *usrptr) {
        log_debug("%s", msg);
}
#endif
