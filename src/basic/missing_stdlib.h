/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <stdlib.h>

/* stdlib.h */
#if !HAVE_SECURE_GETENV
#  if HAVE___SECURE_GETENV
#    define secure_getenv __secure_getenv
#  else
     char *secure_getenv (char const *name);
#  endif
#endif
