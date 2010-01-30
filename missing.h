#ifndef foomissinghfoo
#define foomissinghfoo

/* Missing glibc definitions to access certain kernel APIs */

#include <sys/resource.h>

#ifndef RLIMIT_RTTIME
#define RLIMIT_RTTIME 15
#endif

#endif
