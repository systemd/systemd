#if !HAVE_SECURE_GETENV && !HAVE___SECURE_GETENV
#include <unistd.h>

#include "missing_stdlib.h"

char *
secure_getenv (char const *name)
{
        if (geteuid() != getuid() || getegid() != getgid())
                return NULL;
        return getenv(name);
}
#endif
