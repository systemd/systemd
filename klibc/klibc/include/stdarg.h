/*
 * stdarg.h
 *
 * This is just a wrapper for the gcc one, but defines va_copy()
 * even if gcc doesn't.
 */

/* Note: the _STDARG_H macro belongs to the gcc header... */
#include_next <stdarg.h>

/* Older gcc considers this an extension, so it's double underbar only */
#ifndef va_copy
#define va_copy(d,s) __va_copy(d,s)
#endif
