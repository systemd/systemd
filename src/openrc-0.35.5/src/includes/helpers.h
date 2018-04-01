/*
 * helpers.h
 * This is private to us and not for user consumption
 */

/*
 * Copyright (c) 2007-2015 The OpenRC Authors.
 * See the Authors file at the top-level directory of this distribution and
 * https://github.com/OpenRC/openrc/blob/master/AUTHORS
 *
 * This file is part of OpenRC. It is subject to the license terms in
 * the LICENSE file found in the top-level directory of this
 * distribution and at https://github.com/OpenRC/openrc/blob/master/LICENSE
 * This file may not be copied, modified, propagated, or distributed
 *    except according to the terms contained in the LICENSE file.
 */

#ifndef __HELPERS_H__
#define __HELPERS_H__

#define ERRX fprintf (stderr, "out of memory\n"); exit (1)

#define UNCONST(a)		((void *)(unsigned long)(const void *)(a))

#ifdef lint
# define _unused
#endif
#if __GNUC__ > 2 || defined(__INTEL_COMPILER)
# define _dead __attribute__((__noreturn__))
# define _unused __attribute__((__unused__))
# define _xasprintf(a, b)  __attribute__((__format__(__printf__, a, b)))
#else
# define _dead
# define _unused
# define _xasprintf(a, b)
#endif

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

#ifdef __GLIBC__
#  if ! defined (__UCLIBC__) && ! defined (__dietlibc__)
#    define strlcpy(dst, src, size) snprintf(dst, size, "%s", src)
#  endif
#endif

#ifndef timespecsub
#define	timespecsub(tsp, usp, vsp)					      \
	do {								      \
		(vsp)->tv_sec = (tsp)->tv_sec - (usp)->tv_sec;		      \
		(vsp)->tv_nsec = (tsp)->tv_nsec - (usp)->tv_nsec;	      \
		if ((vsp)->tv_nsec < 0) {				      \
			(vsp)->tv_sec--;				      \
			(vsp)->tv_nsec += 1000000000L;			      \
		}							      \
	} while (/* CONSTCOND */ 0)
#endif

#include <stdarg.h>
#include <stdbool.h>
#include <sys/stat.h>

_unused static void *xmalloc (size_t size)
{
	void *value = malloc(size);

	if (value)
		return (value);

	ERRX;
	/* NOTREACHED */
}

_unused static void *xrealloc(void *ptr, size_t size)
{
	void *value = realloc(ptr, size);

	if (value)
		return (value);

	ERRX;
	/* NOTREACHED */
}

_unused static char *xstrdup(const char *str)
{
	char *value;

	if (! str)
		return (NULL);

	value = strdup(str);

	if (value)
		return (value);

	ERRX;
	/* NOTREACHED */
}

#undef ERRX

/*
 * basename_c never modifies the argument. As such, if there is a trailing
 * slash then an empty string is returned.
 */
_unused static const char *basename_c(const char *path)
{
	const char *slash = strrchr(path, '/');

	if (slash)
		return (++slash);
	return (path);
}

_unused static bool exists(const char *pathname)
{
	struct stat buf;

	return (stat(pathname, &buf) == 0);
}

_unused static bool existss(const char *pathname)
{
	struct stat buf;

	return (stat(pathname, &buf) == 0 && buf.st_size != 0);
}

/*
 * This is an OpenRC specific version of the asprintf() function.
 * We do this to avoid defining the _GNU_SOURCE feature test macro on
 * glibc systems and to insure that we have a consistent function across
 * platforms. This also allows us to call our xmalloc and xrealloc
 * functions to handle memory allocation.
 * this function was originally written by Mike Frysinger.
 */
_unused _xasprintf(2,3) static int xasprintf(char **strp, const char *fmt, ...)
{
	va_list ap;
	int len;
	int memlen;
	char *ret;

	/*
	 * Start with a buffer size that should cover the vast majority of uses
	 * (path construction).
	 */
	memlen = 4096;
	ret = xmalloc(memlen);

	va_start(ap, fmt);
	len = vsnprintf(ret, memlen, fmt, ap);
	va_end(ap);
	if (len >= memlen) {
		/*
		 * Output was truncated, so increase buffer to exactly what we need.
		 */
		memlen = len + 1;
		ret = xrealloc(ret, memlen);
		va_start(ap, fmt);
		len = vsnprintf(ret, len + 1, fmt, ap);
		va_end(ap);
	}
	if (len < 0 || len >= memlen) {
		/* Give up! */
		fprintf(stderr, "xasprintf: unable to format a buffer\n");
		free(ret);
		exit(1);
	}
	*strp = ret;
	return len;
}

#endif
