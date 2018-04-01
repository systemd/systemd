/*
  einfo.c
  Informational functions
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

const char libeinfo_copyright[] = "Copyright (c) 2007-2008 Roy Marples";

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <syslog.h>
#ifdef HAVE_TERMCAP
# include <termcap.h>
#endif
#include <unistd.h>

#include "einfo.h"
#include "helpers.h"
#include "hidden-visibility.h"

hidden_proto(ecolor)
hidden_proto(ebegin)
hidden_proto(ebeginv)
hidden_proto(ebracket)
hidden_proto(eend)
hidden_proto(eendv)
hidden_proto(eerror)
hidden_proto(eerrorn)
hidden_proto(eerrorx)
hidden_proto(eindent)
hidden_proto(eindentv)
hidden_proto(einfo)
hidden_proto(einfon)
hidden_proto(einfov)
hidden_proto(einfovn)
hidden_proto(elog)
hidden_proto(eoutdent)
hidden_proto(eoutdentv)
hidden_proto(eprefix)
hidden_proto(ewarn)
hidden_proto(ewarnn)
hidden_proto(ewarnv)
hidden_proto(ewarnvn)
hidden_proto(ewarnx)
hidden_proto(ewend)
hidden_proto(ewendv)

/* Incase we cannot work out how many columns from ioctl, supply a default */
#define DEFAULT_COLS		 80

#define OK			"ok"
#define NOT_OK			"!!"

/* Number of spaces for an indent */
#define INDENT_WIDTH		2

/* How wide can the indent go? */
#define INDENT_MAX		40

/* Default colours */
#define GOOD                    2
#define WARN                    3
#define BAD                     1
#define HILITE                  6
#define BRACKET                 4

/* We fallback to these escape codes if termcap isn't available
 * like say /usr isn't mounted */
#define AF "\033[3%dm"
#define CE "\033[K"
#define CH "\033[%dC"
#define MD "\033[1m"
#define ME "\033[m"
#define UP "\033[A"

#define _GET_CAP(_d, _c) strlcpy(_d, tgoto(_c, 0, 0), sizeof(_d));
#define _ASSIGN_CAP(_v) do {						      \
		_v = p;							      \
		p += strlcpy(p, tmp, sizeof(ebuffer) - (p - ebuffer)) + 1;    \
	} while (0)

/* A pointer to a string to prefix to einfo/ewarn/eerror messages */
static const char *_eprefix = NULL;

/* Buffers and structures to hold the final colours */
static char ebuffer[100];
struct ecolor {
	ECOLOR color;
	int def;
	const char *name;
};
static char nullstr = '\0';

static const struct ecolor ecolors[] = {
	{ ECOLOR_GOOD,    GOOD,    "good"    },
	{ ECOLOR_WARN,    WARN,    "warn"    },
	{ ECOLOR_BAD,     BAD,     "bad"     },
	{ ECOLOR_HILITE,  HILITE,  "hilite"  },
	{ ECOLOR_BRACKET, BRACKET, "bracket" },
	{ ECOLOR_NORMAL,  0,       NULL      },
};
static const char *ecolors_str[ARRAY_SIZE(ecolors)];

static char *flush = NULL;
static char *up = NULL;
static char *goto_column = NULL;

static const char *term = NULL;
static bool term_is_cons25 = false;

/* Termcap buffers and pointers
 * Static buffers suck hard, but some termcap implementations require them */
#ifdef HAVE_TERMCAP
static char termcapbuf[2048];
static char tcapbuf[512];
#else
/* No curses support, so we hardcode a list of colour capable terms
 * Only terminals without "color" in the name need to be explicitly listed */
static const char *const color_terms[] = {
	"Eterm",
	"ansi",
	"con132x25",
	"con132x30",
	"con132x43",
	"con132x60",
	"con80x25",
	"con80x28",
	"con80x30",
	"con80x43",
	"con80x50",
	"con80x60",
	"cons25",
	"console",
	"cygwin",
	"dtterm",
	"gnome",
	"konsole",
	"kterm",
	"linux",
	"linux-c",
	"mlterm",
	"putty",
	"rxvt",
	"rxvt-cygwin",
	"rxvt-cygwin-native",
	"rxvt-unicode",
	"screen",
	"screen-bce",
	"screen-w",
	"screen.linux",
	"vt100",
	"vt220",
	"wsvt25",
	"xterm",
	"xterm-debian",
	NULL
};
#endif

/* strlcat and strlcpy are nice, shame glibc does not define them */
#ifdef __GLIBC__
#  if ! defined (__UCLIBC__) && ! defined (__dietlibc__)
static size_t
strlcat(char *dst, const char *src, size_t size)
{
	char *d = dst;
	const char *s = src;
	size_t src_n = size;
	size_t dst_n;

	while (src_n-- != 0 && *d != '\0')
		d++;
	dst_n = d - dst;
	src_n = size - dst_n;

	if (src_n == 0)
		return dst_n + strlen(src);

	while (*s != '\0') {
		if (src_n != 1) {
			*d++ = *s;
			src_n--;
		}
		s++;
	}
	*d = '\0';

	return dst_n + (s - src);
}
#  endif
#endif

static bool
yesno(const char *value)
{
	if (!value) {
		errno = ENOENT;
		return false;
	}

	if (strcasecmp(value, "yes") == 0 ||
	    strcasecmp(value, "y") == 0 ||
	    strcasecmp(value, "true") == 0 ||
	    strcasecmp(value, "on") == 0 ||
	    strcasecmp(value, "1") == 0)
		return true;

	if (strcasecmp(value, "no") != 0 &&
	    strcasecmp(value, "n") != 0 &&
	    strcasecmp(value, "false") != 0 &&
	    strcasecmp(value, "off") != 0 &&
	    strcasecmp(value, "0") != 0)
		errno = EINVAL;

	return false;
}

static bool
noyes(const char *value)
{
	int serrno = errno;
	bool retval;

	errno = 0;
	retval = yesno(value);
	if (errno == 0) {
		retval = !retval;
		errno = serrno;
	}

	return retval;
}

static bool
is_quiet(void)
{
	return yesno(getenv("EINFO_QUIET"));
}

static bool
is_really_quiet(void)
{
	return yesno(getenv("EERROR_QUIET"));
}

static bool
is_verbose(void)
{
	return yesno(getenv ("EINFO_VERBOSE"));
}

/* Fake tgoto call - very crapy, but works for our needs */
#ifndef HAVE_TERMCAP
static char *
tgoto(const char *cap, int col, int line)
{
	static char buf[20];
	char *p, *e, c, dbuf[6];
	int oncol = 0, which = line, i;

	p = buf;
	e = p + sizeof(buf);
	while ((c = *cap++)) {
		if (c != '%' || ((c = *cap++) == '%')) {
			*p++ = c;
			if (p >= e) {
				errno = E2BIG;
				return NULL;
			}
			continue;
		}
		switch (c) {
		case '3':
		case '2':
		case 'd':
			i = 0;
			do
				dbuf[i++] = which % 10 | '0';
			while ((which /= 10));
			if (c != 'd') {
				c -= '0';
				if (i > c) {
					errno = EINVAL;
					return NULL;
				}
				while (i < c)
					dbuf[i++] = '0';
			}
			if (p + i >= e) {
				errno = E2BIG;
				return NULL;
			}
			do
				*p++ = dbuf[--i];
			while (i);
			break;
		case 'r':
			oncol = 0;
			break;
		case 'i':
			col++;
			line++;
			which++;
			continue;
		default:
			errno = EINVAL;
			return NULL;
		}

		oncol = 1 - oncol;
		which = oncol ? col : line;
	}
	*p = '\0';
	return buf;
}
#endif

static bool
colour_terminal(FILE * EINFO_RESTRICT f)
{
	static int in_colour = -1;
	char *e, *ee, *end, *d, *p;
	int c;
	const char *_af = NULL, *_ce = NULL, *_ch = NULL;
	const char *_md = NULL, *_me = NULL, *_up = NULL;
	const char *bold;
	char tmp[100];
	unsigned int i = 0;
#ifdef HAVE_TERMCAP
	char *bp;
#endif

	if (f && !isatty(fileno(f)))
		return false;

	if (noyes(getenv("EINFO_COLOR")))
		return false;

	if (in_colour == 0)
		return false;
	if (in_colour == 1)
		return true;

	term_is_cons25 = false;
	if (!term) {
		term = getenv("TERM");
		if (!term)
			return false;
	}
	if (strcmp(term, "cons25") == 0)
		term_is_cons25 = true;

#ifdef HAVE_TERMCAP
	/* Check termcap to see if we can do colour or not */
	if (tgetent(termcapbuf, term) == 1) {
		bp = tcapbuf;
		_af = tgetstr("AF", &bp);
		_ce = tgetstr("ce", &bp);
		_ch = tgetstr("ch", &bp);
		/* Our ch use also works with RI .... for now */
		if (!_ch)
			_ch = tgetstr("RI", &bp);
		_md = tgetstr("md", &bp);
		_me = tgetstr("me", &bp);
		_up = tgetstr("up", &bp);
	}

	/* Cheat here as vanilla BSD has the whole termcap info in /usr
	 * which is not available to us when we boot */
	if (term_is_cons25 || strcmp(term, "wsvt25") == 0) {
#else
		if (strstr(term, "color"))
			in_colour = 1;

		while (color_terms[i] && in_colour != 1) {
			if (strcmp(color_terms[i], term) == 0) {
				in_colour = 1;
			}
			i++;
		}

		if (in_colour != 1) {
			in_colour = 0;
			return false;
		}
#endif
		if (!_af)
			_af = AF;
		if (!_ce)
			_ce = CE;
		if (!_ch)
			_ch = CH;
		if (!_md)
			_md = MD;
		if (!_me)
			_me = ME;
		if (!_up)
			_up = UP;
#ifdef HAVE_TERMCAP
	}

	if (!_af || !_ce || !_me || !_md || !_up) {
		in_colour = 0;
		return false;
	}

	/* Many termcap databases don't have ch or RI even though they
	 * do work */
	if (!_ch)
		_ch = CH;
#endif

	/* Now setup our colours */
	p = ebuffer;
	for (i = 0; i < ARRAY_SIZE(ecolors); ++i) {
		tmp[0] = '\0';
		if (ecolors[i].name) {
			bold = _md;
			c = ecolors[i].def;

			/* See if the user wants to override the colour
			 * We use a :col;bold: format like 2;1: for bold green
			 * and 1;0: for a normal red */
			if ((e = getenv("EINFO_COLOR"))) {
				ee = strstr(e, ecolors[i].name);
				if (ee)
					ee += strlen(ecolors[i].name);

				if (ee && *ee == '=') {
					d = strdup(ee + 1);
					if (d) {
						end = strchr(d, ':');
						if (end)
							*end = '\0';
						c = atoi(d);
						end = strchr(d, ';');
						if (end && *++end == '0')
							bold = _me;
						free(d);
					}
				}
			}
			strlcpy(tmp, tgoto(bold, 0, 0), sizeof(tmp));
			strlcat(tmp, tgoto(_af, 0, c & 0x07), sizeof(tmp));
		} else
			_GET_CAP(tmp, _me);

		if (tmp[0])
			_ASSIGN_CAP(ecolors_str[i]);
		else
			ecolors_str[i] = &nullstr;
	}

	_GET_CAP(tmp, _ce);
	_ASSIGN_CAP(flush);
	_GET_CAP(tmp, _up);
	_ASSIGN_CAP(up);
	strlcpy(tmp, _ch, sizeof(tmp));
	_ASSIGN_CAP(goto_column);

	in_colour = 1;
	return true;
}

static int
get_term_columns(FILE * EINFO_RESTRICT stream)
{
	struct winsize ws;
	char *env = getenv("COLUMNS");
	char *p;
	int i;

	if (env) {
		i = strtoimax(env, &p, 10);
		if (!*p)
			return i;
	}

	if (ioctl(fileno(stream), TIOCGWINSZ, &ws) == 0)
		return ws.ws_col;

	return DEFAULT_COLS;
}

void
eprefix(const char *EINFO_RESTRICT prefix)
{
	_eprefix = prefix;
}
hidden_def(eprefix)

static void EINFO_PRINTF(2, 0)
elogv(int level, const char *EINFO_RESTRICT fmt, va_list ap)
{
	char *e = getenv("EINFO_LOG");
	va_list apc;

	if (fmt && e) {
		closelog();
		openlog(e, LOG_PID, LOG_DAEMON);
		va_copy(apc, ap);
		vsyslog(level, fmt, apc);
		va_end(apc);
		closelog();
	}
}

void
elog(int level, const char *EINFO_RESTRICT fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	elogv(level, fmt, ap);
	va_end(ap);
}
hidden_def(elog)

static int
_eindent(FILE * EINFO_RESTRICT stream)
{
	char *env = getenv("EINFO_INDENT");
	int amount = 0;
	char indent[INDENT_MAX];

	if (env) {
		errno = 0;
		amount = strtoimax(env, NULL, 0);
		if (errno != 0 || amount < 0)
			amount = 0;
		else if (amount > INDENT_MAX)
			amount = INDENT_MAX;

		if (amount > 0)
			memset(indent, ' ', (size_t)amount);
	}

	/* Terminate it */
	memset(indent + amount, 0, 1);
	return fprintf(stream, "%s", indent);
}

static const char *
_ecolor(FILE * EINFO_RESTRICT f, ECOLOR color)
{
	unsigned int i;

	if (!colour_terminal(f))
		return "";

	for (i = 0; i < ARRAY_SIZE(ecolors); ++i)
		if (ecolors[i].color == color)
			return ecolors_str[i];
	return "";
}
hidden_def(ecolor)

const char *
ecolor(ECOLOR color)
{
	FILE *f = stdout;

	/* Try and guess a valid tty */
	if (!isatty(fileno(f))) {
		f = stderr;
		if (!isatty(fileno(f))) {
			f = stdin;
			if (!isatty(fileno(f)))
				f = NULL;
		}
	}

	return _ecolor(f, color);
}

#define LASTCMD(_cmd) {							      \
		unsetenv("EINFO_LASTCMD");				      \
		setenv("EINFO_LASTCMD", _cmd, 1);			      \
	}

static int EINFO_PRINTF(3, 0)
	_einfo(FILE *f, ECOLOR color, const char *EINFO_RESTRICT fmt, va_list va)
{
	int retval = 0;
	char *last = getenv("EINFO_LASTCMD");
	va_list ap;

	if (last &&
	    !colour_terminal(f) &&
	    strcmp(last, "ewarn") != 0 &&
	    last[strlen(last) - 1] == 'n')
		fprintf(f, "\n");
	if (_eprefix)
		fprintf(f, "%s%s%s|", _ecolor(f, color), _eprefix, _ecolor(f, ECOLOR_NORMAL));
	fprintf(f, " %s*%s ", _ecolor(f, color), _ecolor(f, ECOLOR_NORMAL));
	retval += _eindent(f);
	va_copy(ap, va);
	retval += vfprintf(f, fmt, ap) + 3;
	va_end(ap); \
	if (colour_terminal(f))
		fprintf(f, "%s", flush);
	return retval;
}

#define _einfovn(fmt, ap) _einfo(stdout, ECOLOR_GOOD, fmt, ap)
#define _ewarnvn(fmt, ap) _einfo(stderr, ECOLOR_WARN, fmt, ap)
#define _eerrorvn(fmt, ap) _einfo(stderr, ECOLOR_BAD, fmt, ap)

int
einfon(const char *EINFO_RESTRICT fmt, ...)
{
	int retval;
	va_list ap;

	if (!fmt || is_quiet())
		return 0;
	va_start(ap, fmt);
	retval = _einfovn(fmt, ap);
	va_end(ap);
	LASTCMD("einfon");
	return retval;
}
hidden_def(einfon)

int
ewarnn(const char *EINFO_RESTRICT fmt, ...)
{
	int retval;
	va_list ap;

	if (!fmt || is_quiet())
		return 0;
	va_start(ap, fmt);
	retval = _ewarnvn(fmt, ap);
	va_end(ap);
	LASTCMD("ewarnn");
	return retval;
}
hidden_def(ewarnn)

int
eerrorn(const char *EINFO_RESTRICT fmt, ...)
{
	int retval;
	va_list ap;

	if (!fmt || is_really_quiet())
		return 0;
	va_start(ap, fmt);
	retval = _eerrorvn(fmt, ap);
	va_end(ap);
	LASTCMD("errorn");
	return retval;
}
hidden_def(eerrorn)

int
einfo(const char *EINFO_RESTRICT fmt, ...)
{
	int retval;
	va_list ap;

	if (!fmt || is_quiet())
		return 0;
	va_start(ap, fmt);
	retval = _einfovn(fmt, ap);
	retval += printf("\n");
	va_end(ap);
	LASTCMD("einfo");
	return retval;
}
hidden_def(einfo)

int
ewarn(const char *EINFO_RESTRICT fmt, ...)
{
	int retval;
	va_list ap;

	if (!fmt || is_quiet())
		return 0;
	va_start(ap, fmt);
	elogv(LOG_WARNING, fmt, ap);
	retval = _ewarnvn(fmt, ap);
	retval += fprintf(stderr, "\n");
	va_end(ap);
	LASTCMD("ewarn");
	return retval;
}
hidden_def(ewarn)

void
ewarnx(const char *EINFO_RESTRICT fmt, ...)
{
	int retval;
	va_list ap;

	if (fmt && !is_quiet()) {
		va_start(ap, fmt);
		elogv(LOG_WARNING, fmt, ap);
		retval = _ewarnvn(fmt, ap);
		va_end(ap);
		retval += fprintf(stderr, "\n");
	}
	exit(EXIT_FAILURE);
}
hidden_def(ewarnx)

int
eerror(const char *EINFO_RESTRICT fmt, ...)
{
	int retval;
	va_list ap;

	if (!fmt || is_really_quiet())
		return 0;
	va_start(ap, fmt);
	elogv(LOG_ERR, fmt, ap);
	retval = _eerrorvn(fmt, ap);
	va_end(ap);
	retval += fprintf(stderr, "\n");
	LASTCMD("eerror");
	return retval;
}
hidden_def(eerror)

void
eerrorx(const char *EINFO_RESTRICT fmt, ...)
{
	va_list ap;

	if (fmt && !is_really_quiet()) {
		va_start(ap, fmt);
		elogv(LOG_ERR, fmt, ap);
		_eerrorvn(fmt, ap);
		va_end(ap);
		fprintf(stderr, "\n");
	}
	exit(EXIT_FAILURE);
}
hidden_def(eerrorx)

int
ebegin(const char *EINFO_RESTRICT fmt, ...)
{
	int retval;
	va_list ap;

	if (!fmt || is_quiet())
		return 0;
	va_start(ap, fmt);
	retval = _einfovn(fmt, ap);
	va_end(ap);
	retval += printf(" ...");
	if (colour_terminal(stdout))
		retval += printf("\n");
	LASTCMD("ebegin");
	return retval;
}
hidden_def(ebegin)

static void
_eend(FILE * EINFO_RESTRICT fp, int col, ECOLOR color, const char *msg)
{
	int i;
	int cols;

	if (!msg)
		return;

	cols = get_term_columns(fp) - (strlen(msg) + 5);

	/* cons25 is special - we need to remove one char, otherwise things
	 * do not align properly at all. */
	if (!term) {
		term = getenv("TERM");
		if (term && strcmp(term, "cons25") == 0)
			term_is_cons25 = true;
		else
			term_is_cons25 = false;
	}
	if (term_is_cons25)
		cols--;

	if (cols > 0 && colour_terminal(fp)) {
		fprintf(fp, "%s%s %s[%s %s %s]%s\n", up, tgoto(goto_column, 0, cols),
		    ecolor(ECOLOR_BRACKET), ecolor(color), msg,
		    ecolor(ECOLOR_BRACKET), ecolor(ECOLOR_NORMAL));
	} else {
		if (col > 0)
			for (i = 0; i < cols - col; i++)
				fprintf(fp, " ");
		fprintf(fp, " [ %s ]\n", msg);
	}
}

static int EINFO_PRINTF(3, 0)
_do_eend(const char *cmd, int retval,
    const char *EINFO_RESTRICT fmt, va_list ap)
{
	int col = 0;
	FILE *fp = stdout;
	va_list apc;

	if (fmt && *fmt != '\0' && retval != 0) {
		fp = stderr;
		va_copy(apc, ap);
		if (strcmp(cmd, "ewend") == 0)
			col = _ewarnvn(fmt, apc);
		else
			col = _eerrorvn(fmt, apc);
		col += fprintf(fp, "\n");
		va_end(apc);
	}
	_eend(fp, col,
	    retval == 0 ? ECOLOR_GOOD : ECOLOR_BAD,
	    retval == 0 ? OK : NOT_OK);
	return retval;
}

int
eend(int retval, const char *EINFO_RESTRICT fmt, ...)
{
	va_list ap;

	if (is_quiet())
		return retval;
	va_start(ap, fmt);
	_do_eend("eend", retval, fmt, ap);
	va_end(ap);
	LASTCMD("eend");
	return retval;
}
hidden_def(eend)

int
ewend(int retval, const char *EINFO_RESTRICT fmt, ...)
{
	va_list ap;

	if (is_quiet())
		return retval;
	va_start(ap, fmt);
	_do_eend("ewend", retval, fmt, ap);
	va_end(ap);
	LASTCMD("ewend");
	return retval;
}
hidden_def(ewend)

void
ebracket(int col, ECOLOR color, const char *msg)
{
	_eend(stdout, col, color, msg);
}
hidden_def(ebracket)

void
eindent(void)
{
	char *env = getenv("EINFO_INDENT");
	int amount = 0;
	char num[10];

	if (env) {
		errno = 0;
		amount = strtoimax(env, NULL, 0);
		if (errno != 0)
			amount = 0;
	}
	amount += INDENT_WIDTH;
	if (amount > INDENT_MAX)
		amount = INDENT_MAX;
	snprintf(num, 10, "%08d", amount);
	setenv("EINFO_INDENT", num, 1);
}
hidden_def(eindent)

void eoutdent(void)
{
	char *env = getenv("EINFO_INDENT");
	int amount = 0;
	char num[10];
	int serrno = errno;

	if (!env)
		return;
	errno = 0;
	amount = strtoimax(env, NULL, 0);
	if (errno != 0)
		amount = 0;
	else
		amount -= INDENT_WIDTH;
	if (amount <= 0)
		unsetenv("EINFO_INDENT");
	else {
		snprintf(num, 10, "%08d", amount);
		setenv("EINFO_INDENT", num, 1);
	}
	errno = serrno;
}
hidden_def(eoutdent)

int
einfovn(const char *EINFO_RESTRICT fmt, ...)
{
	int retval;
	va_list ap;

	if (!fmt || !is_verbose())
		return 0;
	va_start(ap, fmt);
	retval = _einfovn(fmt, ap);
	va_end(ap);
	LASTCMD("einfovn");
	return retval;
}
hidden_def(einfovn)

int
ewarnvn(const char *EINFO_RESTRICT fmt, ...)
{
	int retval;
	va_list ap;

	if (!fmt || !is_verbose())
		return 0;
	va_start(ap, fmt);
	retval = _ewarnvn(fmt, ap);
	va_end(ap);
	LASTCMD("ewarnvn");
	return retval;
}
hidden_def(ewarnvn)

int
einfov(const char *EINFO_RESTRICT fmt, ...)
{
	int retval;
	va_list ap;

	if (!fmt || !is_verbose())
		return 0;
	va_start(ap, fmt);
	retval = _einfovn(fmt, ap);
	retval += printf("\n");
	va_end(ap);
	LASTCMD("einfov");
	return retval;
}
hidden_def(einfov)

int
ewarnv(const char *EINFO_RESTRICT fmt, ...)
{
	int retval;
	va_list ap;

	if (!fmt || !is_verbose())
		return 0;
	va_start(ap, fmt);
	retval = _ewarnvn(fmt, ap);
	retval += printf("\n");
	va_end(ap);
	LASTCMD("ewarnv");
	return retval;
}
hidden_def(ewarnv)

int
ebeginv(const char *EINFO_RESTRICT fmt, ...)
{
	int retval;
	va_list ap;

	if (!fmt || !is_verbose())
		return 0;

	va_start(ap, fmt);
	retval = _einfovn(fmt, ap);
	retval += printf(" ...");
	if (colour_terminal(stdout))
		retval += printf("\n");
	va_end(ap);
	LASTCMD("ebeginv");
	return retval;
}
hidden_def(ebeginv)

int
eendv(int retval, const char *EINFO_RESTRICT fmt, ...)
{
	va_list ap;

	if (!is_verbose())
		return 0;
	va_start(ap, fmt);
	_do_eend("eendv", retval, fmt, ap);
	va_end(ap);
	LASTCMD("eendv");
	return retval;
}
hidden_def(eendv)

int
ewendv(int retval, const char *EINFO_RESTRICT fmt, ...)
{
	va_list ap;

	if (!is_verbose())
		return 0;
	va_start(ap, fmt);
	_do_eend("ewendv", retval, fmt, ap);
	va_end(ap);
	LASTCMD("ewendv");
	return retval;
}
hidden_def(ewendv)

void
eindentv(void)
{
	if (is_verbose())
		eindent();
}
hidden_def(eindentv)

void
eoutdentv(void)
{
	if (is_verbose())
		eoutdent();
}
hidden_def(eoutdentv)
