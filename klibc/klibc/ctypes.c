/*
 * ctypes.c
 *
 * This is the array that defines <ctype.h> classes.
 * This assumes ISO 8859-1.
 */

#include <ctype.h>

const unsigned char __ctypes[257] = {
  0,				/* EOF */

  0,				/* control character */
  0,				/* control character */
  0,				/* control character */
  0,				/* control character */
  0,				/* control character */
  0,				/* control character */
  0,				/* control character */
  0,				/* control character */
  __ctype_space,		/* BS */
  __ctype_space,		/* TAB */
  __ctype_space,		/* LF */
  __ctype_space,		/* VT */
  __ctype_space,		/* FF */
  __ctype_space,		/* CR */
  0,				/* control character */

  0,				/* control character */
  0,				/* control character */
  0,				/* control character */
  0,				/* control character */
  0,				/* control character */
  0,				/* control character */
  0,				/* control character */
  0,				/* control character */
  0,				/* control character */
  0,				/* control character */
  0,				/* control character */
  0,				/* control character */
  0,				/* control character */
  0,				/* control character */
  0,				/* control character */
  0,				/* control character */
  0,				/* control character */
  
  __ctype_space|__ctype_print,	/* space */
  __ctype_print|__ctype_punct,	/* punctuation */
  __ctype_print|__ctype_punct,	/* punctuation */
  __ctype_print|__ctype_punct,	/* punctuation */
  __ctype_print|__ctype_punct,	/* punctuation */
  __ctype_print|__ctype_punct,	/* punctuation */
  __ctype_print|__ctype_punct,	/* punctuation */
  __ctype_print|__ctype_punct,	/* punctuation */
  __ctype_print|__ctype_punct,	/* punctuation */
  __ctype_print|__ctype_punct,	/* punctuation */
  __ctype_print|__ctype_punct,	/* punctuation */
  __ctype_print|__ctype_punct,	/* punctuation */
  __ctype_print|__ctype_punct,	/* punctuation */
  __ctype_print|__ctype_punct,	/* punctuation */
  __ctype_print|__ctype_punct,	/* punctuation */
  __ctype_print|__ctype_punct,	/* punctuation */

  __ctype_digit|__ctype_xdigit|__ctype_print, /* digit */
  __ctype_digit|__ctype_xdigit|__ctype_print, /* digit */
  __ctype_digit|__ctype_xdigit|__ctype_print, /* digit */
  __ctype_digit|__ctype_xdigit|__ctype_print, /* digit */
  __ctype_digit|__ctype_xdigit|__ctype_print, /* digit */
  __ctype_digit|__ctype_xdigit|__ctype_print, /* digit */
  __ctype_digit|__ctype_xdigit|__ctype_print, /* digit */
  __ctype_digit|__ctype_xdigit|__ctype_print, /* digit */
  __ctype_digit|__ctype_xdigit|__ctype_print, /* digit */
  __ctype_digit|__ctype_xdigit|__ctype_print, /* digit */
  __ctype_print|__ctype_punct,	/* punctuation */
  __ctype_print|__ctype_punct,	/* punctuation */
  __ctype_print|__ctype_punct,	/* punctuation */
  __ctype_print|__ctype_punct,	/* punctuation */
  __ctype_print|__ctype_punct,	/* punctuation */
  __ctype_print|__ctype_punct,	/* punctuation */

  __ctype_print|__ctype_punct,	/* punctuation */
  __ctype_upper|__ctype_print|__ctype_xdigit, /* A-F */
  __ctype_upper|__ctype_print|__ctype_xdigit, /* A-F */
  __ctype_upper|__ctype_print|__ctype_xdigit, /* A-F */
  __ctype_upper|__ctype_print|__ctype_xdigit, /* A-F */
  __ctype_upper|__ctype_print|__ctype_xdigit, /* A-F */
  __ctype_upper|__ctype_print|__ctype_xdigit, /* A-F */
  __ctype_upper|__ctype_print,	/* G-Z */
  __ctype_upper|__ctype_print,	/* G-Z */
  __ctype_upper|__ctype_print,	/* G-Z */
  __ctype_upper|__ctype_print,	/* G-Z */
  __ctype_upper|__ctype_print,	/* G-Z */
  __ctype_upper|__ctype_print,	/* G-Z */
  __ctype_upper|__ctype_print,	/* G-Z */
  __ctype_upper|__ctype_print,	/* G-Z */
  __ctype_upper|__ctype_print,	/* G-Z */

  __ctype_upper|__ctype_print,	/* G-Z */
  __ctype_upper|__ctype_print,	/* G-Z */
  __ctype_upper|__ctype_print,	/* G-Z */
  __ctype_upper|__ctype_print,	/* G-Z */
  __ctype_upper|__ctype_print,	/* G-Z */
  __ctype_upper|__ctype_print,	/* G-Z */
  __ctype_upper|__ctype_print,	/* G-Z */
  __ctype_upper|__ctype_print,	/* G-Z */
  __ctype_upper|__ctype_print,	/* G-Z */
  __ctype_upper|__ctype_print,	/* G-Z */
  __ctype_upper|__ctype_print,	/* G-Z */
  __ctype_print|__ctype_punct,	/* punctuation */
  __ctype_print|__ctype_punct,	/* punctuation */
  __ctype_print|__ctype_punct,	/* punctuation */
  __ctype_print|__ctype_punct,	/* punctuation */
  __ctype_print|__ctype_punct,	/* punctuation */

  __ctype_print|__ctype_punct,	/* punctuation */
  __ctype_lower|__ctype_print|__ctype_xdigit, /* a-f */
  __ctype_lower|__ctype_print|__ctype_xdigit, /* a-f */
  __ctype_lower|__ctype_print|__ctype_xdigit, /* a-f */
  __ctype_lower|__ctype_print|__ctype_xdigit, /* a-f */
  __ctype_lower|__ctype_print|__ctype_xdigit, /* a-f */
  __ctype_lower|__ctype_print|__ctype_xdigit, /* a-f */
  __ctype_lower|__ctype_print,	/* g-z */
  __ctype_lower|__ctype_print,	/* g-z */
  __ctype_lower|__ctype_print,	/* g-z */
  __ctype_lower|__ctype_print,	/* g-z */
  __ctype_lower|__ctype_print,	/* g-z */
  __ctype_lower|__ctype_print,	/* g-z */
  __ctype_lower|__ctype_print,	/* g-z */
  __ctype_lower|__ctype_print,	/* g-z */
  __ctype_lower|__ctype_print,	/* g-z */

  __ctype_lower|__ctype_print,	/* g-z */
  __ctype_lower|__ctype_print,	/* g-z */
  __ctype_lower|__ctype_print,	/* g-z */
  __ctype_lower|__ctype_print,	/* g-z */
  __ctype_lower|__ctype_print,	/* g-z */
  __ctype_lower|__ctype_print,	/* g-z */
  __ctype_lower|__ctype_print,	/* g-z */
  __ctype_lower|__ctype_print,	/* g-z */
  __ctype_lower|__ctype_print,	/* g-z */
  __ctype_lower|__ctype_print,	/* g-z */
  __ctype_lower|__ctype_print,	/* g-z */
  __ctype_print|__ctype_punct,	/* punctuation */
  __ctype_print|__ctype_punct,	/* punctuation */
  __ctype_print|__ctype_punct,	/* punctuation */
  __ctype_print|__ctype_punct,	/* punctuation */
  0,				/* control character */

  0,				/* control character */
  0,				/* control character */
  0,				/* control character */
  0,				/* control character */
  0,				/* control character */
  0,				/* control character */
  0,				/* control character */
  0,				/* control character */
  0,				/* control character */
  0,				/* control character */
  0,				/* control character */
  0,				/* control character */
  0,				/* control character */
  0,				/* control character */
  0,				/* control character */
  0,				/* control character */

  0,				/* control character */
  0,				/* control character */
  0,				/* control character */
  0,				/* control character */
  0,				/* control character */
  0,				/* control character */
  0,				/* control character */
  0,				/* control character */
  0,				/* control character */
  0,				/* control character */
  0,				/* control character */
  0,				/* control character */
  0,				/* control character */
  0,				/* control character */
  0,				/* control character */
  0,				/* control character */

  __ctype_space|__ctype_print,	/* NBSP */
  __ctype_print|__ctype_punct,	/* punctuation */
  __ctype_print|__ctype_punct,	/* punctuation */
  __ctype_print|__ctype_punct,	/* punctuation */
  __ctype_print|__ctype_punct,	/* punctuation */
  __ctype_print|__ctype_punct,	/* punctuation */
  __ctype_print|__ctype_punct,	/* punctuation */
  __ctype_print|__ctype_punct,	/* punctuation */
  __ctype_print|__ctype_punct,	/* punctuation */
  __ctype_print|__ctype_punct,	/* punctuation */
  __ctype_print|__ctype_punct,	/* punctuation */
  __ctype_print|__ctype_punct,	/* punctuation */
  __ctype_print|__ctype_punct,	/* punctuation */
  __ctype_print|__ctype_punct,	/* punctuation */
  __ctype_print|__ctype_punct,	/* punctuation */
  __ctype_print|__ctype_punct,	/* punctuation */

  __ctype_print|__ctype_punct,	/* punctuation */
  __ctype_print|__ctype_punct,	/* punctuation */
  __ctype_print|__ctype_punct,	/* punctuation */
  __ctype_print|__ctype_punct,	/* punctuation */
  __ctype_print|__ctype_punct,	/* punctuation */
  __ctype_print|__ctype_punct,	/* punctuation */
  __ctype_print|__ctype_punct,	/* punctuation */
  __ctype_print|__ctype_punct,	/* punctuation */
  __ctype_print|__ctype_punct,	/* punctuation */
  __ctype_print|__ctype_punct,	/* punctuation */
  __ctype_print|__ctype_punct,	/* punctuation */
  __ctype_print|__ctype_punct,	/* punctuation */
  __ctype_print|__ctype_punct,	/* punctuation */
  __ctype_print|__ctype_punct,	/* punctuation */
  __ctype_print|__ctype_punct,	/* punctuation */
  __ctype_print|__ctype_punct,	/* punctuation */

  __ctype_upper|__ctype_print,	/* upper accented */
  __ctype_upper|__ctype_print,	/* upper accented */
  __ctype_upper|__ctype_print,	/* upper accented */
  __ctype_upper|__ctype_print,	/* upper accented */
  __ctype_upper|__ctype_print,	/* upper accented */
  __ctype_upper|__ctype_print,	/* upper accented */
  __ctype_upper|__ctype_print,	/* upper accented */
  __ctype_upper|__ctype_print,	/* upper accented */
  __ctype_upper|__ctype_print,	/* upper accented */
  __ctype_upper|__ctype_print,	/* upper accented */
  __ctype_upper|__ctype_print,	/* upper accented */
  __ctype_upper|__ctype_print,	/* upper accented */
  __ctype_upper|__ctype_print,	/* upper accented */
  __ctype_upper|__ctype_print,	/* upper accented */
  __ctype_upper|__ctype_print,	/* upper accented */
  __ctype_upper|__ctype_print,	/* upper accented */

  __ctype_upper|__ctype_print,	/* upper accented */
  __ctype_upper|__ctype_print,	/* upper accented */
  __ctype_upper|__ctype_print,	/* upper accented */
  __ctype_upper|__ctype_print,	/* upper accented */
  __ctype_upper|__ctype_print,	/* upper accented */
  __ctype_upper|__ctype_print,	/* upper accented */
  __ctype_upper|__ctype_print,	/* upper accented */
  __ctype_print|__ctype_punct,	/* punctuation */
  __ctype_upper|__ctype_print,	/* upper accented */
  __ctype_upper|__ctype_print,	/* upper accented */
  __ctype_upper|__ctype_print,	/* upper accented */
  __ctype_upper|__ctype_print,	/* upper accented */
  __ctype_upper|__ctype_print,	/* upper accented */
  __ctype_upper|__ctype_print,	/* upper accented */
  __ctype_upper|__ctype_print,	/* upper accented */
  __ctype_lower|__ctype_print,	/* lower accented */

  __ctype_lower|__ctype_print,	/* lower accented */
  __ctype_lower|__ctype_print,	/* lower accented */
  __ctype_lower|__ctype_print,	/* lower accented */
  __ctype_lower|__ctype_print,	/* lower accented */
  __ctype_lower|__ctype_print,	/* lower accented */
  __ctype_lower|__ctype_print,	/* lower accented */
  __ctype_lower|__ctype_print,	/* lower accented */
  __ctype_lower|__ctype_print,	/* lower accented */
  __ctype_lower|__ctype_print,	/* lower accented */
  __ctype_lower|__ctype_print,	/* lower accented */
  __ctype_lower|__ctype_print,	/* lower accented */
  __ctype_lower|__ctype_print,	/* lower accented */
  __ctype_lower|__ctype_print,	/* lower accented */
  __ctype_lower|__ctype_print,	/* lower accented */
  __ctype_lower|__ctype_print,	/* lower accented */
  __ctype_lower|__ctype_print,	/* lower accented */

  __ctype_lower|__ctype_print,	/* lower accented */
  __ctype_lower|__ctype_print,	/* lower accented */
  __ctype_lower|__ctype_print,	/* lower accented */
  __ctype_lower|__ctype_print,	/* lower accented */
  __ctype_lower|__ctype_print,	/* lower accented */
  __ctype_lower|__ctype_print,	/* lower accented */
  __ctype_lower|__ctype_print,	/* lower accented */
  __ctype_print|__ctype_punct,	/* punctuation */
  __ctype_lower|__ctype_print,	/* lower accented */
  __ctype_lower|__ctype_print,	/* lower accented */
  __ctype_lower|__ctype_print,	/* lower accented */
  __ctype_lower|__ctype_print,	/* lower accented */
  __ctype_lower|__ctype_print,	/* lower accented */
  __ctype_lower|__ctype_print,	/* lower accented */
  __ctype_lower|__ctype_print,	/* lower accented */
  __ctype_lower|__ctype_print,	/* lower accented */
};
