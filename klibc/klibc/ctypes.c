/*
 * ctypes.c
 *
 * This is the array that defines <ctype.h> classes.
 * This assumes ISO 8859-1.
 */

#include <ctype.h>

const unsigned char __ctypes[257] = {
  0,				/* EOF */

  __ctype_cntrl,		/* control character */
  __ctype_cntrl,		/* control character */
  __ctype_cntrl,		/* control character */
  __ctype_cntrl,		/* control character */
  __ctype_cntrl,		/* control character */
  __ctype_cntrl,		/* control character */
  __ctype_cntrl,		/* control character */
  __ctype_cntrl,		/* control character */
  __ctype_cntrl|__ctype_space,	/* BS */
  __ctype_cntrl|__ctype_space,	/* TAB */
  __ctype_cntrl|__ctype_space,	/* LF */
  __ctype_cntrl|__ctype_space,	/* VT */
  __ctype_cntrl|__ctype_space,	/* FF */
  __ctype_cntrl|__ctype_space,	/* CR */
  __ctype_cntrl,		/* control character */

  __ctype_cntrl,		/* control character */
  __ctype_cntrl,		/* control character */
  __ctype_cntrl,		/* control character */
  __ctype_cntrl,		/* control character */
  __ctype_cntrl,		/* control character */
  __ctype_cntrl,		/* control character */
  __ctype_cntrl,		/* control character */
  __ctype_cntrl,		/* control character */
  __ctype_cntrl,		/* control character */
  __ctype_cntrl,		/* control character */
  __ctype_cntrl,		/* control character */
  __ctype_cntrl,		/* control character */
  __ctype_cntrl,		/* control character */
  __ctype_cntrl,		/* control character */
  __ctype_cntrl,		/* control character */
  __ctype_cntrl,		/* control character */
  __ctype_cntrl,		/* control character */
  
  __ctype_print|__ctype_space,	/* space */
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

  __ctype_print|__ctype_digit|__ctype_xdigit, /* digit */
  __ctype_print|__ctype_digit|__ctype_xdigit, /* digit */
  __ctype_print|__ctype_digit|__ctype_xdigit, /* digit */
  __ctype_print|__ctype_digit|__ctype_xdigit, /* digit */
  __ctype_print|__ctype_digit|__ctype_xdigit, /* digit */
  __ctype_print|__ctype_digit|__ctype_xdigit, /* digit */
  __ctype_print|__ctype_digit|__ctype_xdigit, /* digit */
  __ctype_print|__ctype_digit|__ctype_xdigit, /* digit */
  __ctype_print|__ctype_digit|__ctype_xdigit, /* digit */
  __ctype_print|__ctype_digit|__ctype_xdigit, /* digit */
  __ctype_print|__ctype_punct,	/* punctuation */
  __ctype_print|__ctype_punct,	/* punctuation */
  __ctype_print|__ctype_punct,	/* punctuation */
  __ctype_print|__ctype_punct,	/* punctuation */
  __ctype_print|__ctype_punct,	/* punctuation */
  __ctype_print|__ctype_punct,	/* punctuation */

  __ctype_print|__ctype_punct,	/* punctuation */
  __ctype_print|__ctype_upper|__ctype_xdigit, /* A-F */
  __ctype_print|__ctype_upper|__ctype_xdigit, /* A-F */
  __ctype_print|__ctype_upper|__ctype_xdigit, /* A-F */
  __ctype_print|__ctype_upper|__ctype_xdigit, /* A-F */
  __ctype_print|__ctype_upper|__ctype_xdigit, /* A-F */
  __ctype_print|__ctype_upper|__ctype_xdigit, /* A-F */
  __ctype_print|__ctype_upper,	/* G-Z */
  __ctype_print|__ctype_upper,	/* G-Z */
  __ctype_print|__ctype_upper,	/* G-Z */
  __ctype_print|__ctype_upper,	/* G-Z */
  __ctype_print|__ctype_upper,	/* G-Z */
  __ctype_print|__ctype_upper,	/* G-Z */
  __ctype_print|__ctype_upper,	/* G-Z */
  __ctype_print|__ctype_upper,	/* G-Z */
  __ctype_print|__ctype_upper,	/* G-Z */

  __ctype_print|__ctype_upper,	/* G-Z */
  __ctype_print|__ctype_upper,	/* G-Z */
  __ctype_print|__ctype_upper,	/* G-Z */
  __ctype_print|__ctype_upper,	/* G-Z */
  __ctype_print|__ctype_upper,	/* G-Z */
  __ctype_print|__ctype_upper,	/* G-Z */
  __ctype_print|__ctype_upper,	/* G-Z */
  __ctype_print|__ctype_upper,	/* G-Z */
  __ctype_print|__ctype_upper,	/* G-Z */
  __ctype_print|__ctype_upper,	/* G-Z */
  __ctype_print|__ctype_upper,	/* G-Z */
  __ctype_print|__ctype_punct,	/* punctuation */
  __ctype_print|__ctype_punct,	/* punctuation */
  __ctype_print|__ctype_punct,	/* punctuation */
  __ctype_print|__ctype_punct,	/* punctuation */
  __ctype_print|__ctype_punct,	/* punctuation */

  __ctype_print|__ctype_punct,	/* punctuation */
  __ctype_print|__ctype_lower|__ctype_xdigit, /* a-f */
  __ctype_print|__ctype_lower|__ctype_xdigit, /* a-f */
  __ctype_print|__ctype_lower|__ctype_xdigit, /* a-f */
  __ctype_print|__ctype_lower|__ctype_xdigit, /* a-f */
  __ctype_print|__ctype_lower|__ctype_xdigit, /* a-f */
  __ctype_print|__ctype_lower|__ctype_xdigit, /* a-f */
  __ctype_print|__ctype_lower,	/* g-z */
  __ctype_print|__ctype_lower,	/* g-z */
  __ctype_print|__ctype_lower,	/* g-z */
  __ctype_print|__ctype_lower,	/* g-z */
  __ctype_print|__ctype_lower,	/* g-z */
  __ctype_print|__ctype_lower,	/* g-z */
  __ctype_print|__ctype_lower,	/* g-z */
  __ctype_print|__ctype_lower,	/* g-z */
  __ctype_print|__ctype_lower,	/* g-z */

  __ctype_print|__ctype_lower,	/* g-z */
  __ctype_print|__ctype_lower,	/* g-z */
  __ctype_print|__ctype_lower,	/* g-z */
  __ctype_print|__ctype_lower,	/* g-z */
  __ctype_print|__ctype_lower,	/* g-z */
  __ctype_print|__ctype_lower,	/* g-z */
  __ctype_print|__ctype_lower,	/* g-z */
  __ctype_print|__ctype_lower,	/* g-z */
  __ctype_print|__ctype_lower,	/* g-z */
  __ctype_print|__ctype_lower,	/* g-z */
  __ctype_print|__ctype_lower,	/* g-z */
  __ctype_print|__ctype_punct,	/* punctuation */
  __ctype_print|__ctype_punct,	/* punctuation */
  __ctype_print|__ctype_punct,	/* punctuation */
  __ctype_print|__ctype_punct,	/* punctuation */
  __ctype_cntrl,				/* control character */

  __ctype_cntrl,				/* control character */
  __ctype_cntrl,				/* control character */
  __ctype_cntrl,				/* control character */
  __ctype_cntrl,				/* control character */
  __ctype_cntrl,				/* control character */
  __ctype_cntrl,				/* control character */
  __ctype_cntrl,				/* control character */
  __ctype_cntrl,				/* control character */
  __ctype_cntrl,				/* control character */
  __ctype_cntrl,				/* control character */
  __ctype_cntrl,				/* control character */
  __ctype_cntrl,				/* control character */
  __ctype_cntrl,				/* control character */
  __ctype_cntrl,				/* control character */
  __ctype_cntrl,				/* control character */
  __ctype_cntrl,				/* control character */

  __ctype_cntrl,				/* control character */
  __ctype_cntrl,				/* control character */
  __ctype_cntrl,				/* control character */
  __ctype_cntrl,				/* control character */
  __ctype_cntrl,				/* control character */
  __ctype_cntrl,				/* control character */
  __ctype_cntrl,				/* control character */
  __ctype_cntrl,				/* control character */
  __ctype_cntrl,				/* control character */
  __ctype_cntrl,				/* control character */
  __ctype_cntrl,				/* control character */
  __ctype_cntrl,				/* control character */
  __ctype_cntrl,				/* control character */
  __ctype_cntrl,				/* control character */
  __ctype_cntrl,				/* control character */
  __ctype_cntrl,				/* control character */

  __ctype_print|__ctype_space,	/* NBSP */
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

  __ctype_print|__ctype_upper,	/* upper accented */
  __ctype_print|__ctype_upper,	/* upper accented */
  __ctype_print|__ctype_upper,	/* upper accented */
  __ctype_print|__ctype_upper,	/* upper accented */
  __ctype_print|__ctype_upper,	/* upper accented */
  __ctype_print|__ctype_upper,	/* upper accented */
  __ctype_print|__ctype_upper,	/* upper accented */
  __ctype_print|__ctype_upper,	/* upper accented */
  __ctype_print|__ctype_upper,	/* upper accented */
  __ctype_print|__ctype_upper,	/* upper accented */
  __ctype_print|__ctype_upper,	/* upper accented */
  __ctype_print|__ctype_upper,	/* upper accented */
  __ctype_print|__ctype_upper,	/* upper accented */
  __ctype_print|__ctype_upper,	/* upper accented */
  __ctype_print|__ctype_upper,	/* upper accented */
  __ctype_print|__ctype_upper,	/* upper accented */

  __ctype_print|__ctype_upper,	/* upper accented */
  __ctype_print|__ctype_upper,	/* upper accented */
  __ctype_print|__ctype_upper,	/* upper accented */
  __ctype_print|__ctype_upper,	/* upper accented */
  __ctype_print|__ctype_upper,	/* upper accented */
  __ctype_print|__ctype_upper,	/* upper accented */
  __ctype_print|__ctype_upper,	/* upper accented */
  __ctype_print|__ctype_punct,	/* punctuation */
  __ctype_print|__ctype_upper,	/* upper accented */
  __ctype_print|__ctype_upper,	/* upper accented */
  __ctype_print|__ctype_upper,	/* upper accented */
  __ctype_print|__ctype_upper,	/* upper accented */
  __ctype_print|__ctype_upper,	/* upper accented */
  __ctype_print|__ctype_upper,	/* upper accented */
  __ctype_print|__ctype_upper,	/* upper accented */
  __ctype_print|__ctype_lower,	/* lower accented */

  __ctype_print|__ctype_lower,	/* lower accented */
  __ctype_print|__ctype_lower,	/* lower accented */
  __ctype_print|__ctype_lower,	/* lower accented */
  __ctype_print|__ctype_lower,	/* lower accented */
  __ctype_print|__ctype_lower,	/* lower accented */
  __ctype_print|__ctype_lower,	/* lower accented */
  __ctype_print|__ctype_lower,	/* lower accented */
  __ctype_print|__ctype_lower,	/* lower accented */
  __ctype_print|__ctype_lower,	/* lower accented */
  __ctype_print|__ctype_lower,	/* lower accented */
  __ctype_print|__ctype_lower,	/* lower accented */
  __ctype_print|__ctype_lower,	/* lower accented */
  __ctype_print|__ctype_lower,	/* lower accented */
  __ctype_print|__ctype_lower,	/* lower accented */
  __ctype_print|__ctype_lower,	/* lower accented */
  __ctype_print|__ctype_lower,	/* lower accented */

  __ctype_print|__ctype_lower,	/* lower accented */
  __ctype_print|__ctype_lower,	/* lower accented */
  __ctype_print|__ctype_lower,	/* lower accented */
  __ctype_print|__ctype_lower,	/* lower accented */
  __ctype_print|__ctype_lower,	/* lower accented */
  __ctype_print|__ctype_lower,	/* lower accented */
  __ctype_print|__ctype_lower,	/* lower accented */
  __ctype_print|__ctype_punct,	/* punctuation */
  __ctype_print|__ctype_lower,	/* lower accented */
  __ctype_print|__ctype_lower,	/* lower accented */
  __ctype_print|__ctype_lower,	/* lower accented */
  __ctype_print|__ctype_lower,	/* lower accented */
  __ctype_print|__ctype_lower,	/* lower accented */
  __ctype_print|__ctype_lower,	/* lower accented */
  __ctype_print|__ctype_lower,	/* lower accented */
  __ctype_print|__ctype_lower,	/* lower accented */
};
