/*
 * vsscanf.c
 *
 * vsscanf(), from which the rest of the scanf()
 * family is built
 */

#include <ctype.h>
#include <stdarg.h>
#include <stddef.h>
#include <inttypes.h>
#include <string.h>
#include <limits.h>
#include <stdio.h>

#ifndef LONG_BIT
#define LONG_BIT (CHAR_BIT*sizeof(long))
#endif

enum flags {
  FL_SPLAT  = 0x01,		/* Drop the value, do not assign */
  FL_INV    = 0x02,		/* Character-set with inverse */
  FL_WIDTH  = 0x04,		/* Field width specified */
  FL_MINUS  = 0x08,		/* Negative number */
};

enum ranks {
  rank_char	= -2,
  rank_short	= -1,
  rank_int 	= 0,
  rank_long	= 1,
  rank_longlong	= 2,
  rank_ptr      = INT_MAX	/* Special value used for pointers */
};

#define MIN_RANK	rank_char
#define MAX_RANK	rank_longlong

#define INTMAX_RANK	rank_longlong
#define SIZE_T_RANK	rank_long
#define PTRDIFF_T_RANK	rank_long

enum bail {
  bail_none = 0,		/* No error condition */
  bail_eof,			/* Hit EOF */
  bail_err			/* Conversion mismatch */
};

static inline const char *
skipspace(const char *p)
{
  while ( isspace((unsigned char)*p) ) p++;
  return p;
}

#undef set_bit
static inline void
set_bit(unsigned long *bitmap, unsigned int bit)
{
  bitmap[bit/LONG_BIT] |= 1UL << (bit%LONG_BIT);
}

#undef test_bit
static inline int
test_bit(unsigned long *bitmap, unsigned int bit)
{
  return (int)(bitmap[bit/LONG_BIT] >> (bit%LONG_BIT)) & 1;
}

int vsscanf(const char *buffer, const char *format, va_list ap)
{
  const char *p = format;
  char ch;
  const char *q = buffer;
  const char *qq;
  uintmax_t val = 0;
  int rank = rank_int;		/* Default rank */
  unsigned int width = UINT_MAX;
  int base;
  enum flags flags = 0;
  enum {
    st_normal,			/* Ground state */
    st_flags,			/* Special flags */
    st_width,			/* Field width */
    st_modifiers,		/* Length or conversion modifiers */
    st_match_init,		/* Initial state of %[ sequence */
    st_match,			/* Main state of %[ sequence */
    st_match_range,		/* After - in a %[ sequence */
  } state = st_normal;
  char *sarg = NULL;		/* %s %c or %[ string argument */
  enum bail bail = bail_none;
  int sign;
  int converted = 0;		/* Successful conversions */
  unsigned long matchmap[((1 << CHAR_BIT)+(LONG_BIT-1))/LONG_BIT];
  int matchinv = 0;		/* Is match map inverted? */
  unsigned char range_start = 0;

  while ( (ch = *p++) && !bail ) {
    switch ( state ) {
    case st_normal:
      if ( ch == '%' ) {
	state = st_flags;
	flags = 0; rank = rank_int; width = UINT_MAX;
      } else if ( isspace((unsigned char)ch) ) {
	q = skipspace(q);
      } else {
	if ( *q == ch )
	  q++;
	else
	  bail = bail_err;	/* Match failure */
      }
      break;

    case st_flags:
      switch ( ch ) {
      case '*':
	flags |= FL_SPLAT;
	break;
      case '0' ... '9':
	width = (ch-'0');
	state = st_width;
	flags |= FL_WIDTH;
	break;
      default:
	state = st_modifiers;
	p--;			/* Process this character again */
	break;
      }
      break;

    case st_width:
      if ( ch >= '0' && ch <= '9' ) {
	width = width*10+(ch-'0');
      } else {
	state = st_modifiers;
	p--;			/* Process this character again */
      }
      break;

    case st_modifiers:
      switch ( ch ) {
	/* Length modifiers - nonterminal sequences */
      case 'h':
	rank--;			/* Shorter rank */
	break;
      case 'l':
	rank++;			/* Longer rank */
	break;
      case 'j':
	rank = INTMAX_RANK;
	break;
      case 'z':
	rank = SIZE_T_RANK;
	break;
      case 't':
	rank = PTRDIFF_T_RANK;
	break;
      case 'L':
      case 'q':
	rank = rank_longlong;	/* long double/long long */
	break;

      default:
	/* Output modifiers - terminal sequences */
	state = st_normal;	/* Next state will be normal */
	if ( rank < MIN_RANK )	/* Canonicalize rank */
	  rank = MIN_RANK;
	else if ( rank > MAX_RANK )
	  rank = MAX_RANK;

	switch ( ch ) {
	case 'P':		/* Upper case pointer */
	case 'p':		/* Pointer */
#if 0	/* Enable this to allow null pointers by name */
	  q = skipspace(q);
	  if ( !isdigit((unsigned char)*q) ) {
	    static const char * const nullnames[] =
	    { "null", "nul", "nil", "(null)", "(nul)", "(nil)", 0 };
	    const char * const *np;

	    /* Check to see if it's a null pointer by name */
	    for ( np = nullnames ; *np ; np++ ) {
	      if ( !strncasecmp(q, *np, strlen(*np)) ) {
		val = (uintmax_t)((void *)NULL);
		goto set_integer;
	      }
	    }
	    /* Failure */
	    bail = bail_err;
	    break;
	  }
	  /* else */
#endif
	  rank = rank_ptr;
	  base = 0; sign = 0;
	  goto scan_int;

	case 'i':		/* Base-independent integer */
	  base = 0; sign = 1;
	  goto scan_int;

	case 'd':		/* Decimal integer */
	  base = 10; sign = 1;
	  goto scan_int;

	case 'o':		/* Octal integer */
	  base = 8; sign = 0;
	  goto scan_int;

	case 'u':		/* Unsigned decimal integer */
	  base = 10; sign = 0;
	  goto scan_int;
	  
	case 'x':		/* Hexadecimal integer */
	case 'X':
	  base = 16; sign = 0;
	  goto scan_int;

	case 'n':		/* Number of characters consumed */
	  val = (q-buffer);
	  goto set_integer;

	scan_int:
	  q = skipspace(q);
	  if ( !*q ) {
	    bail = bail_eof;
	    break;
	  }
	  val = strntoumax(q, (char **)&qq, base, width);
	  if ( qq == q ) {
	    bail = bail_err;
	    break;
	  }
	  q = qq;
	  converted++;
	  /* fall through */

	set_integer:
	  if ( !(flags & FL_SPLAT) ) {
	    switch(rank) {
	    case rank_char:
	      *va_arg(ap, unsigned char *) = (unsigned char)val;
	      break;
	    case rank_short:
	      *va_arg(ap, unsigned short *) = (unsigned short)val;
	      break;
	    case rank_int:
	      *va_arg(ap, unsigned int *) = (unsigned int)val;
	      break;
	    case rank_long:
	      *va_arg(ap, unsigned long *) = (unsigned long)val;
	      break;
	    case rank_longlong:
	      *va_arg(ap, unsigned long long *) = (unsigned long long)val;
	      break;
	    case rank_ptr:
	      *va_arg(ap, void **) = (void *)(uintptr_t)val;
	      break;
	    }
	  }
	  break;
	  
	case 'c':               /* Character */
          width = (flags & FL_WIDTH) ? width : 1; /* Default width == 1 */
          sarg = va_arg(ap, char *);
          while ( width-- ) {
            if ( !*q ) {
              bail = bail_eof;
              break;
            }
            *sarg++ = *q++;
          }
          if ( !bail )
            converted++;
          break;

        case 's':               /* String */
	  {
	    char *sp;
	    sp = sarg = va_arg(ap, char *);
	    while ( width-- && *q && !isspace((unsigned char)*q) ) {
	      *sp++ = *q++;
	    }
	    if ( sarg != sp ) {
	      *sp = '\0';	/* Terminate output */
	      converted++;
	    } else {
	      bail = bail_eof;
	    }
	  }
	  break;
	  
	case '[':		/* Character range */
	  sarg = va_arg(ap, char *);
	  state = st_match_init;
	  matchinv = 0;
	  memset(matchmap, 0, sizeof matchmap);
	  break;

	case '%':		/* %% sequence */
	  if ( *q == '%' )
	    q++;
	  else
	    bail = bail_err;
	  break;

	default:		/* Anything else */
	  bail = bail_err;	/* Unknown sequence */
	  break;
	}
      }
      break;
    
    case st_match_init:		/* Initial state for %[ match */
      if ( ch == '^' && !(flags & FL_INV) ) {
	matchinv = 1;
      } else {
	set_bit(matchmap, (unsigned char)ch);
	state = st_match;
      }
      break;
      
    case st_match:		/* Main state for %[ match */
      if ( ch == ']' ) {
	goto match_run;
      } else if ( ch == '-' ) {
	range_start = (unsigned char)ch;
	state = st_match_range;
      } else {
	set_bit(matchmap, (unsigned char)ch);
      }
      break;
      
    case st_match_range:		/* %[ match after - */
      if ( ch == ']' ) {
	set_bit(matchmap, (unsigned char)'-'); /* - was last character */
	goto match_run;
      } else {
	int i;
	for ( i = range_start ; i < (unsigned char)ch ; i++ )
	  set_bit(matchmap, i);
	state = st_match;
      }
      break;

    match_run:			/* Match expression finished */
      qq = q;
      while ( width && *q && test_bit(matchmap, (unsigned char)*q)^matchinv ) {
	*sarg++ = *q++;
      }
      if ( q != qq ) {
	*sarg = '\0';
	converted++;
      } else {
	bail = *q ? bail_err : bail_eof;
      }
      break;
    }
  }

  if ( bail == bail_eof && !converted )
    converted = -1;		/* Return EOF (-1) */

  return converted;
}
