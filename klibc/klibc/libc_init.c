/*
 * libc_init.c
 *
 * This function takes the raw data block set up by the ELF loader
 * in the kernel and parses it.  It is invoked by crt0.S which makes
 * any necessary adjustments and passes calls this function using
 * the standard C calling convention.
 *
 * The arguments are:
 *  uintptr_t *elfdata	 -- The ELF loader data block; usually from the stack.
 *                          Basically a pointer to argc.
 *  void (*onexit)(void) -- Function to install into onexit
 */

#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>
#include <klibc/compiler.h>
#include <elf.h>

/* This file is included from __static_init.c or __shared_init.c */
#ifndef SHARED
# error "SHARED should be defined to 0 or 1"
#endif

char **environ;
unsigned int __page_size, __page_shift;

struct auxentry {
  uintptr_t type;
  uintptr_t v;
};

__noreturn __libc_init(uintptr_t *elfdata, void (*onexit)(void))
{
  int argc;
  char **argv, **envp, **envend;
  struct auxentry *auxentry;
#if SHARED
  typedef int (*main_t)(int, char **, char **);
  main_t MAIN = NULL;
#else
  extern int main(int, char **, char **);
#define MAIN main
#endif
  unsigned int page_size = 0, page_shift = 0;

  (void)onexit;			/* For now, we ignore this... */

  argc = (int)*elfdata++;
  argv = (char **)elfdata;
  envp = argv+(argc+1);

  /* The auxillary entry vector is after all the environment vars */
  for ( envend = envp ; *envend ; envend++ );
  auxentry = (struct auxentry *)(envend+1);

  while ( auxentry->type ) {
    switch ( auxentry->type ) {
#if SHARED
    case AT_ENTRY:
      MAIN = (main_t)(auxentry->v);
      break;
#endif
    case AT_PAGESZ:
      page_size = (int)(auxentry->v);
      break;
    }
    auxentry++;
  }

  __page_size = page_size;

#if defined(__i386__) || defined(__x86_64__)
  asm("bsrl %1,%0" : "=r" (page_shift) : "rm" (page_size));
#else
  while ( page_size > 1 ) {
    page_shift++;
    page_size >>= 1;
  }
#endif
  __page_shift = page_shift;

  environ = envp;
  exit(MAIN(argc, argv, envp));
}
