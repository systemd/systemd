/*
 * __static_init.c
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

char **environ;

extern int main(int, char **, char **);

__noreturn __libc_init(uintptr_t *elfdata, void (*onexit)(void))
{
  int argc;
  char **argv, **envp;

  (void)onexit;			/* For now, we ignore this... */

  argc = (int)*elfdata++;
  argv = (char **)elfdata;
  envp = argv+(argc+1);

  environ = envp;
  exit(main(argc, argv, envp));
}
