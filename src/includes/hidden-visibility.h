/*
 * Written by Mike Frysinger
 * Placed in the Public Domain
 */

#ifndef _HIDDEN_VISIBILITY_H_
#define _HIDDEN_VISIBILITY_H_

#if defined(__ELF__) && defined(__GNUC__)
# define __hidden_asmname(name) __hidden_asmname1 (__USER_LABEL_PREFIX__, name)
# define __hidden_asmname1(prefix, name) __hidden_asmname2(prefix, name)
# define __hidden_asmname2(prefix, name) #prefix name
# define __hidden_proto(name, internal) \
	extern __typeof (name) name __asm__ (__hidden_asmname (#internal)) \
	__attribute__ ((visibility ("hidden")));
# define __hidden_ver(local, internal, name) \
   extern __typeof (name) __EI_##name __asm__(__hidden_asmname (#internal)); \
   extern __typeof (name) __EI_##name __attribute__((alias (__hidden_asmname1 (,#local))))
# define hidden_proto(name) __hidden_proto(name, __RC_##name)
# define hidden_def(name) __hidden_ver(__RC_##name, name, name);
#else
# define hidden_proto(name)
# define hidden_def(name)
#endif

#endif
