/*
 * sys/module.h
 *
 * This is a bastardized version of linux/module.h, since the latter
 * doesn't have __KERNEL__ guards where it needs them...
 */

#ifndef _SYS_MODULE_H
#define _SYS_MODULE_H

/*
 * Dynamic loading of modules into the kernel.
 *
 * Rewritten by Richard Henderson <rth@tamu.edu> Dec 1996
 */

#include <asm/atomic.h>

/* Don't need to bring in all of uaccess.h just for this decl.  */
struct exception_table_entry;

/* Used by get_kernel_syms, which is obsolete.  */
struct kernel_sym
{
	unsigned long value;
	char name[60];		/* should have been 64-sizeof(long); oh well */
};

struct module_symbol
{
	unsigned long value;
	const char *name;
};

struct module_ref
{
	struct module *dep;	/* "parent" pointer */
	struct module *ref;	/* "child" pointer */
	struct module_ref *next_ref;
};

/* TBD */
struct module_persist;

struct module
{
	unsigned long size_of_struct;	/* == sizeof(module) */
	struct module *next;
	const char *name;
	unsigned long size;

	union
	{
		atomic_t usecount;
		long pad;
	} uc;				/* Needs to keep its size - so says rth */

	unsigned long flags;		/* AUTOCLEAN et al */

	unsigned nsyms;
	unsigned ndeps;

	struct module_symbol *syms;
	struct module_ref *deps;
	struct module_ref *refs;
	int (*init)(void);
	void (*cleanup)(void);
	const struct exception_table_entry *ex_table_start;
	const struct exception_table_entry *ex_table_end;
#ifdef __alpha__
	unsigned long gp;
#endif
	/* Members past this point are extensions to the basic
	   module support and are optional.  Use mod_member_present()
	   to examine them.  */
	const struct module_persist *persist_start;
	const struct module_persist *persist_end;
	int (*can_unload)(void);
	int runsize;			/* In modutils, not currently used */
	const char *kallsyms_start;	/* All symbols for kernel debugging */
	const char *kallsyms_end;
	const char *archdata_start;	/* arch specific data for module */
	const char *archdata_end;
	const char *kernel_data;	/* Reserved for kernel internal use */
};

struct module_info
{
	unsigned long addr;
	unsigned long size;
	unsigned long flags;
	long usecount;
};

/* Bits of module.flags.  */

#define MOD_UNINITIALIZED	0
#define MOD_RUNNING		1
#define MOD_DELETED		2
#define MOD_AUTOCLEAN		4
#define MOD_VISITED  		8
#define MOD_USED_ONCE		16
#define MOD_JUST_FREED		32
#define MOD_INITIALIZING	64

/* Values for query_module's which.  */

#define QM_MODULES	1
#define QM_DEPS		2
#define QM_REFS		3
#define QM_SYMBOLS	4
#define QM_INFO		5

/* Can the module be queried? */
#define MOD_CAN_QUERY(mod) (((mod)->flags & (MOD_RUNNING | MOD_INITIALIZING)) && !((mod)->flags & MOD_DELETED))

/* When struct module is extended, we must test whether the new member
   is present in the header received from insmod before we can use it.  
   This function returns true if the member is present.  */

#define mod_member_present(mod,member) 					\
	((unsigned long)(&((struct module *)0L)->member + 1)		\
	 <= (mod)->size_of_struct)

/*
 * Ditto for archdata.  Assumes mod->archdata_start and mod->archdata_end
 * are validated elsewhere.
 */
#define mod_archdata_member_present(mod, type, member)			\
	(((unsigned long)(&((type *)0L)->member) +			\
	  sizeof(((type *)0L)->member)) <=				\
	 ((mod)->archdata_end - (mod)->archdata_start))
	 

/* Check if an address p with number of entries n is within the body of module m */
#define mod_bound(p, n, m) ((unsigned long)(p) >= ((unsigned long)(m) + ((m)->size_of_struct)) && \
	         (unsigned long)((p)+(n)) <= (unsigned long)(m) + (m)->size)

/* Backwards compatibility definition.  */

#define GET_USE_COUNT(module)	(atomic_read(&(module)->uc.usecount))

/* Poke the use count of a module.  */

#define __MOD_INC_USE_COUNT(mod)					\
	(atomic_inc(&(mod)->uc.usecount), (mod)->flags |= MOD_VISITED|MOD_USED_ONCE)
#define __MOD_DEC_USE_COUNT(mod)					\
	(atomic_dec(&(mod)->uc.usecount), (mod)->flags |= MOD_VISITED)
#define __MOD_IN_USE(mod)						\
	(mod_member_present((mod), can_unload) && (mod)->can_unload	\
	 ? (mod)->can_unload() : atomic_read(&(mod)->uc.usecount))

/* Indirect stringification.  */

#define __MODULE_STRING_1(x)	#x
#define __MODULE_STRING(x)	__MODULE_STRING_1(x)

#endif /* _SYS_MODULE_H */
