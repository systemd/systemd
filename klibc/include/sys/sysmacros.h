/*
 * sys/sysmacros.h
 *
 * Constructs to create and pick apart dev_t.  This applies to the Linux 2.6
 * 32-bit dev_t format.
 */

#ifndef _SYS_SYSMACROS_H
#define _SYS_SYSMACROS_H

#ifndef _SYS_TYPES_H
# include <sys/types.h>
#endif

static __inline__ int major(dev_t __d)
{
  return (__d >> 8) & 0xfff;
}

static __inline__ int minor(dev_t __d)
{
  return (__d & 0xff) | ((__d >> 12) & 0xfff00);
}

static __inline__ dev_t makedev(int __ma, int __mi)
{
  return ((__ma & 0xfff) << 8) | (__mi & 0xff) | ((__mi & 0xfff00) << 12);
}

#endif /* _SYS_SYSMACROS_H */

