/* Public domain. */

#ifndef GEN_ALLOC_H
#define GEN_ALLOC_H

#define GEN_ALLOC_typedef(ta,type,field,len,a) \
  typedef struct ta { type *field; unsigned int len; unsigned int a; } ta;

#endif
