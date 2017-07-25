/* Public domain. */

#ifndef GEN_ALLOC_DEFS_H
#define GEN_ALLOC_DEFS_H

#define GEN_ALLOC_ready(ta,type,field,len,a,i,n,x,base,ta_ready) \
int ta_ready(register ta *x,register unsigned int n) \
{ register unsigned int i; \
  if (x->field) { \
    i = x->a; \
    if (n > i) { \
      x->a = base + n + (n >> 3); \
      if (alloc_re(&x->field,i * sizeof(type),x->a * sizeof(type))) return 1; \
      x->a = i; return 0; } \
    return 1; } \
  x->len = 0; \
  return !!(x->field = (type *) alloc((x->a = n) * sizeof(type))); }

#define GEN_ALLOC_readyplus(ta,type,field,len,a,i,n,x,base,ta_rplus) \
int ta_rplus(register ta *x,register unsigned int n) \
{ register unsigned int i; \
  if (x->field) { \
    i = x->a; n += x->len; \
    if (n > i) { \
      x->a = base + n + (n >> 3); \
      if (alloc_re(&x->field,i * sizeof(type),x->a * sizeof(type))) return 1; \
      x->a = i; return 0; } \
    return 1; } \
  x->len = 0; \
  return !!(x->field = (type *) alloc((x->a = n) * sizeof(type))); }

#define GEN_ALLOC_append(ta,type,field,len,a,i,n,x,base,ta_rplus,ta_append) \
int ta_append(register ta *x,register const type *i) \
{ if (!ta_rplus(x,1)) return 0; x->field[x->len++] = *i; return 1; }

#endif
