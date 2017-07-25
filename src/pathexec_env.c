/* Public domain. */

#include "stralloc.h"
#include "alloc.h"
#include "str.h"
#include "byte.h"
#include "env.h"
#include "pathexec.h"

static stralloc plus;
static stralloc tmp;

int pathexec_env(const char *s,const char *t)
{
  if (!s) return 1;
  if (!stralloc_copys(&tmp,s)) return 0;
  if (t) {
    if (!stralloc_cats(&tmp,"=")) return 0;
    if (!stralloc_cats(&tmp,t)) return 0;
  }
  if (!stralloc_0(&tmp)) return 0;
  return stralloc_cat(&plus,&tmp);
}

void pathexec_env_run(const char *file, const char *const *argv)
{
  const char **e;
  unsigned int elen;
  unsigned int i;
  unsigned int j;
  unsigned int split;
  unsigned int t;

  if (!stralloc_cats(&plus,"")) return;

  elen = 0;
  for (i = 0;environ[i];++i)
    ++elen;
  for (i = 0;i < plus.len;++i)
    if (!plus.s[i])
      ++elen;

  e = (const char **) alloc((elen + 1) * sizeof(char *));
  if (!e) return;

  elen = 0;
  for (i = 0;environ[i];++i)
    e[elen++] = environ[i];

  j = 0;
  for (i = 0;i < plus.len;++i)
    if (!plus.s[i]) {
      split = str_chr(plus.s + j,'=');
      for (t = 0;t < elen;++t)
        if (byte_equal(plus.s + j,split,e[t]))
          if (e[t][split] == '=') {
            --elen;
            e[t] = e[elen];
            break;
          }
      if (plus.s[j + split])
        e[elen++] = plus.s + j;
      j = i + 1;
    }
  e[elen] = 0;

  pathexec_run(file,argv,e);
  alloc_free(e);
}

void pathexec(const char *const *argv)
{
  return pathexec_env_run(*argv, argv);
}
