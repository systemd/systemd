/* Public domain. */

#ifndef PATHEXEC_H
#define PATHEXEC_H

extern void pathexec_run(const char *,const char * const *,const char * const *);
extern int pathexec_env(const char *,const char *);
extern void pathexec_env_run(const char *, const char * const *);
extern void pathexec(const char * const *);

#endif
