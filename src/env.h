/* Public domain. */

#ifndef ENV_H
#define ENV_H

extern char **environ;

extern /*@null@*/char *env_get(const char *);

#endif
