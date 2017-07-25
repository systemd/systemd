/* Public domain. */

#ifndef OPEN_H
#define OPEN_H

extern int open_read(const char *);
extern int open_excl(const char *);
extern int open_append(const char *);
extern int open_trunc(const char *);
extern int open_write(const char *);

#endif
