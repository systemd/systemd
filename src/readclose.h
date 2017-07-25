/* Public domain. */

#ifndef READCLOSE_H
#define READCLOSE_H

#include "stralloc.h"

extern int readclose_append(int,stralloc *,unsigned int);
extern int readclose(int,stralloc *,unsigned int);

#endif
