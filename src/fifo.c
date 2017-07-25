/* Public domain. */

#include <sys/types.h>
#include <sys/stat.h>
#include "hasmkffo.h"
#include "fifo.h"

#ifdef HASMKFIFO
int fifo_make(const char *fn,int mode) { return mkfifo(fn,mode); }
#else
int fifo_make(const char *fn,int mode) { return mknod(fn,S_IFIFO | mode,0); }
#endif
