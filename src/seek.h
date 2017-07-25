/* Public domain. */

#ifndef SEEK_H
#define SEEK_H

typedef unsigned long seek_pos;

extern seek_pos seek_cur(int);

extern int seek_set(int,seek_pos);
extern int seek_end(int);

extern int seek_trunc(int,seek_pos);

#define seek_begin(fd) (seek_set((fd),(seek_pos) 0))

#endif
