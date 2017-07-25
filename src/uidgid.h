#ifndef UIDGID_H
#define UIDGID_H

#include <sys/types.h>

struct uidgid {
  uid_t uid;
  gid_t gid[61];
  int gids;
};

/* user */
extern unsigned int uidgid_get(struct uidgid *, char *);

/* [:]user[:group[:group]...] */
extern unsigned int uidgids_get(struct uidgid *, char *);

#endif
