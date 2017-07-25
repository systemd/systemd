#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include "uidgid.h"
#include "str.h"
#include "scan.h"

/* user */
unsigned int uidgid_get(struct uidgid *u, char *ug) {
  struct passwd *pwd =0;

  if (! (pwd =getpwnam(ug))) return(0);
  u->gid[0] =pwd->pw_gid; u->gids =1;
  u->uid =pwd->pw_uid;
  return(1);
}

/* uid:gid[:gid[:gid]...] */
unsigned int uidgids_set(struct uidgid *u, char *ug) {
  unsigned long id;
  int i;

  if (*(ug +=scan_ulong(ug, &id)) != ':') return(0);
  u->uid =(uid_t)id;
  ++ug;
  for (i =0; i < 60; ++i, ++ug) {
    ug +=scan_ulong(ug, &id);
    u->gid[i] =(gid_t)id;
    if (*ug != ':') { ++i; break; }
  }
  u->gid[i] =0;
  u->gids =i;
  if (*ug) return(0);
  return(1);
}

/* [:]user[:group[:group]...] */
unsigned int uidgids_get(struct uidgid *u, char *ug) {
  char *g =0;
  struct passwd *pwd =0;
  struct group *gr =0;
  int i, d =0;

  if (*ug == ':') return(uidgids_set(u, ug +1));
  if (ug[(d =str_chr(ug, ':'))] == ':') {
    ug[d] =0;
    g =ug +d +1;
  }
  if (! (pwd =getpwnam(ug))) { if (g) ug[d] =':'; return(0); }
  u->uid =pwd->pw_uid;
  if (! g) {
    u->gid[0] =pwd->pw_gid;
    u->gids =1;
    return(1);
  }
  ug[d] =':';
  for (i =0; i < 60; ++i) {
    if (g[(d =str_chr(g, ':'))] == ':') {
      g[d] =0;
      if (! (gr =getgrnam(g))) { g[d] =':'; return(0); }
      g[d] =':';
      u->gid[i] =gr->gr_gid;
      g +=d +1;
    }
    else {
      if (! (gr =getgrnam(g))) return(0);
      u->gid[i++] =gr->gr_gid;
      break;
    }
  }
  u->gid[i] =0;
  u->gids =i;
  return(1);
}
