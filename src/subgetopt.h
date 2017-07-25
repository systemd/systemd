/* Public domain. */

#ifndef SUBGETOPT_H
#define SUBGETOPT_H

#ifndef SUBGETOPTNOSHORT
#define sgopt subgetopt
#define sgoptarg subgetoptarg
#define sgoptind subgetoptind
#define sgoptpos subgetoptpos
#define sgoptproblem subgetoptproblem
#define sgoptprogname subgetoptprogname
#define sgoptdone subgetoptdone
#endif

#define SUBGETOPTDONE -1

extern int subgetopt(int,const char *const *,const char *);
extern const char *subgetoptarg;
extern int subgetoptind;
extern int subgetoptpos;
extern int subgetoptproblem;
extern const char *subgetoptprogname;
extern int subgetoptdone;

#endif
