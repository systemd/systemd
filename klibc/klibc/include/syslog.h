/*
 * syslog.h
 */

#ifndef _SYSLOG_H
#define _SYSLOG_H

#include <klibc/extern.h>

/* Alert levels */
#define LOG_EMERG	0
#define LOG_ALERT	1
#define LOG_CRIT	2
#define LOG_ERR		3
#define LOG_WARNING	4
#define LOG_NOTICE	5
#define LOG_INFO	6
#define LOG_DEBUG	7

#define LOG_PRIMASK	7
#define LOG_PRI(x)	((x) & LOG_PRIMASK)


/* Facilities; not actually used */
#define LOG_KERN	0000
#define LOG_USER	0010
#define LOG_MAIL	0020
#define LOG_DAEMON	0030
#define LOG_AUTH	0040
#define LOG_SYSLOG	0050
#define LOG_LPR		0060
#define LOG_NEWS	0070
#define LOG_UUCP	0100
#define LOG_CRON	0110
#define LOG_AUTHPRIV	0120
#define LOG_FTP		0130
#define LOG_LOCAL0	0200
#define LOG_LOCAL1	0210
#define LOG_LOCAL2	0220
#define LOG_LOCAL3	0230
#define LOG_LOCAL4	0240
#define LOG_LOCAL5	0250
#define LOG_LOCAL6	0260
#define LOG_LOCAL7	0270

#define LOG_FACMASK	01770
#define LOG_FAC(x)	(((x) >> 3) & (LOG_FACMASK >> 3))

__extern void openlog(const char *, int, int);
__extern void syslog(int, const char *, ...);
__extern void closelog(void);

#endif /* _SYSLOG_H */
