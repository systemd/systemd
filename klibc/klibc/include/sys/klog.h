/*
 * sys/klog.h
 */

#ifndef _SYS_KLOG_H
#define _SYS_KLOG_H

#include <klibc/extern.h>

#define KLOG_CLOSE	0
#define KLOG_OPEN	1
#define KLOG_READ	2
#define KLOG_READ_ALL	3
#define KLOG_READ_CLEAR	4
#define KLOG_CLEAR	5
#define KLOG_DISABLE	6
#define KLOG_ENABLE	7
#define KLOG_SETLEVEL	8
#define KLOG_UNREADSIZE	9
#define KLOG_WRITE	10

__extern int klogctl(int, char *, int);

#endif /* _SYS_KLOG_H */
