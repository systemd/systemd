/*
 * arpa/inet.h
 */

#ifndef _ARPA_INET_H
#define _ARPA_INET_H

#include <klibc/extern.h>
#include <stdint.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/in6.h>

__extern uint32_t inet_addr(const char *);
__extern int inet_aton(const char *, struct in_addr *);
__extern char *inet_ntoa(struct in_addr);
__extern int inet_pton(int, const char *, void *);
__extern const char *inet_ntop(int, const void *, char *, size_t);
__extern unsigned int inet_nsap_addr(const char *, unsigned char *, int);
__extern char *inet_nsap_ntoa(int, const unsigned char *, char *);

#endif /* _ARPA_INET_H */


