/*
 * netinet/in.h
 */

#ifndef _NETINET_IN_H
#define _NETINET_IN_H

/* added this include by Mats Petersson */
#include <linux/socket.h>

#include <klibc/extern.h>
#include <stdint.h>
#include <endian.h>		/* Must be included *before* <linux/in.h> */
#include <linux/in.h>

#ifndef htons
# define htons(x)	__cpu_to_be16(x)
#endif
#ifndef ntohs
# define ntohs(x)	__be16_to_cpu(x)
#endif
#ifndef htonl
# define htonl(x)	__cpu_to_be32(x)
#endif
#ifndef ntohl
# define ntohl(x)	__be32_to_cpu(x)
#endif

#define IPPORT_RESERVED	1024

__extern int bindresvport (int sd, struct sockaddr_in *sin);

#endif /* _NETINET_IN_H */
