/*
 * netinet/udp.h
 */

#ifndef _NETINET_UDP_H
#define _NETINET_UDP_H

/*
 * We would include linux/udp.h, but it brings in too much other stuff
 */

struct udphdr {
	__u16	source;
	__u16	dest;
	__u16	len;
	__u16	check;
};

#endif /* _NETINET_UDP_H */
