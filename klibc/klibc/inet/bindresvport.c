/*
 * inet/bindresvport.c
 */

#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>

#define START_PORT	768
#define END_PORT	IPPORT_RESERVED
#define NUM_PORTS	(END_PORT - START_PORT)

int bindresvport(int sd, struct sockaddr_in *sin)
{
	struct sockaddr_in me;
	static short port;
	int ret = 0;
	int i;

	if (sin == NULL) {
		memset(&me, 0, sizeof(me));
		sin = &me;
		sin->sin_family = AF_INET;
	} else if (sin->sin_family != AF_INET) {
		errno = EPFNOSUPPORT;
		return -1;
	}
	
	if (port == 0) {
		port = START_PORT + (getpid() % NUM_PORTS);
	}
	
	for (i = 0; i < NUM_PORTS; i++, port++) {
		if (port == END_PORT)
			port = START_PORT;
		sin->sin_port = htons(port);
		if ((ret = bind(sd, (struct sockaddr *)sin, sizeof(*sin))) != -1)
			break;
	}

	return ret;
}
