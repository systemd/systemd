#include <sys/types.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <sys/mount.h>
#include <netinet/in.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/* Default path we try to mount. "%s" gets replaced by our IP address */
#define NFS_ROOT		"/tftpboot/%s"
#define NFS_DEF_FILE_IO_BUFFER_SIZE	4096
#define NFS_MAXPATHLEN	1024
#define NFS_MNT_PROGRAM	100005
#define NFS_MNT_PORT	627
#define NFS_PROGRAM	100003
#define NFS_PORT	2049
#define NFS2_VERSION		2
#define NFS3_VERSION		3
#define NFS_MNT_PROGRAM		100005
#define NFS_MNT_VERSION		1
#define NFS_MNT3_VERSION	3
#define MNTPROC_MNT		1
#define MOUNTPROC3_MNT		1
#define RPC_PMAP_PROGRAM	100000
#define RPC_PMAP_VERSION	2
#define RPC_PMAP_PORT		111

#define NFS2_FHSIZE	32
#define NFS3_FHSIZE	64

#define RPC_VERSION 2

enum rpc_msg_type {
	RPC_CALL = 0,
	RPC_REPLY = 1
};

enum rpc_auth_flavor {
	RPC_AUTH_NULL  = 0,
	RPC_AUTH_UNIX  = 1,
	RPC_AUTH_SHORT = 2,
	RPC_AUTH_DES   = 3,
	RPC_AUTH_KRB   = 4,
};

enum rpc_reply_stat {
	RPC_MSG_ACCEPTED = 0,
	RPC_MSG_DENIED = 1
};

#define NFS_MAXFHSIZE		64
struct nfs_fh {
	unsigned short		size;
	unsigned char		data[NFS_MAXFHSIZE];
};

struct nfs2_fh {
	char			data[NFS2_FHSIZE];
};

#define NFS_MOUNT_VERSION	4

struct nfs_mount_data {
	int		version;
	int		fd;
	struct nfs2_fh	old_root;
	int		flags;
	int		rsize;
	int		wsize;
	int		timeo;
	int		retrans;
	int		acregmin;
	int		acregmax;
	int		acdirmin;
	int		acdirmax;
	struct sockaddr_in addr;
	char		hostname[256];
	int		namlen;
	unsigned int	bsize;
	struct nfs_fh	root;
};

#define NFS_MOUNT_SOFT		0x0001	/* 1 */
#define NFS_MOUNT_INTR		0x0002	/* 1 */
#define NFS_MOUNT_SECURE	0x0004	/* 1 */
#define NFS_MOUNT_POSIX		0x0008	/* 1 */
#define NFS_MOUNT_NOCTO		0x0010	/* 1 */
#define NFS_MOUNT_NOAC		0x0020	/* 1 */
#define NFS_MOUNT_TCP		0x0040	/* 2 */
#define NFS_MOUNT_VER3		0x0080	/* 3 */
#define NFS_MOUNT_KERBEROS	0x0100	/* 3 */
#define NFS_MOUNT_NONLM		0x0200	/* 3 */
#define NFS_MOUNT_BROKEN_SUID	0x0400	/* 4 */
#define NFS_MOUNT_FLAGMASK	0xFFFF

static char nfs_root_name[256];
static u_int32_t root_server_addr;
static char root_server_path[256];

/* Address of NFS server */
static u_int32_t servaddr;

/* Name of directory to mount */
static char nfs_path[NFS_MAXPATHLEN];

/* NFS-related data */
static struct nfs_mount_data nfs_data = {
	.version  =	NFS_MOUNT_VERSION,
	.flags    =	NFS_MOUNT_NONLM,	/* No lockd in nfs root yet */
	.rsize    =	NFS_DEF_FILE_IO_BUFFER_SIZE,
	.wsize    =	NFS_DEF_FILE_IO_BUFFER_SIZE,
	.bsize	  =	0,
	.timeo    =	7,
	.retrans  =	3,
	.acregmin =	3,
	.acregmax =	60,
	.acdirmin =	30,
	.acdirmax =	60,
};
static int nfs_port = -1;
static int mount_port;

/***************************************************************************

			     Parsing of options

 ***************************************************************************/

/*
 *  The following integer options are recognized
 */
static struct nfs_int_opts {
	const char *name;
	int  *val;
} root_int_opts[] = {
	{ "port",	&nfs_port },
	{ "rsize",	&nfs_data.rsize },
	{ "wsize",	&nfs_data.wsize },
	{ "timeo",	&nfs_data.timeo },
	{ "retrans",	&nfs_data.retrans },
	{ "acregmin",	&nfs_data.acregmin },
	{ "acregmax",	&nfs_data.acregmax },
	{ "acdirmin",	&nfs_data.acdirmin },
	{ "acdirmax",	&nfs_data.acdirmax },
	{ NULL,		NULL }
};

/*
 *  And now the flag options
 */
static struct nfs_bool_opts {
	const char *name;
	int  and_mask;
	int  or_mask;
} root_bool_opts[] = {
	{ "soft",	~NFS_MOUNT_SOFT,	NFS_MOUNT_SOFT },
	{ "hard",	~NFS_MOUNT_SOFT,	0 },
	{ "intr",	~NFS_MOUNT_INTR,	NFS_MOUNT_INTR },
	{ "nointr",	~NFS_MOUNT_INTR,	0 },
	{ "posix",	~NFS_MOUNT_POSIX,	NFS_MOUNT_POSIX },
	{ "noposix",	~NFS_MOUNT_POSIX,	0 },
	{ "cto",	~NFS_MOUNT_NOCTO,	0 },
	{ "nocto",	~NFS_MOUNT_NOCTO,	NFS_MOUNT_NOCTO },
	{ "ac",		~NFS_MOUNT_NOAC,	0 },
	{ "noac",	~NFS_MOUNT_NOAC,	NFS_MOUNT_NOAC },
	{ "lock",	~NFS_MOUNT_NONLM,	0 },
	{ "nolock",	~NFS_MOUNT_NONLM,	NFS_MOUNT_NONLM },
#ifdef CONFIG_NFS_V3
	{ "v2",		~NFS_MOUNT_VER3,	0 },
	{ "v3",		~NFS_MOUNT_VER3,	NFS_MOUNT_VER3 },
#endif
	{ "udp",	~NFS_MOUNT_TCP,		0 },
	{ "tcp",	~NFS_MOUNT_TCP,		NFS_MOUNT_TCP },
	{ "broken_suid",~NFS_MOUNT_BROKEN_SUID,	NFS_MOUNT_BROKEN_SUID },
	{ NULL,		0,			0 }
};
/*
 *  Parse option string.
 */
static void root_nfs_parse(char *name, char *buf)
{
	char *options, *val, *cp;

	if ((options = strchr(name, ','))) {
		*options++ = 0;
		cp = strtok(options, ",");
		while (cp) {
			if ((val = strchr(cp, '='))) {
				struct nfs_int_opts *opts = root_int_opts;
				*val++ = '\0';
				while (opts->name && strcmp(opts->name, cp))
					opts++;
				if (opts->name)
					*(opts->val) = (int) strtoul(val, NULL, 10);
			} else {
				struct nfs_bool_opts *opts = root_bool_opts;
				while (opts->name && strcmp(opts->name, cp))
					opts++;
				if (opts->name) {
					nfs_data.flags &= opts->and_mask;
					nfs_data.flags |= opts->or_mask;
				}
			}
			cp = strtok(NULL, ",");
		}
	}
	if (name[0] && strcmp(name, "default")) {
		strncpy(buf, name, NFS_MAXPATHLEN-1);
		buf[NFS_MAXPATHLEN-1] = 0;
	}
}

/*
 *  Prepare the NFS data structure and parse all options.
 */
static int root_nfs_name(char *name)
{
	char buf[NFS_MAXPATHLEN];
	struct utsname uname_buf;

	/* Set some default values */
	strcpy(buf, NFS_ROOT);

	/* Process options received from the remote server */
	root_nfs_parse(root_server_path, buf);

	/* Override them by options set on kernel command-line */
	root_nfs_parse(name, buf);

	uname(&uname_buf);
	if (strlen(buf) + strlen(uname_buf.nodename) > NFS_MAXPATHLEN) {
		printf("nfsroot: Pathname for remote directory too long.\n");
		return -1;
	}
	sprintf(nfs_path, buf, uname_buf.nodename);

	return 1;
}

/***************************************************************************

	       Routines to actually mount the root directory

 ***************************************************************************/

/*
 *  Construct sockaddr_in from address and port number.
 */
static inline void
set_sockaddr(struct sockaddr_in *sin, u_int32_t addr, u_int16_t port)
{
	memset(sin, 0, sizeof(*sin));
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = addr;
	sin->sin_port = port;
}

/*
 * Extremely crude RPC-over-UDP call. We get an already encoded request
 * to pass, we do that and put the reply into buffer. That (and callers
 * below - getport, getfh2 and getfh3) should be replaced with proper
 * librpc use. Now, if we only had one that wasn't bloated as a dead
 * gnu that had lied for a while under the sun...
 */

static u_int32_t XID;
static int flag;
static void timeout(int n)
{
	(void)n;
	flag = 1;
}
static int do_call(struct sockaddr_in *sin, u_int32_t msg[], u_int32_t rmsg[],
		u_int32_t len, u_int32_t rlen)
{
	struct sockaddr_in from;
	int slen = sizeof(struct sockaddr_in);
	struct timeval tv = {1, 0};
	int n;
	int fd;

	signal(SIGALRM, timeout);
	fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (fd < 0)
		goto Esocket;
	setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (void*)&tv, sizeof(tv));
	len *= 4;
	if (sendto(fd, msg, len, 0, (struct sockaddr *)sin, slen)!=(int)len)
		goto Esend;
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (void*)&tv, sizeof(tv));
	alarm(0);
	flag = 0;
	alarm(5);
	rlen *= 4;
	do  {
		slen = sizeof(from);
		n = recvfrom(fd, rmsg, rlen, 0, (struct sockaddr*)&from, &slen);
		if (flag || n < 0)
			goto Erecv;
	} while (memcmp(&from, sin, sizeof(from)) || rmsg[0] != msg[0]);

	if (n < 6*4 || n % 4 || ntohl(rmsg[1]) != 1 || rmsg[2] ||
					rmsg[3] || rmsg[4] || rmsg[5])
		goto Einval;
	alarm(0);
	close(fd);
	return n / 4 - 6;

Esend:	printf("rpc: write failed\n");
	goto out;
Erecv:	printf("rpc: read failed\n");
	goto out;
Einval:	printf("rpc: invalid response\n");
	goto out;
Esocket:printf("rpc: can't create socket\n");
	return -1;
out:
	alarm(0);
	close(fd);
	return -1;
}

enum {
	PMAP_GETPORT = 3
};

static void do_header(u_int32_t msg[], u_int32_t prog, u_int32_t vers, u_int32_t proc)
{
	msg[0] = XID++;
	msg[1] = htonl(RPC_CALL);
	msg[2] = htonl(RPC_VERSION);
	msg[3] = htonl(prog);
	msg[4] = htonl(vers);
	msg[5] = htonl(proc);
	msg[6] = htonl(RPC_AUTH_NULL);
	msg[7] = htonl(0);
	msg[8] = htonl(RPC_AUTH_NULL);
	msg[9] = htonl(0);
}

static int getport(u_int32_t prog, u_int32_t vers, u_int32_t prot)
{
	struct sockaddr_in sin;
	unsigned msg[14];
	unsigned rmsg[7];
	int n;
	set_sockaddr(&sin, servaddr, htons(RPC_PMAP_PORT));
	do_header(msg, RPC_PMAP_PROGRAM, RPC_PMAP_VERSION, PMAP_GETPORT);
	msg[10] = htonl(prog);
	msg[11] = htonl(vers);
	msg[12] = htonl(prot);
	msg[13] = htonl(0);
	n = do_call(&sin, msg, rmsg, 14, 7);
	if (n <= 0)
		return -1;
	else
		return ntohl(rmsg[6]);
}

static int getfh2(void)
{
	struct sockaddr_in sin;
	unsigned msg[10+1+256/4];
	unsigned rmsg[6 + 1 + NFS2_FHSIZE/4];
	int n;
	int len = strlen(nfs_path);
	set_sockaddr(&sin, servaddr, mount_port);

	if (len > 255) {
		printf("nfsroot: pathname is too long");
		return -1;
	}
	memset(msg, 0, sizeof(msg));
	do_header(msg, NFS_MNT_PROGRAM, NFS_MNT_VERSION, MNTPROC_MNT);
	msg[10] = htonl(len);
	strcpy((char*)&msg[11], nfs_path);
	n = do_call(&sin, msg, rmsg, 11 + (len + 3)/4, 7 + NFS2_FHSIZE/4);
	if (n < 0)
		return -1;
	if (n != NFS2_FHSIZE/4 + 1)
		goto Esize;
	if (rmsg[6]) {
		printf("nfsroot: mountd returned an error (%d)",htonl(rmsg[6]));
		return -1;
	}
	nfs_data.root.size = NFS2_FHSIZE;
	memcpy(nfs_data.root.data, &rmsg[7], NFS2_FHSIZE);
	return 0;
Esize:
	printf("nfsroot: bad fhandle size");
	return -1;
}

static int getfh3(void)
{
	struct sockaddr_in sin;
	unsigned msg[10+1+256/4];
	unsigned rmsg[6 + 1 + 1 + NFS3_FHSIZE/4];
	int n;
	int len = strlen(nfs_path);
	int size;
	set_sockaddr(&sin, servaddr, mount_port);

	if (len > 255) {
		printf("nfsroot: pathname is too long");
		return -1;
	}
	memset(msg, 0, sizeof(msg));
	do_header(msg, NFS_MNT_PROGRAM, NFS_MNT3_VERSION, MOUNTPROC3_MNT);
	msg[10] = htonl(len);
	strcpy((char*)&msg[11], nfs_path);
	n = do_call(&sin, msg, rmsg, 11 + (len + 3)/4, 8 + NFS3_FHSIZE/4);
	if (n < 0)
		return -1;
	if (n <= 2)
		goto Esize;
	if (rmsg[6]) {
		printf("nfsroot: mountd returned an error (%d)",htonl(rmsg[6]));
		return -1;
	}
	size = ntohl(rmsg[7]);
	if (size > NFS3_FHSIZE || n != 2 + size/4)
		goto Esize;
	nfs_data.root.size = size;
	memcpy(nfs_data.root.data, &rmsg[8], size);
	return 0;
Esize:
	printf("nfsroot: bad fhandle size");
	return -1;
}

/*
 *  Use portmapper to find mountd and nfsd port numbers if not overriden
 *  by the user. Use defaults if portmapper is not available.
 *  XXX: Is there any nfs server with no portmapper?
 */
static int root_nfs_ports(void)
{
	int port;
	int nfsd_ver, mountd_ver;
	int proto;

	if (nfs_data.flags & NFS_MOUNT_VER3) {
		nfsd_ver = NFS3_VERSION;
		mountd_ver = NFS_MNT3_VERSION;
	} else {
		nfsd_ver = NFS2_VERSION;
		mountd_ver = NFS_MNT_VERSION;
	}

	proto = (nfs_data.flags & NFS_MOUNT_TCP) ? IPPROTO_TCP : IPPROTO_UDP;

	if (nfs_port < 0) {
		if ((port = getport(NFS_PROGRAM, nfsd_ver, proto)) < 0) {
			printf("nfsroot: Unable to get nfsd port "
					"number from server, using default\n");
			port = NFS_PORT;
		}
		nfs_port = htons(port);
		printf("nfsroot: Portmapper on server returned %d "
			"as nfsd port\n", port);
	}

	if ((port = getport(NFS_MNT_PROGRAM, mountd_ver, proto)) < 0) {
		printf("nfsroot: Unable to get mountd port "
				"number from server, using default\n");
		port = NFS_MNT_PORT;
	}
	mount_port = htons(port);
	printf("nfsroot: mountd port is %d\n", port);

	return 0;
}

int main(void)
{
	unsigned char *p;
	struct timeval tv;
	char *s;

	/* FIX: use getopt() instead of this */

	s = getenv("root_server_addr");
	if (s)
		root_server_addr = strtoul(s, NULL, 10);
	s = getenv("root_server_path");
	if (s)
		strncpy(root_server_path, s, 255);
	s = getenv("nfs_root_name");
	if (s)
		strncpy(nfs_root_name, s, 255);

	/*
	 * Decode the root directory path name and NFS options from
	 * the kernel command line. This has to go here in order to
	 * be able to use the client IP address for the remote root
	 * directory (necessary for pure RARP booting).
	 */
	if (root_nfs_name(nfs_root_name) < 0)
		return 0;
	if ((servaddr = root_server_addr) == INADDR_NONE) {
		printf("nfsroot: No NFS server available, giving up.\n");
		return 0;
	}

	p = (char *) &servaddr;
	sprintf(nfs_data.hostname, "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);

#ifdef NFSROOT_DEBUG
	printf("nfsroot: Mounting %s on server %s as root\n",
		nfs_path, nfs_data.hostname);
	printf("nfsroot:     rsize = %d, wsize = %d, timeo = %d, retrans = %d\n",
		nfs_data.rsize, nfs_data.wsize, nfs_data.timeo, nfs_data.retrans);
	printf("nfsroot:     acreg (min,max) = (%d,%d), acdir (min,max) = (%d,%d)\n",
		nfs_data.acregmin, nfs_data.acregmax,
		nfs_data.acdirmin, nfs_data.acdirmax);
	printf("nfsroot:     nfsd port = %d, mountd port = %d, flags = %08x\n",
		nfs_port, mount_port, nfs_data.flags);
#endif

	gettimeofday(&tv, NULL);
	XID = (tv.tv_sec << 15) ^ tv.tv_usec;

	if (root_nfs_ports() < 0)
		return 0;
	if (nfs_data.flags & NFS_MOUNT_VER3) {
		if (getfh3())
			return 0;
	} else {
		if (getfh2())
			return 0;
	}
	set_sockaddr((struct sockaddr_in *) &nfs_data.addr, servaddr, nfs_port);
	return mount("/dev/root", "/mnt", "nfs", 0, &nfs_data) == 0;
}
