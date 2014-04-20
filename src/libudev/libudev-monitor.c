/***
  This file is part of systemd.

  Copyright 2008-2012 Kay Sievers <kay@vrfy.org>

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <dirent.h>
#include <sys/poll.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <linux/netlink.h>
#include <linux/filter.h>

#include "libudev.h"
#include "libudev-private.h"
#include "socket-util.h"
#include "missing.h"

/**
 * SECTION:libudev-monitor
 * @short_description: device event source
 *
 * Connects to a device event source.
 */

/**
 * udev_monitor:
 *
 * Opaque object handling an event source.
 */
struct udev_monitor {
        struct udev *udev;
        int refcount;
        int sock;
        union sockaddr_union snl;
        union sockaddr_union snl_trusted_sender;
        union sockaddr_union snl_destination;
        socklen_t addrlen;
        struct udev_list filter_subsystem_list;
        struct udev_list filter_tag_list;
        bool bound;
};

enum udev_monitor_netlink_group {
        UDEV_MONITOR_NONE,
        UDEV_MONITOR_KERNEL,
        UDEV_MONITOR_UDEV,
};

#define UDEV_MONITOR_MAGIC                0xfeedcafe
struct udev_monitor_netlink_header {
        /* "libudev" prefix to distinguish libudev and kernel messages */
        char prefix[8];
        /*
         * magic to protect against daemon <-> library message format mismatch
         * used in the kernel from socket filter rules; needs to be stored in network order
         */
        unsigned int magic;
        /* total length of header structure known to the sender */
        unsigned int header_size;
        /* properties string buffer */
        unsigned int properties_off;
        unsigned int properties_len;
        /*
         * hashes of primary device properties strings, to let libudev subscribers
         * use in-kernel socket filters; values need to be stored in network order
         */
        unsigned int filter_subsystem_hash;
        unsigned int filter_devtype_hash;
        unsigned int filter_tag_bloom_hi;
        unsigned int filter_tag_bloom_lo;
};

static struct udev_monitor *udev_monitor_new(struct udev *udev)
{
        struct udev_monitor *udev_monitor;

        udev_monitor = new0(struct udev_monitor, 1);
        if (udev_monitor == NULL)
                return NULL;
        udev_monitor->refcount = 1;
        udev_monitor->udev = udev;
        udev_list_init(udev, &udev_monitor->filter_subsystem_list, false);
        udev_list_init(udev, &udev_monitor->filter_tag_list, true);
        return udev_monitor;
}

/* we consider udev running when /dev is on devtmpfs */
static bool udev_has_devtmpfs(struct udev *udev) {

        union file_handle_union h = {
                .handle.handle_bytes = MAX_HANDLE_SZ
        };

        _cleanup_fclose_ FILE *f = NULL;
        char line[LINE_MAX], *e;
        int mount_id;
        int r;

        r = name_to_handle_at(AT_FDCWD, "/dev", &h.handle, &mount_id, 0);
        if (r < 0) {
                if (errno != EOPNOTSUPP)
                        udev_err(udev, "name_to_handle_at on /dev: %m\n");
                return false;
        }

        f = fopen("/proc/self/mountinfo", "re");
        if (!f)
                return false;

        FOREACH_LINE(line, f, return false) {
                int mid;

                if (sscanf(line, "%i", &mid) != 1)
                        continue;

                if (mid != mount_id)
                        continue;

                e = strstr(line, " - ");
                if (!e)
                        continue;

                /* accept any name that starts with the currently expected type */
                if (startswith(e + 3, "devtmpfs"))
                        return true;
        }

        return false;
}

struct udev_monitor *udev_monitor_new_from_netlink_fd(struct udev *udev, const char *name, int fd)
{
        struct udev_monitor *udev_monitor;
        unsigned int group;

        if (udev == NULL)
                return NULL;

        if (name == NULL)
                group = UDEV_MONITOR_NONE;
        else if (streq(name, "udev")) {
                /*
                 * We do not support subscribing to uevents if no instance of
                 * udev is running. Uevents would otherwise broadcast the
                 * processing data of the host into containers, which is not
                 * desired.
                 *
                 * Containers will currently not get any udev uevents, until
                 * a supporting infrastructure is available.
                 *
                 * We do not set a netlink multicast group here, so the socket
                 * will not receive any messages.
                 */
                if (access("/run/udev/control", F_OK) < 0 && !udev_has_devtmpfs(udev)) {
                        udev_dbg(udev, "the udev service seems not to be active, disable the monitor\n");
                        group = UDEV_MONITOR_NONE;
                } else
                        group = UDEV_MONITOR_UDEV;
        } else if (streq(name, "kernel"))
                group = UDEV_MONITOR_KERNEL;
        else
                return NULL;

        udev_monitor = udev_monitor_new(udev);
        if (udev_monitor == NULL)
                return NULL;

        if (fd < 0) {
                udev_monitor->sock = socket(PF_NETLINK, SOCK_RAW|SOCK_CLOEXEC|SOCK_NONBLOCK, NETLINK_KOBJECT_UEVENT);
                if (udev_monitor->sock == -1) {
                        udev_err(udev, "error getting socket: %m\n");
                        free(udev_monitor);
                        return NULL;
                }
        } else {
                udev_monitor->bound = true;
                udev_monitor->sock = fd;
        }

        udev_monitor->snl.nl.nl_family = AF_NETLINK;
        udev_monitor->snl.nl.nl_groups = group;

        /* default destination for sending */
        udev_monitor->snl_destination.nl.nl_family = AF_NETLINK;
        udev_monitor->snl_destination.nl.nl_groups = UDEV_MONITOR_UDEV;

        return udev_monitor;
}

/**
 * udev_monitor_new_from_netlink:
 * @udev: udev library context
 * @name: name of event source
 *
 * Create new udev monitor and connect to a specified event
 * source. Valid sources identifiers are "udev" and "kernel".
 *
 * Applications should usually not connect directly to the
 * "kernel" events, because the devices might not be useable
 * at that time, before udev has configured them, and created
 * device nodes. Accessing devices at the same time as udev,
 * might result in unpredictable behavior. The "udev" events
 * are sent out after udev has finished its event processing,
 * all rules have been processed, and needed device nodes are
 * created.
 *
 * The initial refcount is 1, and needs to be decremented to
 * release the resources of the udev monitor.
 *
 * Returns: a new udev monitor, or #NULL, in case of an error
 **/
_public_ struct udev_monitor *udev_monitor_new_from_netlink(struct udev *udev, const char *name)
{
        return udev_monitor_new_from_netlink_fd(udev, name, -1);
}

static inline void bpf_stmt(struct sock_filter *inss, unsigned int *i,
                            unsigned short code, unsigned int data)
{
        struct sock_filter *ins = &inss[*i];

        ins->code = code;
        ins->k = data;
        (*i)++;
}

static inline void bpf_jmp(struct sock_filter *inss, unsigned int *i,
                           unsigned short code, unsigned int data,
                           unsigned short jt, unsigned short jf)
{
        struct sock_filter *ins = &inss[*i];

        ins->code = code;
        ins->jt = jt;
        ins->jf = jf;
        ins->k = data;
        (*i)++;
}

/**
 * udev_monitor_filter_update:
 * @udev_monitor: monitor
 *
 * Update the installed socket filter. This is only needed,
 * if the filter was removed or changed.
 *
 * Returns: 0 on success, otherwise a negative error value.
 */
_public_ int udev_monitor_filter_update(struct udev_monitor *udev_monitor)
{
        struct sock_filter ins[512];
        struct sock_fprog filter;
        unsigned int i;
        struct udev_list_entry *list_entry;
        int err;

        if (udev_list_get_entry(&udev_monitor->filter_subsystem_list) == NULL &&
            udev_list_get_entry(&udev_monitor->filter_tag_list) == NULL)
                return 0;

        memzero(ins, sizeof(ins));
        i = 0;

        /* load magic in A */
        bpf_stmt(ins, &i, BPF_LD|BPF_W|BPF_ABS, offsetof(struct udev_monitor_netlink_header, magic));
        /* jump if magic matches */
        bpf_jmp(ins, &i, BPF_JMP|BPF_JEQ|BPF_K, UDEV_MONITOR_MAGIC, 1, 0);
        /* wrong magic, pass packet */
        bpf_stmt(ins, &i, BPF_RET|BPF_K, 0xffffffff);

        if (udev_list_get_entry(&udev_monitor->filter_tag_list) != NULL) {
                int tag_matches;

                /* count tag matches, to calculate end of tag match block */
                tag_matches = 0;
                udev_list_entry_foreach(list_entry, udev_list_get_entry(&udev_monitor->filter_tag_list))
                        tag_matches++;

                /* add all tags matches */
                udev_list_entry_foreach(list_entry, udev_list_get_entry(&udev_monitor->filter_tag_list)) {
                        uint64_t tag_bloom_bits = util_string_bloom64(udev_list_entry_get_name(list_entry));
                        uint32_t tag_bloom_hi = tag_bloom_bits >> 32;
                        uint32_t tag_bloom_lo = tag_bloom_bits & 0xffffffff;

                        /* load device bloom bits in A */
                        bpf_stmt(ins, &i, BPF_LD|BPF_W|BPF_ABS, offsetof(struct udev_monitor_netlink_header, filter_tag_bloom_hi));
                        /* clear bits (tag bits & bloom bits) */
                        bpf_stmt(ins, &i, BPF_ALU|BPF_AND|BPF_K, tag_bloom_hi);
                        /* jump to next tag if it does not match */
                        bpf_jmp(ins, &i, BPF_JMP|BPF_JEQ|BPF_K, tag_bloom_hi, 0, 3);

                        /* load device bloom bits in A */
                        bpf_stmt(ins, &i, BPF_LD|BPF_W|BPF_ABS, offsetof(struct udev_monitor_netlink_header, filter_tag_bloom_lo));
                        /* clear bits (tag bits & bloom bits) */
                        bpf_stmt(ins, &i, BPF_ALU|BPF_AND|BPF_K, tag_bloom_lo);
                        /* jump behind end of tag match block if tag matches */
                        tag_matches--;
                        bpf_jmp(ins, &i, BPF_JMP|BPF_JEQ|BPF_K, tag_bloom_lo, 1 + (tag_matches * 6), 0);
                }

                /* nothing matched, drop packet */
                bpf_stmt(ins, &i, BPF_RET|BPF_K, 0);
        }

        /* add all subsystem matches */
        if (udev_list_get_entry(&udev_monitor->filter_subsystem_list) != NULL) {
                udev_list_entry_foreach(list_entry, udev_list_get_entry(&udev_monitor->filter_subsystem_list)) {
                        unsigned int hash = util_string_hash32(udev_list_entry_get_name(list_entry));

                        /* load device subsystem value in A */
                        bpf_stmt(ins, &i, BPF_LD|BPF_W|BPF_ABS, offsetof(struct udev_monitor_netlink_header, filter_subsystem_hash));
                        if (udev_list_entry_get_value(list_entry) == NULL) {
                                /* jump if subsystem does not match */
                                bpf_jmp(ins, &i, BPF_JMP|BPF_JEQ|BPF_K, hash, 0, 1);
                        } else {
                                /* jump if subsystem does not match */
                                bpf_jmp(ins, &i, BPF_JMP|BPF_JEQ|BPF_K, hash, 0, 3);

                                /* load device devtype value in A */
                                bpf_stmt(ins, &i, BPF_LD|BPF_W|BPF_ABS, offsetof(struct udev_monitor_netlink_header, filter_devtype_hash));
                                /* jump if value does not match */
                                hash = util_string_hash32(udev_list_entry_get_value(list_entry));
                                bpf_jmp(ins, &i, BPF_JMP|BPF_JEQ|BPF_K, hash, 0, 1);
                        }

                        /* matched, pass packet */
                        bpf_stmt(ins, &i, BPF_RET|BPF_K, 0xffffffff);

                        if (i+1 >= ELEMENTSOF(ins))
                                return -E2BIG;
                }

                /* nothing matched, drop packet */
                bpf_stmt(ins, &i, BPF_RET|BPF_K, 0);
        }

        /* matched, pass packet */
        bpf_stmt(ins, &i, BPF_RET|BPF_K, 0xffffffff);

        /* install filter */
        memzero(&filter, sizeof(filter));
        filter.len = i;
        filter.filter = ins;
        err = setsockopt(udev_monitor->sock, SOL_SOCKET, SO_ATTACH_FILTER, &filter, sizeof(filter));
        return err < 0 ? -errno : 0;
}

int udev_monitor_allow_unicast_sender(struct udev_monitor *udev_monitor, struct udev_monitor *sender)
{
        udev_monitor->snl_trusted_sender.nl.nl_pid = sender->snl.nl.nl_pid;
        return 0;
}
/**
 * udev_monitor_enable_receiving:
 * @udev_monitor: the monitor which should receive events
 *
 * Binds the @udev_monitor socket to the event source.
 *
 * Returns: 0 on success, otherwise a negative error value.
 */
_public_ int udev_monitor_enable_receiving(struct udev_monitor *udev_monitor)
{
        int err = 0;
        const int on = 1;

        udev_monitor_filter_update(udev_monitor);

        if (!udev_monitor->bound) {
                err = bind(udev_monitor->sock,
                           &udev_monitor->snl.sa, sizeof(struct sockaddr_nl));
                if (err == 0)
                        udev_monitor->bound = true;
        }

        if (err >= 0) {
                union sockaddr_union snl;
                socklen_t addrlen;

                /*
                 * get the address the kernel has assigned us
                 * it is usually, but not necessarily the pid
                 */
                addrlen = sizeof(struct sockaddr_nl);
                err = getsockname(udev_monitor->sock, &snl.sa, &addrlen);
                if (err == 0)
                        udev_monitor->snl.nl.nl_pid = snl.nl.nl_pid;
        } else {
                udev_err(udev_monitor->udev, "bind failed: %m\n");
                return -errno;
        }

        /* enable receiving of sender credentials */
        setsockopt(udev_monitor->sock, SOL_SOCKET, SO_PASSCRED, &on, sizeof(on));
        return 0;
}

/**
 * udev_monitor_set_receive_buffer_size:
 * @udev_monitor: the monitor which should receive events
 * @size: the size in bytes
 *
 * Set the size of the kernel socket buffer. This call needs the
 * appropriate privileges to succeed.
 *
 * Returns: 0 on success, otherwise -1 on error.
 */
_public_ int udev_monitor_set_receive_buffer_size(struct udev_monitor *udev_monitor, int size)
{
        if (udev_monitor == NULL)
                return -EINVAL;
        return setsockopt(udev_monitor->sock, SOL_SOCKET, SO_RCVBUFFORCE, &size, sizeof(size));
}

int udev_monitor_disconnect(struct udev_monitor *udev_monitor)
{
        int err;

        err = close(udev_monitor->sock);
        udev_monitor->sock = -1;
        return err < 0 ? -errno : 0;
}

/**
 * udev_monitor_ref:
 * @udev_monitor: udev monitor
 *
 * Take a reference of a udev monitor.
 *
 * Returns: the passed udev monitor
 **/
_public_ struct udev_monitor *udev_monitor_ref(struct udev_monitor *udev_monitor)
{
        if (udev_monitor == NULL)
                return NULL;
        udev_monitor->refcount++;
        return udev_monitor;
}

/**
 * udev_monitor_unref:
 * @udev_monitor: udev monitor
 *
 * Drop a reference of a udev monitor. If the refcount reaches zero,
 * the bound socket will be closed, and the resources of the monitor
 * will be released.
 *
 * Returns: #NULL
 **/
_public_ struct udev_monitor *udev_monitor_unref(struct udev_monitor *udev_monitor)
{
        if (udev_monitor == NULL)
                return NULL;
        udev_monitor->refcount--;
        if (udev_monitor->refcount > 0)
                return NULL;
        if (udev_monitor->sock >= 0)
                close(udev_monitor->sock);
        udev_list_cleanup(&udev_monitor->filter_subsystem_list);
        udev_list_cleanup(&udev_monitor->filter_tag_list);
        free(udev_monitor);
        return NULL;
}

/**
 * udev_monitor_get_udev:
 * @udev_monitor: udev monitor
 *
 * Retrieve the udev library context the monitor was created with.
 *
 * Returns: the udev library context
 **/
_public_ struct udev *udev_monitor_get_udev(struct udev_monitor *udev_monitor)
{
        if (udev_monitor == NULL)
                return NULL;
        return udev_monitor->udev;
}

/**
 * udev_monitor_get_fd:
 * @udev_monitor: udev monitor
 *
 * Retrieve the socket file descriptor associated with the monitor.
 *
 * Returns: the socket file descriptor
 **/
_public_ int udev_monitor_get_fd(struct udev_monitor *udev_monitor)
{
        if (udev_monitor == NULL)
                return -EINVAL;
        return udev_monitor->sock;
}

static int passes_filter(struct udev_monitor *udev_monitor, struct udev_device *udev_device)
{
        struct udev_list_entry *list_entry;

        if (udev_list_get_entry(&udev_monitor->filter_subsystem_list) == NULL)
                goto tag;
        udev_list_entry_foreach(list_entry, udev_list_get_entry(&udev_monitor->filter_subsystem_list)) {
                const char *subsys = udev_list_entry_get_name(list_entry);
                const char *dsubsys = udev_device_get_subsystem(udev_device);
                const char *devtype;
                const char *ddevtype;

                if (!streq(dsubsys, subsys))
                        continue;

                devtype = udev_list_entry_get_value(list_entry);
                if (devtype == NULL)
                        goto tag;
                ddevtype = udev_device_get_devtype(udev_device);
                if (ddevtype == NULL)
                        continue;
                if (streq(ddevtype, devtype))
                        goto tag;
        }
        return 0;

tag:
        if (udev_list_get_entry(&udev_monitor->filter_tag_list) == NULL)
                return 1;
        udev_list_entry_foreach(list_entry, udev_list_get_entry(&udev_monitor->filter_tag_list)) {
                const char *tag = udev_list_entry_get_name(list_entry);

                if (udev_device_has_tag(udev_device, tag))
                        return 1;
        }
        return 0;
}

/**
 * udev_monitor_receive_device:
 * @udev_monitor: udev monitor
 *
 * Receive data from the udev monitor socket, allocate a new udev
 * device, fill in the received data, and return the device.
 *
 * Only socket connections with uid=0 are accepted.
 *
 * The monitor socket is by default set to NONBLOCK. A variant of poll() on
 * the file descriptor returned by udev_monitor_get_fd() should to be used to
 * wake up when new devices arrive, or alternatively the file descriptor
 * switched into blocking mode.
 *
 * The initial refcount is 1, and needs to be decremented to
 * release the resources of the udev device.
 *
 * Returns: a new udev device, or #NULL, in case of an error
 **/
_public_ struct udev_device *udev_monitor_receive_device(struct udev_monitor *udev_monitor)
{
        struct udev_device *udev_device;
        struct msghdr smsg;
        struct iovec iov;
        char cred_msg[CMSG_SPACE(sizeof(struct ucred))];
        struct cmsghdr *cmsg;
        union sockaddr_union snl;
        struct ucred *cred;
        char buf[8192];
        ssize_t buflen;
        ssize_t bufpos;

retry:
        if (udev_monitor == NULL)
                return NULL;
        iov.iov_base = &buf;
        iov.iov_len = sizeof(buf);
        memzero(&smsg, sizeof(struct msghdr));
        smsg.msg_iov = &iov;
        smsg.msg_iovlen = 1;
        smsg.msg_control = cred_msg;
        smsg.msg_controllen = sizeof(cred_msg);
        smsg.msg_name = &snl;
        smsg.msg_namelen = sizeof(snl);

        buflen = recvmsg(udev_monitor->sock, &smsg, 0);
        if (buflen < 0) {
                if (errno != EINTR)
                        udev_dbg(udev_monitor->udev, "unable to receive message\n");
                return NULL;
        }

        if (buflen < 32 || (size_t)buflen >= sizeof(buf)) {
                udev_dbg(udev_monitor->udev, "invalid message length\n");
                return NULL;
        }

        if (snl.nl.nl_groups == 0) {
                /* unicast message, check if we trust the sender */
                if (udev_monitor->snl_trusted_sender.nl.nl_pid == 0 ||
                    snl.nl.nl_pid != udev_monitor->snl_trusted_sender.nl.nl_pid) {
                        udev_dbg(udev_monitor->udev, "unicast netlink message ignored\n");
                        return NULL;
                }
        } else if (snl.nl.nl_groups == UDEV_MONITOR_KERNEL) {
                if (snl.nl.nl_pid > 0) {
                        udev_dbg(udev_monitor->udev, "multicast kernel netlink message from pid %d ignored\n",
                             snl.nl.nl_pid);
                        return NULL;
                }
        }

        cmsg = CMSG_FIRSTHDR(&smsg);
        if (cmsg == NULL || cmsg->cmsg_type != SCM_CREDENTIALS) {
                udev_dbg(udev_monitor->udev, "no sender credentials received, message ignored\n");
                return NULL;
        }

        cred = (struct ucred *)CMSG_DATA(cmsg);
        if (cred->uid != 0) {
                udev_dbg(udev_monitor->udev, "sender uid=%d, message ignored\n", cred->uid);
                return NULL;
        }

        udev_device = udev_device_new(udev_monitor->udev);
        if (udev_device == NULL)
                return NULL;

        if (memcmp(buf, "libudev", 8) == 0) {
                struct udev_monitor_netlink_header *nlh;

                /* udev message needs proper version magic */
                nlh = (struct udev_monitor_netlink_header *) buf;
                if (nlh->magic != htonl(UDEV_MONITOR_MAGIC)) {
                        udev_err(udev_monitor->udev, "unrecognized message signature (%x != %x)\n",
                                 nlh->magic, htonl(UDEV_MONITOR_MAGIC));
                        udev_device_unref(udev_device);
                        return NULL;
                }
                if (nlh->properties_off+32 > (size_t)buflen) {
                        udev_device_unref(udev_device);
                        return NULL;
                }

                bufpos = nlh->properties_off;

                /* devices received from udev are always initialized */
                udev_device_set_is_initialized(udev_device);
        } else {
                /* kernel message with header */
                bufpos = strlen(buf) + 1;
                if ((size_t)bufpos < sizeof("a@/d") || bufpos >= buflen) {
                        udev_dbg(udev_monitor->udev, "invalid message length\n");
                        udev_device_unref(udev_device);
                        return NULL;
                }

                /* check message header */
                if (strstr(buf, "@/") == NULL) {
                        udev_dbg(udev_monitor->udev, "unrecognized message header\n");
                        udev_device_unref(udev_device);
                        return NULL;
                }
        }

        udev_device_set_info_loaded(udev_device);

        while (bufpos < buflen) {
                char *key;
                size_t keylen;

                key = &buf[bufpos];
                keylen = strlen(key);
                if (keylen == 0)
                        break;
                bufpos += keylen + 1;
                udev_device_add_property_from_string_parse(udev_device, key);
        }

        if (udev_device_add_property_from_string_parse_finish(udev_device) < 0) {
                udev_dbg(udev_monitor->udev, "missing values, invalid device\n");
                udev_device_unref(udev_device);
                return NULL;
        }

        /* skip device, if it does not pass the current filter */
        if (!passes_filter(udev_monitor, udev_device)) {
                struct pollfd pfd[1];
                int rc;

                udev_device_unref(udev_device);

                /* if something is queued, get next device */
                pfd[0].fd = udev_monitor->sock;
                pfd[0].events = POLLIN;
                rc = poll(pfd, 1, 0);
                if (rc > 0)
                        goto retry;
                return NULL;
        }

        return udev_device;
}

int udev_monitor_send_device(struct udev_monitor *udev_monitor,
                             struct udev_monitor *destination, struct udev_device *udev_device)
{
        const char *buf;
        ssize_t blen;
        ssize_t count;
        struct msghdr smsg;
        struct iovec iov[2];
        const char *val;
        struct udev_monitor_netlink_header nlh;
        struct udev_list_entry *list_entry;
        uint64_t tag_bloom_bits;

        blen = udev_device_get_properties_monitor_buf(udev_device, &buf);
        if (blen < 32)
                return -EINVAL;

        /* add versioned header */
        memzero(&nlh, sizeof(struct udev_monitor_netlink_header));
        memcpy(nlh.prefix, "libudev", 8);
        nlh.magic = htonl(UDEV_MONITOR_MAGIC);
        nlh.header_size = sizeof(struct udev_monitor_netlink_header);
        val = udev_device_get_subsystem(udev_device);
        nlh.filter_subsystem_hash = htonl(util_string_hash32(val));
        val = udev_device_get_devtype(udev_device);
        if (val != NULL)
                nlh.filter_devtype_hash = htonl(util_string_hash32(val));
        iov[0].iov_base = &nlh;
        iov[0].iov_len = sizeof(struct udev_monitor_netlink_header);

        /* add tag bloom filter */
        tag_bloom_bits = 0;
        udev_list_entry_foreach(list_entry, udev_device_get_tags_list_entry(udev_device))
                tag_bloom_bits |= util_string_bloom64(udev_list_entry_get_name(list_entry));
        if (tag_bloom_bits > 0) {
                nlh.filter_tag_bloom_hi = htonl(tag_bloom_bits >> 32);
                nlh.filter_tag_bloom_lo = htonl(tag_bloom_bits & 0xffffffff);
        }

        /* add properties list */
        nlh.properties_off = iov[0].iov_len;
        nlh.properties_len = blen;
        iov[1].iov_base = (char *)buf;
        iov[1].iov_len = blen;

        memzero(&smsg, sizeof(struct msghdr));
        smsg.msg_iov = iov;
        smsg.msg_iovlen = 2;
        /*
         * Use custom address for target, or the default one.
         *
         * If we send to a multicast group, we will get
         * ECONNREFUSED, which is expected.
         */
        if (destination != NULL)
                smsg.msg_name = &destination->snl;
        else
                smsg.msg_name = &udev_monitor->snl_destination;
        smsg.msg_namelen = sizeof(struct sockaddr_nl);
        count = sendmsg(udev_monitor->sock, &smsg, 0);
        udev_dbg(udev_monitor->udev, "passed %zi bytes to netlink monitor %p\n", count, udev_monitor);
        return count;
}

/**
 * udev_monitor_filter_add_match_subsystem_devtype:
 * @udev_monitor: the monitor
 * @subsystem: the subsystem value to match the incoming devices against
 * @devtype: the devtype value to match the incoming devices against
 *
 * This filter is efficiently executed inside the kernel, and libudev subscribers
 * will usually not be woken up for devices which do not match.
 *
 * The filter must be installed before the monitor is switched to listening mode.
 *
 * Returns: 0 on success, otherwise a negative error value.
 */
_public_ int udev_monitor_filter_add_match_subsystem_devtype(struct udev_monitor *udev_monitor, const char *subsystem, const char *devtype)
{
        if (udev_monitor == NULL)
                return -EINVAL;
        if (subsystem == NULL)
                return -EINVAL;
        if (udev_list_entry_add(&udev_monitor->filter_subsystem_list, subsystem, devtype) == NULL)
                return -ENOMEM;
        return 0;
}

/**
 * udev_monitor_filter_add_match_tag:
 * @udev_monitor: the monitor
 * @tag: the name of a tag
 *
 * This filter is efficiently executed inside the kernel, and libudev subscribers
 * will usually not be woken up for devices which do not match.
 *
 * The filter must be installed before the monitor is switched to listening mode.
 *
 * Returns: 0 on success, otherwise a negative error value.
 */
_public_ int udev_monitor_filter_add_match_tag(struct udev_monitor *udev_monitor, const char *tag)
{
        if (udev_monitor == NULL)
                return -EINVAL;
        if (tag == NULL)
                return -EINVAL;
        if (udev_list_entry_add(&udev_monitor->filter_tag_list, tag, NULL) == NULL)
                return -ENOMEM;
        return 0;
}

/**
 * udev_monitor_filter_remove:
 * @udev_monitor: monitor
 *
 * Remove all filters from monitor.
 *
 * Returns: 0 on success, otherwise a negative error value.
 */
_public_ int udev_monitor_filter_remove(struct udev_monitor *udev_monitor)
{
        static struct sock_fprog filter = { 0, NULL };

        udev_list_cleanup(&udev_monitor->filter_subsystem_list);
        return setsockopt(udev_monitor->sock, SOL_SOCKET, SO_ATTACH_FILTER, &filter, sizeof(filter));
}
