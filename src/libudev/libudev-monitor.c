/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <linux/filter.h>
#include <linux/netlink.h>
#include <poll.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "libudev.h"

#include "alloc-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "format-util.h"
#include "libudev-private.h"
#include "missing.h"
#include "mount-util.h"
#include "socket-util.h"
#include "string-util.h"
#include "strv.h"

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
        unsigned n_ref;
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
        unsigned magic;
        /* total length of header structure known to the sender */
        unsigned header_size;
        /* properties string buffer */
        unsigned properties_off;
        unsigned properties_len;
        /*
         * hashes of primary device properties strings, to let libudev subscribers
         * use in-kernel socket filters; values need to be stored in network order
         */
        unsigned filter_subsystem_hash;
        unsigned filter_devtype_hash;
        unsigned filter_tag_bloom_hi;
        unsigned filter_tag_bloom_lo;
};

int udev_monitor_disconnect(struct udev_monitor *udev_monitor) {
        assert_return(udev_monitor, -EINVAL);

        udev_monitor->sock = safe_close(udev_monitor->sock);

        return 0;
}

static struct udev_monitor *udev_monitor_free(struct udev_monitor *udev_monitor) {
        if (!udev_monitor)
                return NULL;

        udev_monitor_disconnect(udev_monitor);
        udev_list_cleanup(&udev_monitor->filter_subsystem_list);
        udev_list_cleanup(&udev_monitor->filter_tag_list);

        return mfree(udev_monitor);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(struct udev_monitor*, udev_monitor_free);

static int udev_monitor_new(struct udev_monitor **ret) {
        _cleanup_(udev_monitor_freep) struct udev_monitor *udev_monitor = NULL;

        assert(ret);

        udev_monitor = new(struct udev_monitor, 1);
        if (!udev_monitor)
                return -ENOMEM;

        *udev_monitor = (struct udev_monitor) {
                .n_ref = 1,
        };

        udev_list_init(&udev_monitor->filter_subsystem_list, false);
        udev_list_init(&udev_monitor->filter_tag_list, true);

        *ret = TAKE_PTR(udev_monitor);
        return 0;
}

static int udev_monitor_set_nl_address(struct udev_monitor *udev_monitor) {
        union sockaddr_union snl;
        socklen_t addrlen;

        assert(udev_monitor);

        /* Get the address the kernel has assigned us.
         * It is usually, but not necessarily the pid. */
        addrlen = sizeof(struct sockaddr_nl);
        if (getsockname(udev_monitor->sock, &snl.sa, &addrlen) < 0)
                return -errno;

        udev_monitor->snl.nl.nl_pid = snl.nl.nl_pid;
        return 0;
}

int udev_monitor_new_from_netlink_fd(const char *name, int fd, struct udev_monitor **ret) {
        _cleanup_(udev_monitor_freep) struct udev_monitor *udev_monitor = NULL;
        unsigned group;
        int r;

        assert_return(!name || STR_IN_SET(name, "udev", "kernel"), -EINVAL);
        assert_return(ret, -EINVAL);

        if (!name)
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
                if (access("/run/udev/control", F_OK) < 0 && dev_is_devtmpfs() <= 0) {
                        log_debug("The udev service seems not to be active, disabling the monitor");
                        group = UDEV_MONITOR_NONE;
                } else
                        group = UDEV_MONITOR_UDEV;
        } else {
                assert(streq(name, "kernel"));
                group = UDEV_MONITOR_KERNEL;
        }

        r = udev_monitor_new(&udev_monitor);
        if (r < 0)
                return log_oom();

        if (fd < 0) {
                udev_monitor->sock = socket(PF_NETLINK, SOCK_RAW|SOCK_CLOEXEC|SOCK_NONBLOCK, NETLINK_KOBJECT_UEVENT);
                if (udev_monitor->sock < 0)
                        return log_debug_errno(errno, "Failed to create socket: %m");
        } else {
                udev_monitor->bound = true;
                udev_monitor->sock = fd;
                r = udev_monitor_set_nl_address(udev_monitor);
                if (r < 0)
                        return log_debug_errno(r, "Failed to set netlink address: %m");
        }

        udev_monitor->snl.nl.nl_family = AF_NETLINK;
        udev_monitor->snl.nl.nl_groups = group;

        /* default destination for sending */
        udev_monitor->snl_destination.nl.nl_family = AF_NETLINK;
        udev_monitor->snl_destination.nl.nl_groups = UDEV_MONITOR_UDEV;

        *ret = TAKE_PTR(udev_monitor);
        return 0;
}

/**
 * udev_monitor_new_from_netlink:
 * @udev: udev library context (not used)
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
 * The initial n_ref is 1, and needs to be decremented to
 * release the resources of the udev monitor.
 *
 * Returns: a new udev monitor, or #NULL, in case of an error
 **/
_public_ struct udev_monitor *udev_monitor_new_from_netlink(struct udev *udev, const char *name) {
        struct udev_monitor *udev_monitor;
        int r;

        r = udev_monitor_new_from_netlink_fd(name, -1, &udev_monitor);
        if (r < 0) {
                errno = -r;
                return NULL;
        }

        return udev_monitor;
}

static void bpf_stmt(struct sock_filter *ins, unsigned *i,
                     unsigned short code, unsigned data) {
        ins[(*i)++] = (struct sock_filter) {
                .code = code,
                .k = data,
        };
}

static void bpf_jmp(struct sock_filter *ins, unsigned *i,
                    unsigned short code, unsigned data,
                    unsigned short jt, unsigned short jf) {
        ins[(*i)++] = (struct sock_filter) {
                .code = code,
                .jt = jt,
                .jf = jf,
                .k = data,
        };
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
_public_ int udev_monitor_filter_update(struct udev_monitor *udev_monitor) {
        struct udev_list_entry *list_entry;
        struct sock_filter ins[512] = {};
        struct sock_fprog filter;
        unsigned i;

        assert_return(udev_monitor, -EINVAL);

        if (!udev_list_get_entry(&udev_monitor->filter_subsystem_list) &&
            !udev_list_get_entry(&udev_monitor->filter_tag_list))
                return 0;

        i = 0;

        /* load magic in A */
        bpf_stmt(ins, &i, BPF_LD|BPF_W|BPF_ABS, offsetof(struct udev_monitor_netlink_header, magic));
        /* jump if magic matches */
        bpf_jmp(ins, &i, BPF_JMP|BPF_JEQ|BPF_K, UDEV_MONITOR_MAGIC, 1, 0);
        /* wrong magic, pass packet */
        bpf_stmt(ins, &i, BPF_RET|BPF_K, 0xffffffff);

        if (udev_list_get_entry(&udev_monitor->filter_tag_list)) {
                int tag_matches;

                /* count tag matches, to calculate end of tag match block */
                tag_matches = 0;
                UDEV_LIST_ENTRY_FOREACH(list_entry, udev_list_get_entry(&udev_monitor->filter_tag_list))
                        tag_matches++;

                /* add all tags matches */
                UDEV_LIST_ENTRY_FOREACH(list_entry, udev_list_get_entry(&udev_monitor->filter_tag_list)) {
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
        if (udev_list_get_entry(&udev_monitor->filter_subsystem_list)) {
                UDEV_LIST_ENTRY_FOREACH(list_entry, udev_list_get_entry(&udev_monitor->filter_subsystem_list)) {
                        uint32_t hash = util_string_hash32(udev_list_entry_get_name(list_entry));

                        /* load device subsystem value in A */
                        bpf_stmt(ins, &i, BPF_LD|BPF_W|BPF_ABS, offsetof(struct udev_monitor_netlink_header, filter_subsystem_hash));
                        if (!udev_list_entry_get_value(list_entry)) {
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
        filter = (struct sock_fprog) {
                .len = i,
                .filter = ins,
        };
        if (setsockopt(udev_monitor->sock, SOL_SOCKET, SO_ATTACH_FILTER, &filter, sizeof(filter)) < 0)
                return -errno;

        return 0;
}

int udev_monitor_allow_unicast_sender(struct udev_monitor *udev_monitor, struct udev_monitor *sender) {
        assert_return(udev_monitor, -EINVAL);
        assert_return(sender, -EINVAL);

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
_public_ int udev_monitor_enable_receiving(struct udev_monitor *udev_monitor) {
        const int on = 1;

        assert_return(udev_monitor, -EINVAL);

        udev_monitor_filter_update(udev_monitor);

        if (!udev_monitor->bound) {
                if (bind(udev_monitor->sock, &udev_monitor->snl.sa, sizeof(struct sockaddr_nl)) < 0)
                        return log_debug_errno(errno, "Failed to bind udev monitor socket to event source: %m");

                udev_monitor->bound = true;
        }

        udev_monitor_set_nl_address(udev_monitor);

        /* enable receiving of sender credentials */
        if (setsockopt(udev_monitor->sock, SOL_SOCKET, SO_PASSCRED, &on, sizeof(on)) < 0)
                return log_debug_errno(errno, "Failed to set socket option SO_PASSCRED: %m");

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
_public_ int udev_monitor_set_receive_buffer_size(struct udev_monitor *udev_monitor, int size) {
        assert_return(udev_monitor, -EINVAL);

        if (setsockopt(udev_monitor->sock, SOL_SOCKET, SO_RCVBUFFORCE, &size, sizeof(size)) < 0)
                return -errno;

        return 0;
}

/**
 * udev_monitor_ref:
 * @udev_monitor: udev monitor
 *
 * Take a reference of a udev monitor.
 *
 * Returns: the passed udev monitor
 **/
_public_ struct udev_monitor *udev_monitor_ref(struct udev_monitor *udev_monitor) {
        if (!udev_monitor)
                return NULL;

        udev_monitor->n_ref++;
        return udev_monitor;
}

/**
 * udev_monitor_unref:
 * @udev_monitor: udev monitor
 *
 * Drop a reference of a udev monitor. If the n_ref reaches zero,
 * the bound socket will be closed, and the resources of the monitor
 * will be released.
 *
 * Returns: #NULL
 **/
_public_ struct udev_monitor *udev_monitor_unref(struct udev_monitor *udev_monitor) {
        if (!udev_monitor)
                return NULL;

        udev_monitor->n_ref--;
        if (udev_monitor->n_ref > 0)
                return NULL;

        return udev_monitor_free(udev_monitor);
}

/**
 * udev_monitor_get_udev:
 * @udev_monitor: udev monitor
 *
 * This function is deprecated.
 *
 * Returns: NULL.
 **/
_public_ struct udev *udev_monitor_get_udev(struct udev_monitor *udev_monitor) {
        return NULL;
}

/**
 * udev_monitor_get_fd:
 * @udev_monitor: udev monitor
 *
 * Retrieve the socket file descriptor associated with the monitor.
 *
 * Returns: the socket file descriptor
 **/
_public_ int udev_monitor_get_fd(struct udev_monitor *udev_monitor) {
        assert_return(udev_monitor, -EINVAL);

        return udev_monitor->sock;
}

static int passes_filter(struct udev_monitor *udev_monitor, struct udev_device *udev_device) {
        struct udev_list_entry *list_entry;

        assert_return(udev_monitor, -EINVAL);
        assert_return(udev_device, -EINVAL);

        if (!udev_list_get_entry(&udev_monitor->filter_subsystem_list))
                goto tag;

        UDEV_LIST_ENTRY_FOREACH(list_entry, udev_list_get_entry(&udev_monitor->filter_subsystem_list)) {
                const char *subsys = udev_list_entry_get_name(list_entry);
                const char *dsubsys = udev_device_get_subsystem(udev_device);
                const char *devtype, *ddevtype;

                if (!streq(dsubsys, subsys))
                        continue;

                devtype = udev_list_entry_get_value(list_entry);
                if (!devtype)
                        goto tag;

                ddevtype = udev_device_get_devtype(udev_device);
                if (!ddevtype)
                        continue;

                if (streq(ddevtype, devtype))
                        goto tag;
        }

        return 0;

tag:
        if (!udev_list_get_entry(&udev_monitor->filter_tag_list))
                return 1;

        UDEV_LIST_ENTRY_FOREACH(list_entry, udev_list_get_entry(&udev_monitor->filter_tag_list)) {
                const char *tag = udev_list_entry_get_name(list_entry);

                if (udev_device_has_tag(udev_device, tag))
                        return 1;
        }

        return 0;
}

DEFINE_TRIVIAL_CLEANUP_FUNC(struct udev_device*, udev_device_unref);

static int udev_monitor_receive_device_one(struct udev_monitor *udev_monitor, struct udev_device **ret) {
        _cleanup_(udev_device_unrefp) struct udev_device *udev_device = NULL;
        union {
                struct udev_monitor_netlink_header nlh;
                char raw[8192];
        } buf;
        struct iovec iov = {
                .iov_base = &buf,
                .iov_len = sizeof(buf)
        };
        char cred_msg[CMSG_SPACE(sizeof(struct ucred))];
        union sockaddr_union snl;
        struct msghdr smsg = {
                .msg_iov = &iov,
                .msg_iovlen = 1,
                .msg_control = cred_msg,
                .msg_controllen = sizeof(cred_msg),
                .msg_name = &snl,
                .msg_namelen = sizeof(snl),
        };
        struct cmsghdr *cmsg;
        struct ucred *cred;
        ssize_t buflen, bufpos;
        bool is_initialized = false;
        int r;

        buflen = recvmsg(udev_monitor->sock, &smsg, 0);
        if (buflen < 0) {
                if (errno != EINTR)
                        log_debug("unable to receive message");
                return -errno;
        }

        if (buflen < 32 || (smsg.msg_flags & MSG_TRUNC))
                return log_debug_errno(EINVAL, "invalid message length");

        if (snl.nl.nl_groups == UDEV_MONITOR_NONE) {
                /* unicast message, check if we trust the sender */
                if (udev_monitor->snl_trusted_sender.nl.nl_pid == 0 ||
                    snl.nl.nl_pid != udev_monitor->snl_trusted_sender.nl.nl_pid)
                        return log_debug_errno(EAGAIN, "unicast netlink message ignored");
        } else if (snl.nl.nl_groups == UDEV_MONITOR_KERNEL) {
                if (snl.nl.nl_pid > 0)
                        return log_debug_errno(EAGAIN, "multicast kernel netlink message from PID %"PRIu32" ignored", snl.nl.nl_pid);
        }

        cmsg = CMSG_FIRSTHDR(&smsg);
        if (!cmsg || cmsg->cmsg_type != SCM_CREDENTIALS)
                return log_debug_errno(EAGAIN, "no sender credentials received, message ignored");

        cred = (struct ucred*) CMSG_DATA(cmsg);
        if (cred->uid != 0)
                return log_debug_errno(EAGAIN, "sender uid="UID_FMT", message ignored", cred->uid);

        if (streq(buf.raw, "libudev")) {
                /* udev message needs proper version magic */
                if (buf.nlh.magic != htobe32(UDEV_MONITOR_MAGIC))
                        return log_debug_errno(EAGAIN, "unrecognized message signature (%x != %x)",
                                               buf.nlh.magic, htobe32(UDEV_MONITOR_MAGIC));

                if (buf.nlh.properties_off+32 > (size_t) buflen)
                        return log_debug_errno(EAGAIN, "message smaller than expected (%u > %zd)",
                                               buf.nlh.properties_off+32, buflen);

                bufpos = buf.nlh.properties_off;

                /* devices received from udev are always initialized */
                is_initialized = true;
        } else {
                /* kernel message with header */
                bufpos = strlen(buf.raw) + 1;
                if ((size_t) bufpos < sizeof("a@/d") || bufpos >= buflen)
                        return log_debug_errno(EAGAIN, "invalid message length");

                /* check message header */
                if (!strstr(buf.raw, "@/"))
                        return log_debug_errno(EAGAIN, "unrecognized message header");
        }

        r = udev_device_new_from_nulstr(&buf.raw[bufpos], buflen - bufpos, &udev_device);
        if (r < 0)
                return log_debug_errno(r, "Failed to create device: %m");

        if (is_initialized)
                udev_device_set_is_initialized(udev_device);

        /* skip device, if it does not pass the current filter */
        if (passes_filter(udev_monitor, udev_device) <= 0) {
                struct pollfd pfd = {
                        .fd = udev_monitor->sock,
                        .events = POLLIN,
                };

                if (poll(&pfd, 1, 0) <= 0)
                        return -EAGAIN;

                /* if something is queued, get next device */
                return 0;
        }

        *ret = TAKE_PTR(udev_device);
        return 1;
}

static int udev_monitor_receive_device_internal(struct udev_monitor *udev_monitor, struct udev_device **ret) {
        int r;

        assert_return(udev_monitor, -EINVAL);
        assert_return(ret, -EINVAL);

        for (;;) {
                r = udev_monitor_receive_device_one(udev_monitor, ret);
                if (r != 0)
                        return r;
        }
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
 * The initial n_ref is 1, and needs to be decremented to
 * release the resources of the udev device.
 *
 * Returns: a new udev device, or #NULL, in case of an error
 **/
_public_ struct udev_device *udev_monitor_receive_device(struct udev_monitor *udev_monitor) {
        struct udev_device *udev_device;
        int r;

        r = udev_monitor_receive_device_internal(udev_monitor, &udev_device);
        if (r < 0) {
                errno = -r;
                return NULL;
        }

        return udev_device;
}

int udev_monitor_send_device(struct udev_monitor *udev_monitor,
                             struct udev_monitor *destination, struct udev_device *udev_device) {
        struct udev_monitor_netlink_header nlh = {
                .prefix = "libudev",
                .magic = htobe32(UDEV_MONITOR_MAGIC),
                .header_size = sizeof nlh,
        };
        struct iovec iov[2] = {
                { .iov_base = &nlh, .iov_len = sizeof nlh },
        };
        struct msghdr smsg = {
                .msg_iov = iov,
                .msg_iovlen = 2,
        };
        struct udev_list_entry *list_entry;
        uint64_t tag_bloom_bits;
        const char *buf, *val;
        ssize_t blen, count;

        assert_return(udev_monitor, -EINVAL);
        assert_return(udev_device, -EINVAL);

        blen = udev_device_get_properties_monitor_buf(udev_device, &buf);
        if (blen < 32) {
                log_debug("device buffer is too small to contain a valid device");
                return -EINVAL;
        }

        /* fill in versioned header */
        val = udev_device_get_subsystem(udev_device);
        nlh.filter_subsystem_hash = htobe32(util_string_hash32(val));

        val = udev_device_get_devtype(udev_device);
        if (val)
                nlh.filter_devtype_hash = htobe32(util_string_hash32(val));

        /* add tag bloom filter */
        tag_bloom_bits = 0;
        UDEV_LIST_ENTRY_FOREACH(list_entry, udev_device_get_tags_list_entry(udev_device))
                tag_bloom_bits |= util_string_bloom64(udev_list_entry_get_name(list_entry));
        if (tag_bloom_bits > 0) {
                nlh.filter_tag_bloom_hi = htobe32(tag_bloom_bits >> 32);
                nlh.filter_tag_bloom_lo = htobe32(tag_bloom_bits & 0xffffffff);
        }

        /* add properties list */
        nlh.properties_off = iov[0].iov_len;
        nlh.properties_len = blen;
        iov[1] = (struct iovec) {
                .iov_base = (char*) buf,
                .iov_len = blen,
        };

        /*
         * Use custom address for target, or the default one.
         *
         * If we send to a multicast group, we will get
         * ECONNREFUSED, which is expected.
         */
        smsg.msg_name = destination ? &destination->snl : &udev_monitor->snl_destination;
        smsg.msg_namelen = sizeof(struct sockaddr_nl);
        count = sendmsg(udev_monitor->sock, &smsg, 0);
        if (count < 0) {
                if (!destination && errno == ECONNREFUSED) {
                        log_debug("passed device to netlink monitor %p", udev_monitor);
                        return 0;
                } else
                        return -errno;
        }

        log_debug("passed %zi byte device to netlink monitor %p", count, udev_monitor);
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
_public_ int udev_monitor_filter_add_match_subsystem_devtype(struct udev_monitor *udev_monitor, const char *subsystem, const char *devtype) {
        assert_return(udev_monitor, -EINVAL);
        assert_return(subsystem, -EINVAL);

        return udev_list_entry_add(&udev_monitor->filter_subsystem_list, subsystem, devtype, NULL);
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
_public_ int udev_monitor_filter_add_match_tag(struct udev_monitor *udev_monitor, const char *tag) {
        assert_return(udev_monitor, -EINVAL);
        assert_return(tag, -EINVAL);

        return udev_list_entry_add(&udev_monitor->filter_tag_list, tag, NULL, NULL);
}

/**
 * udev_monitor_filter_remove:
 * @udev_monitor: monitor
 *
 * Remove all filters from monitor.
 *
 * Returns: 0 on success, otherwise a negative error value.
 */
_public_ int udev_monitor_filter_remove(struct udev_monitor *udev_monitor) {
        static const struct sock_fprog filter = { 0, NULL };

        assert_return(udev_monitor, -EINVAL);

        udev_list_cleanup(&udev_monitor->filter_subsystem_list);
        if (setsockopt(udev_monitor->sock, SOL_SOCKET, SO_ATTACH_FILTER, &filter, sizeof(filter)) < 0)
                return -errno;

        return 0;
}
