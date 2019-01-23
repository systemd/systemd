/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <linux/filter.h>
#include <linux/netlink.h>
#include <sys/socket.h>

#include "sd-device.h"
#include "sd-event.h"

#include "MurmurHash2.h"
#include "alloc-util.h"
#include "device-monitor-private.h"
#include "device-private.h"
#include "device-util.h"
#include "fd-util.h"
#include "format-util.h"
#include "hashmap.h"
#include "io-util.h"
#include "missing.h"
#include "mountpoint-util.h"
#include "set.h"
#include "socket-util.h"
#include "string-util.h"
#include "strv.h"

struct sd_device_monitor {
        unsigned n_ref;

        int sock;
        union sockaddr_union snl;
        union sockaddr_union snl_trusted_sender;
        bool bound;

        Hashmap *subsystem_filter;
        Set *tag_filter;
        bool filter_uptodate;

        sd_event *event;
        sd_event_source *event_source;
        sd_device_monitor_handler_t callback;
        void *userdata;
};

#define UDEV_MONITOR_MAGIC                0xfeedcafe

typedef struct monitor_netlink_header {
        /* "libudev" prefix to distinguish libudev and kernel messages */
        char prefix[8];
        /* Magic to protect against daemon <-> Library message format mismatch
         * Used in the kernel from socket filter rules; needs to be stored in network order */
        unsigned magic;
        /* Total length of header structure known to the sender */
        unsigned header_size;
        /* Properties string buffer */
        unsigned properties_off;
        unsigned properties_len;
        /* Hashes of primary device properties strings, to let libudev subscribers
         * use in-kernel socket filters; values need to be stored in network order */
        unsigned filter_subsystem_hash;
        unsigned filter_devtype_hash;
        unsigned filter_tag_bloom_hi;
        unsigned filter_tag_bloom_lo;
} monitor_netlink_header;

static int monitor_set_nl_address(sd_device_monitor *m) {
        union sockaddr_union snl;
        socklen_t addrlen;

        assert(m);

        /* Get the address the kernel has assigned us.
         * It is usually, but not necessarily the pid. */
        addrlen = sizeof(struct sockaddr_nl);
        if (getsockname(m->sock, &snl.sa, &addrlen) < 0)
                return -errno;

        m->snl.nl.nl_pid = snl.nl.nl_pid;
        return 0;
}

int device_monitor_allow_unicast_sender(sd_device_monitor *m, sd_device_monitor *sender) {
        assert_return(m, -EINVAL);
        assert_return(sender, -EINVAL);

        m->snl_trusted_sender.nl.nl_pid = sender->snl.nl.nl_pid;
        return 0;
}

_public_ int sd_device_monitor_set_receive_buffer_size(sd_device_monitor *m, size_t size) {
        int r, n = (int) size;

        assert_return(m, -EINVAL);
        assert_return((size_t) n == size, -EINVAL);

        if (setsockopt_int(m->sock, SOL_SOCKET, SO_RCVBUFFORCE, n) < 0) {
                r = setsockopt_int(m->sock, SOL_SOCKET, SO_RCVBUF, n);
                if (r < 0)
                        return r;
        }

        return 0;
}

int device_monitor_disconnect(sd_device_monitor *m) {
        assert(m);

        m->sock = safe_close(m->sock);
        return 0;
}

int device_monitor_get_fd(sd_device_monitor *m) {
        assert_return(m, -EINVAL);

        return m->sock;
}

int device_monitor_new_full(sd_device_monitor **ret, MonitorNetlinkGroup group, int fd) {
        _cleanup_(sd_device_monitor_unrefp) sd_device_monitor *m = NULL;
        _cleanup_close_ int sock = -1;
        int r;

        assert_return(ret, -EINVAL);
        assert_return(group >= 0 && group < _MONITOR_NETLINK_GROUP_MAX, -EINVAL);

        if (group == MONITOR_GROUP_UDEV &&
            access("/run/udev/control", F_OK) < 0 &&
            dev_is_devtmpfs() <= 0) {

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

                log_debug("sd-device-monitor: The udev service seems not to be active, disabling the monitor");
                group = MONITOR_GROUP_NONE;
        }

        if (fd < 0) {
                sock = socket(PF_NETLINK, SOCK_RAW|SOCK_CLOEXEC|SOCK_NONBLOCK, NETLINK_KOBJECT_UEVENT);
                if (sock < 0)
                        return log_debug_errno(errno, "sd-device-monitor: Failed to create socket: %m");
        }

        m = new(sd_device_monitor, 1);
        if (!m)
                return -ENOMEM;

        *m = (sd_device_monitor) {
                .n_ref = 1,
                .sock = fd >= 0 ? fd : TAKE_FD(sock),
                .bound = fd >= 0,
                .snl.nl.nl_family = AF_NETLINK,
                .snl.nl.nl_groups = group,
        };

        if (fd >= 0) {
                r = monitor_set_nl_address(m);
                if (r < 0)
                        return log_debug_errno(r, "sd-device-monitor: Failed to set netlink address: %m");
        }

        *ret = TAKE_PTR(m);
        return 0;
}

_public_ int sd_device_monitor_new(sd_device_monitor **ret) {
        return device_monitor_new_full(ret, MONITOR_GROUP_UDEV, -1);
}

_public_ int sd_device_monitor_stop(sd_device_monitor *m) {
        assert_return(m, -EINVAL);

        m->event_source = sd_event_source_unref(m->event_source);
        (void) device_monitor_disconnect(m);

        return 0;
}

static int device_monitor_event_handler(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        _cleanup_(sd_device_unrefp) sd_device *device = NULL;
        sd_device_monitor *m = userdata;

        assert(m);

        if (device_monitor_receive_device(m, &device) <= 0)
                return 0;

        if (m->callback)
                return m->callback(m, device, m->userdata);

        return 0;
}

_public_ int sd_device_monitor_start(sd_device_monitor *m, sd_device_monitor_handler_t callback, void *userdata) {
        int r;

        assert_return(m, -EINVAL);

        if (!m->event) {
                r = sd_device_monitor_attach_event(m, NULL);
                if (r < 0)
                        return r;
        }

        r = device_monitor_enable_receiving(m);
        if (r < 0)
                return r;

        m->callback = callback;
        m->userdata = userdata;

        r = sd_event_add_io(m->event, &m->event_source, m->sock, EPOLLIN, device_monitor_event_handler, m);
        if (r < 0)
                return r;

        (void) sd_event_source_set_description(m->event_source, "sd-device-monitor");

        return 0;
}

_public_ int sd_device_monitor_detach_event(sd_device_monitor *m) {
        assert_return(m, -EINVAL);

        (void) sd_device_monitor_stop(m);
        m->event = sd_event_unref(m->event);

        return 0;
}

_public_ int sd_device_monitor_attach_event(sd_device_monitor *m, sd_event *event) {
        int r;

        assert_return(m, -EINVAL);
        assert_return(!m->event, -EBUSY);

        if (event)
                m->event = sd_event_ref(event);
        else {
                r = sd_event_default(&m->event);
                if (r < 0)
                        return r;
        }

        return 0;
}

_public_ sd_event *sd_device_monitor_get_event(sd_device_monitor *m) {
        assert_return(m, NULL);

        return m->event;
}

_public_ sd_event_source *sd_device_monitor_get_event_source(sd_device_monitor *m) {
        assert_return(m, NULL);

        return m->event_source;
}

int device_monitor_enable_receiving(sd_device_monitor *m) {
        int r;

        assert_return(m, -EINVAL);

        r = sd_device_monitor_filter_update(m);
        if (r < 0)
                return log_debug_errno(r, "sd-device-monitor: Failed to update filter: %m");

        if (!m->bound) {
                /* enable receiving of sender credentials */
                r = setsockopt_int(m->sock, SOL_SOCKET, SO_PASSCRED, true);
                if (r < 0)
                        return log_debug_errno(r, "sd-device-monitor: Failed to set socket option SO_PASSCRED: %m");

                if (bind(m->sock, &m->snl.sa, sizeof(struct sockaddr_nl)) < 0)
                        return log_debug_errno(errno, "sd-device-monitor: Failed to bind monitoring socket: %m");

                m->bound = true;

                r = monitor_set_nl_address(m);
                if (r < 0)
                        return log_debug_errno(r, "sd-device-monitor: Failed to set address: %m");
        }

        return 0;
}

static sd_device_monitor *device_monitor_free(sd_device_monitor *m) {
        assert(m);

        (void) sd_device_monitor_detach_event(m);

        hashmap_free_free_free(m->subsystem_filter);
        set_free_free(m->tag_filter);

        return mfree(m);
}

DEFINE_PUBLIC_TRIVIAL_REF_UNREF_FUNC(sd_device_monitor, sd_device_monitor, device_monitor_free);

static int passes_filter(sd_device_monitor *m, sd_device *device) {
        const char *tag, *subsystem, *devtype, *s, *d = NULL;
        Iterator i;
        int r;

        assert_return(m, -EINVAL);
        assert_return(device, -EINVAL);

        if (hashmap_isempty(m->subsystem_filter))
                goto tag;

        r = sd_device_get_subsystem(device, &s);
        if (r < 0)
                return r;

        r = sd_device_get_devtype(device, &d);
        if (r < 0 && r != -ENOENT)
                return r;

        HASHMAP_FOREACH_KEY(devtype, subsystem, m->subsystem_filter, i) {
                if (!streq(s, subsystem))
                        continue;

                if (!devtype)
                        goto tag;

                if (!d)
                        continue;

                if (streq(d, devtype))
                        goto tag;
        }

        return 0;

tag:
        if (set_isempty(m->tag_filter))
                return 1;

        SET_FOREACH(tag, m->tag_filter, i)
                if (sd_device_has_tag(device, tag) > 0)
                        return 1;

        return 0;
}

int device_monitor_receive_device(sd_device_monitor *m, sd_device **ret) {
        _cleanup_(sd_device_unrefp) sd_device *device = NULL;
        union {
                monitor_netlink_header nlh;
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

        assert(ret);

        buflen = recvmsg(m->sock, &smsg, 0);
        if (buflen < 0) {
                if (errno != EINTR)
                        log_debug_errno(errno, "sd-device-monitor: Failed to receive message: %m");
                return -errno;
        }

        if (buflen < 32 || (smsg.msg_flags & MSG_TRUNC))
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "sd-device-monitor: Invalid message length.");

        if (snl.nl.nl_groups == MONITOR_GROUP_NONE) {
                /* unicast message, check if we trust the sender */
                if (m->snl_trusted_sender.nl.nl_pid == 0 ||
                    snl.nl.nl_pid != m->snl_trusted_sender.nl.nl_pid)
                        return log_debug_errno(SYNTHETIC_ERRNO(EAGAIN),
                                               "sd-device-monitor: Unicast netlink message ignored.");

        } else if (snl.nl.nl_groups == MONITOR_GROUP_KERNEL) {
                if (snl.nl.nl_pid > 0)
                        return log_debug_errno(SYNTHETIC_ERRNO(EAGAIN),
                                               "sd-device-monitor: Multicast kernel netlink message from PID %"PRIu32" ignored.", snl.nl.nl_pid);
        }

        cmsg = CMSG_FIRSTHDR(&smsg);
        if (!cmsg || cmsg->cmsg_type != SCM_CREDENTIALS)
                return log_debug_errno(SYNTHETIC_ERRNO(EAGAIN),
                                       "sd-device-monitor: No sender credentials received, message ignored.");

        cred = (struct ucred*) CMSG_DATA(cmsg);
        if (cred->uid != 0)
                return log_debug_errno(SYNTHETIC_ERRNO(EAGAIN),
                                       "sd-device-monitor: Sender uid="UID_FMT", message ignored.", cred->uid);

        if (streq(buf.raw, "libudev")) {
                /* udev message needs proper version magic */
                if (buf.nlh.magic != htobe32(UDEV_MONITOR_MAGIC))
                        return log_debug_errno(SYNTHETIC_ERRNO(EAGAIN),
                                               "sd-device-monitor: Invalid message signature (%x != %x)",
                                               buf.nlh.magic, htobe32(UDEV_MONITOR_MAGIC));

                if (buf.nlh.properties_off+32 > (size_t) buflen)
                        return log_debug_errno(SYNTHETIC_ERRNO(EAGAIN),
                                               "sd-device-monitor: Invalid message length (%u > %zd)",
                                               buf.nlh.properties_off+32, buflen);

                bufpos = buf.nlh.properties_off;

                /* devices received from udev are always initialized */
                is_initialized = true;

        } else {
                /* kernel message with header */
                bufpos = strlen(buf.raw) + 1;
                if ((size_t) bufpos < sizeof("a@/d") || bufpos >= buflen)
                        return log_debug_errno(SYNTHETIC_ERRNO(EAGAIN),
                                               "sd-device-monitor: Invalid message length");

                /* check message header */
                if (!strstr(buf.raw, "@/"))
                        return log_debug_errno(SYNTHETIC_ERRNO(EAGAIN),
                                               "sd-device-monitor: Invalid message header");
        }

        r = device_new_from_nulstr(&device, (uint8_t*) &buf.raw[bufpos], buflen - bufpos);
        if (r < 0)
                return log_debug_errno(r, "sd-device-monitor: Failed to create device from received message: %m");

        if (is_initialized)
                device_set_is_initialized(device);

        /* Skip device, if it does not pass the current filter */
        r = passes_filter(m, device);
        if (r < 0)
                return log_device_debug_errno(device, r, "sd-device-monitor: Failed to check received device passing filter: %m");
        if (r == 0)
                log_device_debug(device, "sd-device-monitor: Received device does not pass filter, ignoring");
        else
                *ret = TAKE_PTR(device);

        return r;
}

static uint32_t string_hash32(const char *str) {
        return MurmurHash2(str, strlen(str), 0);
}

/* Get a bunch of bit numbers out of the hash, and set the bits in our bit field */
static uint64_t string_bloom64(const char *str) {
        uint64_t bits = 0;
        uint32_t hash = string_hash32(str);

        bits |= 1LLU << (hash & 63);
        bits |= 1LLU << ((hash >> 6) & 63);
        bits |= 1LLU << ((hash >> 12) & 63);
        bits |= 1LLU << ((hash >> 18) & 63);
        return bits;
}

int device_monitor_send_device(
                sd_device_monitor *m,
                sd_device_monitor *destination,
                sd_device *device) {

        monitor_netlink_header nlh = {
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
        /* default destination for sending */
        union sockaddr_union default_destination = {
                .nl.nl_family = AF_NETLINK,
                .nl.nl_groups = MONITOR_GROUP_UDEV,
        };
        uint64_t tag_bloom_bits;
        const char *buf, *val;
        ssize_t count;
        size_t blen;
        int r;

        assert(m);
        assert(device);

        r = device_get_properties_nulstr(device, (const uint8_t **) &buf, &blen);
        if (r < 0)
                return log_device_debug_errno(device, r, "sd-device-monitor: Failed to get device properties: %m");
        if (blen < 32) {
                log_device_debug(device, "sd-device-monitor: Length of device property nulstr is too small to contain valid device information");
                return -EINVAL;
        }

        /* fill in versioned header */
        r = sd_device_get_subsystem(device, &val);
        if (r < 0)
                return log_device_debug_errno(device, r, "sd-device-monitor: Failed to get device subsystem: %m");
        nlh.filter_subsystem_hash = htobe32(string_hash32(val));

        if (sd_device_get_devtype(device, &val) >= 0)
                nlh.filter_devtype_hash = htobe32(string_hash32(val));

        /* add tag bloom filter */
        tag_bloom_bits = 0;
        FOREACH_DEVICE_TAG(device, val)
                tag_bloom_bits |= string_bloom64(val);

        if (tag_bloom_bits > 0) {
                nlh.filter_tag_bloom_hi = htobe32(tag_bloom_bits >> 32);
                nlh.filter_tag_bloom_lo = htobe32(tag_bloom_bits & 0xffffffff);
        }

        /* add properties list */
        nlh.properties_off = iov[0].iov_len;
        nlh.properties_len = blen;
        iov[1] = IOVEC_MAKE((char*) buf, blen);

        /*
         * Use custom address for target, or the default one.
         *
         * If we send to a multicast group, we will get
         * ECONNREFUSED, which is expected.
         */
        smsg.msg_name = destination ? &destination->snl : &default_destination;
        smsg.msg_namelen = sizeof(struct sockaddr_nl);
        count = sendmsg(m->sock, &smsg, 0);
        if (count < 0) {
                if (!destination && errno == ECONNREFUSED) {
                        log_device_debug(device, "sd-device-monitor: Passed to netlink monitor");
                        return 0;
                } else
                        return log_device_debug_errno(device, errno, "sd-device-monitor: Failed to send device to netlink monitor: %m");
        }

        log_device_debug(device, "sd-device-monitor: Passed %zi byte to netlink monitor", count);
        return count;
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

_public_ int sd_device_monitor_filter_update(sd_device_monitor *m) {
        struct sock_filter ins[512] = {};
        struct sock_fprog filter;
        const char *subsystem, *devtype, *tag;
        unsigned i = 0;
        Iterator it;

        assert_return(m, -EINVAL);

        if (m->filter_uptodate)
                return 0;

        if (hashmap_isempty(m->subsystem_filter) &&
            set_isempty(m->tag_filter)) {
                m->filter_uptodate = true;
                return 0;
        }

        /* load magic in A */
        bpf_stmt(ins, &i, BPF_LD|BPF_W|BPF_ABS, offsetof(monitor_netlink_header, magic));
        /* jump if magic matches */
        bpf_jmp(ins, &i, BPF_JMP|BPF_JEQ|BPF_K, UDEV_MONITOR_MAGIC, 1, 0);
        /* wrong magic, pass packet */
        bpf_stmt(ins, &i, BPF_RET|BPF_K, 0xffffffff);

        if (!set_isempty(m->tag_filter)) {
                int tag_matches = set_size(m->tag_filter);

                /* add all tags matches */
                SET_FOREACH(tag, m->tag_filter, it) {
                        uint64_t tag_bloom_bits = string_bloom64(tag);
                        uint32_t tag_bloom_hi = tag_bloom_bits >> 32;
                        uint32_t tag_bloom_lo = tag_bloom_bits & 0xffffffff;

                        /* load device bloom bits in A */
                        bpf_stmt(ins, &i, BPF_LD|BPF_W|BPF_ABS, offsetof(monitor_netlink_header, filter_tag_bloom_hi));
                        /* clear bits (tag bits & bloom bits) */
                        bpf_stmt(ins, &i, BPF_ALU|BPF_AND|BPF_K, tag_bloom_hi);
                        /* jump to next tag if it does not match */
                        bpf_jmp(ins, &i, BPF_JMP|BPF_JEQ|BPF_K, tag_bloom_hi, 0, 3);

                        /* load device bloom bits in A */
                        bpf_stmt(ins, &i, BPF_LD|BPF_W|BPF_ABS, offsetof(monitor_netlink_header, filter_tag_bloom_lo));
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
        if (!hashmap_isempty(m->subsystem_filter)) {
                HASHMAP_FOREACH_KEY(devtype, subsystem, m->subsystem_filter, it) {
                        uint32_t hash = string_hash32(subsystem);

                        /* load device subsystem value in A */
                        bpf_stmt(ins, &i, BPF_LD|BPF_W|BPF_ABS, offsetof(monitor_netlink_header, filter_subsystem_hash));
                        if (!devtype) {
                                /* jump if subsystem does not match */
                                bpf_jmp(ins, &i, BPF_JMP|BPF_JEQ|BPF_K, hash, 0, 1);
                        } else {
                                /* jump if subsystem does not match */
                                bpf_jmp(ins, &i, BPF_JMP|BPF_JEQ|BPF_K, hash, 0, 3);
                                /* load device devtype value in A */
                                bpf_stmt(ins, &i, BPF_LD|BPF_W|BPF_ABS, offsetof(monitor_netlink_header, filter_devtype_hash));
                                /* jump if value does not match */
                                hash = string_hash32(devtype);
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
        if (setsockopt(m->sock, SOL_SOCKET, SO_ATTACH_FILTER, &filter, sizeof(filter)) < 0)
                return -errno;

        m->filter_uptodate = true;
        return 0;
}

_public_ int sd_device_monitor_filter_add_match_subsystem_devtype(sd_device_monitor *m, const char *subsystem, const char *devtype) {
        _cleanup_free_ char *s = NULL, *d = NULL;
        int r;

        assert_return(m, -EINVAL);
        assert_return(subsystem, -EINVAL);

        s = strdup(subsystem);
        if (!s)
                return -ENOMEM;

        if (devtype) {
                d = strdup(devtype);
                if (!d)
                        return -ENOMEM;
        }

        r = hashmap_ensure_allocated(&m->subsystem_filter, NULL);
        if (r < 0)
                return r;

        r = hashmap_put(m->subsystem_filter, s, d);
        if (r < 0)
                return r;

        s = d = NULL;
        m->filter_uptodate = false;

        return 0;
}

_public_ int sd_device_monitor_filter_add_match_tag(sd_device_monitor *m, const char *tag) {
        _cleanup_free_ char *t = NULL;
        int r;

        assert_return(m, -EINVAL);
        assert_return(tag, -EINVAL);

        t = strdup(tag);
        if (!t)
                return -ENOMEM;

        r = set_ensure_allocated(&m->tag_filter, &string_hash_ops);
        if (r < 0)
                return r;

        r = set_put(m->tag_filter, t);
        if (r == -EEXIST)
                return 0;
        if (r < 0)
                return r;

        TAKE_PTR(t);
        m->filter_uptodate = false;

        return 0;
}

_public_ int sd_device_monitor_filter_remove(sd_device_monitor *m) {
        static const struct sock_fprog filter = { 0, NULL };

        assert_return(m, -EINVAL);

        m->subsystem_filter = hashmap_free_free_free(m->subsystem_filter);
        m->tag_filter = set_free_free(m->tag_filter);

        if (setsockopt(m->sock, SOL_SOCKET, SO_DETACH_FILTER, &filter, sizeof(filter)) < 0)
                return -errno;

        m->filter_uptodate = true;
        return 0;
}
