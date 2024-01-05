/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <linux/filter.h>
#include <linux/netlink.h>
#include <linux/sockios.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "sd-device.h"
#include "sd-event.h"

#include "MurmurHash2.h"
#include "alloc-util.h"
#include "device-filter.h"
#include "device-monitor-private.h"
#include "device-private.h"
#include "device-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "format-util.h"
#include "hashmap.h"
#include "iovec-util.h"
#include "missing_socket.h"
#include "mountpoint-util.h"
#include "set.h"
#include "socket-util.h"
#include "stat-util.h"
#include "string-util.h"
#include "strv.h"
#include "uid-range.h"

#define log_monitor(m, format, ...)                                     \
        log_debug("sd-device-monitor(%s): " format, strna(m ? m->description : NULL), ##__VA_ARGS__)
#define log_monitor_errno(m, r, format, ...)                            \
        log_debug_errno(r, "sd-device-monitor(%s): " format, strna(m ? m->description : NULL), ##__VA_ARGS__)
#define log_device_monitor(d, m, format, ...)                           \
        log_device_debug(d, "sd-device-monitor(%s): " format, strna(m ? m->description : NULL), ##__VA_ARGS__)
#define log_device_monitor_errno(d, m, r, format, ...)                  \
        log_device_debug_errno(d, r, "sd-device-monitor(%s): " format, strna(m ? m->description : NULL), ##__VA_ARGS__)

struct sd_device_monitor {
        unsigned n_ref;

        int sock;
        union sockaddr_union snl;
        union sockaddr_union snl_trusted_sender;
        bool bound;

        UidRange *mapped_userns_uid_range;

        Hashmap *subsystem_filter;
        Set *tag_filter;
        Hashmap *match_sysattr_filter;
        Hashmap *nomatch_sysattr_filter;
        Set *match_parent_filter;
        Set *nomatch_parent_filter;
        bool filter_uptodate;

        sd_event *event;
        sd_event_source *event_source;
        char *description;
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
        assert(m);
        assert(sender);

        m->snl_trusted_sender.nl.nl_pid = sender->snl.nl.nl_pid;
        return 0;
}

_public_ int sd_device_monitor_set_receive_buffer_size(sd_device_monitor *m, size_t size) {
        assert_return(m, -EINVAL);

        return fd_set_rcvbuf(m->sock, size, false);
}

int device_monitor_disconnect(sd_device_monitor *m) {
        assert(m);

        m->sock = safe_close(m->sock);
        return 0;
}

int device_monitor_get_fd(sd_device_monitor *m) {
        assert(m);

        return m->sock;
}

int device_monitor_new_full(sd_device_monitor **ret, MonitorNetlinkGroup group, int fd) {
        _cleanup_(sd_device_monitor_unrefp) sd_device_monitor *m = NULL;
        _cleanup_close_ int sock = -EBADF;
        int r;

        assert(group >= 0 && group < _MONITOR_NETLINK_GROUP_MAX);
        assert_return(ret, -EINVAL);

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

                log_monitor(m, "The udev service seems not to be active, disabling the monitor.");
                group = MONITOR_GROUP_NONE;
        }

        if (fd < 0) {
                sock = socket(AF_NETLINK, SOCK_RAW|SOCK_CLOEXEC|SOCK_NONBLOCK, NETLINK_KOBJECT_UEVENT);
                if (sock < 0)
                        return log_monitor_errno(m, errno, "Failed to create socket: %m");
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
                if (r < 0) {
                        log_monitor_errno(m, r, "Failed to set netlink address: %m");
                        goto fail;
                }
        }

        if (DEBUG_LOGGING) {
                _cleanup_close_ int netns = -EBADF;

                /* So here's the thing: only AF_NETLINK sockets from the main network namespace will get
                 * hardware events. Let's check if ours is from there, and if not generate a debug message,
                 * since we cannot possibly work correctly otherwise. This is just a safety check to make
                 * things easier to debug. */

                netns = ioctl(m->sock, SIOCGSKNS);
                if (netns < 0)
                        log_monitor_errno(m, errno, "Unable to get network namespace of udev netlink socket, unable to determine if we are in host netns, ignoring: %m");
                else {
                        struct stat a, b;

                        if (fstat(netns, &a) < 0) {
                                r = log_monitor_errno(m, errno, "Failed to stat netns of udev netlink socket: %m");
                                goto fail;
                        }

                        if (stat("/proc/1/ns/net", &b) < 0) {
                                if (ERRNO_IS_PRIVILEGE(errno))
                                        /* If we can't access PID1's netns info due to permissions, it's fine, this is a
                                         * safety check only after all. */
                                        log_monitor_errno(m, errno, "No permission to stat PID1's netns, unable to determine if we are in host netns, ignoring: %m");
                                else
                                        log_monitor_errno(m, errno, "Failed to stat PID1's netns, ignoring: %m");

                        } else if (!stat_inode_same(&a, &b))
                                log_monitor(m, "Netlink socket we listen on is not from host netns, we won't see device events.");
                }
        }

        /* Let's bump the receive buffer size, but only if we are not called via socket activation, as in
         * that case the service manager sets the receive buffer size for us, and the value in the .socket
         * unit should take full effect. */
        if (fd < 0) {
                r = sd_device_monitor_set_receive_buffer_size(m, 128*1024*1024);
                if (r < 0)
                        log_monitor_errno(m, r, "Failed to increase receive buffer size, ignoring: %m");
        }

        *ret = TAKE_PTR(m);
        return 0;

fail:
        /* Let's unset the socket fd in the monitor object before we destroy it so that the fd passed in is
         * not closed on failure. */
        if (fd >= 0)
                m->sock = -1;

        return r;
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
        _unused_ _cleanup_(log_context_unrefp) LogContext *c = NULL;
        sd_device_monitor *m = ASSERT_PTR(userdata);

        if (device_monitor_receive_device(m, &device) <= 0)
                return 0;

        if (log_context_enabled())
                c = log_context_new_strv_consume(device_make_log_fields(device));

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

        (void) sd_event_source_set_description(m->event_source, m->description ?: "sd-device-monitor");

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

_public_ int sd_device_monitor_set_description(sd_device_monitor *m, const char *description) {
        int r;

        assert_return(m, -EINVAL);

        r = free_and_strdup(&m->description, description);
        if (r <= 0)
                return r;

        if (m->event_source)
                (void) sd_event_source_set_description(m->event_source, description);

        return r;
}

_public_ int sd_device_monitor_get_description(sd_device_monitor *m, const char **ret) {
        assert_return(m, -EINVAL);
        assert_return(ret, -EINVAL);

        *ret = m->description;
        return 0;
}

int device_monitor_enable_receiving(sd_device_monitor *m) {
        int r;

        assert(m);

        r = sd_device_monitor_filter_update(m);
        if (r < 0)
                return log_monitor_errno(m, r, "Failed to update filter: %m");

        if (!m->bound) {
                /* enable receiving of sender credentials */
                r = setsockopt_int(m->sock, SOL_SOCKET, SO_PASSCRED, true);
                if (r < 0)
                        return log_monitor_errno(m, r, "Failed to set socket option SO_PASSCRED: %m");

                if (bind(m->sock, &m->snl.sa, sizeof(struct sockaddr_nl)) < 0)
                        return log_monitor_errno(m, errno, "Failed to bind monitoring socket: %m");

                m->bound = true;

                r = monitor_set_nl_address(m);
                if (r < 0)
                        return log_monitor_errno(m, r, "Failed to set address: %m");
        }

        return 0;
}

static sd_device_monitor *device_monitor_free(sd_device_monitor *m) {
        assert(m);

        (void) sd_device_monitor_detach_event(m);

        uid_range_free(m->mapped_userns_uid_range);
        free(m->description);
        hashmap_free(m->subsystem_filter);
        set_free(m->tag_filter);
        hashmap_free(m->match_sysattr_filter);
        hashmap_free(m->nomatch_sysattr_filter);
        set_free(m->match_parent_filter);
        set_free(m->nomatch_parent_filter);

        return mfree(m);
}

DEFINE_PUBLIC_TRIVIAL_REF_UNREF_FUNC(sd_device_monitor, sd_device_monitor, device_monitor_free);

static int check_subsystem_filter(sd_device_monitor *m, sd_device *device) {
        const char *s, *d;

        assert(m);
        assert(device);

        if (hashmap_isempty(m->subsystem_filter))
                return true;

        HASHMAP_FOREACH_KEY(d, s, m->subsystem_filter) {
                if (!device_in_subsystem(device, s))
                        continue;

                if (d && !device_is_devtype(device, d))
                        continue;

                return true;
        }

        return false;
}

static bool check_tag_filter(sd_device_monitor *m, sd_device *device) {
        const char *tag;

        assert(m);
        assert(device);

        if (set_isempty(m->tag_filter))
                return true;

        SET_FOREACH(tag, m->tag_filter)
                if (sd_device_has_tag(device, tag) > 0)
                        return true;

        return false;
}

static int passes_filter(sd_device_monitor *m, sd_device *device) {
        int r;

        assert(m);
        assert(device);

        r = check_subsystem_filter(m, device);
        if (r <= 0)
                return r;

        if (!check_tag_filter(m, device))
                return false;

        if (!device_match_sysattr(device, m->match_sysattr_filter, m->nomatch_sysattr_filter))
                return false;

        return device_match_parent(device, m->match_parent_filter, m->nomatch_parent_filter);
}

static bool check_sender_uid(sd_device_monitor *m, uid_t uid) {
        int r;

        assert(m);

        /* Always trust messages from uid 0. */
        if (uid == 0)
                return true;

        /* Trust messages sent by the same UID we are running. Currently, such situation happens only for
         * unicast messages. */
        if (uid == getuid() || uid == geteuid())
                return true;

        if (!m->mapped_userns_uid_range) {
                r = uid_range_load_userns(&m->mapped_userns_uid_range, NULL, UID_RANGE_USERNS_INSIDE);
                if (r < 0)
                        log_monitor_errno(m, r, "Failed to load UID ranges mapped to the current user namespace, ignoring: %m");
        }

        /* Trust messages come from outside of the current user namespace. */
        if (!uid_range_contains(m->mapped_userns_uid_range, uid))
                return true;

        /* Otherwise, refuse messages. */
        return false;
}

int device_monitor_receive_device(sd_device_monitor *m, sd_device **ret) {
        _cleanup_(sd_device_unrefp) sd_device *device = NULL;
        _cleanup_free_ uint8_t *buf_alloc = NULL;
        union {
                monitor_netlink_header *nlh;
                char *nulstr;
                uint8_t *buf;
        } message;
        struct iovec iov;
        CMSG_BUFFER_TYPE(CMSG_SPACE(sizeof(struct ucred))) control;
        union sockaddr_union snl;
        struct msghdr smsg = {
                .msg_iov = &iov,
                .msg_iovlen = 1,
                .msg_control = &control,
                .msg_controllen = sizeof(control),
                .msg_name = &snl,
                .msg_namelen = sizeof(snl),
        };
        struct ucred *cred;
        size_t offset;
        ssize_t n;
        bool is_initialized = false;
        int r;

        assert(m);
        assert(ret);

        n = next_datagram_size_fd(m->sock);
        if (n < 0) {
                if (!ERRNO_IS_TRANSIENT(n))
                        log_monitor_errno(m, n, "Failed to get the received message size: %m");
                return n;
        }

        if ((size_t) n < ALLOCA_MAX / sizeof(uint8_t) / 2)
                message.buf = newa(uint8_t, n);
        else {
                buf_alloc = new(uint8_t, n);
                if (!buf_alloc)
                        return log_oom_debug();

                message.buf = buf_alloc;
        }

        iov = IOVEC_MAKE(message.buf, n);

        n = recvmsg(m->sock, &smsg, 0);
        if (n < 0) {
                if (!ERRNO_IS_TRANSIENT(errno))
                        log_monitor_errno(m, errno, "Failed to receive message: %m");
                return -errno;
        }

        if (smsg.msg_flags & MSG_TRUNC)
                return log_monitor_errno(m, SYNTHETIC_ERRNO(EINVAL), "Received truncated message, ignoring message.");

        if (n < 32)
                return log_monitor_errno(m, SYNTHETIC_ERRNO(EINVAL), "Invalid message length (%zi), ignoring message.", n);

        if (snl.nl.nl_groups == MONITOR_GROUP_NONE) {
                /* unicast message, check if we trust the sender */
                if (m->snl_trusted_sender.nl.nl_pid == 0 ||
                    snl.nl.nl_pid != m->snl_trusted_sender.nl.nl_pid)
                        return log_monitor_errno(m, SYNTHETIC_ERRNO(EAGAIN),
                                                 "Unicast netlink message ignored.");

        } else if (snl.nl.nl_groups == MONITOR_GROUP_KERNEL) {
                if (snl.nl.nl_pid > 0)
                        return log_monitor_errno(m, SYNTHETIC_ERRNO(EAGAIN),
                                                 "Multicast kernel netlink message from PID %"PRIu32" ignored.",
                                                 snl.nl.nl_pid);
        }

        cred = CMSG_FIND_DATA(&smsg, SOL_SOCKET, SCM_CREDENTIALS, struct ucred);
        if (!cred)
                return log_monitor_errno(m, SYNTHETIC_ERRNO(EAGAIN),
                                         "No sender credentials received, ignoring message.");

        if (!check_sender_uid(m, cred->uid))
                return log_monitor_errno(m, SYNTHETIC_ERRNO(EAGAIN),
                                         "Sender uid="UID_FMT", message ignored.", cred->uid);

        if (!memchr(message.buf, 0, n))
                return log_monitor_errno(m, SYNTHETIC_ERRNO(EAGAIN), "Received message without NUL, ignoring message.");

        if (streq(message.nulstr, "libudev")) {
                /* udev message needs proper version magic */
                if (message.nlh->magic != htobe32(UDEV_MONITOR_MAGIC))
                        return log_monitor_errno(m, SYNTHETIC_ERRNO(EAGAIN),
                                                 "Invalid message signature (%x != %x).",
                                                 message.nlh->magic, htobe32(UDEV_MONITOR_MAGIC));

                if (message.nlh->properties_off + 32 > (size_t) n)
                        return log_monitor_errno(m, SYNTHETIC_ERRNO(EAGAIN),
                                                 "Invalid offset for properties (%u > %zi).",
                                                 message.nlh->properties_off + 32, n);

                offset = message.nlh->properties_off;

                /* devices received from udev are always initialized */
                is_initialized = true;

        } else {
                /* check kernel message header */
                if (!strstr(message.nulstr, "@/"))
                        return log_monitor_errno(m, SYNTHETIC_ERRNO(EAGAIN), "Invalid message header.");

                offset = strlen(message.nulstr) + 1;
                if (offset >= (size_t) n)
                        return log_monitor_errno(m, SYNTHETIC_ERRNO(EAGAIN), "Invalid message length.");
        }

        r = device_new_from_nulstr(&device, message.nulstr + offset, n - offset);
        if (r < 0)
                return log_monitor_errno(m, r, "Failed to create device from received message: %m");

        if (is_initialized)
                device_set_is_initialized(device);

        /* Skip device, if it does not pass the current filter */
        r = passes_filter(m, device);
        if (r < 0)
                return log_device_monitor_errno(device, m, r, "Failed to check received device passing filter: %m");
        if (r == 0)
                log_device_monitor(device, m, "Received device does not pass filter, ignoring.");
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

        bits |= UINT64_C(1) << (hash & 63);
        bits |= UINT64_C(1) << ((hash >> 6) & 63);
        bits |= UINT64_C(1) << ((hash >> 12) & 63);
        bits |= UINT64_C(1) << ((hash >> 18) & 63);
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

        r = device_get_properties_nulstr(device, &buf, &blen);
        if (r < 0)
                return log_device_monitor_errno(device, m, r, "Failed to get device properties: %m");
        if (blen < 32)
                return log_device_monitor_errno(device, m, SYNTHETIC_ERRNO(EINVAL),
                                                "Length of device property nulstr is too small to contain valid device information.");

        /* fill in versioned header */
        r = sd_device_get_subsystem(device, &val);
        if (r < 0)
                return log_device_monitor_errno(device, m, r, "Failed to get device subsystem: %m");
        nlh.filter_subsystem_hash = htobe32(string_hash32(val));

        if (sd_device_get_devtype(device, &val) >= 0)
                nlh.filter_devtype_hash = htobe32(string_hash32(val));

        /* add tag bloom filter */
        tag_bloom_bits = 0;
        FOREACH_DEVICE_TAG(device, tag)
                tag_bloom_bits |= string_bloom64(tag);

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
                        log_device_monitor(device, m, "Passed to netlink monitor.");
                        return 0;
                } else
                        return log_device_monitor_errno(device, m, errno, "Failed to send device to netlink monitor: %m");
        }

        log_device_monitor(device, m, "Passed %zi byte to netlink monitor.", count);
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

        assert_return(m, -EINVAL);

        if (m->filter_uptodate)
                return 0;

        if (m->snl.nl.nl_groups == MONITOR_GROUP_KERNEL ||
            (hashmap_isempty(m->subsystem_filter) &&
             set_isempty(m->tag_filter))) {
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
                SET_FOREACH(tag, m->tag_filter) {
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
                HASHMAP_FOREACH_KEY(devtype, subsystem, m->subsystem_filter) {
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
        int r;

        assert_return(m, -EINVAL);
        assert_return(subsystem, -EINVAL);

        /* Do not use string_has_ops_free_free or hashmap_put_strdup() here, as this may be called
         * multiple times with the same subsystem but different devtypes. */
        r = hashmap_put_strdup_full(&m->subsystem_filter, &trivial_hash_ops_free_free, subsystem, devtype);
        if (r <= 0)
                return r;

        m->filter_uptodate = false;
        return r;
}

_public_ int sd_device_monitor_filter_add_match_tag(sd_device_monitor *m, const char *tag) {
        int r;

        assert_return(m, -EINVAL);
        assert_return(tag, -EINVAL);

        r = set_put_strdup(&m->tag_filter, tag);
        if (r <= 0)
                return r;

        m->filter_uptodate = false;
        return r;
}

_public_ int sd_device_monitor_filter_add_match_sysattr(sd_device_monitor *m, const char *sysattr, const char *value, int match) {
        Hashmap **hashmap;

        assert_return(m, -EINVAL);
        assert_return(sysattr, -EINVAL);

        if (match)
                hashmap = &m->match_sysattr_filter;
        else
                hashmap = &m->nomatch_sysattr_filter;

        /* TODO: unset m->filter_uptodate on success when we support this filter on BPF. */
        return update_match_strv(hashmap, sysattr, value, /* clear_on_null = */ true);
}

_public_ int sd_device_monitor_filter_add_match_parent(sd_device_monitor *m, sd_device *device, int match) {
        const char *syspath;
        Set **set;
        int r;

        assert_return(m, -EINVAL);
        assert_return(device, -EINVAL);

        r = sd_device_get_syspath(device, &syspath);
        if (r < 0)
                return r;

        if (match)
                set = &m->match_parent_filter;
        else
                set = &m->nomatch_parent_filter;

        /* TODO: unset m->filter_uptodate on success when we support this filter on BPF. */
        return set_put_strdup(set, syspath);
}

_public_ int sd_device_monitor_filter_remove(sd_device_monitor *m) {
        static const struct sock_fprog filter = { 0, NULL };

        assert_return(m, -EINVAL);

        m->subsystem_filter = hashmap_free(m->subsystem_filter);
        m->tag_filter = set_free(m->tag_filter);
        m->match_sysattr_filter = hashmap_free(m->match_sysattr_filter);
        m->nomatch_sysattr_filter = hashmap_free(m->nomatch_sysattr_filter);
        m->match_parent_filter = set_free(m->match_parent_filter);
        m->nomatch_parent_filter = set_free(m->nomatch_parent_filter);

        if (setsockopt(m->sock, SOL_SOCKET, SO_DETACH_FILTER, &filter, sizeof(filter)) < 0)
                return -errno;

        m->filter_uptodate = true;
        return 0;
}
