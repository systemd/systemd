/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <linux/filter.h>
#include <linux/netlink.h>
#include <linux/sockios.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "sd-device.h"
#include "sd-event.h"

#include "alloc-util.h"
#include "device-internal.h"
#include "device-util.h"
#include "device-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "format-util.h"
#include "hashmap.h"
#include "io-util.h"
#include "missing_socket.h"
#include "mountpoint-util.h"
#include "set.h"
#include "socket-util.h"
#include "stat-util.h"
#include "string-util.h"
#include "strv.h"

static sd_device_monitor *device_monitor_free(sd_device_monitor *m) {
        assert(m);

        (void) sd_device_monitor_detach_event(m);

        hashmap_free(m->subsystem_filter);
        set_free(m->tag_filter);
        hashmap_free(m->match_sysattr_filter);
        hashmap_free(m->nomatch_sysattr_filter);
        set_free(m->match_parent_filter);
        set_free(m->nomatch_parent_filter);

        return mfree(m);
}

DEFINE_PUBLIC_TRIVIAL_REF_UNREF_FUNC(sd_device_monitor, sd_device_monitor, device_monitor_free);

_public_ int sd_device_monitor_set_receive_buffer_size(sd_device_monitor *m, size_t size) {
        assert_return(m, -EINVAL);

        return fd_set_rcvbuf(m->sock, size, false);
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
        return hashmap_put_strdup_full(hashmap, &trivial_hash_ops_free_free, sysattr, value);
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
