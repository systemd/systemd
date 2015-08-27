/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2013 Lennart Poettering

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

#ifdef HAVE_VALGRIND_MEMCHECK_H
#include <valgrind/memcheck.h>
#endif

#include <fcntl.h>
#include <malloc.h>
#include <sys/mman.h>
#include <sys/prctl.h>

/* When we include libgen.h because we need dirname() we immediately
 * undefine basename() since libgen.h defines it as a macro to the POSIX
 * version which is really broken. We prefer GNU basename(). */
#include <libgen.h>
#undef basename

#include "util.h"
#include "strv.h"
#include "memfd-util.h"
#include "capability.h"
#include "fileio.h"
#include "formats-util.h"

#include "bus-internal.h"
#include "bus-message.h"
#include "bus-kernel.h"
#include "bus-bloom.h"
#include "bus-util.h"
#include "bus-label.h"

#define UNIQUE_NAME_MAX (3+DECIMAL_STR_MAX(uint64_t))

int bus_kernel_parse_unique_name(const char *s, uint64_t *id) {
        int r;

        assert(s);
        assert(id);

        if (!startswith(s, ":1."))
                return 0;

        r = safe_atou64(s + 3, id);
        if (r < 0)
                return r;

        return 1;
}

static void append_payload_vec(struct kdbus_item **d, const void *p, size_t sz) {
        assert(d);
        assert(sz > 0);

        *d = ALIGN8_PTR(*d);

        /* Note that p can be NULL, which encodes a region full of
         * zeroes, which is useful to optimize certain padding
         * conditions */

        (*d)->size = offsetof(struct kdbus_item, vec) + sizeof(struct kdbus_vec);
        (*d)->type = KDBUS_ITEM_PAYLOAD_VEC;
        (*d)->vec.address = PTR_TO_UINT64(p);
        (*d)->vec.size = sz;

        *d = (struct kdbus_item *) ((uint8_t*) *d + (*d)->size);
}

static void append_payload_memfd(struct kdbus_item **d, int memfd, size_t start, size_t sz) {
        assert(d);
        assert(memfd >= 0);
        assert(sz > 0);

        *d = ALIGN8_PTR(*d);
        (*d)->size = offsetof(struct kdbus_item, memfd) + sizeof(struct kdbus_memfd);
        (*d)->type = KDBUS_ITEM_PAYLOAD_MEMFD;
        (*d)->memfd.fd = memfd;
        (*d)->memfd.start = start;
        (*d)->memfd.size = sz;

        *d = (struct kdbus_item *) ((uint8_t*) *d + (*d)->size);
}

static void append_destination(struct kdbus_item **d, const char *s, size_t length) {
        assert(d);
        assert(s);

        *d = ALIGN8_PTR(*d);

        (*d)->size = offsetof(struct kdbus_item, str) + length + 1;
        (*d)->type = KDBUS_ITEM_DST_NAME;
        memcpy((*d)->str, s, length + 1);

        *d = (struct kdbus_item *) ((uint8_t*) *d + (*d)->size);
}

static struct kdbus_bloom_filter *append_bloom(struct kdbus_item **d, size_t length) {
        struct kdbus_item *i;

        assert(d);

        i = ALIGN8_PTR(*d);

        i->size = offsetof(struct kdbus_item, bloom_filter) +
                  offsetof(struct kdbus_bloom_filter, data) +
                  length;
        i->type = KDBUS_ITEM_BLOOM_FILTER;

        *d = (struct kdbus_item *) ((uint8_t*) i + i->size);

        return &i->bloom_filter;
}

static void append_fds(struct kdbus_item **d, const int fds[], unsigned n_fds) {
        assert(d);
        assert(fds);
        assert(n_fds > 0);

        *d = ALIGN8_PTR(*d);
        (*d)->size = offsetof(struct kdbus_item, fds) + sizeof(int) * n_fds;
        (*d)->type = KDBUS_ITEM_FDS;
        memcpy((*d)->fds, fds, sizeof(int) * n_fds);

        *d = (struct kdbus_item *) ((uint8_t*) *d + (*d)->size);
}

static void add_bloom_arg(void *data, size_t size, unsigned n_hash, unsigned i, const char *t) {
        char buf[sizeof("arg")-1 + 2 + sizeof("-slash-prefix")];
        char *e;

        assert(data);
        assert(size > 0);
        assert(i < 64);
        assert(t);

        e = stpcpy(buf, "arg");
        if (i < 10)
                *(e++) = '0' + (char) i;
        else {
                *(e++) = '0' + (char) (i / 10);
                *(e++) = '0' + (char) (i % 10);
        }

        *e = 0;
        bloom_add_pair(data, size, n_hash, buf, t);

        strcpy(e, "-dot-prefix");
        bloom_add_prefixes(data, size, n_hash, buf, t, '.');
        strcpy(e, "-slash-prefix");
        bloom_add_prefixes(data, size, n_hash, buf, t, '/');
}

static void add_bloom_arg_has(void *data, size_t size, unsigned n_hash, unsigned i, const char *t) {
        char buf[sizeof("arg")-1 + 2 + sizeof("-has")];
        char *e;

        assert(data);
        assert(size > 0);
        assert(i < 64);
        assert(t);

        e = stpcpy(buf, "arg");
        if (i < 10)
                *(e++) = '0' + (char) i;
        else {
                *(e++) = '0' + (char) (i / 10);
                *(e++) = '0' + (char) (i % 10);
        }

        strcpy(e, "-has");
        bloom_add_pair(data, size, n_hash, buf, t);
}

static int bus_message_setup_bloom(sd_bus_message *m, struct kdbus_bloom_filter *bloom) {
        void *data;
        unsigned i;
        int r;

        assert(m);
        assert(bloom);

        data = bloom->data;
        memzero(data, m->bus->bloom_size);
        bloom->generation = 0;

        bloom_add_pair(data, m->bus->bloom_size, m->bus->bloom_n_hash, "message-type", bus_message_type_to_string(m->header->type));

        if (m->interface)
                bloom_add_pair(data, m->bus->bloom_size, m->bus->bloom_n_hash, "interface", m->interface);
        if (m->member)
                bloom_add_pair(data, m->bus->bloom_size, m->bus->bloom_n_hash, "member", m->member);
        if (m->path) {
                bloom_add_pair(data, m->bus->bloom_size, m->bus->bloom_n_hash, "path", m->path);
                bloom_add_pair(data, m->bus->bloom_size, m->bus->bloom_n_hash, "path-slash-prefix", m->path);
                bloom_add_prefixes(data, m->bus->bloom_size, m->bus->bloom_n_hash, "path-slash-prefix", m->path, '/');
        }

        r = sd_bus_message_rewind(m, true);
        if (r < 0)
                return r;

        for (i = 0; i < 64; i++) {
                const char *t, *contents;
                char type;

                r = sd_bus_message_peek_type(m, &type, &contents);
                if (r < 0)
                        return r;

                if (IN_SET(type, SD_BUS_TYPE_STRING, SD_BUS_TYPE_OBJECT_PATH, SD_BUS_TYPE_SIGNATURE)) {

                        /* The bloom filter includes simple strings of any kind */
                        r = sd_bus_message_read_basic(m, type, &t);
                        if (r < 0)
                                return r;

                        add_bloom_arg(data, m->bus->bloom_size, m->bus->bloom_n_hash, i, t);
                }

                if (type == SD_BUS_TYPE_ARRAY && STR_IN_SET(contents, "s", "o", "g")) {

                        /* As well as array of simple strings of any kinds */
                        r = sd_bus_message_enter_container(m, type, contents);
                        if (r < 0)
                                return r;

                        while ((r = sd_bus_message_read_basic(m, contents[0], &t)) > 0)
                                add_bloom_arg_has(data, m->bus->bloom_size, m->bus->bloom_n_hash, i, t);
                        if (r < 0)
                                return r;

                        r = sd_bus_message_exit_container(m);
                        if (r < 0)
                                return r;

                } else
                        /* Stop adding to bloom filter as soon as we
                         * run into the first argument we cannot add
                         * to it. */
                        break;
        }

        return 0;
}

static int bus_message_setup_kmsg(sd_bus *b, sd_bus_message *m) {
        struct bus_body_part *part;
        struct kdbus_item *d;
        const char *destination;
        bool well_known;
        uint64_t unique;
        size_t sz, dl;
        unsigned i;
        int r;

        assert(b);
        assert(m);
        assert(m->sealed);

        /* We put this together only once, if this message is reused
         * we reuse the earlier-built version */
        if (m->kdbus)
                return 0;

        destination = m->destination ?: m->destination_ptr;

        if (destination) {
                r = bus_kernel_parse_unique_name(destination, &unique);
                if (r < 0)
                        return r;

                well_known = r == 0;
        } else
                well_known = false;

        sz = offsetof(struct kdbus_msg, items);

        /* Add in fixed header, fields header and payload */
        sz += (1 + m->n_body_parts) * ALIGN8(offsetof(struct kdbus_item, vec) +
                                             MAX(sizeof(struct kdbus_vec),
                                                 sizeof(struct kdbus_memfd)));

        /* Add space for bloom filter */
        sz += ALIGN8(offsetof(struct kdbus_item, bloom_filter) +
                     offsetof(struct kdbus_bloom_filter, data) +
                     m->bus->bloom_size);

        /* Add in well-known destination header */
        if (well_known) {
                dl = strlen(destination);
                sz += ALIGN8(offsetof(struct kdbus_item, str) + dl + 1);
        }

        /* Add space for unix fds */
        if (m->n_fds > 0)
                sz += ALIGN8(offsetof(struct kdbus_item, fds) + sizeof(int)*m->n_fds);

        m->kdbus = memalign(8, sz);
        if (!m->kdbus) {
                r = -ENOMEM;
                goto fail;
        }

        m->free_kdbus = true;
        memzero(m->kdbus, sz);

        m->kdbus->flags =
                ((m->header->flags & BUS_MESSAGE_NO_REPLY_EXPECTED) ? 0 : KDBUS_MSG_EXPECT_REPLY) |
                ((m->header->flags & BUS_MESSAGE_NO_AUTO_START) ? KDBUS_MSG_NO_AUTO_START : 0) |
                ((m->header->type == SD_BUS_MESSAGE_SIGNAL) ? KDBUS_MSG_SIGNAL : 0);

        if (well_known)
                /* verify_destination_id will usually be 0, which makes the kernel driver only look
                 * at the provided well-known name. Otherwise, the kernel will make sure the provided
                 * destination id matches the owner of the provided weel-known-name, and fail if they
                 * differ. Currently, this is only needed for bus-proxyd. */
                m->kdbus->dst_id = m->verify_destination_id;
        else
                m->kdbus->dst_id = destination ? unique : KDBUS_DST_ID_BROADCAST;

        m->kdbus->payload_type = KDBUS_PAYLOAD_DBUS;
        m->kdbus->cookie = m->header->dbus2.cookie;
        m->kdbus->priority = m->priority;

        if (m->header->flags & BUS_MESSAGE_NO_REPLY_EXPECTED)
                m->kdbus->cookie_reply = m->reply_cookie;
        else {
                struct timespec now;

                assert_se(clock_gettime(CLOCK_MONOTONIC_COARSE, &now) == 0);
                m->kdbus->timeout_ns = now.tv_sec * NSEC_PER_SEC + now.tv_nsec +
                                       m->timeout * NSEC_PER_USEC;
        }

        d = m->kdbus->items;

        if (well_known)
                append_destination(&d, destination, dl);

        append_payload_vec(&d, m->header, BUS_MESSAGE_BODY_BEGIN(m));

        MESSAGE_FOREACH_PART(part, i, m) {
                if (part->is_zero) {
                        /* If this is padding then simply send a
                         * vector with a NULL data pointer which the
                         * kernel will just pass through. This is the
                         * most efficient way to encode zeroes */

                        append_payload_vec(&d, NULL, part->size);
                        continue;
                }

                if (part->memfd >= 0 && part->sealed && destination) {
                        /* Try to send a memfd, if the part is
                         * sealed and this is not a broadcast. Since we can only  */

                        append_payload_memfd(&d, part->memfd, part->memfd_offset, part->size);
                        continue;
                }

                /* Otherwise, let's send a vector to the actual data.
                 * For that, we need to map it first. */
                r = bus_body_part_map(part);
                if (r < 0)
                        goto fail;

                append_payload_vec(&d, part->data, part->size);
        }

        if (m->header->type == SD_BUS_MESSAGE_SIGNAL) {
                struct kdbus_bloom_filter *bloom;

                bloom = append_bloom(&d, m->bus->bloom_size);
                r = bus_message_setup_bloom(m, bloom);
                if (r < 0)
                        goto fail;
        }

        if (m->n_fds > 0)
                append_fds(&d, m->fds, m->n_fds);

        m->kdbus->size = (uint8_t*) d - (uint8_t*) m->kdbus;
        assert(m->kdbus->size <= sz);

        return 0;

fail:
        m->poisoned = true;
        return r;
}

static void unset_memfds(struct sd_bus_message *m) {
        struct bus_body_part *part;
        unsigned i;

        assert(m);

        /* Make sure the memfds are not freed twice */
        MESSAGE_FOREACH_PART(part, i, m)
                if (part->memfd >= 0)
                        part->memfd = -1;
}

static void message_set_timestamp(sd_bus *bus, sd_bus_message *m, const struct kdbus_timestamp *ts) {
        assert(bus);
        assert(m);

        if (!ts)
                return;

        if (!(bus->attach_flags & KDBUS_ATTACH_TIMESTAMP))
                return;

        m->realtime = ts->realtime_ns / NSEC_PER_USEC;
        m->monotonic = ts->monotonic_ns / NSEC_PER_USEC;
        m->seqnum = ts->seqnum;
}

static int bus_kernel_make_message(sd_bus *bus, struct kdbus_msg *k) {
        sd_bus_message *m = NULL;
        struct kdbus_item *d;
        unsigned n_fds = 0;
        _cleanup_free_ int *fds = NULL;
        struct bus_header *header = NULL;
        void *footer = NULL;
        size_t header_size = 0, footer_size = 0;
        size_t n_bytes = 0, idx = 0;
        const char *destination = NULL, *seclabel = NULL;
        bool last_was_memfd = false;
        int r;

        assert(bus);
        assert(k);
        assert(k->payload_type == KDBUS_PAYLOAD_DBUS);

        KDBUS_ITEM_FOREACH(d, k, items) {
                size_t l;

                l = d->size - offsetof(struct kdbus_item, data);

                switch (d->type) {

                case KDBUS_ITEM_PAYLOAD_OFF:
                        if (!header) {
                                header = (struct bus_header*)((uint8_t*) k + d->vec.offset);
                                header_size = d->vec.size;
                        }

                        footer = (uint8_t*) k + d->vec.offset;
                        footer_size = d->vec.size;

                        n_bytes += d->vec.size;
                        last_was_memfd = false;
                        break;

                case KDBUS_ITEM_PAYLOAD_MEMFD:
                        if (!header) /* memfd cannot be first part */
                                return -EBADMSG;

                        n_bytes += d->memfd.size;
                        last_was_memfd = true;
                        break;

                case KDBUS_ITEM_FDS: {
                        int *f;
                        unsigned j;

                        j = l / sizeof(int);
                        f = realloc(fds, sizeof(int) * (n_fds + j));
                        if (!f)
                                return -ENOMEM;

                        fds = f;
                        memcpy(fds + n_fds, d->fds, sizeof(int) * j);
                        n_fds += j;
                        break;
                }

                case KDBUS_ITEM_SECLABEL:
                        seclabel = d->str;
                        break;
                }
        }

        if (last_was_memfd) /* memfd cannot be last part */
                return -EBADMSG;

        if (!header)
                return -EBADMSG;

        if (header_size < sizeof(struct bus_header))
                return -EBADMSG;

        /* on kdbus we only speak native endian gvariant, never dbus1
         * marshalling or reverse endian */
        if (header->version != 2 ||
            header->endian != BUS_NATIVE_ENDIAN)
                return -EPROTOTYPE;

        r = bus_message_from_header(
                        bus,
                        header, header_size,
                        footer, footer_size,
                        n_bytes,
                        fds, n_fds,
                        seclabel, 0, &m);
        if (r < 0)
                return r;

        /* The well-known names list is different from the other
        credentials. If we asked for it, but nothing is there, this
        means that the list of well-known names is simply empty, not
        that we lack any data */

        m->creds.mask |= (SD_BUS_CREDS_UNIQUE_NAME|SD_BUS_CREDS_WELL_KNOWN_NAMES) & bus->creds_mask;

        KDBUS_ITEM_FOREACH(d, k, items) {
                size_t l;

                l = d->size - offsetof(struct kdbus_item, data);

                switch (d->type) {

                case KDBUS_ITEM_PAYLOAD_OFF: {
                        size_t begin_body;

                        begin_body = BUS_MESSAGE_BODY_BEGIN(m);

                        if (idx + d->vec.size > begin_body) {
                                struct bus_body_part *part;

                                /* Contains body material */

                                part = message_append_part(m);
                                if (!part) {
                                        r = -ENOMEM;
                                        goto fail;
                                }

                                /* A -1 offset is NUL padding. */
                                part->is_zero = d->vec.offset == ~0ULL;

                                if (idx >= begin_body) {
                                        if (!part->is_zero)
                                                part->data = (uint8_t* )k + d->vec.offset;
                                        part->size = d->vec.size;
                                } else {
                                        if (!part->is_zero)
                                                part->data = (uint8_t*) k + d->vec.offset + (begin_body - idx);
                                        part->size = d->vec.size - (begin_body - idx);
                                }

                                part->sealed = true;
                        }

                        idx += d->vec.size;
                        break;
                }

                case KDBUS_ITEM_PAYLOAD_MEMFD: {
                        struct bus_body_part *part;

                        if (idx < BUS_MESSAGE_BODY_BEGIN(m)) {
                                r = -EBADMSG;
                                goto fail;
                        }

                        part = message_append_part(m);
                        if (!part) {
                                r = -ENOMEM;
                                goto fail;
                        }

                        part->memfd = d->memfd.fd;
                        part->memfd_offset = d->memfd.start;
                        part->size = d->memfd.size;
                        part->sealed = true;

                        idx += d->memfd.size;
                        break;
                }

                case KDBUS_ITEM_PIDS:

                        /* The PID/TID might be missing, when the data
                         * is faked by a bus proxy and it lacks that
                         * information about the real client (since
                         * SO_PEERCRED is used for that). Also kernel
                         * namespacing might make some of this data
                         * unavailable when untranslatable. */

                        if (d->pids.pid > 0) {
                                m->creds.pid = (pid_t) d->pids.pid;
                                m->creds.mask |= SD_BUS_CREDS_PID & bus->creds_mask;
                        }

                        if (d->pids.tid > 0) {
                                m->creds.tid = (pid_t) d->pids.tid;
                                m->creds.mask |= SD_BUS_CREDS_TID & bus->creds_mask;
                        }

                        if (d->pids.ppid > 0) {
                                m->creds.ppid = (pid_t) d->pids.ppid;
                                m->creds.mask |= SD_BUS_CREDS_PPID & bus->creds_mask;
                        } else if (d->pids.pid == 1) {
                                m->creds.ppid = 0;
                                m->creds.mask |= SD_BUS_CREDS_PPID & bus->creds_mask;
                        }

                        break;

                case KDBUS_ITEM_CREDS:

                        /* EUID/SUID/FSUID/EGID/SGID/FSGID might be
                         * missing too (see above). */

                        if ((uid_t) d->creds.uid != UID_INVALID) {
                                m->creds.uid = (uid_t) d->creds.uid;
                                m->creds.mask |= SD_BUS_CREDS_UID & bus->creds_mask;
                        }

                        if ((uid_t) d->creds.euid != UID_INVALID) {
                                m->creds.euid = (uid_t) d->creds.euid;
                                m->creds.mask |= SD_BUS_CREDS_EUID & bus->creds_mask;
                        }

                        if ((uid_t) d->creds.suid != UID_INVALID) {
                                m->creds.suid = (uid_t) d->creds.suid;
                                m->creds.mask |= SD_BUS_CREDS_SUID & bus->creds_mask;
                        }

                        if ((uid_t) d->creds.fsuid != UID_INVALID) {
                                m->creds.fsuid = (uid_t) d->creds.fsuid;
                                m->creds.mask |= SD_BUS_CREDS_FSUID & bus->creds_mask;
                        }

                        if ((gid_t) d->creds.gid != GID_INVALID) {
                                m->creds.gid = (gid_t) d->creds.gid;
                                m->creds.mask |= SD_BUS_CREDS_GID & bus->creds_mask;
                        }

                        if ((gid_t) d->creds.egid != GID_INVALID) {
                                m->creds.egid = (gid_t) d->creds.egid;
                                m->creds.mask |= SD_BUS_CREDS_EGID & bus->creds_mask;
                        }

                        if ((gid_t) d->creds.sgid != GID_INVALID) {
                                m->creds.sgid = (gid_t) d->creds.sgid;
                                m->creds.mask |= SD_BUS_CREDS_SGID & bus->creds_mask;
                        }

                        if ((gid_t) d->creds.fsgid != GID_INVALID) {
                                m->creds.fsgid = (gid_t) d->creds.fsgid;
                                m->creds.mask |= SD_BUS_CREDS_FSGID & bus->creds_mask;
                        }

                        break;

                case KDBUS_ITEM_TIMESTAMP:
                        message_set_timestamp(bus, m, &d->timestamp);
                        break;

                case KDBUS_ITEM_PID_COMM:
                        m->creds.comm = d->str;
                        m->creds.mask |= SD_BUS_CREDS_COMM & bus->creds_mask;
                        break;

                case KDBUS_ITEM_TID_COMM:
                        m->creds.tid_comm = d->str;
                        m->creds.mask |= SD_BUS_CREDS_TID_COMM & bus->creds_mask;
                        break;

                case KDBUS_ITEM_EXE:
                        m->creds.exe = d->str;
                        m->creds.mask |= SD_BUS_CREDS_EXE & bus->creds_mask;
                        break;

                case KDBUS_ITEM_CMDLINE:
                        m->creds.cmdline = d->str;
                        m->creds.cmdline_size = l;
                        m->creds.mask |= SD_BUS_CREDS_CMDLINE & bus->creds_mask;
                        break;

                case KDBUS_ITEM_CGROUP:
                        m->creds.cgroup = d->str;
                        m->creds.mask |= (SD_BUS_CREDS_CGROUP|SD_BUS_CREDS_UNIT|SD_BUS_CREDS_USER_UNIT|SD_BUS_CREDS_SLICE|SD_BUS_CREDS_SESSION|SD_BUS_CREDS_OWNER_UID) & bus->creds_mask;

                        r = bus_get_root_path(bus);
                        if (r < 0)
                                goto fail;

                        m->creds.cgroup_root = bus->cgroup_root;
                        break;

                case KDBUS_ITEM_AUDIT:
                        m->creds.audit_session_id = (uint32_t) d->audit.sessionid;
                        m->creds.mask |= SD_BUS_CREDS_AUDIT_SESSION_ID & bus->creds_mask;

                        m->creds.audit_login_uid = (uid_t) d->audit.loginuid;
                        m->creds.mask |= SD_BUS_CREDS_AUDIT_LOGIN_UID & bus->creds_mask;
                        break;

                case KDBUS_ITEM_CAPS:
                        if (d->caps.last_cap != cap_last_cap() ||
                            d->size - offsetof(struct kdbus_item, caps.caps) < DIV_ROUND_UP(d->caps.last_cap, 32U) * 4 * 4) {
                                r = -EBADMSG;
                                goto fail;
                        }

                        m->creds.capability = d->caps.caps;
                        m->creds.mask |= (SD_BUS_CREDS_EFFECTIVE_CAPS|SD_BUS_CREDS_PERMITTED_CAPS|SD_BUS_CREDS_INHERITABLE_CAPS|SD_BUS_CREDS_BOUNDING_CAPS) & bus->creds_mask;
                        break;

                case KDBUS_ITEM_DST_NAME:
                        if (!service_name_is_valid(d->str)) {
                                r = -EBADMSG;
                                goto fail;
                        }

                        destination = d->str;
                        break;

                case KDBUS_ITEM_OWNED_NAME:
                        if (!service_name_is_valid(d->name.name)) {
                                r = -EBADMSG;
                                goto fail;
                        }

                        if (bus->creds_mask & SD_BUS_CREDS_WELL_KNOWN_NAMES) {
                                char **wkn;
                                size_t n;

                                /* We just extend the array here, but
                                 * do not allocate the strings inside
                                 * of it, instead we just point to our
                                 * buffer directly. */
                                n = strv_length(m->creds.well_known_names);
                                wkn = realloc(m->creds.well_known_names, (n + 2) * sizeof(char*));
                                if (!wkn) {
                                        r = -ENOMEM;
                                        goto fail;
                                }

                                wkn[n] = d->name.name;
                                wkn[n+1] = NULL;
                                m->creds.well_known_names = wkn;

                                m->creds.mask |= SD_BUS_CREDS_WELL_KNOWN_NAMES;
                        }
                        break;

                case KDBUS_ITEM_CONN_DESCRIPTION:
                        m->creds.description = d->str;
                        m->creds.mask |= SD_BUS_CREDS_DESCRIPTION & bus->creds_mask;
                        break;

                case KDBUS_ITEM_AUXGROUPS:

                        if (bus->creds_mask & SD_BUS_CREDS_SUPPLEMENTARY_GIDS) {
                                size_t i, n;
                                gid_t *g;

                                n = (d->size - offsetof(struct kdbus_item, data64)) / sizeof(uint64_t);
                                g = new(gid_t, n);
                                if (!g) {
                                        r = -ENOMEM;
                                        goto fail;
                                }

                                for (i = 0; i < n; i++)
                                        g[i] = d->data64[i];

                                m->creds.supplementary_gids = g;
                                m->creds.n_supplementary_gids = n;
                                m->creds.mask |= SD_BUS_CREDS_SUPPLEMENTARY_GIDS;
                        }

                        break;

                case KDBUS_ITEM_FDS:
                case KDBUS_ITEM_SECLABEL:
                case KDBUS_ITEM_BLOOM_FILTER:
                        break;

                default:
                        log_debug("Got unknown field from kernel %llu", d->type);
                }
        }

        /* If we requested the list of well-known names to be appended
         * and the sender had none no item for it will be
         * attached. However, this does *not* mean that the kernel
         * didn't want to provide this information to us. Hence, let's
         * explicitly mark this information as available if it was
         * requested. */
        m->creds.mask |= bus->creds_mask & SD_BUS_CREDS_WELL_KNOWN_NAMES;

        r = bus_message_parse_fields(m);
        if (r < 0)
                goto fail;

        /* Refuse messages if kdbus and dbus1 cookie doesn't match up */
        if ((uint64_t) m->header->dbus2.cookie != k->cookie) {
                r = -EBADMSG;
                goto fail;
        }

        /* Refuse messages where the reply flag doesn't match up */
        if (!(m->header->flags & BUS_MESSAGE_NO_REPLY_EXPECTED) != !!(k->flags & KDBUS_MSG_EXPECT_REPLY)) {
                r = -EBADMSG;
                goto fail;
        }

        /* Refuse reply messages where the reply cookie doesn't match up */
        if ((m->header->flags & BUS_MESSAGE_NO_REPLY_EXPECTED) && m->reply_cookie != k->cookie_reply) {
                r = -EBADMSG;
                goto fail;
        }

        /* Refuse messages where the autostart flag doesn't match up */
        if (!(m->header->flags & BUS_MESSAGE_NO_AUTO_START) != !(k->flags & KDBUS_MSG_NO_AUTO_START)) {
                r = -EBADMSG;
                goto fail;
        }

        /* Override information from the user header with data from the kernel */
        if (k->src_id == KDBUS_SRC_ID_KERNEL)
                bus_message_set_sender_driver(bus, m);
        else {
                snprintf(m->sender_buffer, sizeof(m->sender_buffer), ":1.%llu", (unsigned long long) k->src_id);
                m->sender = m->creds.unique_name = m->sender_buffer;
        }

        if (destination)
                m->destination = destination;
        else if (k->dst_id == KDBUS_DST_ID_BROADCAST)
                m->destination = NULL;
        else if (k->dst_id == KDBUS_DST_ID_NAME)
                m->destination = bus->unique_name; /* fill in unique name if the well-known name is missing */
        else {
                snprintf(m->destination_buffer, sizeof(m->destination_buffer), ":1.%llu", (unsigned long long) k->dst_id);
                m->destination = m->destination_buffer;
        }

        /* We take possession of the kmsg struct now */
        m->kdbus = k;
        m->release_kdbus = true;
        m->free_fds = true;
        fds = NULL;

        bus->rqueue[bus->rqueue_size++] = m;

        return 1;

fail:
        unset_memfds(m);
        sd_bus_message_unref(m);

        return r;
}

int bus_kernel_take_fd(sd_bus *b) {
        struct kdbus_bloom_parameter *bloom = NULL;
        struct kdbus_item *items, *item;
        struct kdbus_cmd_hello *hello;
        _cleanup_free_ char *g = NULL;
        const char *name;
        size_t l = 0, m = 0, sz;
        int r;

        assert(b);

        if (b->is_server)
                return -EINVAL;

        b->use_memfd = 1;

        if (b->description) {
                g = bus_label_escape(b->description);
                if (!g)
                        return -ENOMEM;

                name = g;
        } else {
                char pr[17] = {};

                /* If no name is explicitly set, we'll include a hint
                 * indicating the library implementation, a hint which
                 * kind of bus this is and the thread name */

                assert_se(prctl(PR_GET_NAME, (unsigned long) pr) >= 0);

                if (isempty(pr)) {
                        name = b->is_system ? "sd-system" :
                                b->is_user ? "sd-user" : "sd";
                } else {
                        _cleanup_free_ char *e = NULL;

                        e = bus_label_escape(pr);
                        if (!e)
                                return -ENOMEM;

                        g = strappend(b->is_system ? "sd-system-" :
                                      b->is_user ? "sd-user-" : "sd-",
                                      e);
                        if (!g)
                                return -ENOMEM;

                        name = g;
                }

                b->description = bus_label_unescape(name);
                if (!b->description)
                        return -ENOMEM;
        }

        m = strlen(name);

        sz = ALIGN8(offsetof(struct kdbus_cmd_hello, items)) +
                ALIGN8(offsetof(struct kdbus_item, str) + m + 1);

        if (b->fake_creds_valid)
                sz += ALIGN8(offsetof(struct kdbus_item, creds) + sizeof(struct kdbus_creds));

        if (b->fake_pids_valid)
                sz += ALIGN8(offsetof(struct kdbus_item, pids) + sizeof(struct kdbus_pids));

        if (b->fake_label) {
                l = strlen(b->fake_label);
                sz += ALIGN8(offsetof(struct kdbus_item, str) + l + 1);
        }

        hello = alloca0_align(sz, 8);
        hello->size = sz;
        hello->flags = b->hello_flags;
        hello->attach_flags_send = _KDBUS_ATTACH_ANY;
        hello->attach_flags_recv = b->attach_flags;
        hello->pool_size = KDBUS_POOL_SIZE;

        item = hello->items;

        item->size = offsetof(struct kdbus_item, str) + m + 1;
        item->type = KDBUS_ITEM_CONN_DESCRIPTION;
        memcpy(item->str, name, m + 1);
        item = KDBUS_ITEM_NEXT(item);

        if (b->fake_creds_valid) {
                item->size = offsetof(struct kdbus_item, creds) + sizeof(struct kdbus_creds);
                item->type = KDBUS_ITEM_CREDS;
                item->creds = b->fake_creds;

                item = KDBUS_ITEM_NEXT(item);
        }

        if (b->fake_pids_valid) {
                item->size = offsetof(struct kdbus_item, pids) + sizeof(struct kdbus_pids);
                item->type = KDBUS_ITEM_PIDS;
                item->pids = b->fake_pids;

                item = KDBUS_ITEM_NEXT(item);
        }

        if (b->fake_label) {
                item->size = offsetof(struct kdbus_item, str) + l + 1;
                item->type = KDBUS_ITEM_SECLABEL;
                memcpy(item->str, b->fake_label, l+1);
        }

        r = ioctl(b->input_fd, KDBUS_CMD_HELLO, hello);
        if (r < 0) {
                if (errno == ENOTTY)
                        /* If the ioctl is not supported we assume that the
                         * API version changed in a major incompatible way,
                         * let's indicate an API incompatibility in this
                         * case. */
                        return -ESOCKTNOSUPPORT;

                return -errno;
        }

        if (!b->kdbus_buffer) {
                b->kdbus_buffer = mmap(NULL, KDBUS_POOL_SIZE, PROT_READ, MAP_SHARED, b->input_fd, 0);
                if (b->kdbus_buffer == MAP_FAILED) {
                        b->kdbus_buffer = NULL;
                        r = -errno;
                        goto fail;
                }
        }

        /* The higher 32bit of the bus_flags fields are considered
         * 'incompatible flags'. Refuse them all for now. */
        if (hello->bus_flags > 0xFFFFFFFFULL) {
                r = -ESOCKTNOSUPPORT;
                goto fail;
        }

        /* extract bloom parameters from items */
        items = (void*)((uint8_t*)b->kdbus_buffer + hello->offset);
        KDBUS_FOREACH(item, items, hello->items_size) {
                switch (item->type) {
                case KDBUS_ITEM_BLOOM_PARAMETER:
                        bloom = &item->bloom_parameter;
                        break;
                }
        }

        if (!bloom || !bloom_validate_parameters((size_t) bloom->size, (unsigned) bloom->n_hash)) {
                r = -EOPNOTSUPP;
                goto fail;
        }

        b->bloom_size = (size_t) bloom->size;
        b->bloom_n_hash = (unsigned) bloom->n_hash;

        if (asprintf(&b->unique_name, ":1.%llu", (unsigned long long) hello->id) < 0) {
                r = -ENOMEM;
                goto fail;
        }

        b->unique_id = hello->id;

        b->is_kernel = true;
        b->bus_client = true;
        b->can_fds = !!(hello->flags & KDBUS_HELLO_ACCEPT_FD);
        b->message_version = 2;
        b->message_endian = BUS_NATIVE_ENDIAN;

        /* the kernel told us the UUID of the underlying bus */
        memcpy(b->server_id.bytes, hello->id128, sizeof(b->server_id.bytes));

        /* free returned items */
        (void) bus_kernel_cmd_free(b, hello->offset);
        return bus_start_running(b);

fail:
        (void) bus_kernel_cmd_free(b, hello->offset);
        return r;
}

int bus_kernel_connect(sd_bus *b) {
        assert(b);
        assert(b->input_fd < 0);
        assert(b->output_fd < 0);
        assert(b->kernel);

        if (b->is_server)
                return -EINVAL;

        b->input_fd = open(b->kernel, O_RDWR|O_NOCTTY|O_CLOEXEC);
        if (b->input_fd < 0)
                return -errno;

        b->output_fd = b->input_fd;

        return bus_kernel_take_fd(b);
}

int bus_kernel_cmd_free(sd_bus *bus, uint64_t offset) {
        struct kdbus_cmd_free cmd = {
                .size = sizeof(cmd),
                .offset = offset,
        };
        int r;

        assert(bus);
        assert(bus->is_kernel);

        r = ioctl(bus->input_fd, KDBUS_CMD_FREE, &cmd);
        if (r < 0)
                return -errno;

        return 0;
}

static void close_kdbus_msg(sd_bus *bus, struct kdbus_msg *k) {
        struct kdbus_item *d;

        assert(bus);
        assert(k);

        KDBUS_ITEM_FOREACH(d, k, items) {
                if (d->type == KDBUS_ITEM_FDS)
                        close_many(d->fds, (d->size - offsetof(struct kdbus_item, fds)) / sizeof(int));
                else if (d->type == KDBUS_ITEM_PAYLOAD_MEMFD)
                        safe_close(d->memfd.fd);
        }

        bus_kernel_cmd_free(bus, (uint8_t*) k - (uint8_t*) bus->kdbus_buffer);
}

int bus_kernel_write_message(sd_bus *bus, sd_bus_message *m, bool hint_sync_call) {
        struct kdbus_cmd_send cmd = { };
        int r;

        assert(bus);
        assert(m);
        assert(bus->state == BUS_RUNNING);

        /* If we can't deliver, we want room for the error message */
        r = bus_rqueue_make_room(bus);
        if (r < 0)
                return r;

        r = bus_message_setup_kmsg(bus, m);
        if (r < 0)
                return r;

        cmd.size = sizeof(cmd);
        cmd.msg_address = (uintptr_t)m->kdbus;

        /* If this is a synchronous method call, then let's tell the
         * kernel, so that it can pass CPU time/scheduling to the
         * destination for the time, if it wants to. If we
         * synchronously wait for the result anyway, we won't need CPU
         * anyway. */
        if (hint_sync_call) {
                m->kdbus->flags |= KDBUS_MSG_EXPECT_REPLY;
                cmd.flags |= KDBUS_SEND_SYNC_REPLY;
        }

        r = ioctl(bus->output_fd, KDBUS_CMD_SEND, &cmd);
        if (r < 0) {
                _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
                sd_bus_message *reply;

                if (errno == EAGAIN || errno == EINTR)
                        return 0;
                else if (errno == ENXIO || errno == ESRCH) {

                        /* ENXIO: unique name not known
                         * ESRCH: well-known name not known */

                        if (m->header->type == SD_BUS_MESSAGE_METHOD_CALL)
                                sd_bus_error_setf(&error, SD_BUS_ERROR_SERVICE_UNKNOWN, "Destination %s not known", m->destination);
                        else {
                                log_debug("Could not deliver message to %s as destination is not known. Ignoring.", m->destination);
                                return 0;
                        }

                } else if (errno == EADDRNOTAVAIL) {

                        /* EADDRNOTAVAIL: activation is possible, but turned off in request flags */

                        if (m->header->type == SD_BUS_MESSAGE_METHOD_CALL)
                                sd_bus_error_setf(&error, SD_BUS_ERROR_SERVICE_UNKNOWN, "Activation of %s not requested", m->destination);
                        else {
                                log_debug("Could not deliver message to %s as destination is not activated. Ignoring.", m->destination);
                                return 0;
                        }
                } else
                        return -errno;

                r = bus_message_new_synthetic_error(
                                bus,
                                BUS_MESSAGE_COOKIE(m),
                                &error,
                                &reply);

                if (r < 0)
                        return r;

                r = bus_seal_synthetic_message(bus, reply);
                if (r < 0)
                        return r;

                bus->rqueue[bus->rqueue_size++] = reply;

        } else if (hint_sync_call) {
                struct kdbus_msg *k;

                k = (struct kdbus_msg *)((uint8_t *)bus->kdbus_buffer + cmd.reply.offset);
                assert(k);

                if (k->payload_type == KDBUS_PAYLOAD_DBUS) {

                        r = bus_kernel_make_message(bus, k);
                        if (r < 0) {
                                close_kdbus_msg(bus, k);

                                /* Anybody can send us invalid messages, let's just drop them. */
                                if (r == -EBADMSG || r == -EPROTOTYPE)
                                        log_debug_errno(r, "Ignoring invalid synchronous reply: %m");
                                else
                                        return r;
                        }
                } else {
                        log_debug("Ignoring message with unknown payload type %llu.", (unsigned long long) k->payload_type);
                        close_kdbus_msg(bus, k);
                }
        }

        return 1;
}

static int push_name_owner_changed(
                sd_bus *bus,
                const char *name,
                const char *old_owner,
                const char *new_owner,
                const struct kdbus_timestamp *ts) {

        _cleanup_bus_message_unref_ sd_bus_message *m = NULL;
        int r;

        assert(bus);

        r = sd_bus_message_new_signal(
                        bus,
                        &m,
                        "/org/freedesktop/DBus",
                        "org.freedesktop.DBus",
                        "NameOwnerChanged");
        if (r < 0)
                return r;

        r = sd_bus_message_append(m, "sss", name, old_owner, new_owner);
        if (r < 0)
                return r;

        bus_message_set_sender_driver(bus, m);
        message_set_timestamp(bus, m, ts);

        r = bus_seal_synthetic_message(bus, m);
        if (r < 0)
                return r;

        bus->rqueue[bus->rqueue_size++] = m;
        m = NULL;

        return 1;
}

static int translate_name_change(
                sd_bus *bus,
                const struct kdbus_msg *k,
                const struct kdbus_item *d,
                const struct kdbus_timestamp *ts) {

        char new_owner[UNIQUE_NAME_MAX], old_owner[UNIQUE_NAME_MAX];

        assert(bus);
        assert(k);
        assert(d);

        if (d->type == KDBUS_ITEM_NAME_ADD || (d->name_change.old_id.flags & (KDBUS_NAME_IN_QUEUE|KDBUS_NAME_ACTIVATOR)))
                old_owner[0] = 0;
        else
                sprintf(old_owner, ":1.%llu", (unsigned long long) d->name_change.old_id.id);

        if (d->type == KDBUS_ITEM_NAME_REMOVE || (d->name_change.new_id.flags & (KDBUS_NAME_IN_QUEUE|KDBUS_NAME_ACTIVATOR))) {

                if (isempty(old_owner))
                        return 0;

                new_owner[0] = 0;
        } else
                sprintf(new_owner, ":1.%llu", (unsigned long long) d->name_change.new_id.id);

        return push_name_owner_changed(bus, d->name_change.name, old_owner, new_owner, ts);
}

static int translate_id_change(
                sd_bus *bus,
                const struct kdbus_msg *k,
                const struct kdbus_item *d,
                const struct kdbus_timestamp *ts) {

        char owner[UNIQUE_NAME_MAX];

        assert(bus);
        assert(k);
        assert(d);

        sprintf(owner, ":1.%llu", d->id_change.id);

        return push_name_owner_changed(
                        bus, owner,
                        d->type == KDBUS_ITEM_ID_ADD ? NULL : owner,
                        d->type == KDBUS_ITEM_ID_ADD ? owner : NULL,
                        ts);
}

static int translate_reply(
                sd_bus *bus,
                const struct kdbus_msg *k,
                const struct kdbus_item *d,
                const struct kdbus_timestamp *ts) {

        _cleanup_bus_message_unref_ sd_bus_message *m = NULL;
        int r;

        assert(bus);
        assert(k);
        assert(d);

        r = bus_message_new_synthetic_error(
                        bus,
                        k->cookie_reply,
                        d->type == KDBUS_ITEM_REPLY_TIMEOUT ?
                        &SD_BUS_ERROR_MAKE_CONST(SD_BUS_ERROR_NO_REPLY, "Method call timed out") :
                        &SD_BUS_ERROR_MAKE_CONST(SD_BUS_ERROR_NO_REPLY, "Method call peer died"),
                        &m);
        if (r < 0)
                return r;

        message_set_timestamp(bus, m, ts);

        r = bus_seal_synthetic_message(bus, m);
        if (r < 0)
                return r;

        bus->rqueue[bus->rqueue_size++] = m;
        m = NULL;

        return 1;
}

static int bus_kernel_translate_message(sd_bus *bus, struct kdbus_msg *k) {
        static int (* const translate[])(sd_bus *bus, const struct kdbus_msg *k, const struct kdbus_item *d, const struct kdbus_timestamp *ts) = {
                [KDBUS_ITEM_NAME_ADD - _KDBUS_ITEM_KERNEL_BASE] = translate_name_change,
                [KDBUS_ITEM_NAME_REMOVE - _KDBUS_ITEM_KERNEL_BASE] = translate_name_change,
                [KDBUS_ITEM_NAME_CHANGE - _KDBUS_ITEM_KERNEL_BASE] = translate_name_change,

                [KDBUS_ITEM_ID_ADD - _KDBUS_ITEM_KERNEL_BASE] = translate_id_change,
                [KDBUS_ITEM_ID_REMOVE - _KDBUS_ITEM_KERNEL_BASE] = translate_id_change,

                [KDBUS_ITEM_REPLY_TIMEOUT - _KDBUS_ITEM_KERNEL_BASE] = translate_reply,
                [KDBUS_ITEM_REPLY_DEAD - _KDBUS_ITEM_KERNEL_BASE] = translate_reply,
        };

        struct kdbus_item *d, *found = NULL;
        struct kdbus_timestamp *ts = NULL;

        assert(bus);
        assert(k);
        assert(k->payload_type == KDBUS_PAYLOAD_KERNEL);

        KDBUS_ITEM_FOREACH(d, k, items) {
                if (d->type == KDBUS_ITEM_TIMESTAMP)
                        ts = &d->timestamp;
                else if (d->type >= _KDBUS_ITEM_KERNEL_BASE && d->type < _KDBUS_ITEM_KERNEL_BASE + ELEMENTSOF(translate)) {
                        if (found)
                                return -EBADMSG;
                        found = d;
                } else
                        log_debug("Got unknown field from kernel %llu", d->type);
        }

        if (!found) {
                log_debug("Didn't find a kernel message to translate.");
                return 0;
        }

        return translate[found->type - _KDBUS_ITEM_KERNEL_BASE](bus, k, found, ts);
}

int bus_kernel_read_message(sd_bus *bus, bool hint_priority, int64_t priority) {
        struct kdbus_cmd_recv recv = { .size = sizeof(recv) };
        struct kdbus_msg *k;
        int r;

        assert(bus);

        r = bus_rqueue_make_room(bus);
        if (r < 0)
                return r;

        if (hint_priority) {
                recv.flags |= KDBUS_RECV_USE_PRIORITY;
                recv.priority = priority;
        }

        r = ioctl(bus->input_fd, KDBUS_CMD_RECV, &recv);
        if (recv.return_flags & KDBUS_RECV_RETURN_DROPPED_MSGS)
                log_debug("%s: kdbus reports %" PRIu64 " dropped broadcast messages, ignoring.", strna(bus->description), (uint64_t) recv.dropped_msgs);
        if (r < 0) {
                if (errno == EAGAIN)
                        return 0;

                return -errno;
        }

        k = (struct kdbus_msg *)((uint8_t *)bus->kdbus_buffer + recv.msg.offset);
        if (k->payload_type == KDBUS_PAYLOAD_DBUS) {
                r = bus_kernel_make_message(bus, k);

                /* Anybody can send us invalid messages, let's just drop them. */
                if (r == -EBADMSG || r == -EPROTOTYPE) {
                        log_debug_errno(r, "Ignoring invalid message: %m");
                        r = 0;
                }

                if (r <= 0)
                        close_kdbus_msg(bus, k);
        } else if (k->payload_type == KDBUS_PAYLOAD_KERNEL) {
                r = bus_kernel_translate_message(bus, k);
                close_kdbus_msg(bus, k);
        } else {
                log_debug("Ignoring message with unknown payload type %llu.", (unsigned long long) k->payload_type);
                r = 0;
                close_kdbus_msg(bus, k);
        }

        return r < 0 ? r : 1;
}

int bus_kernel_pop_memfd(sd_bus *bus, void **address, size_t *mapped, size_t *allocated) {
        struct memfd_cache *c;
        int fd;

        assert(address);
        assert(mapped);
        assert(allocated);

        if (!bus || !bus->is_kernel)
                return -EOPNOTSUPP;

        assert_se(pthread_mutex_lock(&bus->memfd_cache_mutex) >= 0);

        if (bus->n_memfd_cache <= 0) {
                int r;

                assert_se(pthread_mutex_unlock(&bus->memfd_cache_mutex) >= 0);

                r = memfd_new(bus->description);
                if (r < 0)
                        return r;

                *address = NULL;
                *mapped = 0;
                *allocated = 0;
                return r;
        }

        c = &bus->memfd_cache[--bus->n_memfd_cache];

        assert(c->fd >= 0);
        assert(c->mapped == 0 || c->address);

        *address = c->address;
        *mapped = c->mapped;
        *allocated = c->allocated;
        fd = c->fd;

        assert_se(pthread_mutex_unlock(&bus->memfd_cache_mutex) >= 0);

        return fd;
}

static void close_and_munmap(int fd, void *address, size_t size) {
        if (size > 0)
                assert_se(munmap(address, PAGE_ALIGN(size)) >= 0);

        safe_close(fd);
}

void bus_kernel_push_memfd(sd_bus *bus, int fd, void *address, size_t mapped, size_t allocated) {
        struct memfd_cache *c;
        uint64_t max_mapped = PAGE_ALIGN(MEMFD_CACHE_ITEM_SIZE_MAX);

        assert(fd >= 0);
        assert(mapped == 0 || address);

        if (!bus || !bus->is_kernel) {
                close_and_munmap(fd, address, mapped);
                return;
        }

        assert_se(pthread_mutex_lock(&bus->memfd_cache_mutex) >= 0);

        if (bus->n_memfd_cache >= ELEMENTSOF(bus->memfd_cache)) {
                assert_se(pthread_mutex_unlock(&bus->memfd_cache_mutex) >= 0);

                close_and_munmap(fd, address, mapped);
                return;
        }

        c = &bus->memfd_cache[bus->n_memfd_cache++];
        c->fd = fd;
        c->address = address;

        /* If overly long, let's return a bit to the OS */
        if (mapped > max_mapped) {
                assert_se(memfd_set_size(fd, max_mapped) >= 0);
                assert_se(munmap((uint8_t*) address + max_mapped, PAGE_ALIGN(mapped - max_mapped)) >= 0);
                c->mapped = c->allocated = max_mapped;
        } else {
                c->mapped = mapped;
                c->allocated = allocated;
        }

        assert_se(pthread_mutex_unlock(&bus->memfd_cache_mutex) >= 0);
}

void bus_kernel_flush_memfd(sd_bus *b) {
        unsigned i;

        assert(b);

        for (i = 0; i < b->n_memfd_cache; i++)
                close_and_munmap(b->memfd_cache[i].fd, b->memfd_cache[i].address, b->memfd_cache[i].mapped);
}

uint64_t request_name_flags_to_kdbus(uint64_t flags) {
        uint64_t f = 0;

        if (flags & SD_BUS_NAME_ALLOW_REPLACEMENT)
                f |= KDBUS_NAME_ALLOW_REPLACEMENT;

        if (flags & SD_BUS_NAME_REPLACE_EXISTING)
                f |= KDBUS_NAME_REPLACE_EXISTING;

        if (flags & SD_BUS_NAME_QUEUE)
                f |= KDBUS_NAME_QUEUE;

        return f;
}

uint64_t attach_flags_to_kdbus(uint64_t mask) {
        uint64_t m = 0;

        if (mask & (SD_BUS_CREDS_UID|SD_BUS_CREDS_EUID|SD_BUS_CREDS_SUID|SD_BUS_CREDS_FSUID|
                    SD_BUS_CREDS_GID|SD_BUS_CREDS_EGID|SD_BUS_CREDS_SGID|SD_BUS_CREDS_FSGID))
                m |= KDBUS_ATTACH_CREDS;

        if (mask & (SD_BUS_CREDS_PID|SD_BUS_CREDS_TID|SD_BUS_CREDS_PPID))
                m |= KDBUS_ATTACH_PIDS;

        if (mask & SD_BUS_CREDS_COMM)
                m |= KDBUS_ATTACH_PID_COMM;

        if (mask & SD_BUS_CREDS_TID_COMM)
                m |= KDBUS_ATTACH_TID_COMM;

        if (mask & SD_BUS_CREDS_EXE)
                m |= KDBUS_ATTACH_EXE;

        if (mask & SD_BUS_CREDS_CMDLINE)
                m |= KDBUS_ATTACH_CMDLINE;

        if (mask & (SD_BUS_CREDS_CGROUP|SD_BUS_CREDS_UNIT|SD_BUS_CREDS_USER_UNIT|SD_BUS_CREDS_SLICE|SD_BUS_CREDS_SESSION|SD_BUS_CREDS_OWNER_UID))
                m |= KDBUS_ATTACH_CGROUP;

        if (mask & (SD_BUS_CREDS_EFFECTIVE_CAPS|SD_BUS_CREDS_PERMITTED_CAPS|SD_BUS_CREDS_INHERITABLE_CAPS|SD_BUS_CREDS_BOUNDING_CAPS))
                m |= KDBUS_ATTACH_CAPS;

        if (mask & SD_BUS_CREDS_SELINUX_CONTEXT)
                m |= KDBUS_ATTACH_SECLABEL;

        if (mask & (SD_BUS_CREDS_AUDIT_SESSION_ID|SD_BUS_CREDS_AUDIT_LOGIN_UID))
                m |= KDBUS_ATTACH_AUDIT;

        if (mask & SD_BUS_CREDS_WELL_KNOWN_NAMES)
                m |= KDBUS_ATTACH_NAMES;

        if (mask & SD_BUS_CREDS_DESCRIPTION)
                m |= KDBUS_ATTACH_CONN_DESCRIPTION;

        if (mask & SD_BUS_CREDS_SUPPLEMENTARY_GIDS)
                m |= KDBUS_ATTACH_AUXGROUPS;

        return m;
}

int bus_kernel_create_bus(const char *name, bool world, char **s) {
        struct kdbus_cmd *make;
        struct kdbus_item *n;
        size_t l;
        int fd;

        assert(name);
        assert(s);

        fd = open("/sys/fs/kdbus/control", O_RDWR|O_NOCTTY|O_CLOEXEC);
        if (fd < 0)
                return -errno;

        l = strlen(name);
        make = alloca0_align(offsetof(struct kdbus_cmd, items) +
                             ALIGN8(offsetof(struct kdbus_item, bloom_parameter) + sizeof(struct kdbus_bloom_parameter)) +
                             ALIGN8(offsetof(struct kdbus_item, data64) + sizeof(uint64_t)) +
                             ALIGN8(offsetof(struct kdbus_item, str) + DECIMAL_STR_MAX(uid_t) + 1 + l + 1),
                             8);

        make->size = offsetof(struct kdbus_cmd, items);

        /* Set the bloom parameters */
        n = make->items;
        n->size = offsetof(struct kdbus_item, bloom_parameter) +
                  sizeof(struct kdbus_bloom_parameter);
        n->type = KDBUS_ITEM_BLOOM_PARAMETER;
        n->bloom_parameter.size = DEFAULT_BLOOM_SIZE;
        n->bloom_parameter.n_hash = DEFAULT_BLOOM_N_HASH;

        assert_cc(DEFAULT_BLOOM_SIZE > 0);
        assert_cc(DEFAULT_BLOOM_N_HASH > 0);

        make->size += ALIGN8(n->size);

        /* Provide all metadata via bus-owner queries */
        n = KDBUS_ITEM_NEXT(n);
        n->type = KDBUS_ITEM_ATTACH_FLAGS_SEND;
        n->size = offsetof(struct kdbus_item, data64) + sizeof(uint64_t);
        n->data64[0] = _KDBUS_ATTACH_ANY;
        make->size += ALIGN8(n->size);

        /* Set the a good name */
        n = KDBUS_ITEM_NEXT(n);
        sprintf(n->str, UID_FMT "-%s", getuid(), name);
        n->size = offsetof(struct kdbus_item, str) + strlen(n->str) + 1;
        n->type = KDBUS_ITEM_MAKE_NAME;
        make->size += ALIGN8(n->size);

        make->flags = world ? KDBUS_MAKE_ACCESS_WORLD : 0;

        if (ioctl(fd, KDBUS_CMD_BUS_MAKE, make) < 0) {
                safe_close(fd);

                /* Major API change? then the ioctls got shuffled around. */
                if (errno == ENOTTY)
                        return -ESOCKTNOSUPPORT;

                return -errno;
        }

        if (s) {
                char *p;

                p = strjoin("/sys/fs/kdbus/", n->str, "/bus", NULL);
                if (!p) {
                        safe_close(fd);
                        return -ENOMEM;
                }

                *s = p;
        }

        return fd;
}

int bus_kernel_open_bus_fd(const char *bus, char **path) {
        char *p;
        int fd;
        size_t len;

        assert(bus);

        len = strlen("/sys/fs/kdbus/") + DECIMAL_STR_MAX(uid_t) + 1 + strlen(bus) + strlen("/bus") + 1;

        if (path) {
                p = new(char, len);
                if (!p)
                        return -ENOMEM;
        } else
                p = newa(char, len);

        sprintf(p, "/sys/fs/kdbus/" UID_FMT "-%s/bus", getuid(), bus);

        fd = open(p, O_RDWR|O_NOCTTY|O_CLOEXEC);
        if (fd < 0) {
                if (path)
                        free(p);

                return -errno;
        }

        if (path)
                *path = p;

        return fd;
}

int bus_kernel_create_endpoint(const char *bus_name, const char *ep_name, char **ep_path) {
        _cleanup_free_ char *path = NULL;
        struct kdbus_cmd *make;
        struct kdbus_item *n;
        const char *name;
        int fd;

        fd = bus_kernel_open_bus_fd(bus_name, &path);
        if (fd < 0)
                return fd;

        make = alloca0_align(ALIGN8(offsetof(struct kdbus_cmd, items)) +
                             ALIGN8(offsetof(struct kdbus_item, str) + DECIMAL_STR_MAX(uid_t) + 1 + strlen(ep_name) + 1),
                             8);
        make->size = ALIGN8(offsetof(struct kdbus_cmd, items));
        make->flags = KDBUS_MAKE_ACCESS_WORLD;

        n = make->items;
        sprintf(n->str, UID_FMT "-%s", getuid(), ep_name);
        n->size = offsetof(struct kdbus_item, str) + strlen(n->str) + 1;
        n->type = KDBUS_ITEM_MAKE_NAME;
        make->size += ALIGN8(n->size);
        name = n->str;

        if (ioctl(fd, KDBUS_CMD_ENDPOINT_MAKE, make) < 0) {
                safe_close(fd);
                return -errno;
        }

        if (ep_path) {
                char *p;

                p = strjoin(dirname(path), "/", name, NULL);
                if (!p) {
                        safe_close(fd);
                        return -ENOMEM;
                }

                *ep_path = p;
        }

        return fd;
}

int bus_kernel_try_close(sd_bus *bus) {
        struct kdbus_cmd byebye = { .size = sizeof(byebye) };

        assert(bus);
        assert(bus->is_kernel);

        if (ioctl(bus->input_fd, KDBUS_CMD_BYEBYE, &byebye) < 0)
                return -errno;

        return 0;
}

int bus_kernel_drop_one(int fd) {
        struct kdbus_cmd_recv recv = {
                .size = sizeof(recv),
                .flags = KDBUS_RECV_DROP,
        };

        assert(fd >= 0);

        if (ioctl(fd, KDBUS_CMD_RECV, &recv) < 0)
                return -errno;

        return 0;
}

int bus_kernel_realize_attach_flags(sd_bus *bus) {
        struct kdbus_cmd *update;
        struct kdbus_item *n;

        assert(bus);
        assert(bus->is_kernel);

        update = alloca0_align(offsetof(struct kdbus_cmd, items) +
                               ALIGN8(offsetof(struct kdbus_item, data64) + sizeof(uint64_t)),
                               8);

        n = update->items;
        n->type = KDBUS_ITEM_ATTACH_FLAGS_RECV;
        n->size = offsetof(struct kdbus_item, data64) + sizeof(uint64_t);
        n->data64[0] = bus->attach_flags;

        update->size =
                offsetof(struct kdbus_cmd, items) +
                ALIGN8(n->size);

        if (ioctl(bus->input_fd, KDBUS_CMD_UPDATE, update) < 0)
                return -errno;

        return 0;
}

int bus_kernel_get_bus_name(sd_bus *bus, char **name) {
        struct kdbus_cmd_info cmd = {
                .size = sizeof(struct kdbus_cmd_info),
        };
        struct kdbus_info *info;
        struct kdbus_item *item;
        char *n = NULL;
        int r;

        assert(bus);
        assert(name);
        assert(bus->is_kernel);

        r = ioctl(bus->input_fd, KDBUS_CMD_BUS_CREATOR_INFO, &cmd);
        if (r < 0)
                return -errno;

        info = (struct kdbus_info*) ((uint8_t*) bus->kdbus_buffer + cmd.offset);

        KDBUS_ITEM_FOREACH(item, info, items)
                if (item->type == KDBUS_ITEM_MAKE_NAME) {
                        r = free_and_strdup(&n, item->str);
                        break;
                }

        bus_kernel_cmd_free(bus, cmd.offset);

        if (r < 0)
                return r;
        if (!n)
                return -EIO;

        *name = n;
        return 0;
}
