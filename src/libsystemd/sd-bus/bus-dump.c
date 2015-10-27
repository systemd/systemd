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

#include "alloc-util.h"
#include "bus-dump.h"
#include "bus-internal.h"
#include "bus-message.h"
#include "bus-type.h"
#include "cap-list.h"
#include "capability-util.h"
#include "fileio.h"
#include "formats-util.h"
#include "locale-util.h"
#include "macro.h"
#include "string-util.h"
#include "strv.h"
#include "terminal-util.h"
#include "util.h"

static char *indent(unsigned level, unsigned flags) {
        char *p;
        unsigned n, i = 0;

        n = 0;

        if (flags & BUS_MESSAGE_DUMP_SUBTREE_ONLY && level > 0)
                level -= 1;

        if (flags & BUS_MESSAGE_DUMP_WITH_HEADER)
                n += 2;

        p = new(char, n + level*8 + 1);
        if (!p)
                return NULL;

        if (flags & BUS_MESSAGE_DUMP_WITH_HEADER) {
                p[i++] = ' ';
                p[i++] = ' ';
        }

        memset(p + i, ' ', level*8);
        p[i + level*8] = 0;

        return p;
}

int bus_message_dump(sd_bus_message *m, FILE *f, unsigned flags) {
        unsigned level = 1;
        int r;

        assert(m);

        if (!f)
                f = stdout;

        if (flags & BUS_MESSAGE_DUMP_WITH_HEADER) {
                fprintf(f,
                        "%s%s%s Type=%s%s%s  Endian=%c  Flags=%u  Version=%u  Priority=%"PRIi64,
                        m->header->type == SD_BUS_MESSAGE_METHOD_ERROR ? ansi_highlight_red() :
                        m->header->type == SD_BUS_MESSAGE_METHOD_RETURN ? ansi_highlight_green() :
                        m->header->type != SD_BUS_MESSAGE_SIGNAL ? ansi_highlight() : "", draw_special_char(DRAW_TRIANGULAR_BULLET), ansi_normal(),
                        ansi_highlight(), bus_message_type_to_string(m->header->type), ansi_normal(),
                        m->header->endian,
                        m->header->flags,
                        m->header->version,
                        m->priority);

                /* Display synthetic message serial number in a more readable
                 * format than (uint32_t) -1 */
                if (BUS_MESSAGE_COOKIE(m) == 0xFFFFFFFFULL)
                        fprintf(f, " Cookie=-1");
                else
                        fprintf(f, " Cookie=%" PRIu64, BUS_MESSAGE_COOKIE(m));

                if (m->reply_cookie != 0)
                        fprintf(f, "  ReplyCookie=%" PRIu64, m->reply_cookie);

                fputs("\n", f);

                if (m->sender)
                        fprintf(f, "  Sender=%s%s%s", ansi_highlight(), m->sender, ansi_normal());
                if (m->destination)
                        fprintf(f, "  Destination=%s%s%s", ansi_highlight(), m->destination, ansi_normal());
                if (m->path)
                        fprintf(f, "  Path=%s%s%s", ansi_highlight(), m->path, ansi_normal());
                if (m->interface)
                        fprintf(f, "  Interface=%s%s%s", ansi_highlight(), m->interface, ansi_normal());
                if (m->member)
                        fprintf(f, "  Member=%s%s%s", ansi_highlight(), m->member, ansi_normal());

                if (m->sender || m->destination || m->path || m->interface || m->member)
                        fputs("\n", f);

                if (sd_bus_error_is_set(&m->error))
                        fprintf(f,
                                "  ErrorName=%s%s%s"
                                "  ErrorMessage=%s\"%s\"%s\n",
                                ansi_highlight_red(), strna(m->error.name), ansi_normal(),
                                ansi_highlight_red(), strna(m->error.message), ansi_normal());

                if (m->monotonic != 0)
                        fprintf(f, "  Monotonic="USEC_FMT, m->monotonic);
                if (m->realtime != 0)
                        fprintf(f, "  Realtime="USEC_FMT, m->realtime);
                if (m->seqnum != 0)
                        fprintf(f, "  SequenceNumber=%"PRIu64, m->seqnum);

                if (m->monotonic != 0 || m->realtime != 0 || m->seqnum != 0)
                        fputs("\n", f);

                bus_creds_dump(&m->creds, f, true);
        }

        r = sd_bus_message_rewind(m, !(flags & BUS_MESSAGE_DUMP_SUBTREE_ONLY));
        if (r < 0)
                return log_error_errno(r, "Failed to rewind: %m");

        if (!(flags & BUS_MESSAGE_DUMP_SUBTREE_ONLY)) {
                _cleanup_free_ char *prefix = NULL;

                prefix = indent(0, flags);
                if (!prefix)
                        return log_oom();

                fprintf(f, "%sMESSAGE \"%s\" {\n", prefix, strempty(m->root_container.signature));
        }

        for (;;) {
                _cleanup_free_ char *prefix = NULL;
                const char *contents = NULL;
                char type;
                union {
                        uint8_t u8;
                        uint16_t u16;
                        int16_t s16;
                        uint32_t u32;
                        int32_t s32;
                        uint64_t u64;
                        int64_t s64;
                        double d64;
                        const char *string;
                        int i;
                } basic;

                r = sd_bus_message_peek_type(m, &type, &contents);
                if (r < 0)
                        return log_error_errno(r, "Failed to peek type: %m");

                if (r == 0) {
                        if (level <= 1)
                                break;

                        r = sd_bus_message_exit_container(m);
                        if (r < 0)
                                return log_error_errno(r, "Failed to exit container: %m");

                        level--;

                        prefix = indent(level, flags);
                        if (!prefix)
                                return log_oom();

                        fprintf(f, "%s};\n", prefix);
                        continue;
                }

                prefix = indent(level, flags);
                if (!prefix)
                        return log_oom();

                if (bus_type_is_container(type) > 0) {
                        r = sd_bus_message_enter_container(m, type, contents);
                        if (r < 0)
                                return log_error_errno(r, "Failed to enter container: %m");

                        if (type == SD_BUS_TYPE_ARRAY)
                                fprintf(f, "%sARRAY \"%s\" {\n", prefix, contents);
                        else if (type == SD_BUS_TYPE_VARIANT)
                                fprintf(f, "%sVARIANT \"%s\" {\n", prefix, contents);
                        else if (type == SD_BUS_TYPE_STRUCT)
                                fprintf(f, "%sSTRUCT \"%s\" {\n", prefix, contents);
                        else if (type == SD_BUS_TYPE_DICT_ENTRY)
                                fprintf(f, "%sDICT_ENTRY \"%s\" {\n", prefix, contents);

                        level ++;

                        continue;
                }

                r = sd_bus_message_read_basic(m, type, &basic);
                if (r < 0)
                        return log_error_errno(r, "Failed to get basic: %m");

                assert(r > 0);

                switch (type) {

                case SD_BUS_TYPE_BYTE:
                        fprintf(f, "%sBYTE %s%u%s;\n", prefix, ansi_highlight(), basic.u8, ansi_normal());
                        break;

                case SD_BUS_TYPE_BOOLEAN:
                        fprintf(f, "%sBOOLEAN %s%s%s;\n", prefix, ansi_highlight(), true_false(basic.i), ansi_normal());
                        break;

                case SD_BUS_TYPE_INT16:
                        fprintf(f, "%sINT16 %s%i%s;\n", prefix, ansi_highlight(), basic.s16, ansi_normal());
                        break;

                case SD_BUS_TYPE_UINT16:
                        fprintf(f, "%sUINT16 %s%u%s;\n", prefix, ansi_highlight(), basic.u16, ansi_normal());
                        break;

                case SD_BUS_TYPE_INT32:
                        fprintf(f, "%sINT32 %s%i%s;\n", prefix, ansi_highlight(), basic.s32, ansi_normal());
                        break;

                case SD_BUS_TYPE_UINT32:
                        fprintf(f, "%sUINT32 %s%u%s;\n", prefix, ansi_highlight(), basic.u32, ansi_normal());
                        break;

                case SD_BUS_TYPE_INT64:
                        fprintf(f, "%sINT64 %s%"PRIi64"%s;\n", prefix, ansi_highlight(), basic.s64, ansi_normal());
                        break;

                case SD_BUS_TYPE_UINT64:
                        fprintf(f, "%sUINT64 %s%"PRIu64"%s;\n", prefix, ansi_highlight(), basic.u64, ansi_normal());
                        break;

                case SD_BUS_TYPE_DOUBLE:
                        fprintf(f, "%sDOUBLE %s%g%s;\n", prefix, ansi_highlight(), basic.d64, ansi_normal());
                        break;

                case SD_BUS_TYPE_STRING:
                        fprintf(f, "%sSTRING \"%s%s%s\";\n", prefix, ansi_highlight(), basic.string, ansi_normal());
                        break;

                case SD_BUS_TYPE_OBJECT_PATH:
                        fprintf(f, "%sOBJECT_PATH \"%s%s%s\";\n", prefix, ansi_highlight(), basic.string, ansi_normal());
                        break;

                case SD_BUS_TYPE_SIGNATURE:
                        fprintf(f, "%sSIGNATURE \"%s%s%s\";\n", prefix, ansi_highlight(), basic.string, ansi_normal());
                        break;

                case SD_BUS_TYPE_UNIX_FD:
                        fprintf(f, "%sUNIX_FD %s%i%s;\n", prefix, ansi_highlight(), basic.i, ansi_normal());
                        break;

                default:
                        assert_not_reached("Unknown basic type.");
                }
        }

        if (!(flags & BUS_MESSAGE_DUMP_SUBTREE_ONLY)) {
                _cleanup_free_ char *prefix = NULL;

                prefix = indent(0, flags);
                if (!prefix)
                        return log_oom();

                fprintf(f, "%s};\n\n", prefix);
        }

        return 0;
}

static void dump_capabilities(
                sd_bus_creds *c,
                FILE *f,
                const char *name,
                bool terse,
                int (*has)(sd_bus_creds *c, int capability)) {

        unsigned long i, last_cap;
        unsigned n = 0;
        int r;

        assert(c);
        assert(f);
        assert(name);
        assert(has);

        i = 0;
        r = has(c, i);
        if (r < 0)
                return;

        fprintf(f, "%s%s=%s", terse ? "  " : "", name, terse ? "" : ansi_highlight());
        last_cap = cap_last_cap();

        for (;;) {
                if (r > 0) {

                        if (n > 0)
                                fputc(' ', f);
                        if (n % 4 == 3)
                                fprintf(f, terse ? "\n          " : "\n        ");

                        fprintf(f, "%s", strna(capability_to_name(i)));
                        n++;
                }

                i++;

                if (i > last_cap)
                        break;

                r = has(c, i);
        }

        fputs("\n", f);

        if (!terse)
                fputs(ansi_normal(), f);
}

int bus_creds_dump(sd_bus_creds *c, FILE *f, bool terse) {
        uid_t owner, audit_loginuid;
        uint32_t audit_sessionid;
        char **cmdline = NULL, **well_known = NULL;
        const char *prefix, *color, *suffix, *s;
        int r, q, v, w, z;

        assert(c);

        if (!f)
                f = stdout;

        if (terse) {
                prefix = "  ";
                suffix = "";
                color = "";
        } else {
                const char *off;

                prefix = "";
                color = ansi_highlight();

                off = ansi_normal();
                suffix = strjoina(off, "\n");
        }

        if (c->mask & SD_BUS_CREDS_PID)
                fprintf(f, "%sPID=%s"PID_FMT"%s", prefix, color, c->pid, suffix);
        if (c->mask & SD_BUS_CREDS_TID)
                fprintf(f, "%sTID=%s"PID_FMT"%s", prefix, color, c->tid, suffix);
        if (c->mask & SD_BUS_CREDS_PPID) {
                if (c->ppid == 0)
                        fprintf(f, "%sPPID=%sn/a%s", prefix, color, suffix);
                else
                        fprintf(f, "%sPPID=%s"PID_FMT"%s", prefix, color, c->ppid, suffix);
        }
        if (c->mask & SD_BUS_CREDS_TTY)
                fprintf(f, "%sTTY=%s%s%s", prefix, color, strna(c->tty), suffix);

        if (terse && ((c->mask & (SD_BUS_CREDS_PID|SD_BUS_CREDS_TID|SD_BUS_CREDS_PPID|SD_BUS_CREDS_TTY))))
                fputs("\n", f);

        if (c->mask & SD_BUS_CREDS_UID)
                fprintf(f, "%sUID=%s"UID_FMT"%s", prefix, color, c->uid, suffix);
        if (c->mask & SD_BUS_CREDS_EUID)
                fprintf(f, "%sEUID=%s"UID_FMT"%s", prefix, color, c->euid, suffix);
        if (c->mask & SD_BUS_CREDS_SUID)
                fprintf(f, "%sSUID=%s"UID_FMT"%s", prefix, color, c->suid, suffix);
        if (c->mask & SD_BUS_CREDS_FSUID)
                fprintf(f, "%sFSUID=%s"UID_FMT"%s", prefix, color, c->fsuid, suffix);
        r = sd_bus_creds_get_owner_uid(c, &owner);
        if (r >= 0)
                fprintf(f, "%sOwnerUID=%s"UID_FMT"%s", prefix, color, owner, suffix);
        if (c->mask & SD_BUS_CREDS_GID)
                fprintf(f, "%sGID=%s"GID_FMT"%s", prefix, color, c->gid, suffix);
        if (c->mask & SD_BUS_CREDS_EGID)
                fprintf(f, "%sEGID=%s"GID_FMT"%s", prefix, color, c->egid, suffix);
        if (c->mask & SD_BUS_CREDS_SGID)
                fprintf(f, "%sSGID=%s"GID_FMT"%s", prefix, color, c->sgid, suffix);
        if (c->mask & SD_BUS_CREDS_FSGID)
                fprintf(f, "%sFSGID=%s"GID_FMT"%s", prefix, color, c->fsgid, suffix);

        if (c->mask & SD_BUS_CREDS_SUPPLEMENTARY_GIDS) {
                unsigned i;

                fprintf(f, "%sSupplementaryGIDs=%s", prefix, color);
                for (i = 0; i < c->n_supplementary_gids; i++)
                        fprintf(f, "%s" GID_FMT, i > 0 ? " " : "", c->supplementary_gids[i]);
                fprintf(f, "%s", suffix);
        }

        if (terse && ((c->mask & (SD_BUS_CREDS_UID|SD_BUS_CREDS_EUID|SD_BUS_CREDS_SUID|SD_BUS_CREDS_FSUID|
                                  SD_BUS_CREDS_GID|SD_BUS_CREDS_EGID|SD_BUS_CREDS_SGID|SD_BUS_CREDS_FSGID|
                                  SD_BUS_CREDS_SUPPLEMENTARY_GIDS)) || r >= 0))
                fputs("\n", f);

        if (c->mask & SD_BUS_CREDS_COMM)
                fprintf(f, "%sComm=%s%s%s", prefix, color, c->comm, suffix);
        if (c->mask & SD_BUS_CREDS_TID_COMM)
                fprintf(f, "%sTIDComm=%s%s%s", prefix, color, c->tid_comm, suffix);
        if (c->mask & SD_BUS_CREDS_EXE)
                fprintf(f, "%sExe=%s%s%s", prefix, color, strna(c->exe), suffix);

        if (terse && (c->mask & (SD_BUS_CREDS_EXE|SD_BUS_CREDS_COMM|SD_BUS_CREDS_TID_COMM)))
                fputs("\n", f);

        r = sd_bus_creds_get_cmdline(c, &cmdline);
        if (r >= 0) {
                char **i;

                fprintf(f, "%sCommandLine=%s", prefix, color);
                STRV_FOREACH(i, cmdline) {
                        if (i != cmdline)
                                fputc(' ', f);

                        fputs(*i, f);
                }

                fprintf(f, "%s", suffix);
        } else if (r != -ENODATA)
                fprintf(f, "%sCommandLine=%sn/a%s", prefix, color, suffix);

        if (c->mask & SD_BUS_CREDS_SELINUX_CONTEXT)
                fprintf(f, "%sLabel=%s%s%s", prefix, color, c->label, suffix);
        if (c->mask & SD_BUS_CREDS_DESCRIPTION)
                fprintf(f, "%sDescription=%s%s%s", prefix, color, c->description, suffix);

        if (terse && (c->mask & (SD_BUS_CREDS_SELINUX_CONTEXT|SD_BUS_CREDS_DESCRIPTION)))
                fputs("\n", f);

        if (c->mask & SD_BUS_CREDS_CGROUP)
                fprintf(f, "%sCGroup=%s%s%s", prefix, color, c->cgroup, suffix);
        s = NULL;
        r = sd_bus_creds_get_unit(c, &s);
        if (r != -ENODATA)
                fprintf(f, "%sUnit=%s%s%s", prefix, color, strna(s), suffix);
        s = NULL;
        v = sd_bus_creds_get_slice(c, &s);
        if (v != -ENODATA)
                fprintf(f, "%sSlice=%s%s%s", prefix, color, strna(s), suffix);
        s = NULL;
        q = sd_bus_creds_get_user_unit(c, &s);
        if (q != -ENODATA)
                fprintf(f, "%sUserUnit=%s%s%s", prefix, color, strna(s), suffix);
        s = NULL;
        w = sd_bus_creds_get_user_slice(c, &s);
        if (w != -ENODATA)
                fprintf(f, "%sUserSlice=%s%s%s", prefix, color, strna(s), suffix);
        s = NULL;
        z = sd_bus_creds_get_session(c, &s);
        if (z != -ENODATA)
                fprintf(f, "%sSession=%s%s%s", prefix, color, strna(s), suffix);

        if (terse && ((c->mask & SD_BUS_CREDS_CGROUP) || r != -ENODATA || q != -ENODATA || v != -ENODATA || w != -ENODATA || z != -ENODATA))
                fputs("\n", f);

        r = sd_bus_creds_get_audit_login_uid(c, &audit_loginuid);
        if (r >= 0)
                fprintf(f, "%sAuditLoginUID=%s"UID_FMT"%s", prefix, color, audit_loginuid, suffix);
        else if (r != -ENODATA)
                fprintf(f, "%sAuditLoginUID=%sn/a%s", prefix, color, suffix);
        q = sd_bus_creds_get_audit_session_id(c, &audit_sessionid);
        if (q >= 0)
                fprintf(f, "%sAuditSessionID=%s%"PRIu32"%s", prefix, color, audit_sessionid, suffix);
        else if (q != -ENODATA)
                fprintf(f, "%sAuditSessionID=%sn/a%s", prefix, color, suffix);

        if (terse && (r != -ENODATA || q != -ENODATA))
                fputs("\n", f);

        if (c->mask & SD_BUS_CREDS_UNIQUE_NAME)
                fprintf(f, "%sUniqueName=%s%s%s", prefix, color, c->unique_name, suffix);

        if (sd_bus_creds_get_well_known_names(c, &well_known) >= 0) {
                char **i;

                fprintf(f, "%sWellKnownNames=%s", prefix, color);
                STRV_FOREACH(i, well_known) {
                        if (i != well_known)
                                fputc(' ', f);

                        fputs(*i, f);
                }

                fprintf(f, "%s", suffix);
        }

        if (terse && (c->mask & SD_BUS_CREDS_UNIQUE_NAME || well_known))
                fputc('\n', f);

        dump_capabilities(c, f, "EffectiveCapabilities", terse, sd_bus_creds_has_effective_cap);
        dump_capabilities(c, f, "PermittedCapabilities", terse, sd_bus_creds_has_permitted_cap);
        dump_capabilities(c, f, "InheritableCapabilities", terse, sd_bus_creds_has_inheritable_cap);
        dump_capabilities(c, f, "BoundingCapabilities", terse, sd_bus_creds_has_bounding_cap);

        return 0;
}

/*
 * For details about the file format, see:
 *
 * http://wiki.wireshark.org/Development/LibpcapFileFormat
 */

typedef struct _packed_ pcap_hdr_s {
        uint32_t magic_number;   /* magic number */
        uint16_t version_major;  /* major version number */
        uint16_t version_minor;  /* minor version number */
        int32_t  thiszone;       /* GMT to local correction */
        uint32_t sigfigs;        /* accuracy of timestamps */
        uint32_t snaplen;        /* max length of captured packets, in octets */
        uint32_t network;        /* data link type */
} pcap_hdr_t ;

typedef struct  _packed_ pcaprec_hdr_s {
        uint32_t ts_sec;         /* timestamp seconds */
        uint32_t ts_usec;        /* timestamp microseconds */
        uint32_t incl_len;       /* number of octets of packet saved in file */
        uint32_t orig_len;       /* actual length of packet */
} pcaprec_hdr_t;

int bus_pcap_header(size_t snaplen, FILE *f) {

        pcap_hdr_t hdr = {
                .magic_number = 0xa1b2c3d4U,
                .version_major = 2,
                .version_minor = 4,
                .thiszone = 0, /* UTC */
                .sigfigs = 0,
                .network = 231, /* D-Bus */
        };

        if (!f)
                f = stdout;

        assert(snaplen > 0);
        assert((size_t) (uint32_t) snaplen == snaplen);

        hdr.snaplen = (uint32_t) snaplen;

        fwrite(&hdr, 1, sizeof(hdr), f);

        return fflush_and_check(f);
}

int bus_message_pcap_frame(sd_bus_message *m, size_t snaplen, FILE *f) {
        struct bus_body_part *part;
        pcaprec_hdr_t hdr = {};
        struct timeval tv;
        unsigned i;
        size_t w;

        if (!f)
                f = stdout;

        assert(m);
        assert(snaplen > 0);
        assert((size_t) (uint32_t) snaplen == snaplen);

        if (m->realtime != 0)
                timeval_store(&tv, m->realtime);
        else
                assert_se(gettimeofday(&tv, NULL) >= 0);

        hdr.ts_sec = tv.tv_sec;
        hdr.ts_usec = tv.tv_usec;
        hdr.orig_len = BUS_MESSAGE_SIZE(m);
        hdr.incl_len = MIN(hdr.orig_len, snaplen);

        /* write the pcap header */
        fwrite(&hdr, 1, sizeof(hdr), f);

        /* write the dbus header */
        w = MIN(BUS_MESSAGE_BODY_BEGIN(m), snaplen);
        fwrite(m->header, 1, w, f);
        snaplen -= w;

        /* write the dbus body */
        MESSAGE_FOREACH_PART(part, i, m) {
                if (snaplen <= 0)
                        break;

                w = MIN(part->size, snaplen);
                fwrite(part->data, 1, w, f);
                snaplen -= w;
        }

        return fflush_and_check(f);
}
