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

#include "util.h"
#include "capability.h"
#include "strv.h"
#include "audit.h"

#include "bus-message.h"
#include "bus-internal.h"
#include "bus-type.h"
#include "bus-dump.h"

static char *indent(unsigned level) {
        char *p;

        p = new(char, 2 + level + 1);
        if (!p)
                return NULL;

        p[0] = p[1] = ' ';
        memset(p + 2, '\t', level);
        p[2 + level] = 0;

        return p;
}

int bus_message_dump(sd_bus_message *m, FILE *f, bool with_header) {
        unsigned level = 1;
        int r;

        assert(m);

        if (!f)
                f = stdout;

        if (with_header) {
                fprintf(f,
                        "%s%s%s Type=%s%s%s  Endian=%c  Flags=%u  Version=%u  Priority=%lli",
                        m->header->type == SD_BUS_MESSAGE_METHOD_ERROR ? ansi_highlight_red() :
                        m->header->type == SD_BUS_MESSAGE_METHOD_RETURN ? ansi_highlight_green() :
                        m->header->type != SD_BUS_MESSAGE_SIGNAL ? ansi_highlight() : "", draw_special_char(DRAW_TRIANGULAR_BULLET), ansi_highlight_off(),
                        ansi_highlight(), bus_message_type_to_string(m->header->type), ansi_highlight_off(),
                        m->header->endian,
                        m->header->flags,
                        m->header->version,
                        (long long) m->priority);

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
                        fprintf(f, "  Sender=%s%s%s", ansi_highlight(), m->sender, ansi_highlight_off());
                if (m->destination)
                        fprintf(f, "  Destination=%s%s%s", ansi_highlight(), m->destination, ansi_highlight_off());
                if (m->path)
                        fprintf(f, "  Path=%s%s%s", ansi_highlight(), m->path, ansi_highlight_off());
                if (m->interface)
                        fprintf(f, "  Interface=%s%s%s", ansi_highlight(), m->interface, ansi_highlight_off());
                if (m->member)
                        fprintf(f, "  Member=%s%s%s", ansi_highlight(), m->member, ansi_highlight_off());

                if (m->sender || m->destination || m->path || m->interface || m->member)
                        fputs("\n", f);

                if (sd_bus_error_is_set(&m->error))
                        fprintf(f,
                                "  ErrorName=%s%s%s"
                                "  ErrorMessage=%s\"%s\"%s\n",
                                ansi_highlight_red(), strna(m->error.name), ansi_highlight_off(),
                                ansi_highlight_red(), strna(m->error.message), ansi_highlight_off());

                if (m->monotonic != 0)
                        fprintf(f, "  Monotonic="USEC_FMT, m->monotonic);
                if (m->realtime != 0)
                        fprintf(f, "  Realtime="USEC_FMT, m->realtime);
                if (m->seqnum != 0)
                        fprintf(f, "  SequenceNumber=%"PRIu64, m->seqnum);

                if (m->monotonic != 0 || m->realtime != 0 || m->seqnum != 0)
                        fputs("\n", f);

                bus_creds_dump(&m->creds, f);
        }

        r = sd_bus_message_rewind(m, true);
        if (r < 0) {
                log_error("Failed to rewind: %s", strerror(-r));
                return r;
        }

        fprintf(f, "  MESSAGE \"%s\" {\n", strempty(m->root_container.signature));

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
                if (r < 0) {
                        log_error("Failed to peek type: %s", strerror(-r));
                        return r;
                }

                if (r == 0) {
                        if (level <= 1)
                                break;

                        r = sd_bus_message_exit_container(m);
                        if (r < 0) {
                                log_error("Failed to exit container: %s", strerror(-r));
                                return r;
                        }

                        level--;

                        prefix = indent(level);
                        if (!prefix)
                                return log_oom();

                        fprintf(f, "%s};\n", prefix);
                        continue;
                }

                prefix = indent(level);
                if (!prefix)
                        return log_oom();

                if (bus_type_is_container(type) > 0) {
                        r = sd_bus_message_enter_container(m, type, contents);
                        if (r < 0) {
                                log_error("Failed to enter container: %s", strerror(-r));
                                return r;
                        }

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
                if (r < 0) {
                        log_error("Failed to get basic: %s", strerror(-r));
                        return r;
                }

                assert(r > 0);

                switch (type) {

                case SD_BUS_TYPE_BYTE:
                        fprintf(f, "%sBYTE %s%u%s;\n", prefix, ansi_highlight(), basic.u8, ansi_highlight_off());
                        break;

                case SD_BUS_TYPE_BOOLEAN:
                        fprintf(f, "%sBOOLEAN %s%s%s;\n", prefix, ansi_highlight(), true_false(basic.i), ansi_highlight_off());
                        break;

                case SD_BUS_TYPE_INT16:
                        fprintf(f, "%sINT16 %s%i%s;\n", prefix, ansi_highlight(), basic.s16, ansi_highlight_off());
                        break;

                case SD_BUS_TYPE_UINT16:
                        fprintf(f, "%sUINT16 %s%u%s;\n", prefix, ansi_highlight(), basic.u16, ansi_highlight_off());
                        break;

                case SD_BUS_TYPE_INT32:
                        fprintf(f, "%sINT32 %s%i%s;\n", prefix, ansi_highlight(), basic.s32, ansi_highlight_off());
                        break;

                case SD_BUS_TYPE_UINT32:
                        fprintf(f, "%sUINT32 %s%u%s;\n", prefix, ansi_highlight(), basic.u32, ansi_highlight_off());
                        break;

                case SD_BUS_TYPE_INT64:
                        fprintf(f, "%sINT64 %s%"PRIi64"%s;\n", prefix, ansi_highlight(), basic.s64, ansi_highlight_off());
                        break;

                case SD_BUS_TYPE_UINT64:
                        fprintf(f, "%sUINT64 %s%"PRIu64"%s;\n", prefix, ansi_highlight(), basic.u64, ansi_highlight_off());
                        break;

                case SD_BUS_TYPE_DOUBLE:
                        fprintf(f, "%sDOUBLE %s%g%s;\n", prefix, ansi_highlight(), basic.d64, ansi_highlight_off());
                        break;

                case SD_BUS_TYPE_STRING:
                        fprintf(f, "%sSTRING \"%s%s%s\";\n", prefix, ansi_highlight(), basic.string, ansi_highlight_off());
                        break;

                case SD_BUS_TYPE_OBJECT_PATH:
                        fprintf(f, "%sOBJECT_PATH \"%s%s%s\";\n", prefix, ansi_highlight(), basic.string, ansi_highlight_off());
                        break;

                case SD_BUS_TYPE_SIGNATURE:
                        fprintf(f, "%sSIGNATURE \"%s%s%s\";\n", prefix, ansi_highlight(), basic.string, ansi_highlight_off());
                        break;

                case SD_BUS_TYPE_UNIX_FD:
                        fprintf(f, "%sUNIX_FD %s%i%s;\n", prefix, ansi_highlight(), basic.i, ansi_highlight_off());
                        break;

                default:
                        assert_not_reached("Unknown basic type.");
                }
        }

        fprintf(f, "  };\n\n");
        return 0;
}

static void dump_capabilities(
                sd_bus_creds *c,
                FILE *f,
                const char *name,
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

        fprintf(f, "  %s=", name);
        last_cap = cap_last_cap();

        for (;;) {
                if (r > 0) {
                        _cleanup_cap_free_charp_ char *t;

                        if (n > 0)
                                fputc(' ', f);
                        if (n % 4 == 3)
                                fputs("\n          ", f);

                        t = cap_to_name(i);
                        fprintf(f, "%s", t);
                        n++;
                }

                i++;

                if (i > last_cap)
                        break;

                r = has(c, i);
        }

        fputs("\n", f);
}

int bus_creds_dump(sd_bus_creds *c, FILE *f) {
        bool audit_sessionid_is_set = false, audit_loginuid_is_set = false;
        const char *u = NULL, *uu = NULL, *s = NULL, *sl = NULL;
        uid_t owner, audit_loginuid;
        uint32_t audit_sessionid;
        char **cmdline = NULL, **well_known = NULL;
        int r;

        assert(c);

        if (!f)
                f = stdout;

        if (c->mask & SD_BUS_CREDS_PID)
                fprintf(f, "  PID="PID_FMT, c->pid);
        if (c->mask & SD_BUS_CREDS_PID_STARTTIME)
                fprintf(f, "  PIDStartTime="USEC_FMT, c->pid_starttime);
        if (c->mask & SD_BUS_CREDS_TID)
                fprintf(f, "  TID="PID_FMT, c->tid);
        if (c->mask & SD_BUS_CREDS_UID)
                fprintf(f, "  UID="UID_FMT, c->uid);
        r = sd_bus_creds_get_owner_uid(c, &owner);
        if (r >= 0)
                fprintf(f, "  OwnerUID="UID_FMT, owner);
        if (c->mask & SD_BUS_CREDS_GID)
                fprintf(f, "  GID="GID_FMT, c->gid);

        if ((c->mask & (SD_BUS_CREDS_PID|SD_BUS_CREDS_PID_STARTTIME|SD_BUS_CREDS_TID|SD_BUS_CREDS_UID|SD_BUS_CREDS_GID)) || r >= 0)
                fputs("\n", f);

        if (c->mask & SD_BUS_CREDS_EXE)
                fprintf(f, "  Exe=%s", c->exe);
        if (c->mask & SD_BUS_CREDS_COMM)
                fprintf(f, "  Comm=%s", c->comm);
        if (c->mask & SD_BUS_CREDS_TID_COMM)
                fprintf(f, "  TIDComm=%s", c->tid_comm);

        if (c->mask & (SD_BUS_CREDS_EXE|SD_BUS_CREDS_COMM|SD_BUS_CREDS_TID_COMM))
                fputs("\n", f);

        if (c->mask & SD_BUS_CREDS_SELINUX_CONTEXT)
                fprintf(f, "  Label=%s", c->label);
        if (c->mask & SD_BUS_CREDS_CONNECTION_NAME)
                fprintf(f, "  ConnectionName=%s", c->conn_name);

        if (c->mask & (SD_BUS_CREDS_SELINUX_CONTEXT|SD_BUS_CREDS_CONNECTION_NAME))
                fputs("\n", f);

        if (sd_bus_creds_get_cmdline(c, &cmdline) >= 0) {
                char **i;

                fputs("  CommandLine={", f);
                STRV_FOREACH(i, cmdline) {
                        if (i != cmdline)
                                fputc(' ', f);

                        fputs(*i, f);
                }

                fputs("}\n", f);
        }

        if (c->mask & SD_BUS_CREDS_CGROUP)
                fprintf(f, "  CGroup=%s", c->cgroup);
        sd_bus_creds_get_unit(c, &u);
        if (u)
                fprintf(f, "  Unit=%s", u);
        sd_bus_creds_get_user_unit(c, &uu);
        if (uu)
                fprintf(f, "  UserUnit=%s", uu);
        sd_bus_creds_get_slice(c, &sl);
        if (sl)
                fprintf(f, "  Slice=%s", sl);
        sd_bus_creds_get_session(c, &s);
        if (s)
                fprintf(f, "  Session=%s", s);

        if ((c->mask & SD_BUS_CREDS_CGROUP) || u || uu || sl || s)
                fputs("\n", f);

        if (sd_bus_creds_get_audit_login_uid(c, &audit_loginuid) >= 0) {
                audit_loginuid_is_set = true;
                fprintf(f, "  AuditLoginUID="UID_FMT, audit_loginuid);
        }
        if (sd_bus_creds_get_audit_session_id(c, &audit_sessionid) >= 0) {
                audit_sessionid_is_set = true;
                fprintf(f, "  AuditSessionID=%"PRIu32, audit_sessionid);
        }

        if (audit_loginuid_is_set || audit_sessionid_is_set)
                fputs("\n", f);

        if (c->mask & SD_BUS_CREDS_UNIQUE_NAME)
                fprintf(f, "  UniqueName=%s", c->unique_name);

        if (sd_bus_creds_get_well_known_names(c, &well_known) >= 0) {
                char **i;

                fputs("  WellKnownNames={", f);
                STRV_FOREACH(i, well_known) {
                        if (i != well_known)
                                fputc(' ', f);

                        fputs(*i, f);
                }

                fputc('}', f);
        }

        if (c->mask & SD_BUS_CREDS_UNIQUE_NAME || well_known)
                fputc('\n', f);

        dump_capabilities(c, f, "EffectiveCapabilities", sd_bus_creds_has_effective_cap);
        dump_capabilities(c, f, "PermittedCapabilities", sd_bus_creds_has_permitted_cap);
        dump_capabilities(c, f, "InheritableCapabilities", sd_bus_creds_has_inheritable_cap);
        dump_capabilities(c, f, "BoundingCapabilities", sd_bus_creds_has_bounding_cap);

        return 0;
}
