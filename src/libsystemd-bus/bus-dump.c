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

#include <sys/capability.h>

#include "util.h"
#include "capability.h"
#include "strv.h"

#include "bus-message.h"
#include "bus-internal.h"
#include "bus-type.h"
#include "bus-dump.h"

int bus_message_dump(sd_bus_message *m, FILE *f, bool with_header) {
        const char *u = NULL, *uu = NULL, *s = NULL;
        char **cmdline = NULL;
        unsigned level = 1;
        int r;
        uid_t owner, audit_loginuid;
        uint32_t audit_sessionid;

        assert(m);

        if (!f)
                f = stdout;

        if (with_header) {
                fprintf(f,
                        "%sEndian=%c  Type=%s%s%s  Flags=%u  Version=%u  Serial=%u ",
                        draw_special_char(DRAW_TRIANGULAR_BULLET),
                        m->header->endian,
                        ansi_highlight(), bus_message_type_to_string(m->header->type), ansi_highlight_off(),
                        m->header->flags,
                        m->header->version,
                        BUS_MESSAGE_SERIAL(m));

                if (m->reply_serial != 0)
                        fprintf(f, "  ReplySerial=%u", m->reply_serial);

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

                if (m->pid != 0)
                        fprintf(f, "  PID=%lu", (unsigned long) m->pid);
                if (m->pid_starttime != 0)
                        fprintf(f, "  PIDStartTime=%llu", (unsigned long long) m->pid_starttime);
                if (m->tid != 0)
                        fprintf(f, "  TID=%lu", (unsigned long) m->tid);
                if (m->uid_valid)
                        fprintf(f, "  UID=%lu", (unsigned long) m->uid);
                r = sd_bus_message_get_owner_uid(m, &owner);
                if (r >= 0)
                        fprintf(f, "  OwnerUID=%lu", (unsigned long) owner);
                if (m->gid_valid)
                        fprintf(f, "  GID=%lu", (unsigned long) m->gid);

                if (m->pid != 0 || m->pid_starttime != 0 || m->tid != 0 || m->uid_valid || r >= 0 || m->gid_valid)
                        fputs("\n", f);

                if (m->monotonic != 0)
                        fprintf(f, "  Monotonic=%llu", (unsigned long long) m->monotonic);
                if (m->realtime != 0)
                        fprintf(f, "  Realtime=%llu", (unsigned long long) m->realtime);

                if (m->monotonic != 0 || m->realtime != 0)
                        fputs("\n", f);

                if (m->exe)
                        fprintf(f, "  Exe=%s", m->exe);
                if (m->comm)
                        fprintf(f, "  Comm=%s", m->comm);
                if (m->tid_comm)
                        fprintf(f, "  TIDComm=%s", m->tid_comm);
                if (m->label)
                        fprintf(f, "  Label=%s", m->label);

                if (m->exe || m->comm || m->tid_comm || m->label)
                        fputs("\n", f);

                if (sd_bus_message_get_cmdline(m, &cmdline) >= 0) {
                        char **c;

                        fputs("  CommandLine=[", f);
                        STRV_FOREACH(c, cmdline) {
                                if (c != cmdline)
                                        fputc(' ', f);

                                fputs(*c, f);
                        }

                        fputs("]\n", f);
                }

                if (m->cgroup)
                        fprintf(f, "  CGroup=%s\n", m->cgroup);

                sd_bus_message_get_unit(m, &u);
                if (u)
                        fprintf(f, "  Unit=%s", u);
                sd_bus_message_get_user_unit(m, &uu);
                if (uu)
                        fprintf(f, "  UserUnit=%s", uu);
                sd_bus_message_get_session(m, &s);
                if (s)
                        fprintf(f, "  Session=%s", s);
                if (sd_bus_message_get_audit_loginuid(m, &audit_loginuid) >= 0)
                        fprintf(f, "  AuditLoginUID=%lu", (unsigned long) audit_loginuid);
                if (sd_bus_message_get_audit_sessionid(m, &audit_sessionid) >= 0)
                        fprintf(f, "  AuditSessionID=%lu", (unsigned long) audit_sessionid);

                if (u || uu || s || audit_loginuid || audit_sessionid)
                        fputs("\n", f);

                r = sd_bus_message_has_effective_cap(m, 0);
                if (r >= 0) {
                        unsigned long c, last_cap;

                        fprintf(f, "  Capabilities=%s", r ? cap_to_name(0) : "");

                        last_cap = cap_last_cap();
                        for (c = 0; c < last_cap; c++) {
                                r = sd_bus_message_has_effective_cap(m, c);
                                if (r > 0)
                                        fprintf(f, "|%s", cap_to_name(c));
                        }
                }
        }

        r = sd_bus_message_rewind(m, true);
        if (r < 0) {
                log_error("Failed to rewind: %s", strerror(-r));
                return r;
        }

        fprintf(f, "MESSAGE \"%s\" {\n", strempty(m->root_container.signature));

        for(;;) {
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

                        prefix = strrep("\t", level);
                        if (!prefix)
                                return log_oom();

                        fprintf(f, "%s};\n", prefix);
                        continue;
                }

                prefix = strrep("\t", level);
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
                        fprintf(f, "%sBOOLEAN %s%s%s;\n", prefix, ansi_highlight(), yes_no(basic.i), ansi_highlight_off());
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
                        fprintf(f, "%sINT64 %s%lli%s;\n", prefix, ansi_highlight(), (long long) basic.s64, ansi_highlight_off());
                        break;

                case SD_BUS_TYPE_UINT64:
                        fprintf(f, "%sUINT64 %s%llu%s;\n", prefix, ansi_highlight(), (unsigned long long) basic.u64, ansi_highlight_off());
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

        fprintf(f, "};\n");
        return 0;
}
