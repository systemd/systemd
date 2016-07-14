/***
  This file is part of systemd.

  Copyright 2016 Lennart Poettering

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

#include <nss.h>

#include "sd-bus.h"

#include "bus-common-errors.h"
#include "env-util.h"
#include "macro.h"
#include "nss-util.h"
#include "signal-util.h"
#include "user-util.h"
#include "util.h"

NSS_GETPW_PROTOTYPES(systemd);
NSS_GETGR_PROTOTYPES(systemd);

enum nss_status _nss_systemd_getpwnam_r(
                const char *name,
                struct passwd *pwd,
                char *buffer, size_t buflen,
                int *errnop) {

        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message* reply = NULL;
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        uint32_t translated;
        size_t l;
        int r;

        BLOCK_SIGNALS(NSS_SIGNALS_BLOCK);

        assert(name);
        assert(pwd);

        /* Make sure that we don't go in circles when allocating a dynamic UID by checking our own database */
        if (getenv_bool("SYSTEMD_NSS_DYNAMIC_BYPASS") > 0)
                goto not_found;

        r = sd_bus_open_system(&bus);
        if (r < 0)
                goto fail;

        r = sd_bus_call_method(bus,
                               "org.freedesktop.systemd1",
                               "/org/freedesktop/systemd1",
                               "org.freedesktop.systemd1.Manager",
                               "LookupDynamicUserByName",
                               &error,
                               &reply,
                               "s",
                               name);
        if (r < 0) {
                if (sd_bus_error_has_name(&error, BUS_ERROR_NO_SUCH_DYNAMIC_USER))
                        goto not_found;

                goto fail;
        }

        r = sd_bus_message_read(reply, "u", &translated);
        if (r < 0)
                goto fail;

        l = strlen(name);
        if (buflen < l+1) {
                *errnop = ENOMEM;
                return NSS_STATUS_TRYAGAIN;
        }

        memcpy(buffer, name, l+1);

        pwd->pw_name = buffer;
        pwd->pw_uid = (uid_t) translated;
        pwd->pw_gid = (uid_t) translated;
        pwd->pw_gecos = (char*) "Dynamic User";
        pwd->pw_passwd = (char*) "*"; /* locked */
        pwd->pw_dir = (char*) "/";
        pwd->pw_shell = (char*) "/sbin/nologin";

        *errnop = 0;
        return NSS_STATUS_SUCCESS;

not_found:
        *errnop = 0;
        return NSS_STATUS_NOTFOUND;

fail:
        *errnop = -r;
        return NSS_STATUS_UNAVAIL;
}

enum nss_status _nss_systemd_getpwuid_r(
                uid_t uid,
                struct passwd *pwd,
                char *buffer, size_t buflen,
                int *errnop) {

        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message* reply = NULL;
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        const char *translated;
        size_t l;
        int r;

        BLOCK_SIGNALS(NSS_SIGNALS_BLOCK);

        if (!uid_is_valid(uid)) {
                r = -EINVAL;
                goto fail;
        }

        if (uid <= SYSTEM_UID_MAX)
                goto not_found;

        if (getenv_bool("SYSTEMD_NSS_DYNAMIC_BYPASS") > 0)
                goto not_found;

        r = sd_bus_open_system(&bus);
        if (r < 0)
                goto fail;

        r = sd_bus_call_method(bus,
                               "org.freedesktop.systemd1",
                               "/org/freedesktop/systemd1",
                               "org.freedesktop.systemd1.Manager",
                               "LookupDynamicUserByUID",
                               &error,
                               &reply,
                               "u",
                               (uint32_t) uid);
        if (r < 0) {
                if (sd_bus_error_has_name(&error, BUS_ERROR_NO_SUCH_DYNAMIC_USER))
                        goto not_found;

                goto fail;
        }

        r = sd_bus_message_read(reply, "s", &translated);
        if (r < 0)
                goto fail;

        l = strlen(translated) + 1;
        if (buflen < l) {
                *errnop = ENOMEM;
                return NSS_STATUS_TRYAGAIN;
        }

        memcpy(buffer, translated, l);

        pwd->pw_name = buffer;
        pwd->pw_uid = uid;
        pwd->pw_gid = uid;
        pwd->pw_gecos = (char*) "Dynamic User";
        pwd->pw_passwd = (char*) "*"; /* locked */
        pwd->pw_dir = (char*) "/";
        pwd->pw_shell = (char*) "/sbin/nologin";

        *errnop = 0;
        return NSS_STATUS_SUCCESS;

not_found:
        *errnop = 0;
        return NSS_STATUS_NOTFOUND;

fail:
        *errnop = -r;
        return NSS_STATUS_UNAVAIL;
}

enum nss_status _nss_systemd_getgrnam_r(
                const char *name,
                struct group *gr,
                char *buffer, size_t buflen,
                int *errnop) {

        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message* reply = NULL;
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        uint32_t translated;
        size_t l;
        int r;

        BLOCK_SIGNALS(NSS_SIGNALS_BLOCK);

        assert(name);
        assert(gr);

        if (getenv_bool("SYSTEMD_NSS_DYNAMIC_BYPASS") > 0)
                goto not_found;

        r = sd_bus_open_system(&bus);
        if (r < 0)
                goto fail;

        r = sd_bus_call_method(bus,
                               "org.freedesktop.systemd1",
                               "/org/freedesktop/systemd1",
                               "org.freedesktop.systemd1.Manager",
                               "LookupDynamicUserByName",
                               &error,
                               &reply,
                               "s",
                               name);
        if (r < 0) {
                if (sd_bus_error_has_name(&error, BUS_ERROR_NO_SUCH_DYNAMIC_USER))
                        goto not_found;

                goto fail;
        }

        r = sd_bus_message_read(reply, "u", &translated);
        if (r < 0)
                goto fail;

        l = sizeof(char*) + strlen(name) + 1;
        if (buflen < l) {
                *errnop = ENOMEM;
                return NSS_STATUS_TRYAGAIN;
        }

        memzero(buffer, sizeof(char*));
        strcpy(buffer + sizeof(char*), name);

        gr->gr_name = buffer + sizeof(char*);
        gr->gr_gid = (gid_t) translated;
        gr->gr_passwd = (char*) "*"; /* locked */
        gr->gr_mem = (char**) buffer;

        *errnop = 0;
        return NSS_STATUS_SUCCESS;

not_found:
        *errnop = 0;
        return NSS_STATUS_NOTFOUND;

fail:
        *errnop = -r;
        return NSS_STATUS_UNAVAIL;
}

enum nss_status _nss_systemd_getgrgid_r(
                gid_t gid,
                struct group *gr,
                char *buffer, size_t buflen,
                int *errnop) {

        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message* reply = NULL;
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        const char *translated;
        size_t l;
        int r;

        BLOCK_SIGNALS(NSS_SIGNALS_BLOCK);

        if (!gid_is_valid(gid)) {
                r = -EINVAL;
                goto fail;
        }

        if (gid <= SYSTEM_GID_MAX)
                goto not_found;

        if (getenv_bool("SYSTEMD_NSS_DYNAMIC_BYPASS") > 0)
                goto not_found;

        r = sd_bus_open_system(&bus);
        if (r < 0)
                goto fail;

        r = sd_bus_call_method(bus,
                               "org.freedesktop.systemd1",
                               "/org/freedesktop/systemd1",
                               "org.freedesktop.systemd1.Manager",
                               "LookupDynamicUserByUID",
                               &error,
                               &reply,
                               "u",
                               (uint32_t) gid);
        if (r < 0) {
                if (sd_bus_error_has_name(&error, BUS_ERROR_NO_SUCH_DYNAMIC_USER))
                        goto not_found;

                goto fail;
        }

        r = sd_bus_message_read(reply, "s", &translated);
        if (r < 0)
                goto fail;

        l = sizeof(char*) + strlen(translated) + 1;
        if (buflen < l) {
                *errnop = ENOMEM;
                return NSS_STATUS_TRYAGAIN;
        }

        memzero(buffer, sizeof(char*));
        strcpy(buffer + sizeof(char*), translated);

        gr->gr_name = buffer + sizeof(char*);
        gr->gr_gid = gid;
        gr->gr_passwd = (char*) "*"; /* locked */
        gr->gr_mem = (char**) buffer;

        *errnop = 0;
        return NSS_STATUS_SUCCESS;

not_found:
        *errnop = 0;
        return NSS_STATUS_NOTFOUND;

fail:
        *errnop = -r;
        return NSS_STATUS_UNAVAIL;
}
