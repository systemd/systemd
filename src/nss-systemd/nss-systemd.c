/* SPDX-License-Identifier: LGPL-2.1+ */

#include <nss.h>
#include <pthread.h>

#include "sd-bus.h"

#include "alloc-util.h"
#include "bus-common-errors.h"
#include "dirent-util.h"
#include "env-util.h"
#include "fd-util.h"
#include "format-util.h"
#include "fs-util.h"
#include "list.h"
#include "macro.h"
#include "nss-util.h"
#include "signal-util.h"
#include "stdio-util.h"
#include "string-util.h"
#include "user-util.h"
#include "util.h"

#define DYNAMIC_USER_GECOS       "Dynamic User"
#define DYNAMIC_USER_PASSWD      "*" /* locked */
#define DYNAMIC_USER_DIR         "/"
#define DYNAMIC_USER_SHELL       NOLOGIN

static const struct passwd root_passwd = {
        .pw_name = (char*) "root",
        .pw_passwd = (char*) "x", /* see shadow file */
        .pw_uid = 0,
        .pw_gid = 0,
        .pw_gecos = (char*) "Super User",
        .pw_dir = (char*) "/root",
        .pw_shell = (char*) "/bin/sh",
};

static const struct passwd nobody_passwd = {
        .pw_name = (char*) NOBODY_USER_NAME,
        .pw_passwd = (char*) "*", /* locked */
        .pw_uid = UID_NOBODY,
        .pw_gid = GID_NOBODY,
        .pw_gecos = (char*) "User Nobody",
        .pw_dir = (char*) "/",
        .pw_shell = (char*) NOLOGIN,
};

static const struct group root_group = {
        .gr_name = (char*) "root",
        .gr_gid = 0,
        .gr_passwd = (char*) "x", /* see shadow file */
        .gr_mem = (char*[]) { NULL },
};

static const struct group nobody_group = {
        .gr_name = (char*) NOBODY_GROUP_NAME,
        .gr_gid = GID_NOBODY,
        .gr_passwd = (char*) "*", /* locked */
        .gr_mem = (char*[]) { NULL },
};

typedef struct UserEntry UserEntry;
typedef struct GetentData GetentData;

struct UserEntry {
        uid_t id;
        char *name;

        GetentData *data;
        LIST_FIELDS(UserEntry, entries);
};

struct GetentData {
        /* As explained in NOTES section of getpwent_r(3) as 'getpwent_r() is not really
         * reentrant since it shares the reading position in the stream with all other threads',
         * we need to protect the data in UserEntry from multithreaded programs which may call
         * setpwent(), getpwent_r(), or endpwent() simultaneously. So, each function locks the
         * data by using the mutex below. */
        pthread_mutex_t mutex;

        UserEntry *position;
        LIST_HEAD(UserEntry, entries);
};

static GetentData getpwent_data = { PTHREAD_MUTEX_INITIALIZER, NULL, NULL };
static GetentData getgrent_data = { PTHREAD_MUTEX_INITIALIZER, NULL, NULL };

NSS_GETPW_PROTOTYPES(systemd);
NSS_GETGR_PROTOTYPES(systemd);
enum nss_status _nss_systemd_endpwent(void) _public_;
enum nss_status _nss_systemd_setpwent(int stayopen) _public_;
enum nss_status _nss_systemd_getpwent_r(struct passwd *result, char *buffer, size_t buflen, int *errnop) _public_;
enum nss_status _nss_systemd_endgrent(void) _public_;
enum nss_status _nss_systemd_setgrent(int stayopen) _public_;
enum nss_status _nss_systemd_getgrent_r(struct group *result, char *buffer, size_t buflen, int *errnop) _public_;

static int direct_lookup_name(const char *name, uid_t *ret) {
        _cleanup_free_ char *s = NULL;
        const char *path;
        int r;

        assert(name);

        /* Normally, we go via the bus to resolve names. That has the benefit that it is available from any mount
         * namespace and subject to proper authentication. However, there's one problem: if our module is called from
         * dbus-daemon itself we really can't use D-Bus to communicate. In this case, resort to a client-side hack,
         * and look for the dynamic names directly. This is pretty ugly, but breaks the cyclic dependency. */

        path = strjoina("/run/systemd/dynamic-uid/direct:", name);
        r = readlink_malloc(path, &s);
        if (r < 0)
                return r;

        return parse_uid(s, ret);
}

static int direct_lookup_uid(uid_t uid, char **ret) {
        char path[STRLEN("/run/systemd/dynamic-uid/direct:") + DECIMAL_STR_MAX(uid_t) + 1], *s;
        int r;

        xsprintf(path, "/run/systemd/dynamic-uid/direct:" UID_FMT, uid);

        r = readlink_malloc(path, &s);
        if (r < 0)
                return r;
        if (!valid_user_group_name(s)) { /* extra safety check */
                free(s);
                return -EINVAL;
        }

        *ret = s;
        return 0;
}

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
        int bypass, r;

        PROTECT_ERRNO;
        BLOCK_SIGNALS(NSS_SIGNALS_BLOCK);

        assert(name);
        assert(pwd);

        /* If the username is not valid, then we don't know it. Ideally libc would filter these for us anyway. We don't
         * generate EINVAL here, because it isn't really out business to complain about invalid user names. */
        if (!valid_user_group_name(name))
                return NSS_STATUS_NOTFOUND;

        /* Synthesize entries for the root and nobody users, in case they are missing in /etc/passwd */
        if (getenv_bool_secure("SYSTEMD_NSS_BYPASS_SYNTHETIC") <= 0) {
                if (streq(name, root_passwd.pw_name)) {
                        *pwd = root_passwd;
                        return NSS_STATUS_SUCCESS;
                }
                if (synthesize_nobody() &&
                    streq(name, nobody_passwd.pw_name)) {
                        *pwd = nobody_passwd;
                        return NSS_STATUS_SUCCESS;
                }
        }

        /* Make sure that we don't go in circles when allocating a dynamic UID by checking our own database */
        if (getenv_bool_secure("SYSTEMD_NSS_DYNAMIC_BYPASS") > 0)
                return NSS_STATUS_NOTFOUND;

        bypass = getenv_bool_secure("SYSTEMD_NSS_BYPASS_BUS");
        if (bypass <= 0) {
                r = sd_bus_open_system(&bus);
                if (r < 0)
                        bypass = 1;
        }

        if (bypass > 0) {
                r = direct_lookup_name(name, (uid_t*) &translated);
                if (r == -ENOENT)
                        return NSS_STATUS_NOTFOUND;
                if (r < 0)
                        goto fail;
        } else {
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
                                return NSS_STATUS_NOTFOUND;

                        goto fail;
                }

                r = sd_bus_message_read(reply, "u", &translated);
                if (r < 0)
                        goto fail;
        }

        l = strlen(name);
        if (buflen < l+1) {
                UNPROTECT_ERRNO;
                *errnop = ERANGE;
                return NSS_STATUS_TRYAGAIN;
        }

        memcpy(buffer, name, l+1);

        pwd->pw_name = buffer;
        pwd->pw_uid = (uid_t) translated;
        pwd->pw_gid = (uid_t) translated;
        pwd->pw_gecos = (char*) DYNAMIC_USER_GECOS;
        pwd->pw_passwd = (char*) DYNAMIC_USER_PASSWD;
        pwd->pw_dir = (char*) DYNAMIC_USER_DIR;
        pwd->pw_shell = (char*) DYNAMIC_USER_SHELL;

        return NSS_STATUS_SUCCESS;

fail:
        UNPROTECT_ERRNO;
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
        _cleanup_free_ char *direct = NULL;
        const char *translated;
        size_t l;
        int bypass, r;

        PROTECT_ERRNO;
        BLOCK_SIGNALS(NSS_SIGNALS_BLOCK);

        if (!uid_is_valid(uid))
                return NSS_STATUS_NOTFOUND;

        /* Synthesize data for the root user and for nobody in case they are missing from /etc/passwd */
        if (getenv_bool_secure("SYSTEMD_NSS_BYPASS_SYNTHETIC") <= 0) {
                if (uid == root_passwd.pw_uid) {
                        *pwd = root_passwd;
                        return NSS_STATUS_SUCCESS;
                }
                if (synthesize_nobody() &&
                    uid == nobody_passwd.pw_uid) {
                        *pwd = nobody_passwd;
                        return NSS_STATUS_SUCCESS;
                }
        }

        if (!uid_is_dynamic(uid))
                return NSS_STATUS_NOTFOUND;

        if (getenv_bool_secure("SYSTEMD_NSS_DYNAMIC_BYPASS") > 0)
                return NSS_STATUS_NOTFOUND;

        bypass = getenv_bool_secure("SYSTEMD_NSS_BYPASS_BUS");
        if (bypass <= 0) {
                r = sd_bus_open_system(&bus);
                if (r < 0)
                        bypass = 1;
        }

        if (bypass > 0) {
                r = direct_lookup_uid(uid, &direct);
                if (r == -ENOENT)
                        return NSS_STATUS_NOTFOUND;
                if (r < 0)
                        goto fail;

                translated = direct;

        } else {
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
                                return NSS_STATUS_NOTFOUND;

                        goto fail;
                }

                r = sd_bus_message_read(reply, "s", &translated);
                if (r < 0)
                        goto fail;
        }

        l = strlen(translated) + 1;
        if (buflen < l) {
                UNPROTECT_ERRNO;
                *errnop = ERANGE;
                return NSS_STATUS_TRYAGAIN;
        }

        memcpy(buffer, translated, l);

        pwd->pw_name = buffer;
        pwd->pw_uid = uid;
        pwd->pw_gid = uid;
        pwd->pw_gecos = (char*) DYNAMIC_USER_GECOS;
        pwd->pw_passwd = (char*) DYNAMIC_USER_PASSWD;
        pwd->pw_dir = (char*) DYNAMIC_USER_DIR;
        pwd->pw_shell = (char*) DYNAMIC_USER_SHELL;

        return NSS_STATUS_SUCCESS;

fail:
        UNPROTECT_ERRNO;
        *errnop = -r;
        return NSS_STATUS_UNAVAIL;
}

#pragma GCC diagnostic ignored "-Wsizeof-pointer-memaccess"

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
        int bypass, r;

        PROTECT_ERRNO;
        BLOCK_SIGNALS(NSS_SIGNALS_BLOCK);

        assert(name);
        assert(gr);

        if (!valid_user_group_name(name))
                return NSS_STATUS_NOTFOUND;

        /* Synthesize records for root and nobody, in case they are missing form /etc/group */
        if (getenv_bool_secure("SYSTEMD_NSS_BYPASS_SYNTHETIC") <= 0) {
                if (streq(name, root_group.gr_name)) {
                        *gr = root_group;
                        return NSS_STATUS_SUCCESS;
                }
                if (synthesize_nobody() &&
                    streq(name, nobody_group.gr_name)) {
                        *gr = nobody_group;
                        return NSS_STATUS_SUCCESS;
                }
        }

        if (getenv_bool_secure("SYSTEMD_NSS_DYNAMIC_BYPASS") > 0)
                return NSS_STATUS_NOTFOUND;

        bypass = getenv_bool_secure("SYSTEMD_NSS_BYPASS_BUS");
        if (bypass <= 0) {
                r = sd_bus_open_system(&bus);
                if (r < 0)
                        bypass = 1;
        }

        if (bypass > 0) {
                r = direct_lookup_name(name, (uid_t*) &translated);
                if (r == -ENOENT)
                        return NSS_STATUS_NOTFOUND;
                if (r < 0)
                        goto fail;
        } else {
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
                                return NSS_STATUS_NOTFOUND;

                        goto fail;
                }

                r = sd_bus_message_read(reply, "u", &translated);
                if (r < 0)
                        goto fail;
        }

        l = sizeof(char*) + strlen(name) + 1;
        if (buflen < l) {
                UNPROTECT_ERRNO;
                *errnop = ERANGE;
                return NSS_STATUS_TRYAGAIN;
        }

        memzero(buffer, sizeof(char*));
        strcpy(buffer + sizeof(char*), name);

        gr->gr_name = buffer + sizeof(char*);
        gr->gr_gid = (gid_t) translated;
        gr->gr_passwd = (char*) DYNAMIC_USER_PASSWD;
        gr->gr_mem = (char**) buffer;

        return NSS_STATUS_SUCCESS;

fail:
        UNPROTECT_ERRNO;
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
        _cleanup_free_ char *direct = NULL;
        const char *translated;
        size_t l;
        int bypass, r;

        PROTECT_ERRNO;
        BLOCK_SIGNALS(NSS_SIGNALS_BLOCK);

        if (!gid_is_valid(gid))
                return NSS_STATUS_NOTFOUND;

        /* Synthesize records for root and nobody, in case they are missing from /etc/group */
        if (getenv_bool_secure("SYSTEMD_NSS_BYPASS_SYNTHETIC") <= 0) {
                if (gid == root_group.gr_gid) {
                        *gr = root_group;
                        return NSS_STATUS_SUCCESS;
                }
                if (synthesize_nobody() &&
                    gid == nobody_group.gr_gid) {
                        *gr = nobody_group;
                        return NSS_STATUS_SUCCESS;
                }
        }

        if (!gid_is_dynamic(gid))
                return NSS_STATUS_NOTFOUND;

        if (getenv_bool_secure("SYSTEMD_NSS_DYNAMIC_BYPASS") > 0)
                return NSS_STATUS_NOTFOUND;

        bypass = getenv_bool_secure("SYSTEMD_NSS_BYPASS_BUS");
        if (bypass <= 0) {
                r = sd_bus_open_system(&bus);
                if (r < 0)
                        bypass = 1;
        }

        if (bypass > 0) {
                r = direct_lookup_uid(gid, &direct);
                if (r == -ENOENT)
                        return NSS_STATUS_NOTFOUND;
                if (r < 0)
                        goto fail;

                translated = direct;

        } else {
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
                                return NSS_STATUS_NOTFOUND;

                        goto fail;
                }

                r = sd_bus_message_read(reply, "s", &translated);
                if (r < 0)
                        goto fail;
        }

        l = sizeof(char*) + strlen(translated) + 1;
        if (buflen < l) {
                UNPROTECT_ERRNO;
                *errnop = ERANGE;
                return NSS_STATUS_TRYAGAIN;
        }

        memzero(buffer, sizeof(char*));
        strcpy(buffer + sizeof(char*), translated);

        gr->gr_name = buffer + sizeof(char*);
        gr->gr_gid = gid;
        gr->gr_passwd = (char*) DYNAMIC_USER_PASSWD;
        gr->gr_mem = (char**) buffer;

        return NSS_STATUS_SUCCESS;

fail:
        UNPROTECT_ERRNO;
        *errnop = -r;
        return NSS_STATUS_UNAVAIL;
}

static void user_entry_free(UserEntry *p) {
        if (!p)
                return;

        if (p->data)
                LIST_REMOVE(entries, p->data->entries, p);

        free(p->name);
        free(p);
}

static int user_entry_add(GetentData *data, const char *name, uid_t id) {
        UserEntry *p;

        assert(data);

        /* This happens when User= or Group= already exists statically. */
        if (!uid_is_dynamic(id))
                return -EINVAL;

        p = new0(UserEntry, 1);
        if (!p)
                return -ENOMEM;

        p->name = strdup(name);
        if (!p->name) {
                free(p);
                return -ENOMEM;
        }
        p->id = id;
        p->data = data;

        LIST_PREPEND(entries, data->entries, p);

        return 0;
}

static void systemd_endent(GetentData *data) {
        UserEntry *p;

        assert(data);

        while ((p = data->entries))
                user_entry_free(p);

        data->position = NULL;
}

static enum nss_status nss_systemd_endent(GetentData *p) {
        PROTECT_ERRNO;
        BLOCK_SIGNALS(NSS_SIGNALS_BLOCK);

        assert_se(pthread_mutex_lock(&p->mutex) == 0);
        systemd_endent(p);
        assert_se(pthread_mutex_unlock(&p->mutex) == 0);

        return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_systemd_endpwent(void) {
        return nss_systemd_endent(&getpwent_data);
}

enum nss_status _nss_systemd_endgrent(void) {
        return nss_systemd_endent(&getgrent_data);
}

static int direct_enumeration(GetentData *p) {
        _cleanup_closedir_ DIR *d = NULL;
        struct dirent *de;
        int r;

        assert(p);

        d = opendir("/run/systemd/dynamic-uid/");
        if (!d)
                return -errno;

        FOREACH_DIRENT(de, d, return -errno) {
                _cleanup_free_ char *name = NULL;
                uid_t uid, verified;

                if (!dirent_is_file(de))
                        continue;

                r = parse_uid(de->d_name, &uid);
                if (r < 0)
                        continue;

                r = direct_lookup_uid(uid, &name);
                if (r == -ENOMEM)
                        return r;
                if (r < 0)
                        continue;

                r = direct_lookup_name(name, &verified);
                if (r < 0)
                        continue;

                if (uid != verified)
                        continue;

                r = user_entry_add(p, name, uid);
                if (r == -ENOMEM)
                        return r;
                if (r < 0)
                        continue;
        }

        return 0;
}

static enum nss_status systemd_setent(GetentData *p) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message* reply = NULL;
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        const char *name;
        uid_t id;
        int bypass, r;

        PROTECT_ERRNO;
        BLOCK_SIGNALS(NSS_SIGNALS_BLOCK);

        assert(p);

        assert_se(pthread_mutex_lock(&p->mutex) == 0);

        systemd_endent(p);

        if (getenv_bool_secure("SYSTEMD_NSS_DYNAMIC_BYPASS") > 0)
                goto finish;

        bypass = getenv_bool_secure("SYSTEMD_NSS_BYPASS_BUS");

        if (bypass <= 0) {
                r = sd_bus_open_system(&bus);
                if (r < 0)
                        bypass = 1;
        }

        if (bypass > 0) {
                r = direct_enumeration(p);
                if (r < 0)
                        goto fail;

                goto finish;
        }

        r = sd_bus_call_method(bus,
                               "org.freedesktop.systemd1",
                               "/org/freedesktop/systemd1",
                               "org.freedesktop.systemd1.Manager",
                               "GetDynamicUsers",
                               &error,
                               &reply,
                               NULL);
        if (r < 0)
                goto fail;

        r = sd_bus_message_enter_container(reply, 'a', "(us)");
        if (r < 0)
                goto fail;

        while ((r = sd_bus_message_read(reply, "(us)", &id, &name)) > 0) {
                r = user_entry_add(p, name, id);
                if (r == -ENOMEM)
                        goto fail;
                if (r < 0)
                        continue;
        }
        if (r < 0)
                goto fail;

        r = sd_bus_message_exit_container(reply);
        if (r < 0)
                goto fail;

finish:
        p->position = p->entries;
        assert_se(pthread_mutex_unlock(&p->mutex) == 0);

        return NSS_STATUS_SUCCESS;

fail:
        systemd_endent(p);
        assert_se(pthread_mutex_unlock(&p->mutex) == 0);

        return NSS_STATUS_UNAVAIL;
}

enum nss_status _nss_systemd_setpwent(int stayopen) {
        return systemd_setent(&getpwent_data);
}

enum nss_status _nss_systemd_setgrent(int stayopen) {
        return systemd_setent(&getgrent_data);
}

enum nss_status _nss_systemd_getpwent_r(struct passwd *result, char *buffer, size_t buflen, int *errnop) {
        enum nss_status ret;
        UserEntry *p;
        size_t len;

        PROTECT_ERRNO;
        BLOCK_SIGNALS(NSS_SIGNALS_BLOCK);

        assert(result);
        assert(buffer);
        assert(errnop);

        assert_se(pthread_mutex_lock(&getpwent_data.mutex) == 0);

        LIST_FOREACH(entries, p, getpwent_data.position) {
                len = strlen(p->name) + 1;
                if (buflen < len) {
                        UNPROTECT_ERRNO;
                        *errnop = ERANGE;
                        ret = NSS_STATUS_TRYAGAIN;
                        goto finalize;
                }

                memcpy(buffer, p->name, len);

                result->pw_name = buffer;
                result->pw_uid = p->id;
                result->pw_gid = p->id;
                result->pw_gecos = (char*) DYNAMIC_USER_GECOS;
                result->pw_passwd = (char*) DYNAMIC_USER_PASSWD;
                result->pw_dir = (char*) DYNAMIC_USER_DIR;
                result->pw_shell = (char*) DYNAMIC_USER_SHELL;
                break;
        }
        if (!p) {
                ret = NSS_STATUS_NOTFOUND;
                goto finalize;
        }

        /* On success, step to the next entry. */
        p = p->entries_next;
        ret = NSS_STATUS_SUCCESS;

finalize:
        /* Save position for the next call. */
        getpwent_data.position = p;

        assert_se(pthread_mutex_unlock(&getpwent_data.mutex) == 0);

        return ret;
}

enum nss_status _nss_systemd_getgrent_r(struct group *result, char *buffer, size_t buflen, int *errnop) {
        enum nss_status ret;
        UserEntry *p;
        size_t len;

        PROTECT_ERRNO;
        BLOCK_SIGNALS(NSS_SIGNALS_BLOCK);

        assert(result);
        assert(buffer);
        assert(errnop);

        assert_se(pthread_mutex_lock(&getgrent_data.mutex) == 0);

        LIST_FOREACH(entries, p, getgrent_data.position) {
                len = sizeof(char*) + strlen(p->name) + 1;
                if (buflen < len) {
                        UNPROTECT_ERRNO;
                        *errnop = ERANGE;
                        ret = NSS_STATUS_TRYAGAIN;
                        goto finalize;
                }

                memzero(buffer, sizeof(char*));
                strcpy(buffer + sizeof(char*), p->name);

                result->gr_name = buffer + sizeof(char*);
                result->gr_gid = p->id;
                result->gr_passwd = (char*) DYNAMIC_USER_PASSWD;
                result->gr_mem = (char**) buffer;
                break;
        }
        if (!p) {
                ret = NSS_STATUS_NOTFOUND;
                goto finalize;
        }

        /* On success, step to the next entry. */
        p = p->entries_next;
        ret = NSS_STATUS_SUCCESS;

finalize:
        /* Save position for the next call. */
        getgrent_data.position = p;

        assert_se(pthread_mutex_unlock(&getgrent_data.mutex) == 0);

        return ret;
}
