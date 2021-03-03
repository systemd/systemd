/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <security/_pam_macros.h>
#include <security/pam_ext.h>
#include <security/pam_misc.h>
#include <security/pam_modules.h>
#include <security/pam_modutil.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <unistd.h>

#include "alloc-util.h"
#include "audit-util.h"
#include "bus-common-errors.h"
#include "bus-error.h"
#include "bus-internal.h"
#include "bus-locator.h"
#include "cgroup-setup.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "format-util.h"
#include "fs-util.h"
#include "hostname-util.h"
#include "locale-util.h"
#include "login-util.h"
#include "macro.h"
#include "pam-util.h"
#include "parse-util.h"
#include "path-util.h"
#include "percent-util.h"
#include "process-util.h"
#include "rlimit-util.h"
#include "socket-util.h"
#include "stdio-util.h"
#include "strv.h"
#include "terminal-util.h"
#include "user-util.h"
#include "userdb.h"

#define LOGIN_SLOW_BUS_CALL_TIMEOUT_USEC (2*USEC_PER_MINUTE)

static int parse_argv(
                pam_handle_t *handle,
                int argc, const char **argv,
                const char **class,
                const char **type,
                const char **desktop,
                bool *debug) {

        unsigned i;

        assert(argc >= 0);
        assert(argc == 0 || argv);

        for (i = 0; i < (unsigned) argc; i++) {
                const char *p;

                if ((p = startswith(argv[i], "class="))) {
                        if (class)
                                *class = p;

                } else if ((p = startswith(argv[i], "type="))) {
                        if (type)
                                *type = p;

                } else if ((p = startswith(argv[i], "desktop="))) {
                        if (desktop)
                                *desktop = p;

                } else if (streq(argv[i], "debug")) {
                        if (debug)
                                *debug = true;

                } else if ((p = startswith(argv[i], "debug="))) {
                        int k;

                        k = parse_boolean(p);
                        if (k < 0)
                                pam_syslog(handle, LOG_WARNING, "Failed to parse debug= argument, ignoring: %s", p);
                        else if (debug)
                                *debug = k;

                } else
                        pam_syslog(handle, LOG_WARNING, "Unknown parameter '%s', ignoring", argv[i]);
        }

        return 0;
}

static int acquire_user_record(
                pam_handle_t *handle,
                UserRecord **ret_record) {

        _cleanup_(user_record_unrefp) UserRecord *ur = NULL;
        const char *username = NULL, *json = NULL;
        _cleanup_free_ char *field = NULL;
        int r;

        assert(handle);

        r = pam_get_user(handle, &username, NULL);
        if (r != PAM_SUCCESS) {
                pam_syslog(handle, LOG_ERR, "Failed to get user name: %s", pam_strerror(handle, r));
                return r;
        }

        if (isempty(username)) {
                pam_syslog(handle, LOG_ERR, "User name not valid.");
                return PAM_SERVICE_ERR;
        }

        /* If pam_systemd_homed (or some other module) already acquired the user record we can reuse it
         * here. */
        field = strjoin("systemd-user-record-", username);
        if (!field)
                return pam_log_oom(handle);

        r = pam_get_data(handle, field, (const void**) &json);
        if (!IN_SET(r, PAM_SUCCESS, PAM_NO_MODULE_DATA)) {
                pam_syslog(handle, LOG_ERR, "Failed to get PAM user record data: %s", pam_strerror(handle, r));
                return r;
        }
        if (r == PAM_SUCCESS && json) {
                _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;

                /* Parse cached record */
                r = json_parse(json, JSON_PARSE_SENSITIVE, &v, NULL, NULL);
                if (r < 0) {
                        pam_syslog(handle, LOG_ERR, "Failed to parse JSON user record: %s", strerror_safe(r));
                        return PAM_SERVICE_ERR;
                }

                ur = user_record_new();
                if (!ur)
                        return pam_log_oom(handle);

                r = user_record_load(ur, v, USER_RECORD_LOAD_REFUSE_SECRET);
                if (r < 0) {
                        pam_syslog(handle, LOG_ERR, "Failed to load user record: %s", strerror_safe(r));
                        return PAM_SERVICE_ERR;
                }

                /* Safety check if cached record actually matches what we are looking for */
                if (!streq_ptr(username, ur->user_name)) {
                        pam_syslog(handle, LOG_ERR, "Acquired user record does not match user name.");
                        return PAM_SERVICE_ERR;
                }
        } else {
                _cleanup_free_ char *formatted = NULL;

                /* Request the record ourselves */
                r = userdb_by_name(username, 0, &ur);
                if (r < 0) {
                        pam_syslog(handle, LOG_ERR, "Failed to get user record: %s", strerror_safe(r));
                        return PAM_USER_UNKNOWN;
                }

                r = json_variant_format(ur->json, 0, &formatted);
                if (r < 0) {
                        pam_syslog(handle, LOG_ERR, "Failed to format user JSON: %s", strerror_safe(r));
                        return PAM_SERVICE_ERR;
                }

                /* And cache it for everyone else */
                r = pam_set_data(handle, field, formatted, pam_cleanup_free);
                if (r < 0) {
                        pam_syslog(handle, LOG_ERR, "Failed to set PAM user record data '%s': %s",
                                   field, pam_strerror(handle, r));
                        return r;
                }

                TAKE_PTR(formatted);
        }

        if (!uid_is_valid(ur->uid)) {
                pam_syslog(handle, LOG_ERR, "Acquired user record does not have a UID.");
                return PAM_SERVICE_ERR;
        }

        if (ret_record)
                *ret_record = TAKE_PTR(ur);

        return PAM_SUCCESS;
}

static bool display_is_local(const char *display) {
        assert(display);

        return
                display[0] == ':' &&
                display[1] >= '0' &&
                display[1] <= '9';
}

static int socket_from_display(const char *display, char **path) {
        size_t k;
        char *f, *c;

        assert(display);
        assert(path);

        if (!display_is_local(display))
                return -EINVAL;

        k = strspn(display+1, "0123456789");

        f = new(char, STRLEN("/tmp/.X11-unix/X") + k + 1);
        if (!f)
                return -ENOMEM;

        c = stpcpy(f, "/tmp/.X11-unix/X");
        memcpy(c, display+1, k);
        c[k] = 0;

        *path = f;

        return 0;
}

static int get_seat_from_display(const char *display, const char **seat, uint32_t *vtnr) {
        union sockaddr_union sa;
        socklen_t sa_len;
        _cleanup_free_ char *p = NULL, *sys_path = NULL, *tty = NULL;
        _cleanup_close_ int fd = -1;
        struct ucred ucred;
        int v, r;
        dev_t display_ctty;

        assert(display);
        assert(vtnr);

        /* We deduce the X11 socket from the display name, then use
         * SO_PEERCRED to determine the X11 server process, ask for
         * the controlling tty of that and if it's a VC then we know
         * the seat and the virtual terminal. Sounds ugly, is only
         * semi-ugly. */

        r = socket_from_display(display, &p);
        if (r < 0)
                return r;
        r = sockaddr_un_set_path(&sa.un, p);
        if (r < 0)
                return r;
        sa_len = r;

        fd = socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0);
        if (fd < 0)
                return -errno;

        if (connect(fd, &sa.sa, sa_len) < 0)
                return -errno;

        r = getpeercred(fd, &ucred);
        if (r < 0)
                return r;

        r = get_ctty_devnr(ucred.pid, &display_ctty);
        if (r < 0)
                return r;

        if (asprintf(&sys_path, "/sys/dev/char/%d:%d", major(display_ctty), minor(display_ctty)) < 0)
                return -ENOMEM;
        r = readlink_value(sys_path, &tty);
        if (r < 0)
                return r;

        v = vtnr_from_tty(tty);
        if (v < 0)
                return v;
        else if (v == 0)
                return -ENOENT;

        if (seat)
                *seat = "seat0";
        *vtnr = (uint32_t) v;

        return 0;
}

static int export_legacy_dbus_address(
                pam_handle_t *handle,
                const char *runtime) {

        const char *s;
        _cleanup_free_ char *t = NULL;
        int r = PAM_BUF_ERR;

        /* We need to export $DBUS_SESSION_BUS_ADDRESS because various applications will not connect
         * correctly to the bus without it. This setting matches what dbus.socket does for the user
         * session using 'systemctl --user set-environment'. We want to have the same configuration
         * in processes started from the PAM session.
         *
         * The setting of the address is guarded by the access() check because it is also possible to compile
         * dbus without --enable-user-session, in which case this socket is not used, and
         * $DBUS_SESSION_BUS_ADDRESS should not be set. An alternative approach would to not do the access()
         * check here, and let applications try on their own, by using "unix:path=%s/bus;autolaunch:". But we
         * expect the socket to be present by the time we do this check, so we can just as well check once
         * here. */

        s = strjoina(runtime, "/bus");
        if (access(s, F_OK) < 0)
                return PAM_SUCCESS;

        if (asprintf(&t, DEFAULT_USER_BUS_ADDRESS_FMT, runtime) < 0)
                return pam_log_oom(handle);

        r = pam_misc_setenv(handle, "DBUS_SESSION_BUS_ADDRESS", t, 0);
        if (r != PAM_SUCCESS) {
                pam_syslog(handle, LOG_ERR, "Failed to set bus variable: %s", pam_strerror(handle, r));
                return r;
        }

        return PAM_SUCCESS;
}

static int append_session_memory_max(pam_handle_t *handle, sd_bus_message *m, const char *limit) {
        uint64_t val;
        int r;

        if (isempty(limit))
                return PAM_SUCCESS;

        if (streq(limit, "infinity")) {
                r = sd_bus_message_append(m, "(sv)", "MemoryMax", "t", UINT64_MAX);
                if (r < 0)
                        return pam_bus_log_create_error(handle, r);

                return PAM_SUCCESS;
        }

        r = parse_permyriad(limit);
        if (r >= 0) {
                r = sd_bus_message_append(m, "(sv)", "MemoryMaxScale", "u", UINT32_SCALE_FROM_PERMYRIAD(r));
                if (r < 0)
                        return pam_bus_log_create_error(handle, r);

                return PAM_SUCCESS;
        }

        r = parse_size(limit, 1024, &val);
        if (r >= 0) {
                r = sd_bus_message_append(m, "(sv)", "MemoryMax", "t", val);
                if (r < 0)
                        return pam_bus_log_create_error(handle, r);

                return PAM_SUCCESS;
        }

        pam_syslog(handle, LOG_WARNING, "Failed to parse systemd.memory_max, ignoring: %s", limit);
        return PAM_SUCCESS;
}

static int append_session_runtime_max_sec(pam_handle_t *handle, sd_bus_message *m, const char *limit) {
        usec_t val;
        int r;

        /* No need to parse "infinity" here, it will be set by default later in scope_init() */
        if (isempty(limit) || streq(limit, "infinity"))
                return PAM_SUCCESS;

        r = parse_sec(limit, &val);
        if (r >= 0) {
                r = sd_bus_message_append(m, "(sv)", "RuntimeMaxUSec", "t", (uint64_t) val);
                if (r < 0)
                        return pam_bus_log_create_error(handle, r);
        } else
                pam_syslog(handle, LOG_WARNING, "Failed to parse systemd.runtime_max_sec: %s, ignoring.", limit);

        return PAM_SUCCESS;
}

static int append_session_tasks_max(pam_handle_t *handle, sd_bus_message *m, const char *limit) {
        uint64_t val;
        int r;

        /* No need to parse "infinity" here, it will be set unconditionally later in manager_start_scope() */
        if (isempty(limit) || streq(limit, "infinity"))
                return PAM_SUCCESS;

        r = safe_atou64(limit, &val);
        if (r >= 0) {
                r = sd_bus_message_append(m, "(sv)", "TasksMax", "t", val);
                if (r < 0)
                        return pam_bus_log_create_error(handle, r);
        } else
                pam_syslog(handle, LOG_WARNING, "Failed to parse systemd.tasks_max, ignoring: %s", limit);

        return PAM_SUCCESS;
}

static int append_session_cg_weight(pam_handle_t *handle, sd_bus_message *m, const char *limit, const char *field) {
        uint64_t val;
        int r;

        if (isempty(limit))
                return PAM_SUCCESS;

        r = cg_weight_parse(limit, &val);
        if (r >= 0) {
                r = sd_bus_message_append(m, "(sv)", field, "t", val);
                if (r < 0)
                        return pam_bus_log_create_error(handle, r);
        } else if (streq(field, "CPUWeight"))
                pam_syslog(handle, LOG_WARNING, "Failed to parse systemd.cpu_weight, ignoring: %s", limit);
        else
                pam_syslog(handle, LOG_WARNING, "Failed to parse systemd.io_weight, ignoring: %s", limit);

        return PAM_SUCCESS;
}

static const char* getenv_harder(pam_handle_t *handle, const char *key, const char *fallback) {
        const char *v;

        assert(handle);
        assert(key);

        /* Looks for an environment variable, preferably in the environment block associated with the
         * specified PAM handle, falling back to the process' block instead. Why check both? Because we want
         * to permit configuration of session properties from unit files that invoke PAM services, so that
         * PAM services don't have to be reworked to set systemd-specific properties, but these properties
         * can still be set from the unit file Environment= block. */

        v = pam_getenv(handle, key);
        if (!isempty(v))
                return v;

        /* We use secure_getenv() here, since we might get loaded into su/sudo, which are SUID. Ideally
         * they'd clean up the environment before invoking foreign code (such as PAM modules), but alas they
         * currently don't (to be precise, they clean up the environment they pass to their children, but
         * not their own environ[]). */
        v = secure_getenv(key);
        if (!isempty(v))
                return v;

        return fallback;
}

static int update_environment(pam_handle_t *handle, const char *key, const char *value) {
        int r;

        assert(handle);
        assert(key);

        /* Updates the environment, but only if there's actually a value set. Also, log about errors */

        if (isempty(value))
                return PAM_SUCCESS;

        r = pam_misc_setenv(handle, key, value, 0);
        if (r != PAM_SUCCESS)
                pam_syslog(handle, LOG_ERR, "Failed to set environment variable %s: %s", key, pam_strerror(handle, r));

        return r;
}

static bool validate_runtime_directory(pam_handle_t *handle, const char *path, uid_t uid) {
        struct stat st;

        assert(handle);
        assert(path);

        /* Some extra paranoia: let's not set $XDG_RUNTIME_DIR if the directory we'd set it to isn't actually
         * set up properly for us. This is supposed to provide a careful safety net for supporting su/sudo
         * type transitions: in that case the UID changes, but the session and thus the user owning it
         * doesn't change. Since the $XDG_RUNTIME_DIR lifecycle is bound to the session's user being logged
         * in at least once we should be particularly careful when setting the environment variable, since
         * otherwise we might end up setting $XDG_RUNTIME_DIR to some directory owned by the wrong user. */

        if (!path_is_absolute(path)) {
                pam_syslog(handle, LOG_ERR, "Provided runtime directory '%s' is not absolute.", path);
                goto fail;
        }

        if (lstat(path, &st) < 0) {
                pam_syslog(handle, LOG_ERR, "Failed to stat() runtime directory '%s': %s", path, strerror_safe(errno));
                goto fail;
        }

        if (!S_ISDIR(st.st_mode)) {
                pam_syslog(handle, LOG_ERR, "Runtime directory '%s' is not actually a directory.", path);
                goto fail;
        }

        if (st.st_uid != uid) {
                pam_syslog(handle, LOG_ERR, "Runtime directory '%s' is not owned by UID " UID_FMT ", as it should.", path, uid);
                goto fail;
        }

        return true;

fail:
        pam_syslog(handle, LOG_WARNING, "Not setting $XDG_RUNTIME_DIR, as the directory is not in order.");
        return false;
}

static int pam_putenv_and_log(pam_handle_t *handle, const char *e, bool debug) {
        int r;

        assert(handle);
        assert(e);

        r = pam_putenv(handle, e);
        if (r != PAM_SUCCESS) {
                pam_syslog(handle, LOG_ERR, "Failed to set PAM environment variable %s: %s", e, pam_strerror(handle, r));
                return r;
        }

        if (debug)
                pam_syslog(handle, LOG_DEBUG, "PAM environment variable %s set based on user record.", e);

        return PAM_SUCCESS;
}

static int apply_user_record_settings(pam_handle_t *handle, UserRecord *ur, bool debug) {
        char **i;
        int r;

        assert(handle);
        assert(ur);

        if (ur->umask != MODE_INVALID) {
                umask(ur->umask);

                if (debug)
                        pam_syslog(handle, LOG_DEBUG, "Set user umask to %04o based on user record.", ur->umask);
        }

        STRV_FOREACH(i, ur->environment) {
                _cleanup_free_ char *n = NULL;
                const char *e;

                assert_se(e = strchr(*i, '=')); /* environment was already validated while parsing JSON record, this thus must hold */

                n = strndup(*i, e - *i);
                if (!n)
                        return pam_log_oom(handle);

                if (pam_getenv(handle, n)) {
                        if (debug)
                                pam_syslog(handle, LOG_DEBUG, "PAM environment variable $%s already set, not changing based on record.", *i);
                        continue;
                }

                r = pam_putenv_and_log(handle, *i, debug);
                if (r != PAM_SUCCESS)
                        return r;
        }

        if (ur->email_address) {
                if (pam_getenv(handle, "EMAIL")) {
                        if (debug)
                                pam_syslog(handle, LOG_DEBUG, "PAM environment variable $EMAIL already set, not changing based on user record.");
                } else {
                        _cleanup_free_ char *joined = NULL;

                        joined = strjoin("EMAIL=", ur->email_address);
                        if (!joined)
                                return pam_log_oom(handle);

                        r = pam_putenv_and_log(handle, joined, debug);
                        if (r != PAM_SUCCESS)
                                return r;
                }
        }

        if (ur->time_zone) {
                if (pam_getenv(handle, "TZ")) {
                        if (debug)
                                pam_syslog(handle, LOG_DEBUG, "PAM environment variable $TZ already set, not changing based on user record.");
                } else if (!timezone_is_valid(ur->time_zone, LOG_DEBUG)) {
                        if (debug)
                                pam_syslog(handle, LOG_DEBUG, "Time zone specified in user record is not valid locally, not setting $TZ.");
                } else {
                        _cleanup_free_ char *joined = NULL;

                        joined = strjoin("TZ=:", ur->time_zone);
                        if (!joined)
                                return pam_log_oom(handle);

                        r = pam_putenv_and_log(handle, joined, debug);
                        if (r != PAM_SUCCESS)
                                return r;
                }
        }

        if (ur->preferred_language) {
                if (pam_getenv(handle, "LANG")) {
                        if (debug)
                                pam_syslog(handle, LOG_DEBUG, "PAM environment variable $LANG already set, not changing based on user record.");
                } else if (locale_is_installed(ur->preferred_language) <= 0) {
                        if (debug)
                                pam_syslog(handle, LOG_DEBUG, "Preferred language specified in user record is not valid or not installed, not setting $LANG.");
                } else {
                        _cleanup_free_ char *joined = NULL;

                        joined = strjoin("LANG=", ur->preferred_language);
                        if (!joined)
                                return pam_log_oom(handle);

                        r = pam_putenv_and_log(handle, joined, debug);
                        if (r != PAM_SUCCESS)
                                return r;
                }
        }

        if (nice_is_valid(ur->nice_level)) {
                if (nice(ur->nice_level) < 0)
                        pam_syslog(handle, LOG_ERR, "Failed to set nice level to %i, ignoring: %s", ur->nice_level, strerror_safe(errno));
                else if (debug)
                        pam_syslog(handle, LOG_DEBUG, "Nice level set, based on user record.");
        }

        for (int rl = 0; rl < _RLIMIT_MAX; rl++) {

                if (!ur->rlimits[rl])
                        continue;

                r = setrlimit_closest(rl, ur->rlimits[rl]);
                if (r < 0)
                        pam_syslog(handle, LOG_ERR, "Failed to set resource limit %s, ignoring: %s", rlimit_to_string(rl), strerror_safe(r));
                else if (debug)
                        pam_syslog(handle, LOG_DEBUG, "Resource limit %s set, based on user record.", rlimit_to_string(rl));
        }

        return PAM_SUCCESS;
}

static int configure_runtime_directory(
                pam_handle_t *handle,
                UserRecord *ur,
                const char *rt) {

        int r;

        assert(handle);
        assert(ur);
        assert(rt);

        if (!validate_runtime_directory(handle, rt, ur->uid))
                return PAM_SUCCESS;

        r = pam_misc_setenv(handle, "XDG_RUNTIME_DIR", rt, 0);
        if (r != PAM_SUCCESS) {
                pam_syslog(handle, LOG_ERR, "Failed to set runtime dir: %s", pam_strerror(handle, r));
                return r;
        }

        return export_legacy_dbus_address(handle, rt);
}

_public_ PAM_EXTERN int pam_sm_open_session(
                pam_handle_t *handle,
                int flags,
                int argc, const char **argv) {

        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL, *reply = NULL;
        const char
                *id, *object_path, *runtime_path,
                *service = NULL,
                *tty = NULL, *display = NULL,
                *remote_user = NULL, *remote_host = NULL,
                *seat = NULL,
                *type = NULL, *class = NULL,
                *class_pam = NULL, *type_pam = NULL, *cvtnr = NULL, *desktop = NULL, *desktop_pam = NULL,
                *memory_max = NULL, *tasks_max = NULL, *cpu_weight = NULL, *io_weight = NULL, *runtime_max_sec = NULL;
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_(user_record_unrefp) UserRecord *ur = NULL;
        int session_fd = -1, existing, r;
        bool debug = false, remote;
        uint32_t vtnr = 0;
        uid_t original_uid;

        assert(handle);

        if (parse_argv(handle,
                       argc, argv,
                       &class_pam,
                       &type_pam,
                       &desktop_pam,
                       &debug) < 0)
                return PAM_SESSION_ERR;

        if (debug)
                pam_syslog(handle, LOG_DEBUG, "pam-systemd initializing");

        r = acquire_user_record(handle, &ur);
        if (r != PAM_SUCCESS)
                return r;

        /* Make most of this a NOP on non-logind systems */
        if (!logind_running())
                goto success;

        /* Make sure we don't enter a loop by talking to
         * systemd-logind when it is actually waiting for the
         * background to finish start-up. If the service is
         * "systemd-user" we simply set XDG_RUNTIME_DIR and
         * leave. */

        (void) pam_get_item(handle, PAM_SERVICE, (const void**) &service);
        if (streq_ptr(service, "systemd-user")) {
                char rt[STRLEN("/run/user/") + DECIMAL_STR_MAX(uid_t)];

                xsprintf(rt, "/run/user/"UID_FMT, ur->uid);
                r = configure_runtime_directory(handle, ur, rt);
                if (r != PAM_SUCCESS)
                        return r;

                goto success;
        }

        /* Otherwise, we ask logind to create a session for us */

        (void) pam_get_item(handle, PAM_XDISPLAY, (const void**) &display);
        (void) pam_get_item(handle, PAM_TTY, (const void**) &tty);
        (void) pam_get_item(handle, PAM_RUSER, (const void**) &remote_user);
        (void) pam_get_item(handle, PAM_RHOST, (const void**) &remote_host);

        seat = getenv_harder(handle, "XDG_SEAT", NULL);
        cvtnr = getenv_harder(handle, "XDG_VTNR", NULL);
        type = getenv_harder(handle, "XDG_SESSION_TYPE", type_pam);
        class = getenv_harder(handle, "XDG_SESSION_CLASS", class_pam);
        desktop = getenv_harder(handle, "XDG_SESSION_DESKTOP", desktop_pam);

        tty = strempty(tty);

        if (strchr(tty, ':')) {
                /* A tty with a colon is usually an X11 display, placed there to show up in utmp. We rearrange things
                 * and don't pretend that an X display was a tty. */
                if (isempty(display))
                        display = tty;
                tty = NULL;

        } else if (streq(tty, "cron")) {
                /* cron is setting PAM_TTY to "cron" for some reason (the commit carries no information why, but
                 * probably because it wants to set it to something as pam_time/pam_access/… require PAM_TTY to be set
                 * (as they otherwise even try to update it!) — but cron doesn't actually allocate a TTY for its forked
                 * off processes.) */
                type = "unspecified";
                class = "background";
                tty = NULL;

        } else if (streq(tty, "ssh")) {
                /* ssh has been setting PAM_TTY to "ssh" (for the same reason as cron does this, see above. For further
                 * details look for "PAM_TTY_KLUDGE" in the openssh sources). */
                type ="tty";
                class = "user";
                tty = NULL; /* This one is particularly sad, as this means that ssh sessions — even though usually
                             * associated with a pty — won't be tracked by their tty in logind. This is because ssh
                             * does the PAM session registration early for new connections, and registers a pty only
                             * much later (this is because it doesn't know yet if it needs one at all, as whether to
                             * register a pty or not is negotiated much later in the protocol). */

        } else
                /* Chop off leading /dev prefix that some clients specify, but others do not. */
                tty = skip_dev_prefix(tty);

        /* If this fails vtnr will be 0, that's intended */
        if (!isempty(cvtnr))
                (void) safe_atou32(cvtnr, &vtnr);

        if (!isempty(display) && !vtnr) {
                if (isempty(seat))
                        (void) get_seat_from_display(display, &seat, &vtnr);
                else if (streq(seat, "seat0"))
                        (void) get_seat_from_display(display, NULL, &vtnr);
        }

        if (seat && !streq(seat, "seat0") && vtnr != 0) {
                if (debug)
                        pam_syslog(handle, LOG_DEBUG, "Ignoring vtnr %"PRIu32" for %s which is not seat0", vtnr, seat);
                vtnr = 0;
        }

        if (isempty(type))
                type = !isempty(display) ? "x11" :
                           !isempty(tty) ? "tty" : "unspecified";

        if (isempty(class))
                class = streq(type, "unspecified") ? "background" : "user";

        remote = !isempty(remote_host) && !is_localhost(remote_host);

        (void) pam_get_data(handle, "systemd.memory_max", (const void **)&memory_max);
        (void) pam_get_data(handle, "systemd.tasks_max",  (const void **)&tasks_max);
        (void) pam_get_data(handle, "systemd.cpu_weight", (const void **)&cpu_weight);
        (void) pam_get_data(handle, "systemd.io_weight",  (const void **)&io_weight);
        (void) pam_get_data(handle, "systemd.runtime_max_sec", (const void **)&runtime_max_sec);

        /* Talk to logind over the message bus */

        r = pam_acquire_bus_connection(handle, &bus);
        if (r != PAM_SUCCESS)
                return r;

        if (debug) {
                pam_syslog(handle, LOG_DEBUG, "Asking logind to create session: "
                           "uid="UID_FMT" pid="PID_FMT" service=%s type=%s class=%s desktop=%s seat=%s vtnr=%"PRIu32" tty=%s display=%s remote=%s remote_user=%s remote_host=%s",
                           ur->uid, getpid_cached(),
                           strempty(service),
                           type, class, strempty(desktop),
                           strempty(seat), vtnr, strempty(tty), strempty(display),
                           yes_no(remote), strempty(remote_user), strempty(remote_host));
                pam_syslog(handle, LOG_DEBUG, "Session limits: "
                           "memory_max=%s tasks_max=%s cpu_weight=%s io_weight=%s runtime_max_sec=%s",
                           strna(memory_max), strna(tasks_max), strna(cpu_weight), strna(io_weight), strna(runtime_max_sec));
        }

        r = bus_message_new_method_call(bus, &m, bus_login_mgr, "CreateSession");
        if (r < 0)
                return pam_bus_log_create_error(handle, r);

        r = sd_bus_message_append(m, "uusssssussbss",
                        (uint32_t) ur->uid,
                        0,
                        service,
                        type,
                        class,
                        desktop,
                        seat,
                        vtnr,
                        tty,
                        display,
                        remote,
                        remote_user,
                        remote_host);
        if (r < 0)
                return pam_bus_log_create_error(handle, r);

        r = sd_bus_message_open_container(m, 'a', "(sv)");
        if (r < 0)
                return pam_bus_log_create_error(handle, r);

        r = append_session_memory_max(handle, m, memory_max);
        if (r != PAM_SUCCESS)
                return r;

        r = append_session_runtime_max_sec(handle, m, runtime_max_sec);
        if (r != PAM_SUCCESS)
                return r;

        r = append_session_tasks_max(handle, m, tasks_max);
        if (r != PAM_SUCCESS)
                return r;

        r = append_session_cg_weight(handle, m, cpu_weight, "CPUWeight");
        if (r != PAM_SUCCESS)
                return r;

        r = append_session_cg_weight(handle, m, io_weight, "IOWeight");
        if (r != PAM_SUCCESS)
                return r;

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return pam_bus_log_create_error(handle, r);

        r = sd_bus_call(bus, m, LOGIN_SLOW_BUS_CALL_TIMEOUT_USEC, &error, &reply);
        if (r < 0) {
                if (sd_bus_error_has_name(&error, BUS_ERROR_SESSION_BUSY)) {
                        if (debug)
                                pam_syslog(handle, LOG_DEBUG, "Not creating session: %s", bus_error_message(&error, r));

                        /* We are already in a session, don't do anything */
                        goto success;
                } else {
                        pam_syslog(handle, LOG_ERR, "Failed to create session: %s", bus_error_message(&error, r));
                        return PAM_SESSION_ERR;
                }
        }

        r = sd_bus_message_read(reply,
                                "soshusub",
                                &id,
                                &object_path,
                                &runtime_path,
                                &session_fd,
                                &original_uid,
                                &seat,
                                &vtnr,
                                &existing);
        if (r < 0)
                return pam_bus_log_parse_error(handle, r);

        if (debug)
                pam_syslog(handle, LOG_DEBUG, "Reply from logind: "
                           "id=%s object_path=%s runtime_path=%s session_fd=%d seat=%s vtnr=%u original_uid=%u",
                           id, object_path, runtime_path, session_fd, seat, vtnr, original_uid);

        r = update_environment(handle, "XDG_SESSION_ID", id);
        if (r != PAM_SUCCESS)
                return r;

        if (original_uid == ur->uid) {
                /* Don't set $XDG_RUNTIME_DIR if the user we now authenticated for does not match the
                 * original user of the session. We do this in order not to result in privileged apps
                 * clobbering the runtime directory unnecessarily. */

                r = configure_runtime_directory(handle, ur, runtime_path);
                if (r != PAM_SUCCESS)
                        return r;
        }

        /* Most likely we got the session/type/class from environment variables, but might have gotten the data
         * somewhere else (for example PAM module parameters). Let's now update the environment variables, so that this
         * data is inherited into the session processes, and programs can rely on them to be initialized. */

        r = update_environment(handle, "XDG_SESSION_TYPE", type);
        if (r != PAM_SUCCESS)
                return r;

        r = update_environment(handle, "XDG_SESSION_CLASS", class);
        if (r != PAM_SUCCESS)
                return r;

        r = update_environment(handle, "XDG_SESSION_DESKTOP", desktop);
        if (r != PAM_SUCCESS)
                return r;

        r = update_environment(handle, "XDG_SEAT", seat);
        if (r != PAM_SUCCESS)
                return r;

        if (vtnr > 0) {
                char buf[DECIMAL_STR_MAX(vtnr)];
                sprintf(buf, "%u", vtnr);

                r = update_environment(handle, "XDG_VTNR", buf);
                if (r != PAM_SUCCESS)
                        return r;
        }

        r = pam_set_data(handle, "systemd.existing", INT_TO_PTR(!!existing), NULL);
        if (r != PAM_SUCCESS) {
                pam_syslog(handle, LOG_ERR, "Failed to install existing flag: %s", pam_strerror(handle, r));
                return r;
        }

        if (session_fd >= 0) {
                session_fd = fcntl(session_fd, F_DUPFD_CLOEXEC, 3);
                if (session_fd < 0) {
                        pam_syslog(handle, LOG_ERR, "Failed to dup session fd: %m");
                        return PAM_SESSION_ERR;
                }

                r = pam_set_data(handle, "systemd.session-fd", FD_TO_PTR(session_fd), NULL);
                if (r != PAM_SUCCESS) {
                        pam_syslog(handle, LOG_ERR, "Failed to install session fd: %s", pam_strerror(handle, r));
                        safe_close(session_fd);
                        return r;
                }
        }

success:
        r = apply_user_record_settings(handle, ur, debug);
        if (r != PAM_SUCCESS)
                return r;

        /* Let's release the D-Bus connection, after all the session might live quite a long time, and we are
         * not going to use the bus connection in that time, so let's better close before the daemon kicks us
         * off because we are not processing anything. */
        (void) pam_release_bus_connection(handle);
        return PAM_SUCCESS;
}

_public_ PAM_EXTERN int pam_sm_close_session(
                pam_handle_t *handle,
                int flags,
                int argc, const char **argv) {

        const void *existing = NULL;
        bool debug = false;
        const char *id;
        int r;

        assert(handle);

        if (parse_argv(handle,
                       argc, argv,
                       NULL,
                       NULL,
                       NULL,
                       &debug) < 0)
                return PAM_SESSION_ERR;

        if (debug)
                pam_syslog(handle, LOG_DEBUG, "pam-systemd shutting down");

        /* Only release session if it wasn't pre-existing when we
         * tried to create it */
        (void) pam_get_data(handle, "systemd.existing", &existing);

        id = pam_getenv(handle, "XDG_SESSION_ID");
        if (id && !existing) {
                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;

                /* Before we go and close the FIFO we need to tell logind that this is a clean session
                 * shutdown, so that it doesn't just go and slaughter us immediately after closing the fd */

                r = pam_acquire_bus_connection(handle, &bus);
                if (r != PAM_SUCCESS)
                        return r;

                r = bus_call_method(bus, bus_login_mgr, "ReleaseSession", &error, NULL, "s", id);
                if (r < 0) {
                        pam_syslog(handle, LOG_ERR, "Failed to release session: %s", bus_error_message(&error, r));
                        return PAM_SESSION_ERR;
                }
        }

        /* Note that we are knowingly leaking the FIFO fd here. This way, logind can watch us die. If we
         * closed it here it would not have any clue when that is completed. Given that one cannot really
         * have multiple PAM sessions open from the same process this means we will leak one FD at max. */

        return PAM_SUCCESS;
}
