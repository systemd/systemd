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
#include "cap-list.h"
#include "capability-util.h"
#include "cgroup-setup.h"
#include "devnum-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "format-util.h"
#include "fs-util.h"
#include "hostname-util.h"
#include "locale-util.h"
#include "login-util.h"
#include "macro.h"
#include "missing_syscall.h"
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

static int parse_caps(
                pam_handle_t *handle,
                const char *value,
                uint64_t *caps) {

        bool subtract;
        int r;

        assert(handle);
        assert(value);

        if (value[0] == '~') {
                subtract = true;
                value++;
        } else
                subtract = false;

        for (;;) {
                _cleanup_free_ char *s = NULL;
                uint64_t b, m;
                int c;

                /* We can't use spaces as separators here, as PAM's simplistic argument parser doesn't allow
                 * spaces inside of arguments. We use commas instead (which is similar to cap_from_text(),
                 * which also uses commas). */
                r = extract_first_word(&value, &s, ",", EXTRACT_DONT_COALESCE_SEPARATORS);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                c = capability_from_name(s);
                if (c < 0) {
                        pam_syslog(handle, LOG_WARNING, "Unknown capability, ignoring: %s", s);
                        continue;
                }

                m = UINT64_C(1) << c;

                if (!caps)
                        continue;

                if (*caps == UINT64_MAX)
                        b = subtract ? all_capabilities() : 0;
                else
                        b = *caps;

                if (subtract)
                        *caps = b & ~m;
                else
                        *caps = b | m;
        }

        return 0;
}

static int parse_argv(
                pam_handle_t *handle,
                int argc, const char **argv,
                const char **class,
                const char **type,
                const char **desktop,
                bool *debug,
                uint64_t *default_capability_bounding_set,
                uint64_t *default_capability_ambient_set) {

        int r;

        assert(handle);
        assert(argc >= 0);
        assert(argc == 0 || argv);

        for (int i = 0; i < argc; i++) {
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
                        r = parse_boolean(p);
                        if (r < 0)
                                pam_syslog(handle, LOG_WARNING, "Failed to parse debug= argument, ignoring: %s", p);
                        else if (debug)
                                *debug = r;

                } else if ((p = startswith(argv[i], "default-capability-bounding-set="))) {
                        r = parse_caps(handle, p, default_capability_bounding_set);
                        if (r < 0)
                                pam_syslog(handle, LOG_WARNING, "Failed to parse default-capability-bounding-set= argument, ignoring: %s", p);

                } else if ((p = startswith(argv[i], "default-capability-ambient-set="))) {
                        r = parse_caps(handle, p, default_capability_ambient_set);
                        if (r < 0)
                                pam_syslog(handle, LOG_WARNING, "Failed to parse default-capability-ambient-set= argument, ignoring: %s", p);

                } else
                        pam_syslog(handle, LOG_WARNING, "Unknown parameter '%s', ignoring.", argv[i]);
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
        if (r != PAM_SUCCESS)
                return pam_syslog_pam_error(handle, LOG_ERR, r, "Failed to get user name: @PAMERR@");

        if (isempty(username))
                return pam_syslog_pam_error(handle, LOG_ERR, PAM_SERVICE_ERR, "User name not valid.");

        /* If pam_systemd_homed (or some other module) already acquired the user record we can reuse it
         * here. */
        field = strjoin("systemd-user-record-", username);
        if (!field)
                return pam_log_oom(handle);

        r = pam_get_data(handle, field, (const void**) &json);
        if (!IN_SET(r, PAM_SUCCESS, PAM_NO_MODULE_DATA))
                return pam_syslog_pam_error(handle, LOG_ERR, r, "Failed to get PAM user record data: @PAMERR@");
        if (r == PAM_SUCCESS && json) {
                _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;

                /* Parse cached record */
                r = json_parse(json, JSON_PARSE_SENSITIVE, &v, NULL, NULL);
                if (r < 0)
                        return pam_syslog_errno(handle, LOG_ERR, r, "Failed to parse JSON user record: %m");

                ur = user_record_new();
                if (!ur)
                        return pam_log_oom(handle);

                r = user_record_load(ur, v, USER_RECORD_LOAD_REFUSE_SECRET|USER_RECORD_PERMISSIVE);
                if (r < 0)
                        return pam_syslog_errno(handle, LOG_ERR, r, "Failed to load user record: %m");

                /* Safety check if cached record actually matches what we are looking for */
                if (!streq_ptr(username, ur->user_name))
                        return pam_syslog_pam_error(handle, LOG_ERR, PAM_SERVICE_ERR,
                                                    "Acquired user record does not match user name.");
        } else {
                _cleanup_free_ char *formatted = NULL;

                /* Request the record ourselves */
                r = userdb_by_name(username, 0, &ur);
                if (r < 0) {
                        pam_syslog_errno(handle, LOG_ERR, r, "Failed to get user record: %m");
                        return PAM_USER_UNKNOWN;
                }

                r = json_variant_format(ur->json, 0, &formatted);
                if (r < 0)
                        return pam_syslog_errno(handle, LOG_ERR, r, "Failed to format user JSON: %m");

                /* And cache it for everyone else */
                r = pam_set_data(handle, field, formatted, pam_cleanup_free);
                if (r != PAM_SUCCESS)
                        return pam_syslog_pam_error(handle, LOG_ERR, r,
                                                    "Failed to set PAM user record data '%s': @PAMERR@", field);
                TAKE_PTR(formatted);
        }

        if (!uid_is_valid(ur->uid))
                return pam_syslog_pam_error(handle, LOG_ERR, PAM_SERVICE_ERR,
                                            "Acquired user record does not have a UID.");

        if (ret_record)
                *ret_record = TAKE_PTR(ur);

        return PAM_SUCCESS;
}

static bool display_is_local(const char *display) {
        assert(display);

        return
                display[0] == ':' &&
                ascii_isdigit(display[1]);
}

static int socket_from_display(const char *display) {
        _cleanup_free_ char *f = NULL;
        size_t k;
        char *c;
        union sockaddr_union sa;
        socklen_t sa_len;
        _cleanup_close_ int fd = -EBADF;
        int r;

        assert(display);

        if (!display_is_local(display))
                return -EINVAL;

        k = strspn(display+1, "0123456789");

        /* Try abstract socket first. */
        f = new(char, STRLEN("@/tmp/.X11-unix/X") + k + 1);
        if (!f)
                return -ENOMEM;

        c = stpcpy(f, "@/tmp/.X11-unix/X");
        memcpy(c, display+1, k);
        c[k] = 0;

        r = sockaddr_un_set_path(&sa.un, f);
        if (r < 0)
                return r;
        sa_len = r;

        fd = RET_NERRNO(socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0));
        if (fd < 0)
                return fd;

        r = RET_NERRNO(connect(fd, &sa.sa, sa_len));
        if (r >= 0)
                return TAKE_FD(fd);
        if (r != -ECONNREFUSED)
                return r;

        /* Try also non-abstract socket. */
        r = sockaddr_un_set_path(&sa.un, f + 1);
        if (r < 0)
                return r;
        sa_len = r;

        r = RET_NERRNO(connect(fd, &sa.sa, sa_len));
        if (r >= 0)
                return TAKE_FD(fd);
        return r;
}

static int get_seat_from_display(const char *display, const char **seat, uint32_t *vtnr) {
        _cleanup_free_ char *sys_path = NULL, *tty = NULL;
        _cleanup_close_ int fd = -EBADF;
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

        fd = socket_from_display(display);
        if (fd < 0)
                return fd;

        r = getpeercred(fd, &ucred);
        if (r < 0)
                return r;

        r = get_ctty_devnr(ucred.pid, &display_ctty);
        if (r < 0)
                return r;

        if (asprintf(&sys_path, "/sys/dev/char/" DEVNUM_FORMAT_STR, DEVNUM_FORMAT_VAL(display_ctty)) < 0)
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
        if (r != PAM_SUCCESS)
                return pam_syslog_pam_error(handle, LOG_ERR, r, "Failed to set bus variable: @PAMERR@");

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

static int append_session_cpu_weight(pam_handle_t *handle, sd_bus_message *m, const char *limit) {
        uint64_t val;
        int r;

        if (isempty(limit))
                return PAM_SUCCESS;

        r = cg_cpu_weight_parse(limit, &val);
        if (r < 0)
                pam_syslog(handle, LOG_WARNING, "Failed to parse systemd.cpu_weight, ignoring: %s", limit);
        else {
                r = sd_bus_message_append(m, "(sv)", "CPUWeight", "t", val);
                if (r < 0)
                        return pam_bus_log_create_error(handle, r);
        }

        return PAM_SUCCESS;
}

static int append_session_io_weight(pam_handle_t *handle, sd_bus_message *m, const char *limit) {
        uint64_t val;
        int r;

        if (isempty(limit))
                return PAM_SUCCESS;

        r = cg_weight_parse(limit, &val);
        if (r < 0)
                pam_syslog(handle, LOG_WARNING, "Failed to parse systemd.io_weight, ignoring: %s", limit);
        else {
                r = sd_bus_message_append(m, "(sv)", "IOWeight", "t", val);
                if (r < 0)
                        return pam_bus_log_create_error(handle, r);
        }

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
                return pam_syslog_pam_error(handle, LOG_ERR, r,
                                            "Failed to set environment variable %s: @PAMERR@", key);

        return PAM_SUCCESS;
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
                pam_syslog_errno(handle, LOG_ERR, errno, "Failed to stat() runtime directory '%s': %m", path);
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
        if (r != PAM_SUCCESS)
                return pam_syslog_pam_error(handle, LOG_ERR, r,
                                            "Failed to set PAM environment variable %s: @PAMERR@", e);

        pam_debug_syslog(handle, debug, "PAM environment variable %s set based on user record.", e);

        return PAM_SUCCESS;
}

static int apply_user_record_settings(
                pam_handle_t *handle,
                UserRecord *ur,
                bool debug,
                uint64_t default_capability_bounding_set,
                uint64_t default_capability_ambient_set) {
        int r;

        assert(handle);
        assert(ur);

        if (ur->umask != MODE_INVALID) {
                umask(ur->umask);
                pam_debug_syslog(handle, debug, "Set user umask to %04o based on user record.", ur->umask);
        }

        STRV_FOREACH(i, ur->environment) {
                _cleanup_free_ char *n = NULL;
                const char *e;

                assert_se(e = strchr(*i, '=')); /* environment was already validated while parsing JSON record, this thus must hold */

                n = strndup(*i, e - *i);
                if (!n)
                        return pam_log_oom(handle);

                if (pam_getenv(handle, n)) {
                        pam_debug_syslog(handle, debug,
                                         "PAM environment variable $%s already set, not changing based on record.", *i);
                        continue;
                }

                r = pam_putenv_and_log(handle, *i, debug);
                if (r != PAM_SUCCESS)
                        return r;
        }

        if (ur->email_address) {
                if (pam_getenv(handle, "EMAIL"))
                        pam_debug_syslog(handle, debug,
                                         "PAM environment variable $EMAIL already set, not changing based on user record.");
                else {
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
                if (pam_getenv(handle, "TZ"))
                        pam_debug_syslog(handle, debug,
                                         "PAM environment variable $TZ already set, not changing based on user record.");
                else if (!timezone_is_valid(ur->time_zone, LOG_DEBUG))
                        pam_debug_syslog(handle, debug,
                                         "Time zone specified in user record is not valid locally, not setting $TZ.");
                else {
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
                if (pam_getenv(handle, "LANG"))
                        pam_debug_syslog(handle, debug,
                                         "PAM environment variable $LANG already set, not changing based on user record.");
                else if (locale_is_installed(ur->preferred_language) <= 0)
                        pam_debug_syslog(handle, debug,
                                         "Preferred language specified in user record is not valid or not installed, not setting $LANG.");
                else {
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
                        pam_syslog_errno(handle, LOG_ERR, errno,
                                         "Failed to set nice level to %i, ignoring: %m", ur->nice_level);
                else
                        pam_debug_syslog(handle, debug,
                                         "Nice level set to %i, based on user record.", ur->nice_level);
        }

        for (int rl = 0; rl < _RLIMIT_MAX; rl++) {

                if (!ur->rlimits[rl])
                        continue;

                r = setrlimit_closest(rl, ur->rlimits[rl]);
                if (r < 0)
                        pam_syslog_errno(handle, LOG_ERR, r,
                                         "Failed to set resource limit %s, ignoring: %m", rlimit_to_string(rl));
                else
                        pam_debug_syslog(handle, debug,
                                         "Resource limit %s set, based on user record.", rlimit_to_string(rl));
        }

        uint64_t a, b;
        a = user_record_capability_ambient_set(ur);
        if (a == UINT64_MAX)
                a = default_capability_ambient_set;

        b = user_record_capability_bounding_set(ur);
        if (b == UINT64_MAX)
                b = default_capability_bounding_set;

        if (a != UINT64_MAX && a != 0) {
                a &= b;

                r = capability_ambient_set_apply(a, /* also_inherit= */ true);
                if (r < 0)
                        pam_syslog_errno(handle, LOG_ERR, r,
                                         "Failed to set ambient capabilities, ignoring: %m");
        }

        if (b != UINT64_MAX && !cap_test_all(b)) {
                r = capability_bounding_set_drop(b, /* right_now= */ false);
                if (r < 0)
                        pam_syslog_errno(handle, LOG_ERR, r,
                                         "Failed to set bounding capabilities, ignoring: %m");
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
        if (r != PAM_SUCCESS)
                return pam_syslog_pam_error(handle, LOG_ERR, r, "Failed to set runtime dir: @PAMERR@");

        return export_legacy_dbus_address(handle, rt);
}

static uint64_t pick_default_capability_ambient_set(
                UserRecord *ur,
                const char *service,
                const char *seat) {

        /* If not configured otherwise, let's enable CAP_WAKE_ALARM for regular users when logging in on a
         * seat (i.e. when they are present physically on the device), or when invoked for the systemd --user
         * instances. This allows desktops to install CAP_WAKE_ALARM to implement alarm clock apps without
         * much fuss. */

        return ur &&
                user_record_disposition(ur) == USER_REGULAR &&
                (streq_ptr(service, "systemd-user") || !isempty(seat)) ? (UINT64_C(1) << CAP_WAKE_ALARM) : UINT64_MAX;
}

typedef struct SessionContext {
        const uid_t uid;
        const pid_t pid;
        const char *service;
        const char *type;
        const char *class;
        const char *desktop;
        const char *seat;
        const uint32_t vtnr;
        const char *tty;
        const char *display;
        const bool remote;
        const char *remote_user;
        const char *remote_host;
        const char *memory_max;
        const char *tasks_max;
        const char *cpu_weight;
        const char *io_weight;
        const char *runtime_max_sec;
} SessionContext;

static int create_session_message(sd_bus *bus, pam_handle_t *handle, const SessionContext *context, bool avoid_pidfd, sd_bus_message **ret) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        int r, pidfd = -EBADFD;

        assert(bus);
        assert(handle);
        assert(context);

        if (!avoid_pidfd) {
                pidfd = pidfd_open(getpid_cached(), 0);
                if (pidfd < 0 && !ERRNO_IS_NOT_SUPPORTED(errno))
                        return -errno;
        }

        r = bus_message_new_method_call(bus, &m, bus_login_mgr, pidfd >= 0 ? "CreateSessionWithPIDFD" : "CreateSession");
        if (r < 0)
                return r;

        r = sd_bus_message_append(m,
                                  pidfd >= 0 ? "uhsssssussbss" : "uusssssussbss",
                                  (uint32_t) context->uid,
                                  pidfd >= 0 ? pidfd : context->pid,
                                  context->service,
                                  context->type,
                                  context->class,
                                  context->desktop,
                                  context->seat,
                                  context->vtnr,
                                  context->tty,
                                  context->display,
                                  context->remote,
                                  context->remote_user,
                                  context->remote_host);
        if (r < 0)
                return r;

        if (pidfd >= 0) {
                r = sd_bus_message_append(m, "t", UINT64_C(0));
                if (r < 0)
                        return r;
        }

        r = sd_bus_message_open_container(m, 'a', "(sv)");
        if (r < 0)
                return r;

        r = append_session_memory_max(handle, m, context->memory_max);
        if (r != PAM_SUCCESS)
                return r;

        r = append_session_runtime_max_sec(handle, m, context->runtime_max_sec);
        if (r != PAM_SUCCESS)
                return r;

        r = append_session_tasks_max(handle, m, context->tasks_max);
        if (r != PAM_SUCCESS)
                return r;

        r = append_session_cpu_weight(handle, m, context->cpu_weight);
        if (r != PAM_SUCCESS)
                return r;

        r = append_session_io_weight(handle, m, context->io_weight);
        if (r != PAM_SUCCESS)
                return r;

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(m);
        return 0;
}

_public_ PAM_EXTERN int pam_sm_open_session(
                pam_handle_t *handle,
                int flags,
                int argc, const char **argv) {

        /* Let's release the D-Bus connection once this function exits, after all the session might live
         * quite a long time, and we are not going to process the bus connection in that time, so let's
         * better close before the daemon kicks us off because we are not processing anything. */
        _cleanup_(pam_bus_data_disconnectp) PamBusData *d = NULL;
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
        uint64_t default_capability_bounding_set = UINT64_MAX, default_capability_ambient_set = UINT64_MAX;
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_(user_record_unrefp) UserRecord *ur = NULL;
        int session_fd = -EBADF, existing, r;
        bool debug = false, remote;
        uint32_t vtnr = 0;
        uid_t original_uid;

        assert(handle);

        if (parse_argv(handle,
                       argc, argv,
                       &class_pam,
                       &type_pam,
                       &desktop_pam,
                       &debug,
                       &default_capability_bounding_set,
                       &default_capability_ambient_set) < 0)
                return PAM_SESSION_ERR;

        pam_debug_syslog(handle, debug, "pam-systemd initializing");

        r = acquire_user_record(handle, &ur);
        if (r != PAM_SUCCESS)
                return r;

        /* Make most of this a NOP on non-logind systems */
        if (!logind_running())
                goto success;

        r = pam_get_item_many(
                        handle,
                        PAM_SERVICE, &service,
                        PAM_XDISPLAY, &display,
                        PAM_TTY, &tty,
                        PAM_RUSER, &remote_user,
                        PAM_RHOST, &remote_host);
        if (r != PAM_SUCCESS)
                return pam_syslog_pam_error(handle, LOG_ERR, r, "Failed to get PAM items: @PAMERR@");

        /* Make sure we don't enter a loop by talking to systemd-logind when it is actually waiting for the
         * background to finish start-up. If the service is "systemd-user" we simply set XDG_RUNTIME_DIR and
         * leave. */

        if (streq_ptr(service, "systemd-user")) {
                char rt[STRLEN("/run/user/") + DECIMAL_STR_MAX(uid_t)];

                xsprintf(rt, "/run/user/"UID_FMT, ur->uid);
                r = configure_runtime_directory(handle, ur, rt);
                if (r != PAM_SUCCESS)
                        return r;

                goto success;
        }

        /* Otherwise, we ask logind to create a session for us */

        seat = getenv_harder(handle, "XDG_SEAT", NULL);
        cvtnr = getenv_harder(handle, "XDG_VTNR", NULL);
        type = getenv_harder(handle, "XDG_SESSION_TYPE", type_pam);
        class = getenv_harder(handle, "XDG_SESSION_CLASS", class_pam);
        desktop = getenv_harder(handle, "XDG_SESSION_DESKTOP", desktop_pam);

        if (tty && strchr(tty, ':')) {
                /* A tty with a colon is usually an X11 display, placed there to show up in utmp. We rearrange things
                 * and don't pretend that an X display was a tty. */
                if (isempty(display))
                        display = tty;
                tty = NULL;

        } else if (streq_ptr(tty, "cron")) {
                /* cron is setting PAM_TTY to "cron" for some reason (the commit carries no information why, but
                 * probably because it wants to set it to something as pam_time/pam_access/… require PAM_TTY to be set
                 * (as they otherwise even try to update it!) — but cron doesn't actually allocate a TTY for its forked
                 * off processes.) */
                type = "unspecified";
                class = "background";
                tty = NULL;

        } else if (streq_ptr(tty, "ssh")) {
                /* ssh has been setting PAM_TTY to "ssh" (for the same reason as cron does this, see above. For further
                 * details look for "PAM_TTY_KLUDGE" in the openssh sources). */
                type = "tty";
                class = "user";
                tty = NULL; /* This one is particularly sad, as this means that ssh sessions — even though usually
                             * associated with a pty — won't be tracked by their tty in logind. This is because ssh
                             * does the PAM session registration early for new connections, and registers a pty only
                             * much later (this is because it doesn't know yet if it needs one at all, as whether to
                             * register a pty or not is negotiated much later in the protocol). */

        } else if (tty)
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
                pam_debug_syslog(handle, debug, "Ignoring vtnr %"PRIu32" for %s which is not seat0", vtnr, seat);
                vtnr = 0;
        }

        if (isempty(type))
                type = !isempty(display) ? "x11" :
                           !isempty(tty) ? "tty" : "unspecified";

        if (isempty(class))
                class = streq(type, "unspecified") ? "background" : "user";

        remote = !isempty(remote_host) && !is_localhost(remote_host);

        r = pam_get_data(handle, "systemd.memory_max", (const void **)&memory_max);
        if (!IN_SET(r, PAM_SUCCESS, PAM_NO_MODULE_DATA))
                return pam_syslog_pam_error(handle, LOG_ERR, r, "Failed to get PAM systemd.memory_max data: @PAMERR@");
        r = pam_get_data(handle, "systemd.tasks_max",  (const void **)&tasks_max);
        if (!IN_SET(r, PAM_SUCCESS, PAM_NO_MODULE_DATA))
                return pam_syslog_pam_error(handle, LOG_ERR, r, "Failed to get PAM systemd.tasks_max data: @PAMERR@");
        r = pam_get_data(handle, "systemd.cpu_weight", (const void **)&cpu_weight);
        if (!IN_SET(r, PAM_SUCCESS, PAM_NO_MODULE_DATA))
                return pam_syslog_pam_error(handle, LOG_ERR, r, "Failed to get PAM systemd.cpu_weight data: @PAMERR@");
        r = pam_get_data(handle, "systemd.io_weight",  (const void **)&io_weight);
        if (!IN_SET(r, PAM_SUCCESS, PAM_NO_MODULE_DATA))
                return pam_syslog_pam_error(handle, LOG_ERR, r, "Failed to get PAM systemd.io_weight data: @PAMERR@");
        r = pam_get_data(handle, "systemd.runtime_max_sec", (const void **)&runtime_max_sec);
        if (!IN_SET(r, PAM_SUCCESS, PAM_NO_MODULE_DATA))
                return pam_syslog_pam_error(handle, LOG_ERR, r, "Failed to get PAM systemd.runtime_max_sec data: @PAMERR@");

        /* Talk to logind over the message bus */
        r = pam_acquire_bus_connection(handle, "pam-systemd", &bus, &d);
        if (r != PAM_SUCCESS)
                return r;

        pam_debug_syslog(handle, debug,
                         "Asking logind to create session: "
                         "uid="UID_FMT" pid="PID_FMT" service=%s type=%s class=%s desktop=%s seat=%s vtnr=%"PRIu32" tty=%s display=%s remote=%s remote_user=%s remote_host=%s",
                         ur->uid, getpid_cached(),
                         strempty(service),
                         type, class, strempty(desktop),
                         strempty(seat), vtnr, strempty(tty), strempty(display),
                         yes_no(remote), strempty(remote_user), strempty(remote_host));
        pam_debug_syslog(handle, debug,
                         "Session limits: "
                         "memory_max=%s tasks_max=%s cpu_weight=%s io_weight=%s runtime_max_sec=%s",
                         strna(memory_max), strna(tasks_max), strna(cpu_weight), strna(io_weight), strna(runtime_max_sec));

        const SessionContext context = {
                .uid = ur->uid,
                .pid = 0,
                .service = service,
                .type = type,
                .class = class,
                .desktop = desktop,
                .seat = seat,
                .vtnr = vtnr,
                .tty = tty,
                .display = display,
                .remote = remote,
                .remote_user = remote_user,
                .remote_host = remote_host,
                .memory_max = memory_max,
                .tasks_max = tasks_max,
                .cpu_weight = cpu_weight,
                .io_weight = io_weight,
                .runtime_max_sec = runtime_max_sec,
        };

        r = create_session_message(bus,
                                   handle,
                                   &context,
                                   false /* avoid_pidfd = */,
                                   &m);
        if (r < 0)
                return pam_bus_log_create_error(handle, r);

        r = sd_bus_call(bus, m, LOGIN_SLOW_BUS_CALL_TIMEOUT_USEC, &error, &reply);
        if (r < 0) {
                if (sd_bus_error_has_name(&error, BUS_ERROR_SESSION_BUSY)) {
                        pam_debug_syslog(handle, debug,
                                         "Not creating session: %s", bus_error_message(&error, r));
                        /* We are already in a session, don't do anything */
                        goto success;
                } else if (sd_bus_error_has_name(&error, SD_BUS_ERROR_UNKNOWN_METHOD)) {
                        pam_debug_syslog(handle, debug,
                                         "CreateSessionWithPIDFD() API is not available, retrying with CreateSession().");

                        m = sd_bus_message_unref(m);
                        r = create_session_message(bus,
                                                   handle,
                                                   &context,
                                                   true /* avoid_pidfd = */,
                                                   &m);
                        if (r < 0)
                                return pam_bus_log_create_error(handle, r);

                        sd_bus_error_free(&error);
                        r = sd_bus_call(bus, m, LOGIN_SLOW_BUS_CALL_TIMEOUT_USEC, &error, &reply);
                }
                if (r < 0) {
                        pam_syslog(handle, LOG_ERR,
                                   "Failed to create session: %s", bus_error_message(&error, r));
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

        pam_debug_syslog(handle, debug,
                         "Reply from logind: "
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
        if (r != PAM_SUCCESS)
                return pam_syslog_pam_error(handle, LOG_ERR, r, "Failed to install existing flag: @PAMERR@");

        if (session_fd >= 0) {
                _cleanup_close_ int fd = fcntl(session_fd, F_DUPFD_CLOEXEC, 3);
                if (fd < 0)
                        return pam_syslog_errno(handle, LOG_ERR, errno, "Failed to dup session fd: %m");

                r = pam_set_data(handle, "systemd.session-fd", FD_TO_PTR(fd), NULL);
                if (r != PAM_SUCCESS)
                        return pam_syslog_pam_error(handle, LOG_ERR, r, "Failed to install session fd: @PAMERR@");
                TAKE_FD(fd);
        }

success:
        if (default_capability_ambient_set == UINT64_MAX)
                default_capability_ambient_set = pick_default_capability_ambient_set(ur, service, seat);

        return apply_user_record_settings(handle, ur, debug, default_capability_bounding_set, default_capability_ambient_set);
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
                       &debug,
                       NULL,
                       NULL) < 0)
                return PAM_SESSION_ERR;

        pam_debug_syslog(handle, debug, "pam-systemd shutting down");

        /* Only release session if it wasn't pre-existing when we
         * tried to create it */
        r = pam_get_data(handle, "systemd.existing", &existing);
        if (!IN_SET(r, PAM_SUCCESS, PAM_NO_MODULE_DATA))
                return pam_syslog_pam_error(handle, LOG_ERR, r,
                                            "Failed to get PAM systemd.existing data: @PAMERR@");

        id = pam_getenv(handle, "XDG_SESSION_ID");
        if (id && !existing) {
                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;

                /* Before we go and close the FIFO we need to tell logind that this is a clean session
                 * shutdown, so that it doesn't just go and slaughter us immediately after closing the fd */

                r = pam_acquire_bus_connection(handle, "pam-systemd", &bus, NULL);
                if (r != PAM_SUCCESS)
                        return r;

                r = bus_call_method(bus, bus_login_mgr, "ReleaseSession", &error, NULL, "s", id);
                if (r < 0)
                        return pam_syslog_pam_error(handle, LOG_ERR, PAM_SESSION_ERR,
                                                    "Failed to release session: %s", bus_error_message(&error, r));
        }

        /* Note that we are knowingly leaking the FIFO fd here. This way, logind can watch us die. If we
         * closed it here it would not have any clue when that is completed. Given that one cannot really
         * have multiple PAM sessions open from the same process this means we will leak one FD at max. */

        return PAM_SUCCESS;
}
