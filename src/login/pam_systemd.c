/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <endian.h>
#include <fcntl.h>
#include <pwd.h>
#include <security/_pam_macros.h>
#include <security/pam_ext.h>
#include <security/pam_misc.h>
#include <security/pam_modules.h>
#include <security/pam_modutil.h>
#include <sys/file.h>
#include "time-util.h"
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#include "sd-bus.h"
#include "sd-daemon.h"
#include "sd-varlink.h"

#include "alloc-util.h"
#include "bus-common-errors.h"
#include "bus-error.h"
#include "bus-internal.h"
#include "bus-locator.h"
#include "capability-list.h"
#include "capability-util.h"
#include "cgroup-setup.h"
#include "chase.h"
#include "creds-util.h"
#include "devnum-util.h"
#include "errno-util.h"
#include "extract-word.h"
#include "fd-util.h"
#include "format-util.h"
#include "fs-util.h"
#include "hostname-util.h"
#include "io-util.h"
#include "json-util.h"
#include "locale-util.h"
#include "login-util.h"
#include "osc-context.h"
#include "pam-util.h"
#include "parse-util.h"
#include "path-util.h"
#include "percent-util.h"
#include "pidfd-util.h"
#include "pidref.h"
#include "process-util.h"
#include "rlimit-util.h"
#include "socket-util.h"
#include "stdio-util.h"
#include "string-util.h"
#include "strv.h"
#include "terminal-util.h"
#include "tmpfile-util.h"
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
                const char **area,
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

                } else if ((p = startswith(argv[i], "area="))) {

                        if (!isempty(p) && !filename_is_valid(p))
                                pam_syslog(handle, LOG_WARNING, "Area name specified among PAM module parameters is not valid, ignoring: %s", p);
                        else if (area)
                                *area = p;

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

        int r;

        assert(handle);

        const char *username = NULL;
        r = pam_get_user(handle, &username, NULL);
        if (r != PAM_SUCCESS)
                return pam_syslog_pam_error(handle, LOG_ERR, r, "Failed to get user name: @PAMERR@");
        if (isempty(username))
                return pam_syslog_pam_error(handle, LOG_ERR, PAM_SERVICE_ERR, "User name not valid.");

        /* If pam_systemd_homed (or some other module) already acquired the user record we can reuse it
         * here. */
        _cleanup_free_ char *field = strjoin("systemd-user-record-", username);
        if (!field)
                return pam_log_oom(handle);

        _cleanup_(user_record_unrefp) UserRecord *ur = NULL;
        const char *json = NULL;
        r = pam_get_data(handle, field, (const void**) &json);
        if (!IN_SET(r, PAM_SUCCESS, PAM_NO_MODULE_DATA))
                return pam_syslog_pam_error(handle, LOG_ERR, r, "Failed to get PAM user record data: @PAMERR@");
        if (r == PAM_SUCCESS && json) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;

                /* Parse cached record */
                r = sd_json_parse(json, SD_JSON_PARSE_SENSITIVE, &v, NULL, NULL);
                if (r < 0)
                        return pam_syslog_errno(handle, LOG_ERR, r, "Failed to parse JSON user record: %m");

                ur = user_record_new();
                if (!ur)
                        return pam_log_oom(handle);

                r = user_record_load(ur, v, USER_RECORD_LOAD_REFUSE_SECRET|USER_RECORD_PERMISSIVE);
                if (r < 0)
                        return pam_syslog_errno(handle, LOG_ERR, r, "Failed to load user record: %m");

                /* Safety check if cached record actually matches what we are looking for */
                if (!user_record_matches_user_name(ur, username))
                        return pam_syslog_pam_error(handle, LOG_ERR, PAM_SERVICE_ERR,
                                                    "Acquired user record does not match user name.");
        } else {
                _cleanup_free_ char *formatted = NULL;

                /* Request the record ourselves */
                r = userdb_by_name(username, /* match= */ NULL, /* flags= */ 0, &ur);
                if (r < 0) {
                        pam_syslog_errno(handle, LOG_ERR, r, "Failed to get user record: %m");
                        return PAM_USER_UNKNOWN;
                }

                if (!uid_is_valid(ur->uid))
                        return pam_syslog_pam_error(handle, LOG_ERR, PAM_USER_UNKNOWN,
                                                    "User record of user '%s' has no UID, refusing.", username);

                r = sd_json_variant_format(ur->json, 0, &formatted);
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
        assert(v > 0);

        if (seat)
                *seat = "seat0";
        *vtnr = (uint32_t) v;

        return 0;
}

static int append_session_memory_max(pam_handle_t *handle, sd_bus_message *m, const char *limit) {
        int r;

        assert(handle);
        assert(m);

        if (isempty(limit))
                return 0;

        if (streq(limit, "infinity"))
                return sd_bus_message_append(m, "(sv)", "MemoryMax", "t", UINT64_MAX);

        r = parse_permyriad(limit);
        if (r >= 0)
                return sd_bus_message_append(m, "(sv)", "MemoryMaxScale", "u", UINT32_SCALE_FROM_PERMYRIAD(r));

        uint64_t val;
        r = parse_size(limit, 1024, &val);
        if (r < 0) {
                pam_syslog(handle, LOG_WARNING, "Failed to parse systemd.memory_max, ignoring: %s", limit);
                return 0;
        }

        return sd_bus_message_append(m, "(sv)", "MemoryMax", "t", val);
}

static int append_session_runtime_max_sec(pam_handle_t *handle, sd_bus_message *m, const char *limit) {
        int r;

        assert(handle);
        assert(m);

        /* No need to parse "infinity" here, it will be set by default later in scope_init() */
        if (isempty(limit) || streq(limit, "infinity"))
                return 0;

        usec_t val;
        r = parse_sec(limit, &val);
        if (r < 0) {
                pam_syslog(handle, LOG_WARNING, "Failed to parse systemd.runtime_max_sec: %s, ignoring.", limit);
                return 0;
        }

        return sd_bus_message_append(m, "(sv)", "RuntimeMaxUSec", "t", (uint64_t) val);
}

static int append_session_tasks_max(pam_handle_t *handle, sd_bus_message *m, const char *limit) {
        int r;

        assert(handle);
        assert(m);

        /* No need to parse "infinity" here, it will be set unconditionally later in manager_start_scope() */
        if (isempty(limit) || streq(limit, "infinity"))
                return 0;

        uint64_t val;
        r = safe_atou64(limit, &val);
        if (r < 0) {
                pam_syslog(handle, LOG_WARNING, "Failed to parse systemd.tasks_max, ignoring: %s", limit);
                return 0;
        }

        return sd_bus_message_append(m, "(sv)", "TasksMax", "t", val);
}

static int append_session_cpu_weight(pam_handle_t *handle, sd_bus_message *m, const char *limit) {
        int r;

        assert(handle);
        assert(m);

        if (isempty(limit))
                return 0;

        uint64_t val;
        r = cg_cpu_weight_parse(limit, &val);
        if (r < 0) {
                pam_syslog(handle, LOG_WARNING, "Failed to parse systemd.cpu_weight, ignoring: %s", limit);
                return 0;
        }

        return sd_bus_message_append(m, "(sv)", "CPUWeight", "t", val);
}

static int append_session_io_weight(pam_handle_t *handle, sd_bus_message *m, const char *limit) {
        int r;

        assert(handle);
        assert(m);

        if (isempty(limit))
                return 0;

        uint64_t val;
        r = cg_weight_parse(limit, &val);
        if (r < 0) {
                pam_syslog(handle, LOG_WARNING, "Failed to parse systemd.io_weight, ignoring: %s", limit);
                return 0;
        }

        return sd_bus_message_append(m, "(sv)", "IOWeight", "t", val);
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

static bool getenv_harder_bool(pam_handle_t *handle, const char *key, bool fallback) {
        const char *v;
        int r;

        assert(handle);
        assert(key);

        v = getenv_harder(handle, key, NULL);
        if (isempty(v))
                return fallback;

        r = parse_boolean(v);
        if (r < 0) {
                pam_syslog(handle, LOG_WARNING,
                           "Failed to parse environment variable value '%s' of '%s', falling back to using '%s'.",
                           v, key, true_false(fallback));
                return fallback;
        }

        return r;
}

static uint32_t getenv_harder_uint32(pam_handle_t *handle, const char *key, uint32_t fallback) {
        int r;

        assert(handle);
        assert(key);

        const char *v = getenv_harder(handle, key, NULL);
        if (isempty(v))
                return fallback;

        uint32_t u;
        r = safe_atou32(v, &u);
        if (r < 0) {
                pam_syslog(handle, LOG_WARNING,
                           "Failed to parse environment variable value '%s' of '%s' as unsigned integer, falling back to using %" PRIu32 ".",
                           v, key, fallback);
                return fallback;
        }

        return u;
}

static int update_environment(pam_handle_t *handle, const char *key, const char *value) {
        int r;

        assert(handle);
        assert(key);

        /* Updates the environment, and removes environment variables if value is NULL or empty. Also, log
         * about errors. */

        if (isempty(value)) {
                /* Unset the variable if set. Note that pam_putenv() would log nastily behind our back if we
                 * call it without the variable actually being set. Hence we check explicitly if it's set
                 * before. */

                if (!pam_getenv(handle, key))
                        return PAM_SUCCESS;

                r = pam_putenv(handle, key);
                if (!IN_SET(r, PAM_SUCCESS, PAM_BAD_ITEM))
                        return pam_syslog_pam_error(handle, LOG_WARNING, r,
                                                    "Failed to unset %s environment variable: @PAMERR@", key);

                return PAM_SUCCESS;
        }

        r = pam_misc_setenv(handle, key, value, /* readonly= */ false);
        if (r != PAM_SUCCESS)
                return pam_syslog_pam_error(handle, LOG_ERR, r,
                                            "Failed to set environment variable %s: @PAMERR@", key);

        return PAM_SUCCESS;
}

static int propagate_credential_to_environment(pam_handle_t *handle, bool debug, const char *credential, const char *varname) {
        int r;

        assert(handle);
        assert(credential);
        assert(varname);

        _cleanup_free_ char *value = NULL;

        /* Read a service credential, and propagate it into an environment variable */

        r = read_credential(credential, (void**) &value, /* ret_size= */ NULL);
        if (r < 0) {
                pam_debug_syslog_errno(handle, debug, r, "Failed to read credential '%s', ignoring: %m", credential);
                return PAM_SUCCESS;
        }

        r = pam_misc_setenv(handle, varname, value, 0);
        if (r != PAM_SUCCESS)
                return pam_syslog_pam_error(handle, LOG_ERR, r,
                                            "Failed to set environment variable %s: @PAMERR@", varname);

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
        _cleanup_strv_free_ char **langs = NULL;
        int r;

        assert(handle);
        assert(ur);

        if (ur->umask != MODE_INVALID) {
                umask(ur->umask);
                pam_debug_syslog(handle, debug, "Set user umask to %04o based on user record.", ur->umask);
        }

        STRV_FOREACH(i, ur->environment) {
                r = pam_putenv_and_log(handle, *i, debug);
                if (r != PAM_SUCCESS)
                        return r;
        }

        if (ur->email_address) {
                _cleanup_free_ char *joined = NULL;

                joined = strjoin("EMAIL=", ur->email_address);
                if (!joined)
                        return pam_log_oom(handle);

                r = pam_putenv_and_log(handle, joined, debug);
                if (r != PAM_SUCCESS)
                        return r;
        }

        if (ur->time_zone) {
                if (!timezone_is_valid(ur->time_zone, LOG_DEBUG))
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

        r = user_record_languages(ur, &langs);
        if (r < 0)
                pam_syslog_errno(handle, LOG_ERR, r,
                                 "Failed to acquire user's language preferences, ignoring: %m");
        else if (strv_isempty(langs))
                ; /* User has no preference set so we do nothing */
        else if (locale_is_installed(langs[0]) <= 0)
                pam_debug_syslog(handle, debug,
                                 "Preferred languages specified in user record are not installed locally, not setting $LANG or $LANGUAGE.");
        else {
                _cleanup_free_ char *lang = NULL;

                lang = strjoin("LANG=", langs[0]);
                if (!lang)
                        return pam_log_oom(handle);

                r = pam_putenv_and_log(handle, lang, debug);
                if (r != PAM_SUCCESS)
                        return r;

                if (strv_length(langs) > 1) {
                        _cleanup_free_ char *joined = NULL, *language = NULL;

                        joined = strv_join(langs, ":");
                        if (!joined)
                                return pam_log_oom(handle);

                        language = strjoin("LANGUAGE=", joined);
                        if (!language)
                                return pam_log_oom(handle);

                        r = pam_putenv_and_log(handle, language, debug);
                        if (r != PAM_SUCCESS)
                                return r;
                }
        }

        if (nice_is_valid(ur->nice_level)) {
                if (nice(ur->nice_level) < 0)
                        pam_syslog_errno(handle, LOG_WARNING, errno,
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
        const char *service;
        const char *type;
        const char *class;
        const char *desktop;
        const char *seat;
        uint32_t vtnr;
        const char *tty;
        const char *display;
        bool remote;
        const char *remote_user;
        const char *remote_host;
        const char *memory_max;
        const char *tasks_max;
        const char *cpu_weight;
        const char *io_weight;
        const char *runtime_max_sec;
        const char *area;
        bool incomplete;
} SessionContext;

static int create_session_message(
                sd_bus *bus,
                pam_handle_t *handle,
                UserRecord *ur,
                const SessionContext *context,
                bool avoid_pidfd,
                sd_bus_message **ret) {

        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        _cleanup_close_ int pidfd = -EBADF;
        int r;

        assert(bus);
        assert(handle);
        assert(ur);
        assert(context);
        assert(ret);

        if (!avoid_pidfd) {
                pidfd = pidfd_open(getpid_cached(), 0);
                if (pidfd < 0)
                        return -errno;
        }

        r = bus_message_new_method_call(bus, &m, bus_login_mgr, pidfd >= 0 ? "CreateSessionWithPIDFD" : "CreateSession");
        if (r < 0)
                return r;

        r = sd_bus_message_append(
                        m,
                        pidfd >= 0 ? "uhsssssussbss" : "uusssssussbss",
                        (uint32_t) ur->uid,
                        pidfd >= 0 ? pidfd : 0,
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
        if (r < 0)
                return r;

        r = append_session_runtime_max_sec(handle, m, context->runtime_max_sec);
        if (r < 0)
                return r;

        r = append_session_tasks_max(handle, m, context->tasks_max);
        if (r < 0)
                return r;

        r = append_session_cpu_weight(handle, m, context->cpu_weight);
        if (r < 0)
                return r;

        r = append_session_io_weight(handle, m, context->io_weight);
        if (r < 0)
                return r;

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(m);
        return 0;
}

static void session_context_mangle(
                pam_handle_t *handle,
                SessionContext *c,
                UserRecord *ur,
                bool debug) {

        assert(handle);
        assert(c);
        assert(ur);

        if (streq_ptr(c->service, "systemd-user")) {
                /* If we detect that we are running in the "systemd-user" PAM stack, then let's patch the class to
                 * 'manager' if not set, simply for robustness reasons. */
                c->type = "unspecified";
                c->class = IN_SET(user_record_disposition(ur), USER_INTRINSIC, USER_SYSTEM, USER_DYNAMIC) ?
                        "manager-early" : "manager";
                c->tty = NULL;

        } else if (c->tty && strchr(c->tty, ':')) {
                /* A tty with a colon is usually an X11 display, placed there to show up in utmp. We rearrange things
                 * and don't pretend that an X display was a tty. */
                if (isempty(c->display))
                        c->display = c->tty;
                c->tty = NULL;

        } else if (streq_ptr(c->tty, "cron")) {
                /* cron is setting PAM_TTY to "cron" for some reason (the commit carries no information why, but
                 * probably because it wants to set it to something as pam_time/pam_access/… require PAM_TTY to be set
                 * (as they otherwise even try to update it!) — but cron doesn't actually allocate a TTY for its forked
                 * off processes.) */
                c->type = "unspecified";
                c->class = "background";
                c->tty = NULL;

        } else if (streq_ptr(c->tty, "ssh")) {
                /* ssh has been setting PAM_TTY to "ssh" (for the same reason as cron does this, see above. For further
                 * details look for "PAM_TTY_KLUDGE" in the openssh sources). */
                c->type = "tty";
                c->class = "user";
                c->tty = NULL; /* This one is particularly sad, as this means that ssh sessions — even though
                               * usually associated with a pty — won't be tracked by their tty in
                               * logind. This is because ssh does the PAM session registration early for new
                               * connections, and registers a pty only much later (this is because it doesn't
                               * know yet if it needs one at all, as whether to register a pty or not is
                               * negotiated much later in the protocol). */

        } else if (c->tty)
                /* Chop off leading /dev prefix that some clients specify, but others do not. */
                c->tty = skip_dev_prefix(c->tty);

        if (!isempty(c->display) && !c->vtnr) {
                if (isempty(c->seat))
                        (void) get_seat_from_display(c->display, &c->seat, &c->vtnr);
                else if (streq(c->seat, "seat0"))
                        (void) get_seat_from_display(c->display, /* seat= */ NULL, &c->vtnr);
        }

        if (c->seat && !streq(c->seat, "seat0") && c->vtnr != 0) {
                pam_debug_syslog(handle, debug, "Ignoring vtnr %"PRIu32" for %s which is not seat0.", c->vtnr, c->seat);
                c->vtnr = 0;
        }

        if (isempty(c->type)) {
                c->type = !isempty(c->display) ? "x11" :
                              !isempty(c->tty) ? "tty" : "unspecified";
                pam_debug_syslog(handle, debug, "Automatically chose session type '%s'.", c->type);
        }

        if (!c->area)
                c->area = ur->default_area;

        if (!isempty(c->area) && !filename_is_valid(c->area)) {
                pam_syslog(handle, LOG_WARNING, "Specified area '%s' is not a valid filename, ignoring area request.", c->area);
                c->area = NULL;
        }

        if (isempty(c->class)) {
                c->class = streq(c->type, "unspecified") ? "background" : "user";

                /* For non-regular users tweak the type a bit:
                 *
                 * - Allow root tty logins *before* systemd-user-sessions.service is run, to allow early boot
                 *   logins to debug things.
                 *
                 * - Non-graphical sessions shall be invoked without service manager.
                 *
                 * (Note that this somewhat replicates the class mangling logic on systemd-logind.service's
                 * server side to some degree, in case clients allocate a session and don't specify a
                 * class. This is somewhat redundant, but we need the class set up properly below.)
                 *
                 * For regular users also tweak the type a bit: if an area is specified at login time, switch
                 * to light mode too. (Mostly because at the moment we do no support a per-area service
                 * manager. Once we do, we should change this.).
                 */

                switch (user_record_disposition(ur)) {

                case USER_INTRINSIC:
                case USER_SYSTEM:
                case USER_DYNAMIC:
                        if (streq(c->class, "user"))
                                c->class = user_record_is_root(ur) ? "user-early" :
                                        (STR_IN_SET(c->type, "x11", "wayland", "mir") ? "user" : "user-light");
                        else if (streq(c->class, "background"))
                                c->class = "background-light";
                        break;

                case USER_REGULAR:
                        if (!isempty(c->area)) {
                                if (streq(c->class, "user"))
                                        c->class = "user-light";
                                else if (streq(c->class, "background"))
                                        c->class = "background-light";
                        }

                        break;

                default:
                        ;
                }

                pam_debug_syslog(handle, debug, "Automatically chose session class '%s'.", c->class);
        }

        if (c->incomplete) {
                if (streq(c->class, "user"))
                        c->class = "user-incomplete";
                else
                        pam_syslog(handle, LOG_WARNING, "PAM session of class '%s' is incomplete, which is not supported, ignoring.", c->class);
        }

        c->remote = !isempty(c->remote_host) && !is_localhost(c->remote_host);
}

static bool can_use_varlink(const SessionContext *c) {
        /* Since PID 1 currently doesn't do Varlink right now, we cannot directly set properties for the
         * scope, for now. */
        return !c->memory_max &&
                !c->runtime_max_sec &&
                !c->tasks_max &&
                !c->cpu_weight &&
                !c->io_weight;
}

static int register_session(
                pam_handle_t *handle,
                SessionContext *c,
                UserRecord *ur,
                bool debug,
                char **ret_seat,
                char **ret_type,
                char **ret_runtime_dir) {

        int r;

        assert(handle);
        assert(c);
        assert(ur);
        assert(ret_seat);
        assert(ret_type);
        assert(ret_runtime_dir);

        /* We don't register session class none with logind */
        if (streq(c->class, "none")) {
                pam_debug_syslog(handle, debug, "Skipping logind registration for session class none.");
                *ret_seat = *ret_type = *ret_runtime_dir = NULL;
                return PAM_SUCCESS;
        }

        /* Make most of this a NOP on non-logind systems */
        if (!logind_running()) {
                pam_debug_syslog(handle, debug, "Skipping logind registration as logind is not running.");
                *ret_seat = *ret_type = *ret_runtime_dir = NULL;
                return PAM_SUCCESS;
        }

        pam_debug_syslog(handle, debug,
                         "Asking logind to create session: "
                         "uid="UID_FMT" pid="PID_FMT" service=%s type=%s class=%s desktop=%s seat=%s vtnr=%"PRIu32" tty=%s display=%s remote=%s remote_user=%s remote_host=%s",
                         ur->uid, getpid_cached(),
                         strempty(c->service),
                         c->type, c->class, strempty(c->desktop),
                         strempty(c->seat), c->vtnr, strempty(c->tty), strempty(c->display),
                         yes_no(c->remote), strempty(c->remote_user), strempty(c->remote_host));
        pam_debug_syslog(handle, debug,
                         "Session limits: "
                         "memory_max=%s tasks_max=%s cpu_weight=%s io_weight=%s runtime_max_sec=%s",
                         strna(c->memory_max), strna(c->tasks_max), strna(c->cpu_weight), strna(c->io_weight), strna(c->runtime_max_sec));

        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL; /* the following variables point into this message, hence pin it for longer */
        _cleanup_(sd_varlink_unrefp) sd_varlink *vl = NULL; /* similar */
        const char *id = NULL, *object_path = NULL, *runtime_path = NULL, *real_seat = NULL;
        int existing = false;
        uint32_t original_uid = UID_INVALID, real_vtnr = 0;

        bool done = false;
        if (can_use_varlink(c)) {

                r = sd_varlink_connect_address(&vl, "/run/systemd/io.systemd.Login");
                if (r < 0)
                        pam_debug_syslog_errno(handle, debug, r, "Failed to connect to logind via Varlink, falling back to D-Bus: %m");
                else {
                        r = sd_varlink_set_allow_fd_passing_output(vl, true);
                        if (r < 0)
                                return pam_syslog_errno(handle, LOG_ERR, r, "Failed to enable output fd passing on Varlink socket: %m");

                        r = sd_varlink_set_relative_timeout(vl, LOGIN_SLOW_BUS_CALL_TIMEOUT_USEC);
                        if (r < 0)
                                return pam_syslog_errno(handle, LOG_ERR, r, "Failed to set relative timeout on Varlink socket: %m");

                        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
                        r = pidref_set_self(&pidref);
                        if (r < 0)
                                return pam_syslog_errno(handle, LOG_ERR, r, "Failed to acquire PID reference on ourselves: %m");

                        sd_json_variant *vreply = NULL;
                        const char *error_id = NULL;
                        r = sd_varlink_callbo(
                                        vl,
                                        "io.systemd.Login.CreateSession",
                                        &vreply,
                                        &error_id,
                                        SD_JSON_BUILD_PAIR_UNSIGNED("UID", ur->uid),
                                        JSON_BUILD_PAIR_PIDREF("PID", &pidref),
                                        JSON_BUILD_PAIR_STRING_NON_EMPTY("Service", c->service),
                                        SD_JSON_BUILD_PAIR("Type", JSON_BUILD_STRING_UNDERSCORIFY(c->type)),
                                        SD_JSON_BUILD_PAIR("Class", JSON_BUILD_STRING_UNDERSCORIFY(c->class)),
                                        JSON_BUILD_PAIR_STRING_NON_EMPTY("Desktop", c->desktop),
                                        JSON_BUILD_PAIR_STRING_NON_EMPTY("Seat", c->seat),
                                        SD_JSON_BUILD_PAIR_CONDITION(c->vtnr > 0, "VTNr", SD_JSON_BUILD_UNSIGNED(c->vtnr)),
                                        JSON_BUILD_PAIR_STRING_NON_EMPTY("TTY", c->tty),
                                        JSON_BUILD_PAIR_STRING_NON_EMPTY("Display", c->display),
                                        SD_JSON_BUILD_PAIR_BOOLEAN("Remote", c->remote),
                                        JSON_BUILD_PAIR_STRING_NON_EMPTY("RemoteUser", c->remote_user),
                                        JSON_BUILD_PAIR_STRING_NON_EMPTY("RemoteHost", c->remote_host));
                        if (r < 0)
                                return pam_syslog_errno(handle, LOG_ERR, r,
                                                        "Failed to register session: %s", error_id);
                        if (streq_ptr(error_id, "io.systemd.Login.AlreadySessionMember")) {
                                /* We are already in a session, don't do anything */
                                pam_debug_syslog(handle, debug, "Not creating session: %s", error_id);
                                *ret_seat = *ret_type= *ret_runtime_dir = NULL;
                                return PAM_SUCCESS;
                        }
                        if (error_id)
                                return pam_syslog_errno(handle, LOG_ERR, sd_varlink_error_to_errno(error_id, vreply),
                                                        "Failed to issue CreateSession() varlink call: %s", error_id);

                        struct {
                                const char *id;
                                const char *runtime_path;
                                uid_t uid;
                                const char *seat;
                                unsigned vtnr;
                                bool existing;
                        } p = {
                                .uid = UID_INVALID,
                        };

                        static const sd_json_dispatch_field dispatch_table[] = {
                                { "Id",                    SD_JSON_VARIANT_STRING,        sd_json_dispatch_const_string, voffsetof(p, id),             SD_JSON_MANDATORY },
                                { "RuntimePath",           SD_JSON_VARIANT_STRING,        json_dispatch_const_path,      voffsetof(p, runtime_path),   SD_JSON_MANDATORY },
                                { "UID",                   _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uid_gid,      voffsetof(p, uid),            SD_JSON_MANDATORY },
                                { "Seat",                  SD_JSON_VARIANT_STRING,        sd_json_dispatch_const_string, voffsetof(p, seat),           0                 },
                                { "VTNr",                  _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint,         voffsetof(p, vtnr),           0                 },
                                {}
                        };

                        r = sd_json_dispatch(vreply, dispatch_table, SD_JSON_ALLOW_EXTENSIONS, &p);
                        if (r < 0)
                                return pam_syslog_errno(handle, LOG_ERR, r, "Failed to parse CreateSession() reply: %m");

                        id = p.id;
                        runtime_path = p.runtime_path;
                        original_uid = p.uid;
                        real_seat = p.seat;
                        real_vtnr = p.vtnr;
                        existing = false; /* Even on D-Bus logind only returns false these days */

                        done = true;
                }
        }

        if (!done) {
                /* Let's release the D-Bus connection once we are done here, after all the session might live
                 * quite a long time, and we are not going to process the bus connection in that time, so
                 * let's better close before the daemon kicks us off because we are not processing
                 * anything. */
                _cleanup_(pam_bus_data_disconnectp) PamBusData *d = NULL;
                _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;

                /* Talk to logind over the message bus */
                r = pam_acquire_bus_connection(handle, "pam-systemd", debug, &bus, &d);
                if (r != PAM_SUCCESS)
                        return r;

                _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
                r = create_session_message(
                                bus,
                                handle,
                                ur,
                                c,
                                /* avoid_pidfd = */ false,
                                &m);
                if (r < 0)
                        return pam_bus_log_create_error(handle, r);

                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                r = sd_bus_call(bus, m, LOGIN_SLOW_BUS_CALL_TIMEOUT_USEC, &error, &reply);
                if (r < 0 && sd_bus_error_has_name(&error, SD_BUS_ERROR_UNKNOWN_METHOD)) {
                        sd_bus_error_free(&error);
                        pam_debug_syslog(handle, debug,
                                         "CreateSessionWithPIDFD() API is not available, retrying with CreateSession().");

                        m = sd_bus_message_unref(m);
                        r = create_session_message(bus,
                                                   handle,
                                                   ur,
                                                   c,
                                                   /* avoid_pidfd = */ true,
                                                   &m);
                        if (r < 0)
                                return pam_bus_log_create_error(handle, r);

                        r = sd_bus_call(bus, m, LOGIN_SLOW_BUS_CALL_TIMEOUT_USEC, &error, &reply);
                }
                if (r < 0) {
                        if (sd_bus_error_has_name(&error, BUS_ERROR_SESSION_BUSY)) {
                                /* We are already in a session, don't do anything */
                                pam_debug_syslog(handle, debug,
                                                 "Not creating session: %s", bus_error_message(&error, r));
                                *ret_seat = *ret_type = *ret_runtime_dir = NULL;
                                return PAM_SUCCESS;
                        }

                        pam_syslog(handle, LOG_ERR,
                                   "Failed to create session: %s", bus_error_message(&error, r));
                        return PAM_SESSION_ERR;
                }

                int session_fd;
                r = sd_bus_message_read(
                                reply,
                                "soshusub",
                                &id,
                                &object_path,
                                &runtime_path,
                                &session_fd,
                                &original_uid,
                                &real_seat,
                                &real_vtnr,
                                &existing);
                if (r < 0)
                        return pam_bus_log_parse_error(handle, r);

                /* Since v258, logind fully relies on pidfd to monitor the lifetime of the session leader
                 * process and returns a dummy session_fd (no longer a fifo). However because logind cannot
                 * be restarted (known long-standing issue), we must still be prepared to receive a fifo fd
                 * from a running logind older than v258. */
                if (sd_is_fifo(session_fd, NULL) > 0) {
                        _cleanup_close_ int fd = fcntl(session_fd, F_DUPFD_CLOEXEC, 3);
                        if (fd < 0)
                                return pam_syslog_errno(handle, LOG_ERR, errno, "Failed to dup session fd: %m");

                        r = pam_set_data(handle, "systemd.session-fd", FD_TO_PTR(fd), NULL);
                        if (r != PAM_SUCCESS)
                                return pam_syslog_pam_error(handle, LOG_ERR, r, "Failed to install session fd: @PAMERR@");
                        TAKE_FD(fd);
                }
        }

        pam_debug_syslog(handle, debug,
                         "Reply from logind: "
                         "id=%s object_path=%s runtime_path=%s seat=%s vtnr=%u original_uid=%u",
                         id, strna(object_path), runtime_path, real_seat, real_vtnr, original_uid);

        /* Please update manager_default_environment() in core/manager.c accordingly if more session envvars
         * shall be added. */

        r = update_environment(handle, "XDG_SESSION_ID", id);
        if (r != PAM_SUCCESS)
                return r;

        /* Most likely we got the session/type/class from environment variables, but might have gotten the data
         * somewhere else (for example PAM module parameters). Let's now update the environment variables, so that this
         * data is inherited into the session processes, and programs can rely on them to be initialized. */

        _cleanup_free_ char *real_type = strdup(c->type); /* make copy because this might point to env block, which we are going to update shortly */
        if (!real_type)
                return pam_log_oom(handle);

        r = update_environment(handle, "XDG_SESSION_TYPE", c->type);
        if (r != PAM_SUCCESS)
                return r;

        r = update_environment(handle, "XDG_SESSION_CLASS", c->class);
        if (r != PAM_SUCCESS)
                return r;

        r = update_environment(handle, "XDG_SESSION_DESKTOP", c->desktop);
        if (r != PAM_SUCCESS)
                return r;

        r = update_environment(handle, "XDG_SEAT", real_seat);
        if (r != PAM_SUCCESS)
                return r;

        if (real_vtnr > 0) {
                char buf[DECIMAL_STR_MAX(real_vtnr)];
                xsprintf(buf, "%u", real_vtnr);

                r = update_environment(handle, "XDG_VTNR", buf);
                if (r != PAM_SUCCESS)
                        return r;
        }

        r = pam_set_data(handle, "systemd.existing", INT_TO_PTR(!!existing), NULL);
        if (r != PAM_SUCCESS)
                return pam_syslog_pam_error(handle, LOG_ERR, r, "Failed to install existing flag: @PAMERR@");

        /* Don't set $XDG_RUNTIME_DIR if the user we now authenticated for does not match the
         * original user of the session. We do this in order not to result in privileged apps
         * clobbering the runtime directory unnecessarily. */
        _cleanup_free_ char *rt = NULL;
        if (original_uid == ur->uid && validate_runtime_directory(handle, runtime_path, ur->uid))
                if (strdup_to(&rt, runtime_path) < 0)
                        return pam_log_oom(handle);

        /* Everything worked, hence let's patch in the data we learned. Since 'real_set' points into the
         * D-Bus message, let's copy it and return it as a buffer */
        _cleanup_free_ char *rs = NULL;
        if (strdup_to(&rs, real_seat) < 0)
                return pam_log_oom(handle);

        c->vtnr = real_vtnr;
        c->seat = *ret_seat = TAKE_PTR(rs);
        c->type = *ret_type = TAKE_PTR(real_type);
        *ret_runtime_dir = TAKE_PTR(rt);

        return PAM_SUCCESS;
}

static int import_shell_credentials(pam_handle_t *handle, bool debug) {

        static const char *const propagate[] = {
                "shell.prompt.prefix", "SHELL_PROMPT_PREFIX",
                "shell.prompt.suffix", "SHELL_PROMPT_SUFFIX",
                "shell.welcome",       "SHELL_WELCOME",
                NULL
        };
        int r;

        assert(handle);

        STRV_FOREACH_PAIR(k, v, propagate) {
                r = propagate_credential_to_environment(handle, debug, *k, *v);
                if (r != PAM_SUCCESS)
                        return r;
        }

        return PAM_SUCCESS;
}

static int mkdir_chown_open_directory(
                int parent_fd,
                const char *name,
                uid_t uid,
                gid_t gid,
                mode_t mode) {

        _cleanup_free_ char *t = NULL;
        int r;

        assert(parent_fd >= 0);
        assert(name);
        assert(uid_is_valid(uid));
        assert(gid_is_valid(gid));
        assert(mode != MODE_INVALID);

        for (unsigned attempt = 0;; attempt++) {
                _cleanup_close_ int fd = openat(parent_fd, name, O_CLOEXEC|O_DIRECTORY|O_NOFOLLOW);
                if (fd >= 0)
                        return TAKE_FD(fd);
                if (errno != ENOENT)
                        return -errno;

                /* Let's create the directory under a temporary name first, since we want to make sure that
                 * once it appears under the right name it has the right ownership */
                r = tempfn_random(name, /* extra= */ NULL, &t);
                if (r < 0)
                        return r;

                fd = open_mkdir_at(parent_fd, t, O_CLOEXEC|O_EXCL, 0700); /* Use restrictive mode until ownership is in order */
                if (fd < 0)
                        return fd;

                r = RET_NERRNO(fchown(fd, uid, gid));
                if (r < 0)
                        goto fail;

                r = RET_NERRNO(fchmod(fd, mode));
                if (r < 0)
                        goto fail;

                r = rename_noreplace(parent_fd, t, parent_fd, name);
                if (r >= 0)
                        return TAKE_FD(fd);
                if (r != -EEXIST || attempt >= 5)
                        goto fail;

                /* Maybe some other login attempt created the directory at the same time? Let's retry */
                (void) unlinkat(parent_fd, t, AT_REMOVEDIR);
                t = mfree(t);
        }

fail:
        (void) unlinkat(parent_fd, ASSERT_PTR(t), AT_REMOVEDIR);
        return r;
}

static int make_area_runtime_directory(
                pam_handle_t *handle,
                UserRecord *ur,
                const char *runtime_directory,
                const char *area,
                char **ret) {

        assert(handle);
        assert(ur);
        assert(runtime_directory);
        assert(area);
        assert(ret);

        /* Let's be careful with creating these directories, the runtime directory is owned by the user after all,
         * and they might play symlink games with us. */

        _cleanup_close_ int fd = open(runtime_directory, O_CLOEXEC|O_PATH|O_DIRECTORY);
        if (fd < 0)
                return pam_syslog_errno(handle, LOG_ERR, errno, "Unable to open runtime directory '%s': %m", runtime_directory);

        _cleanup_close_ int fd_areas = mkdir_chown_open_directory(fd, "Areas", ur->uid, user_record_gid(ur), 0755);
        if (fd_areas < 0)
                return pam_syslog_errno(handle, LOG_ERR, fd_areas, "Unable to create 'Areas' directory below '%s': %m", runtime_directory);

        _cleanup_close_ int fd_area = mkdir_chown_open_directory(fd_areas, area, ur->uid, user_record_gid(ur), 0755);
        if (fd_area < 0)
                return pam_syslog_errno(handle, LOG_ERR, fd_area, "Unable to create '%s' directory below '%s/Areas': %m", area, runtime_directory);

        char *j = path_join(runtime_directory, "Areas", area);
        if (!j)
                return pam_log_oom(handle);

        *ret = j;
        return 0;
}

static int export_legacy_dbus_address(
                pam_handle_t *handle,
                const char *runtime) {

        assert(handle);
        assert(runtime);

        /* We need to export $DBUS_SESSION_BUS_ADDRESS because various applications will not connect
         * correctly to the bus without it. This setting matches what dbus.socket does for the user session
         * using 'systemctl --user set-environment'. We want to have the same configuration in processes
         * started from the PAM session.
         *
         * The setting of the address is guarded by the access() check because it is also possible to compile
         * dbus without --enable-user-session, in which case this socket is not used, and
         * $DBUS_SESSION_BUS_ADDRESS should not be set. An alternative approach would to not do the access()
         * check here, and let applications try on their own, by using "unix:path=%s/bus;autolaunch:". But we
         * expect the socket to be present by the time we do this check, so we can just as well check once
         * here. */

        const char *s = strjoina(runtime, "/bus");
        if (access(s, F_OK) < 0) {
                if (errno != ENOENT)
                        pam_syslog_errno(handle, LOG_WARNING, errno, "Failed to check if %s/bus exists, ignoring: %m", runtime);

                return PAM_SUCCESS;
        }

        _cleanup_free_ char *t = NULL;
        if (asprintf(&t, DEFAULT_USER_BUS_ADDRESS_FMT, runtime) < 0)
                return pam_log_oom(handle);

        return update_environment(handle, "DBUS_SESSION_BUS_ADDRESS", t);
}

static int setup_runtime_directory(
                pam_handle_t *handle,
                UserRecord *ur,
                const char *runtime_directory,
                const char *area) {

        int r;

        assert(handle);
        assert(ur);

        if (!runtime_directory) {
                /* If this is an area switch request, always reset $XDG_RUNTIME_DIR if we got nothing
                 * to ensure the main runtime dir won't be clobbered. */
                if (area)
                        return update_environment(handle, "XDG_RUNTIME_DIR", NULL);

                return PAM_SUCCESS;
        }

        /* Also create a per-area subdirectory for $XDG_RUNTIME_DIR, so that each area has their own
         * set of runtime services. We follow the same directory structure as for $HOME. Note that we
         * do not define any form of automatic clean-up for the per-area subdirs beyond the regular
         * clean-up of the whole $XDG_RUNTIME_DIR hierarchy when the user finally logs out. */
        _cleanup_free_ char *per_area_runtime_directory = NULL;
        if (area) {
                r = make_area_runtime_directory(handle, ur, runtime_directory, area, &per_area_runtime_directory);
                if (r != PAM_SUCCESS)
                        return r;

                runtime_directory = per_area_runtime_directory;
        }

        r = update_environment(handle, "XDG_RUNTIME_DIR", runtime_directory);
        if (r != PAM_SUCCESS)
                return r;

        return export_legacy_dbus_address(handle, runtime_directory);
}

static int setup_environment(
                pam_handle_t *handle,
                UserRecord *ur,
                const char *runtime_directory,
                const char *area,
                bool debug) {

        int r;

        assert(handle);
        assert(ur);

        const char *h = ASSERT_PTR(user_record_home_directory(ur));

        /* If an empty area string is specified, this means an explicit: do not use the area logic, normalize this here */
        area = empty_to_null(area);

        _cleanup_free_ char *ha = NULL, *area_copy = NULL;
        if (area) {
                _cleanup_free_ char *j = path_join(h, "Areas", area);
                if (!j)
                        return pam_log_oom(handle);

                _cleanup_close_ int fd = -EBADF;
                r = chase(j, /* root= */ NULL, CHASE_MUST_BE_DIRECTORY, &ha, &fd);
                if (r < 0) {
                        /* Log the precise error */
                        pam_syslog_errno(handle, LOG_WARNING, r, "Path '%s' of requested user area '%s' is not accessible, reverting to regular home directory: %m", j, area);

                        /* Also tell the user directly at login, but a bit more vague */
                        pam_info(handle, "Path '%s' of requested user area '%s' is not accessible, reverting to regular home directory.", j, area);
                        area = NULL;
                } else {
                        /* Validate that the target is definitely owned by user */
                        struct stat st;
                        if (fstat(fd, &st) < 0)
                                return pam_syslog_errno(handle, LOG_ERR, errno, "Unable to fstat() target area directory '%s': %m", ha);

                        if (st.st_uid != ur->uid) {
                                pam_syslog(handle, LOG_ERR, "Path '%s' of requested user area '%s' is not owned by user, reverting to regular home directory.", ha, area);

                                /* Also tell the user directly at login. */
                                pam_info(handle, "Path '%s' of requested user area '%s' is not owned by user, reverting to regular home directory.", ha, area);
                                area = NULL;
                        } else {
                                /* All good, now make a copy of the area string, since we quite likely are
                                 * going to invalidate it (if it points into the environment block), via the
                                 * update_environment() call below */
                                area_copy = strdup(area);
                                if (!area_copy)
                                        return pam_log_oom(handle);

                                pam_debug_syslog(handle, debug, "Area '%s' selected, setting $HOME to '%s'.", area, ha);
                                h = ha;
                                area = area_copy;
                        }
                }
        }

        r = update_environment(handle, "XDG_AREA", area);
        if (r != PAM_SUCCESS)
                return r;

        r = update_environment(handle, "HOME", h);
        if (r != PAM_SUCCESS)
                return r;

        return setup_runtime_directory(handle, ur, runtime_directory, area);
}

static int open_osc_context(pam_handle_t *handle, const char *session_type, UserRecord *ur, bool debug) {
        int r;

        assert(handle);
        assert(ur);

        /* If this is a TTY session, then output the session start OSC sequence */

        if (!streq_ptr(session_type, "tty"))
                return PAM_SUCCESS;

        const char *e = pam_getenv(handle, "TERM");
        if (!e)
                e = getenv("TERM");
        if (streq_ptr(e, "dumb"))
                return PAM_SUCCESS;

        /* NB: we output directly to stdout, instead of going via pam_info() or so, because that's too
         * high-level for us, as it suffixes the output with a newline, expecting a full blown text message
         * as prompt string, not just an ANSI sequence. Note that PAM's conv_misc() actually goes to stdout
         * anyway, hence let's do so here too, but only after careful validation. */
        if (!isatty_safe(STDOUT_FILENO))
                return PAM_SUCCESS;

        /* Keep a reference to the TTY we are operating on, so that we can issue the OSC close sequence also
         * if the TTY is already closed. We use an O_PATH reference here, rather than a properly opened fd,
         * so that we don't delay tty hang-up. */
        _cleanup_close_ int tty_opath_fd = fd_reopen(STDOUT_FILENO, O_PATH|O_CLOEXEC);
        if (tty_opath_fd < 0)
                pam_debug_syslog_errno(handle, debug, tty_opath_fd, "Failed to pin TTY, ignoring: %m");
        else
                tty_opath_fd = fd_move_above_stdio(tty_opath_fd);

        _cleanup_free_ char *osc = NULL;
        sd_id128_t osc_id;
        r = osc_context_open_session(
                        ur->user_name,
                        pam_getenv(handle, "XDG_SESSION_ID"),
                        &osc,
                        &osc_id);
        if (r < 0)
                return pam_syslog_errno(handle, LOG_ERR, r, "Failed to prepare OSC sequence: %m");

        r = loop_write(STDOUT_FILENO, osc, SIZE_MAX);
        if (r < 0)
                return pam_syslog_errno(handle, LOG_ERR, r, "Failed to write OSC sequence to TTY: %m");

        /* Remember the OSC context id, so that we can close it cleanly later */
        _cleanup_free_ sd_id128_t *osc_id_copy = newdup(sd_id128_t, &osc_id, 1);
        if (!osc_id_copy)
                return pam_log_oom(handle);

        r = pam_set_data(handle, "systemd.osc-context-id", osc_id_copy, pam_cleanup_free);
        if (r != PAM_SUCCESS)
                return pam_syslog_pam_error(handle, LOG_ERR, r,
                                            "Failed to set PAM OSC sequence ID data: @PAMERR@");

        TAKE_PTR(osc_id_copy);

        if (tty_opath_fd >= 0) {
                r = pam_set_data(handle, "systemd.osc-context-fd", FD_TO_PTR(tty_opath_fd), pam_cleanup_close);
                if (r != PAM_SUCCESS)
                        return pam_syslog_pam_error(handle, LOG_ERR, r,
                                                    "Failed to set PAM OSC sequence fd data: @PAMERR@");

                TAKE_FD(tty_opath_fd);
        }

        return PAM_SUCCESS;
}

static int close_osc_context(pam_handle_t *handle, bool debug) {
        int r;

        assert(handle);

        const void *p;
        int tty_opath_fd = -EBADF;
        r = pam_get_data(handle, "systemd.osc-context-fd", &p);
        if (r == PAM_SUCCESS)
                tty_opath_fd = PTR_TO_FD(p);
        else if (r != PAM_NO_MODULE_DATA)
                return pam_syslog_pam_error(handle, LOG_ERR, r, "Failed to get PAM OSC context fd: @PAMERR@");
        if (tty_opath_fd < 0)
                return PAM_SUCCESS;

        const sd_id128_t *osc_id = NULL;
        r = pam_get_data(handle, "systemd.osc-context-id", (const void**) &osc_id);
        if (!IN_SET(r, PAM_SUCCESS, PAM_NO_MODULE_DATA))
                return pam_syslog_pam_error(handle, LOG_ERR, r, "Failed to get PAM OSC context id data: @PAMERR@");
        if (!osc_id)
                return PAM_SUCCESS;

        /* Now open the original TTY again, so that we can write on it */
        _cleanup_close_ int fd = fd_reopen(tty_opath_fd, O_WRONLY|O_CLOEXEC|O_NONBLOCK|O_NOCTTY);
        if (fd < 0) {
                pam_debug_syslog_errno(handle, debug, fd, "Failed to reopen TTY, ignoring: %m");
                return PAM_SUCCESS;
        }

        /* /bin/login calls us with fds 0, 1, 2 closed, which is just weird. Let's step outside of that
         * range, just in case pam_syslog() or so logs to stderr */
        fd = fd_move_above_stdio(fd);

        /* Safety check, let's verify this is a valid TTY we just opened */
        if (!isatty_safe(fd))
                return PAM_SUCCESS;

        _cleanup_free_ char *osc = NULL;
        r = osc_context_close(*osc_id, &osc);
        if (r < 0)
                return pam_syslog_errno(handle, LOG_ERR, r, "Failed to prepare OSC sequence: %m");

        /* When we are closing things, the TTY might not take our writes anymore. Accept that gracefully. */
        r = loop_write(fd, osc, SIZE_MAX);
        if (r < 0)
                pam_debug_syslog_errno(handle, debug, r, "Failed to write OSC sequence to TTY, ignoring: %m");

        return PAM_SUCCESS;
}

_public_ PAM_EXTERN int pam_sm_open_session(
                pam_handle_t *handle,
                int flags,
                int argc, const char **argv) {

        int r;

        assert(handle);

        pam_log_setup();

        uint64_t default_capability_bounding_set = UINT64_MAX, default_capability_ambient_set = UINT64_MAX;
        const char *class_pam = NULL, *type_pam = NULL, *desktop_pam = NULL, *area_pam = NULL;
        bool debug = false;
        if (parse_argv(handle,
                       argc, argv,
                       &class_pam,
                       &type_pam,
                       &desktop_pam,
                       &area_pam,
                       &debug,
                       &default_capability_bounding_set,
                       &default_capability_ambient_set) < 0)
                return PAM_SESSION_ERR;

        pam_debug_syslog(handle, debug, "pam-systemd: initializing...");

        _cleanup_(user_record_unrefp) UserRecord *ur = NULL;
        r = acquire_user_record(handle, &ur);
        if (r != PAM_SUCCESS)
                return r;

        SessionContext c = {};
        r = pam_get_item_many(
                        handle,
                        PAM_SERVICE,  &c.service,
                        PAM_XDISPLAY, &c.display,
                        PAM_TTY,      &c.tty,
                        PAM_RUSER,    &c.remote_user,
                        PAM_RHOST,    &c.remote_host);
        if (r != PAM_SUCCESS)
                return pam_syslog_pam_error(handle, LOG_ERR, r, "Failed to get PAM items: @PAMERR@");

        c.seat = getenv_harder(handle, "XDG_SEAT", NULL);
        c.vtnr = getenv_harder_uint32(handle, "XDG_VTNR", 0);
        c.type = getenv_harder(handle, "XDG_SESSION_TYPE", type_pam);
        c.class = getenv_harder(handle, "XDG_SESSION_CLASS", class_pam);
        c.desktop = getenv_harder(handle, "XDG_SESSION_DESKTOP", desktop_pam);
        c.area = getenv_harder(handle, "XDG_AREA", area_pam);
        c.incomplete = getenv_harder_bool(handle, "XDG_SESSION_INCOMPLETE", false);

        r = pam_get_data_many(
                        handle,
                        "systemd.memory_max",      &c.memory_max,
                        "systemd.tasks_max",       &c.tasks_max,
                        "systemd.cpu_weight",      &c.cpu_weight,
                        "systemd.io_weight",       &c.io_weight,
                        "systemd.runtime_max_sec", &c.runtime_max_sec);
        if (r != PAM_SUCCESS)
                return pam_syslog_pam_error(handle, LOG_ERR, r, "Failed to get PAM data: @PAMERR@");

        session_context_mangle(handle, &c, ur, debug);

        _cleanup_free_ char *seat_buffer = NULL, *type_buffer = NULL, *runtime_dir = NULL;
        r = register_session(handle, &c, ur, debug, &seat_buffer, &type_buffer, &runtime_dir);
        if (r != PAM_SUCCESS)
                return r;

        r = import_shell_credentials(handle, debug);
        if (r != PAM_SUCCESS)
                return r;

        r = setup_environment(handle, ur, runtime_dir, c.area, debug);
        if (r != PAM_SUCCESS)
                return r;

        if (default_capability_ambient_set == UINT64_MAX)
                default_capability_ambient_set = pick_default_capability_ambient_set(ur, c.service, c.seat);

        r = apply_user_record_settings(handle, ur, debug, default_capability_bounding_set, default_capability_ambient_set);
        if (r != PAM_SUCCESS)
                return r;

        return open_osc_context(handle, c.type, ur, debug);
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

        pam_log_setup();

        if (parse_argv(handle,
                       argc, argv,
                       /* class= */ NULL,
                       /* type= */ NULL,
                       /* desktop= */ NULL,
                       /* area= */ NULL,
                       &debug,
                       /* default_capability_bounding_set= */ NULL,
                       /* default_capability_ambient_set= */ NULL) < 0)
                return PAM_SESSION_ERR;

        pam_debug_syslog(handle, debug, "pam-systemd: shutting down...");

        /* Only release session if it wasn't pre-existing when we
         * tried to create it */
        r = pam_get_data(handle, "systemd.existing", &existing);
        if (!IN_SET(r, PAM_SUCCESS, PAM_NO_MODULE_DATA))
                return pam_syslog_pam_error(handle, LOG_ERR, r,
                                            "Failed to get PAM systemd.existing data: @PAMERR@");

        (void) close_osc_context(handle, debug);

        id = pam_getenv(handle, "XDG_SESSION_ID");
        if (id && !existing) {
                _cleanup_(sd_varlink_unrefp) sd_varlink *vl = NULL;
                bool done = false;

                r = sd_varlink_connect_address(&vl, "/run/systemd/io.systemd.Login");
                if (r < 0)
                        pam_debug_syslog_errno(handle, debug, r, "Failed to connect to logind via Varlink, falling back to D-Bus: %m");
                else {
                        _cleanup_(sd_json_variant_unrefp) sd_json_variant *vreply = NULL;
                        const char *error_id = NULL;
                        r = sd_varlink_callbo(
                                        vl,
                                        "io.systemd.Login.ReleaseSession",
                                        /* ret_reply= */ NULL,
                                        &error_id,
                                        SD_JSON_BUILD_PAIR_STRING("Id", id));
                        if (r < 0)
                                return pam_syslog_errno(handle, LOG_ERR, r, "Failed to register session: %s", error_id);
                        if (error_id)
                                return pam_syslog_errno(handle, LOG_ERR, sd_varlink_error_to_errno(error_id, vreply),
                                                        "Failed to issue ReleaseSession() varlink call: %s", error_id);

                        done = true;
                }

                if (!done) {
                        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                        _cleanup_(pam_bus_data_disconnectp) PamBusData *d = NULL;
                        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;

                        /* Before we go and close the FIFO we need to tell logind that this is a clean session
                         * shutdown, so that it doesn't just go and slaughter us immediately after closing the fd */

                        r = pam_acquire_bus_connection(handle, "pam-systemd", debug, &bus, &d);
                        if (r != PAM_SUCCESS)
                                return r;

                        r = bus_call_method(bus, bus_login_mgr, "ReleaseSession", &error, NULL, "s", id);
                        if (r < 0)
                                return pam_syslog_pam_error(handle, LOG_ERR, PAM_SESSION_ERR,
                                                            "Failed to release session: %s", bus_error_message(&error, r));
                }
        }

        return PAM_SUCCESS;
}
