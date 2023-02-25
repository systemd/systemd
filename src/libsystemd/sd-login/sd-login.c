/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <poll.h>
#include <sys/inotify.h>
#include <unistd.h>

#include "sd-login.h"

#include "alloc-util.h"
#include "cgroup-util.h"
#include "dirent-util.h"
#include "env-file.h"
#include "escape.h"
#include "extract-word.h"
#include "fd-util.h"
#include "format-util.h"
#include "fs-util.h"
#include "hostname-util.h"
#include "io-util.h"
#include "login-util.h"
#include "macro.h"
#include "parse-util.h"
#include "path-util.h"
#include "process-util.h"
#include "socket-util.h"
#include "stdio-util.h"
#include "string-util.h"
#include "strv.h"
#include "user-util.h"

/* Error codes:
 *
 *    invalid input parameters                → -EINVAL
 *    invalid fd                              → -EBADF
 *    process does not exist                  → -ESRCH
 *    cgroup does not exist                   → -ENOENT
 *    machine, session does not exist         → -ENXIO
 *    requested metadata on object is missing → -ENODATA
 */

#define DEFINE_PID_GETTER_FULL(name, type) \
        _public_ int sd_pid_get_##name(pid_t pid, type *ret) {   \
                int r;                                          \
                                                                \
                assert_return(pid >= 0, -EINVAL);               \
                assert_return(ret, -EINVAL);                    \
                                                                \
                r = cg_pid_get_##name(pid, ret);                \
                return IN_SET(r, -ENXIO, -ENOMEDIUM) ? -ENODATA : r;    \
        }

#define DEFINE_PID_GETTER(name) DEFINE_PID_GETTER_FULL(name, char*)

DEFINE_PID_GETTER(session);
DEFINE_PID_GETTER(unit);
DEFINE_PID_GETTER(user_unit);
DEFINE_PID_GETTER(machine_name);
DEFINE_PID_GETTER(slice);
DEFINE_PID_GETTER(user_slice);
DEFINE_PID_GETTER_FULL(owner_uid, uid_t);

_public_ int sd_pid_get_cgroup(pid_t pid, char **ret_cgroup) {
        _cleanup_free_ char *c = NULL;
        int r;

        assert_return(pid >= 0, -EINVAL);
        assert_return(ret_cgroup, -EINVAL);

        r = cg_pid_get_path(SYSTEMD_CGROUP_CONTROLLER, pid, &c);
        if (r < 0)
                return r;

        /* The internal APIs return the empty string for the root
         * cgroup, let's return the "/" in the public APIs instead, as
         * that's easier and less ambiguous for people to grok. */
        if (isempty(c)) {
                r = free_and_strdup(&c, "/");
                if (r < 0)
                        return r;
        }

        *ret_cgroup = TAKE_PTR(c);
        return 0;
}

#define DEFINE_PIDFD_GETTER(name)                                       \
        _public_ int sd_pidfd_get_##name(int pidfd, char **ret) {       \
                _cleanup_free_ char *str = NULL;                        \
                pid_t pid;                                              \
                int r;                                                  \
                                                                        \
                assert_return(pidfd >= 0, -EBADF);                      \
                assert_return(ret, -EINVAL);                            \
                                                                        \
                r = pidfd_get_pid(pidfd, &pid);                         \
                if (r < 0)                                              \
                        return r;                                       \
                                                                        \
                r = sd_pid_get_##name(pid, &str);                       \
                if (r < 0)                                              \
                        return r;                                       \
                                                                        \
                r = pidfd_verify_pid(pidfd, pid);                       \
                if (r < 0)                                              \
                        return r;                                       \
                                                                        \
                *ret = TAKE_PTR(str);                                   \
                return 0;                                               \
        }

DEFINE_PIDFD_GETTER(session);
DEFINE_PIDFD_GETTER(unit);
DEFINE_PIDFD_GETTER(user_unit);
DEFINE_PIDFD_GETTER(machine_name);
DEFINE_PIDFD_GETTER(slice);
DEFINE_PIDFD_GETTER(user_slice);
DEFINE_PIDFD_GETTER(cgroup);

_public_ int sd_pidfd_get_owner_uid(int pidfd, uid_t *ret_uid) {
        uid_t uid;
        pid_t pid;
        int r;

        assert_return(pidfd >= 0, -EINVAL);
        assert_return(ret_uid, -EINVAL);

        r = pidfd_get_pid(pidfd, &pid);
        if (r < 0)
                return r;

        r = sd_pid_get_owner_uid(pid, &uid);
        if (r < 0)
                return r;

        r = pidfd_verify_pid(pidfd, pid);
        if (r < 0)
                return r;

        *ret_uid = uid;

        return 0;
}

#define DEFINE_PEER_GETTER_FULL(name, type)                     \
        _public_ int sd_peer_get_##name(int fd, type *ret) {    \
                struct ucred ucred = UCRED_INVALID;             \
                int r;                                          \
                                                                \
                assert_return(fd >= 0, -EBADF);                 \
                assert_return(ret, -EINVAL);                    \
                                                                \
                r = getpeercred(fd, &ucred);                    \
                if (r < 0)                                      \
                        return r;                               \
                                                                \
                return sd_pid_get_##name(ucred.pid, ret);       \
        }

#define DEFINE_PEER_GETTER(name) DEFINE_PEER_GETTER_FULL(name, char*)

DEFINE_PEER_GETTER(session);
DEFINE_PEER_GETTER(unit);
DEFINE_PEER_GETTER(user_unit);
DEFINE_PEER_GETTER(machine_name);
DEFINE_PEER_GETTER(slice);
DEFINE_PEER_GETTER(user_slice);
DEFINE_PEER_GETTER(cgroup);
DEFINE_PEER_GETTER_FULL(owner_uid, uid_t);

static int uid_get_string(uid_t uid, const char *key, char **ret) {
        _cleanup_free_ char *p = NULL, *s = NULL;
        int r;

        assert_return(uid_is_valid(uid), -EINVAL);
        assert(key);
        assert(ret);

        if (asprintf(&p, "/run/systemd/users/" UID_FMT, uid) < 0)
                return -ENOMEM;

        r = parse_env_file(NULL, p, key, &s);
        if (r == -ENOENT)
                return -ENXIO;
        if (r < 0)
                return r;
        if (isempty(s))
                return -ENODATA;

        *ret = TAKE_PTR(s);
        return 0;
}

static int uid_get_array(uid_t uid, const char *key, char ***ret) {
        _cleanup_strv_free_ char **a = NULL;
        _cleanup_free_ char *s = NULL;
        int r;

        assert(key);

        r = uid_get_string(uid, key, &s);
        if (r == -ENODATA) {
                if (ret)
                        *ret = NULL;
                return 0;
        }
        if (r < 0)
                return r;

        a = strv_split(s, NULL);
        if (!a)
                return -ENOMEM;

        r = (int) strv_length(strv_uniq(a));

        if (ret)
                *ret = TAKE_PTR(a);

        return r;
}

_public_ int sd_uid_get_state(uid_t uid, char **ret_state) {
        _cleanup_free_ char *s = NULL;
        int r;

        assert_return(ret_state, -EINVAL);

        r = uid_get_string(uid, "STATE", &s);
        if (r == -ENXIO)
                r = free_and_strdup(&s, "offline");
        if (r < 0)
                return r;

        *ret_state = TAKE_PTR(s);
        return 0;
}

_public_ int sd_uid_get_display(uid_t uid, char **ret_display) {
        assert_return(ret_display, -EINVAL);

        return uid_get_string(uid, "DISPLAY", ret_display);
}

static int file_of_seat(const char *seat, char **ret) {
        char *p;
        int r;

        assert(ret);

        if (seat) {
                if (!filename_is_valid(seat))
                        return -EINVAL;

                p = path_join("/run/systemd/seats", seat);
        } else {
                _cleanup_free_ char *buf = NULL;

                r = sd_session_get_seat(NULL, &buf);
                if (r < 0)
                        return r;

                p = path_join("/run/systemd/seats", buf);
        }
        if (!p)
                return -ENOMEM;

        *ret = TAKE_PTR(p);
        return 0;
}

_public_ int sd_uid_is_on_seat(uid_t uid, int require_active, const char *seat) {
        _cleanup_free_ char *filename = NULL, *content = NULL;
        int r;

        assert_return(uid_is_valid(uid), -EINVAL);

        r = file_of_seat(seat, &filename);
        if (r < 0)
                return r;

        r = parse_env_file(NULL, filename,
                           require_active ? "ACTIVE_UID" : "UIDS",
                           &content);
        if (r == -ENOENT)
                return 0;
        if (r < 0)
                return r;
        if (isempty(content))
                return 0;

        char t[DECIMAL_STR_MAX(uid_t)];
        xsprintf(t, UID_FMT, uid);

        return string_contains_word(content, NULL, t);
}

_public_ int sd_uid_get_sessions(uid_t uid, int require_active, char ***ret_sessions) {
        return uid_get_array(
                        uid,
                        require_active == 0 ? "ONLINE_SESSIONS" :
                        require_active > 0  ? "ACTIVE_SESSIONS" :
                                              "SESSIONS",
                        ret_sessions);
}

_public_ int sd_uid_get_seats(uid_t uid, int require_active, char ***ret_seats) {
        return uid_get_array(
                        uid,
                        require_active == 0 ? "ONLINE_SEATS" :
                        require_active > 0  ? "ACTIVE_SEATS" :
                                              "SEATS",
                        ret_seats);
}

static int session_get_string(const char *session, const char *key, char **ret) {
        _cleanup_free_ char *p = NULL, *s = NULL;
        int r;

        assert_return(ret, -EINVAL);
        assert(key);

        if (session) {
                if (!session_id_valid(session))
                        return -EINVAL;

                p = path_join("/run/systemd/sessions", session);
        } else {
                _cleanup_free_ char *buf = NULL;

                r = sd_pid_get_session(0, &buf);
                if (r < 0)
                        return r;

                p = path_join("/run/systemd/sessions", buf);
        }
        if (!p)
                return -ENOMEM;

        r = parse_env_file(NULL, p, key, &s);
        if (r == -ENOENT)
                return -ENXIO;
        if (r < 0)
                return r;
        if (isempty(s))
                return -ENODATA;

        *ret = TAKE_PTR(s);
        return 0;
}

_public_ int sd_session_is_active(const char *session) {
        _cleanup_free_ char *s = NULL;
        int r;

        r = session_get_string(session, "ACTIVE", &s);
        if (r < 0)
                return r;

        return parse_boolean(s);
}

_public_ int sd_session_is_remote(const char *session) {
        _cleanup_free_ char *s = NULL;
        int r;

        r = session_get_string(session, "REMOTE", &s);
        if (r < 0)
                return r;

        return parse_boolean(s);
}

_public_ int sd_session_get_state(const char *session, char **ret_state) {
        assert_return(ret_state, -EINVAL);
        return session_get_string(session, "STATE", ret_state);
}

_public_ int sd_session_get_uid(const char *session, uid_t *ret_uid) {
        _cleanup_free_ char *s = NULL;
        int r;

        assert_return(ret_uid, -EINVAL);

        r = session_get_string(session, "UID", &s);
        if (r < 0)
                return r;

        return parse_uid(s, ret_uid);
}

_public_ int sd_session_get_username(const char *session, char **ret_username) {
        return session_get_string(session, "USER", ret_username);
}

_public_ int sd_session_get_seat(const char *session, char **ret_seat) {
        return session_get_string(session, "SEAT", ret_seat);
}

_public_ int sd_session_get_start_time(const char *session, uint64_t *ret_usec) {
        _cleanup_free_ char *s = NULL;
        int r;

        assert_return(ret_usec, -EINVAL);

        r = session_get_string(session, "REALTIME", &s);
        if (r < 0)
                return r;

        return safe_atou64(s, ret_usec);
}

_public_ int sd_session_get_tty(const char *session, char **ret_tty) {
        return session_get_string(session, "TTY", ret_tty);
}

_public_ int sd_session_get_vt(const char *session, unsigned *ret_vtnr) {
        _cleanup_free_ char *vtnr_string = NULL;
        int r;

        assert_return(ret_vtnr, -EINVAL);

        r = session_get_string(session, "VTNR", &vtnr_string);
        if (r < 0)
                return r;

        return safe_atou(vtnr_string, ret_vtnr);
}

_public_ int sd_session_get_service(const char *session, char **ret_service) {
        return session_get_string(session, "SERVICE", ret_service);
}

_public_ int sd_session_get_type(const char *session, char **ret_type) {
        return session_get_string(session, "TYPE", ret_type);
}

_public_ int sd_session_get_class(const char *session, char **ret_class) {
        return session_get_string(session, "CLASS", ret_class);
}

_public_ int sd_session_get_desktop(const char *session, char **ret_desktop) {
        _cleanup_free_ char *escaped = NULL;
        int r;
        ssize_t l;

        assert_return(ret_desktop, -EINVAL);

        r = session_get_string(session, "DESKTOP", &escaped);
        if (r < 0)
                return r;

        l = cunescape(escaped, 0, ret_desktop);
        if (l < 0)
                return l;
        return 0;
}

_public_ int sd_session_get_display(const char *session, char **ret_display) {
        return session_get_string(session, "DISPLAY", ret_display);
}

_public_ int sd_session_get_remote_user(const char *session, char **ret_remote_user) {
        return session_get_string(session, "REMOTE_USER", ret_remote_user);
}

_public_ int sd_session_get_remote_host(const char *session, char **ret_remote_host) {
        return session_get_string(session, "REMOTE_HOST", ret_remote_host);
}

_public_ int sd_seat_get_active(const char *seat, char **ret_session, uid_t *ret_uid) {
        _cleanup_free_ char *p = NULL, *s = NULL, *t = NULL;
        int r;

        assert_return(ret_session || ret_uid, -EINVAL);

        r = file_of_seat(seat, &p);
        if (r < 0)
                return r;

        r = parse_env_file(NULL, p,
                           "ACTIVE", &s,
                           "ACTIVE_UID", &t);
        if (r == -ENOENT)
                return -ENXIO;
        if (r < 0)
                return r;

        if (ret_session && !s)
                return -ENODATA;

        if (ret_uid && !t)
                return -ENODATA;

        if (ret_uid && t) {
                r = parse_uid(t, ret_uid);
                if (r < 0)
                        return r;
        }

        if (ret_session && s)
                *ret_session = TAKE_PTR(s);

        return 0;
}

_public_ int sd_seat_get_sessions(
                const char *seat,
                char ***ret_sessions,
                uid_t **ret_uids,
                unsigned *ret_n_uids) {

        _cleanup_free_ char *fname = NULL, *session_line = NULL, *uid_line = NULL;
        _cleanup_strv_free_ char **sessions = NULL;
        _cleanup_free_ uid_t *uids = NULL;
        unsigned n_sessions = 0;
        int r;

        r = file_of_seat(seat, &fname);
        if (r < 0)
                return r;

        r = parse_env_file(NULL, fname,
                           "SESSIONS", &session_line,
                           "UIDS", &uid_line);
        if (r == -ENOENT)
                return -ENXIO;
        if (r < 0)
                return r;

        if (session_line) {
                sessions = strv_split(session_line, NULL);
                if (!sessions)
                        return -ENOMEM;

                n_sessions = strv_length(sessions);
        };

        if (ret_uids && uid_line) {
                uids = new(uid_t, n_sessions);
                if (!uids)
                        return -ENOMEM;

                size_t n = 0;
                for (const char *p = uid_line;;) {
                        _cleanup_free_ char *word = NULL;

                        r = extract_first_word(&p, &word, NULL, 0);
                        if (r < 0)
                                return r;
                        if (r == 0)
                                break;

                        r = parse_uid(word, &uids[n++]);
                        if (r < 0)
                                return r;
                }

                if (n != n_sessions)
                        return -EUCLEAN;
        }

        if (ret_sessions)
                *ret_sessions = TAKE_PTR(sessions);
        if (ret_uids)
                *ret_uids = TAKE_PTR(uids);
        if (ret_n_uids)
                *ret_n_uids = n_sessions;

        return n_sessions;
}

static int seat_get_can(const char *seat, const char *variable) {
        _cleanup_free_ char *p = NULL, *s = NULL;
        int r;

        assert(variable);

        r = file_of_seat(seat, &p);
        if (r < 0)
                return r;

        r = parse_env_file(NULL, p,
                           variable, &s);
        if (r == -ENOENT)
                return -ENXIO;
        if (r < 0)
                return r;
        if (isempty(s))
                return -ENODATA;

        return parse_boolean(s);
}

_public_ int sd_seat_can_multi_session(const char *seat) {
        return true;
}

_public_ int sd_seat_can_tty(const char *seat) {
        return seat_get_can(seat, "CAN_TTY");
}

_public_ int sd_seat_can_graphical(const char *seat) {
        return seat_get_can(seat, "CAN_GRAPHICAL");
}

_public_ int sd_get_seats(char ***ret_seats) {
        int r;

        r = get_files_in_directory("/run/systemd/seats/", ret_seats);
        if (r == -ENOENT) {
                if (ret_seats)
                        *ret_seats = NULL;
                return 0;
        }
        return r;
}

_public_ int sd_get_sessions(char ***ret_sessions) {
        int r;

        r = get_files_in_directory("/run/systemd/sessions/", ret_sessions);
        if (r == -ENOENT) {
                if (ret_sessions)
                        *ret_sessions = NULL;
                return 0;
        }
        return r;
}

_public_ int sd_get_uids(uid_t **ret_users) {
        _cleanup_closedir_ DIR *d = NULL;
        int r = 0;
        unsigned n = 0;
        _cleanup_free_ uid_t *l = NULL;

        d = opendir("/run/systemd/users/");
        if (!d) {
                if (errno == ENOENT) {
                        if (ret_users)
                                *ret_users = NULL;
                        return 0;
                }
                return -errno;
        }

        FOREACH_DIRENT_ALL(de, d, return -errno) {
                int k;
                uid_t uid;

                if (!dirent_is_file(de))
                        continue;

                k = parse_uid(de->d_name, &uid);
                if (k < 0)
                        continue;

                if (ret_users) {
                        if ((unsigned) r >= n) {
                                uid_t *t;

                                n = MAX(16, 2*r);
                                t = reallocarray(l, sizeof(uid_t), n);
                                if (!t)
                                        return -ENOMEM;

                                l = t;
                        }

                        assert((unsigned) r < n);
                        l[r++] = uid;
                } else
                        r++;
        }

        if (ret_users)
                *ret_users = TAKE_PTR(l);

        return r;
}

_public_ int sd_get_machine_names(char ***ret_machines) {
        _cleanup_strv_free_ char **l = NULL;
        char **a, **b;
        int r;

        r = get_files_in_directory("/run/systemd/machines/", &l);
        if (r == -ENOENT) {
                if (ret_machines)
                        *ret_machines = NULL;
                return 0;
        }
        if (r < 0)
                return r;

        if (l) {
                r = 0;

                /* Filter out the unit: symlinks */
                for (a = b = l; *a; a++) {
                        if (startswith(*a, "unit:") || !hostname_is_valid(*a, 0))
                                free(*a);
                        else {
                                *b = *a;
                                b++;
                                r++;
                        }
                }

                *b = NULL;
        }

        if (ret_machines)
                *ret_machines = TAKE_PTR(l);

        return r;
}

_public_ int sd_machine_get_class(const char *machine, char **ret_class) {
        _cleanup_free_ char *c = NULL;
        const char *p;
        int r;

        assert_return(ret_class, -EINVAL);

        if (streq(machine, ".host")) {
                c = strdup("host");
                if (!c)
                        return -ENOMEM;
        } else {
                if (!hostname_is_valid(machine, 0))
                        return -EINVAL;

                p = strjoina("/run/systemd/machines/", machine);
                r = parse_env_file(NULL, p, "CLASS", &c);
                if (r == -ENOENT)
                        return -ENXIO;
                if (r < 0)
                        return r;
                if (!c)
                        return -EIO;
        }

        *ret_class = TAKE_PTR(c);
        return 0;
}

_public_ int sd_machine_get_ifindices(const char *machine, int **ret_ifindices) {
        _cleanup_free_ char *netif_line = NULL;
        const char *p;
        int r;

        assert_return(hostname_is_valid(machine, 0), -EINVAL);

        p = strjoina("/run/systemd/machines/", machine);
        r = parse_env_file(NULL, p, "NETIF", &netif_line);
        if (r == -ENOENT)
                return -ENXIO;
        if (r < 0)
                return r;
        if (!netif_line) {
                *ret_ifindices = NULL;
                return 0;
        }

        _cleanup_strv_free_ char **tt = strv_split(netif_line, NULL);
        if (!tt)
                return -ENOMEM;

        _cleanup_free_ int *ifindices = NULL;
        if (ret_ifindices) {
                ifindices = new(int, strv_length(tt));
                if (!ifindices)
                        return -ENOMEM;
        }

        size_t n = 0;
        for (size_t i = 0; tt[i]; i++) {
                int ind;

                ind = parse_ifindex(tt[i]);
                if (ind < 0)
                        /* Return -EUCLEAN to distinguish from -EINVAL for invalid args */
                        return ind == -EINVAL ? -EUCLEAN : ind;

                if (ret_ifindices)
                        ifindices[n] = ind;
                n++;
        }

        if (ret_ifindices)
                *ret_ifindices = TAKE_PTR(ifindices);

        return n;
}

static int MONITOR_TO_FD(sd_login_monitor *m) {
        return (int) (unsigned long) m - 1;
}

static sd_login_monitor* FD_TO_MONITOR(int fd) {
        return (sd_login_monitor*) (unsigned long) (fd + 1);
}

_public_ int sd_login_monitor_new(const char *category, sd_login_monitor **ret_monitor) {
        _cleanup_close_ int fd = -EBADF;
        bool good = false;
        int k;

        assert_return(ret_monitor, -EINVAL);

        fd = inotify_init1(IN_NONBLOCK|IN_CLOEXEC);
        if (fd < 0)
                return -errno;

        if (!category || streq(category, "seat")) {
                k = inotify_add_watch(fd, "/run/systemd/seats/", IN_MOVED_TO|IN_DELETE);
                if (k < 0)
                        return -errno;

                good = true;
        }

        if (!category || streq(category, "session")) {
                k = inotify_add_watch(fd, "/run/systemd/sessions/", IN_MOVED_TO|IN_DELETE);
                if (k < 0)
                        return -errno;

                good = true;
        }

        if (!category || streq(category, "uid")) {
                k = inotify_add_watch(fd, "/run/systemd/users/", IN_MOVED_TO|IN_DELETE);
                if (k < 0)
                        return -errno;

                good = true;
        }

        if (!category || streq(category, "machine")) {
                k = inotify_add_watch(fd, "/run/systemd/machines/", IN_MOVED_TO|IN_DELETE);
                if (k < 0)
                        return -errno;

                good = true;
        }

        if (!good)
                return -EINVAL;

        *ret_monitor = FD_TO_MONITOR(TAKE_FD(fd));
        return 0;
}

_public_ sd_login_monitor* sd_login_monitor_unref(sd_login_monitor *m) {
        if (m)
                (void) close_nointr(MONITOR_TO_FD(m));

        return NULL;
}

_public_ int sd_login_monitor_flush(sd_login_monitor *m) {
        int r;

        assert_return(m, -EINVAL);

        r = flush_fd(MONITOR_TO_FD(m));
        if (r < 0)
                return r;

        return 0;
}

_public_ int sd_login_monitor_get_fd(sd_login_monitor *m) {

        assert_return(m, -EINVAL);

        return MONITOR_TO_FD(m);
}

_public_ int sd_login_monitor_get_events(sd_login_monitor *m) {

        assert_return(m, -EINVAL);

        /* For now we will only return POLLIN here, since we don't
         * need anything else ever for inotify.  However, let's have
         * this API to keep our options open should we later on need
         * it. */
        return POLLIN;
}

_public_ int sd_login_monitor_get_timeout(sd_login_monitor *m, uint64_t *ret_timeout_usec) {

        assert_return(m, -EINVAL);
        assert_return(ret_timeout_usec, -EINVAL);

        /* For now we will only return UINT64_MAX, since we don't
         * need any timeout. However, let's have this API to keep our
         * options open should we later on need it. */
        *ret_timeout_usec = UINT64_MAX;
        return 0;
}
