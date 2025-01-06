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
#include "pidfd-util.h"
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

_public_ int sd_pid_get_session(pid_t pid, char **session) {
        int r;

        assert_return(pid >= 0, -EINVAL);
        assert_return(session, -EINVAL);

        r = cg_pid_get_session(pid, session);
        return IN_SET(r, -ENXIO, -ENOMEDIUM) ? -ENODATA : r;
}

_public_ int sd_pid_get_unit(pid_t pid, char **unit) {
        int r;

        assert_return(pid >= 0, -EINVAL);
        assert_return(unit, -EINVAL);

        r = cg_pid_get_unit(pid, unit);
        return IN_SET(r, -ENXIO, -ENOMEDIUM) ? -ENODATA : r;
}

_public_ int sd_pid_get_user_unit(pid_t pid, char **unit) {
        int r;

        assert_return(pid >= 0, -EINVAL);
        assert_return(unit, -EINVAL);

        r = cg_pid_get_user_unit(pid, unit);
        return IN_SET(r, -ENXIO, -ENOMEDIUM) ? -ENODATA : r;
}

_public_ int sd_pid_get_machine_name(pid_t pid, char **name) {
        int r;

        assert_return(pid >= 0, -EINVAL);
        assert_return(name, -EINVAL);

        r = cg_pid_get_machine_name(pid, name);
        return IN_SET(r, -ENXIO, -ENOMEDIUM) ? -ENODATA : r;
}

_public_ int sd_pid_get_slice(pid_t pid, char **slice) {
        int r;

        assert_return(pid >= 0, -EINVAL);
        assert_return(slice, -EINVAL);

        r = cg_pid_get_slice(pid, slice);
        return IN_SET(r, -ENXIO, -ENOMEDIUM) ? -ENODATA : r;
}

_public_ int sd_pid_get_user_slice(pid_t pid, char **slice) {
        int r;

        assert_return(pid >= 0, -EINVAL);
        assert_return(slice, -EINVAL);

        r = cg_pid_get_user_slice(pid, slice);
        return IN_SET(r, -ENXIO, -ENOMEDIUM) ? -ENODATA : r;
}

_public_ int sd_pid_get_owner_uid(pid_t pid, uid_t *uid) {
        int r;

        assert_return(pid >= 0, -EINVAL);
        assert_return(uid, -EINVAL);

        r = cg_pid_get_owner_uid(pid, uid);
        return IN_SET(r, -ENXIO, -ENOMEDIUM) ? -ENODATA : r;
}

_public_ int sd_pid_get_cgroup(pid_t pid, char **cgroup) {
        char *c;
        int r;

        assert_return(pid >= 0, -EINVAL);
        assert_return(cgroup, -EINVAL);

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

        *cgroup = c;
        return 0;
}

_public_ int sd_pidfd_get_session(int pidfd, char **ret_session) {
        _cleanup_free_ char *session = NULL;
        pid_t pid;
        int r;

        assert_return(pidfd >= 0, -EBADF);
        assert_return(ret_session, -EINVAL);

        r = pidfd_get_pid(pidfd, &pid);
        if (r < 0)
                return r;

        r = sd_pid_get_session(pid, &session);
        if (r < 0)
                return r;

        r = pidfd_verify_pid(pidfd, pid);
        if (r < 0)
                return r;

        *ret_session = TAKE_PTR(session);

        return 0;
}

_public_ int sd_pidfd_get_unit(int pidfd, char **ret_unit) {
        _cleanup_free_ char *unit = NULL;
        pid_t pid;
        int r;

        assert_return(pidfd >= 0, -EBADF);
        assert_return(ret_unit, -EINVAL);

        r = pidfd_get_pid(pidfd, &pid);
        if (r < 0)
                return r;

        r = sd_pid_get_unit(pid, &unit);
        if (r < 0)
                return r;

        r = pidfd_verify_pid(pidfd, pid);
        if (r < 0)
                return r;

        *ret_unit = TAKE_PTR(unit);

        return 0;
}

_public_ int sd_pidfd_get_user_unit(int pidfd, char **ret_unit) {
        _cleanup_free_ char *unit = NULL;
        pid_t pid;
        int r;

        assert_return(pidfd >= 0, -EBADF);
        assert_return(ret_unit, -EINVAL);

        r = pidfd_get_pid(pidfd, &pid);
        if (r < 0)
                return r;

        r = sd_pid_get_user_unit(pid, &unit);
        if (r < 0)
                return r;

        r = pidfd_verify_pid(pidfd, pid);
        if (r < 0)
                return r;

        *ret_unit = TAKE_PTR(unit);

        return 0;
}

_public_ int sd_pidfd_get_machine_name(int pidfd, char **ret_name) {
        _cleanup_free_ char *name = NULL;
        pid_t pid;
        int r;

        assert_return(pidfd >= 0, -EBADF);
        assert_return(ret_name, -EINVAL);

        r = pidfd_get_pid(pidfd, &pid);
        if (r < 0)
                return r;

        r = sd_pid_get_machine_name(pid, &name);
        if (r < 0)
                return r;

        r = pidfd_verify_pid(pidfd, pid);
        if (r < 0)
                return r;

        *ret_name = TAKE_PTR(name);

        return 0;
}

_public_ int sd_pidfd_get_slice(int pidfd, char **ret_slice) {
        _cleanup_free_ char *slice = NULL;
        pid_t pid;
        int r;

        assert_return(pidfd >= 0, -EBADF);
        assert_return(ret_slice, -EINVAL);

        r = pidfd_get_pid(pidfd, &pid);
        if (r < 0)
                return r;

        r = sd_pid_get_slice(pid, &slice);
        if (r < 0)
                return r;

        r = pidfd_verify_pid(pidfd, pid);
        if (r < 0)
                return r;

        *ret_slice = TAKE_PTR(slice);

        return 0;
}

_public_ int sd_pidfd_get_user_slice(int pidfd, char **ret_slice) {
        _cleanup_free_ char *slice = NULL;
        pid_t pid;
        int r;

        assert_return(pidfd >= 0, -EBADF);
        assert_return(ret_slice, -EINVAL);

        r = pidfd_get_pid(pidfd, &pid);
        if (r < 0)
                return r;

        r = sd_pid_get_user_slice(pid, &slice);
        if (r < 0)
                return r;

        r = pidfd_verify_pid(pidfd, pid);
        if (r < 0)
                return r;

        *ret_slice = TAKE_PTR(slice);

        return 0;
}

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

_public_ int sd_pidfd_get_cgroup(int pidfd, char **ret_cgroup) {
        _cleanup_free_ char *cgroup = NULL;
        pid_t pid;
        int r;

        assert_return(pidfd >= 0, -EBADF);
        assert_return(ret_cgroup, -EINVAL);

        r = pidfd_get_pid(pidfd, &pid);
        if (r < 0)
                return r;

        r = sd_pid_get_cgroup(pid, &cgroup);
        if (r < 0)
                return r;

        r = pidfd_verify_pid(pidfd, pid);
        if (r < 0)
                return r;

        *ret_cgroup = TAKE_PTR(cgroup);

        return 0;
}

_public_ int sd_peer_get_session(int fd, char **ret) {
        int r;

        assert_return(fd >= 0, -EBADF);
        assert_return(ret, -EINVAL);

        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        r = getpeerpidref(fd, &pidref);
        if (r < 0)
                return r;

        return cg_pidref_get_session(&pidref, ret);
}

_public_ int sd_peer_get_owner_uid(int fd, uid_t *ret) {
        int r;

        assert_return(fd >= 0, -EBADF);
        assert_return(ret, -EINVAL);

        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        r = getpeerpidref(fd, &pidref);
        if (r < 0)
                return r;

        return cg_pidref_get_owner_uid(&pidref, ret);
}

_public_ int sd_peer_get_unit(int fd, char **ret) {
        int r;

        assert_return(fd >= 0, -EBADF);
        assert_return(ret, -EINVAL);

        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        r = getpeerpidref(fd, &pidref);
        if (r < 0)
                return r;

        return cg_pidref_get_unit(&pidref, ret);
}

_public_ int sd_peer_get_user_unit(int fd, char **unit) {
        struct ucred ucred;
        int r;

        assert_return(fd >= 0, -EBADF);
        assert_return(unit, -EINVAL);

        r = getpeercred(fd, &ucred);
        if (r < 0)
                return r;

        return cg_pid_get_user_unit(ucred.pid, unit);
}

_public_ int sd_peer_get_machine_name(int fd, char **machine) {
        struct ucred ucred;
        int r;

        assert_return(fd >= 0, -EBADF);
        assert_return(machine, -EINVAL);

        r = getpeercred(fd, &ucred);
        if (r < 0)
                return r;

        return cg_pid_get_machine_name(ucred.pid, machine);
}

_public_ int sd_peer_get_slice(int fd, char **slice) {
        struct ucred ucred;
        int r;

        assert_return(fd >= 0, -EBADF);
        assert_return(slice, -EINVAL);

        r = getpeercred(fd, &ucred);
        if (r < 0)
                return r;

        return cg_pid_get_slice(ucred.pid, slice);
}

_public_ int sd_peer_get_user_slice(int fd, char **slice) {
        struct ucred ucred;
        int r;

        assert_return(fd >= 0, -EBADF);
        assert_return(slice, -EINVAL);

        r = getpeercred(fd, &ucred);
        if (r < 0)
                return r;

        return cg_pid_get_user_slice(ucred.pid, slice);
}

_public_ int sd_peer_get_cgroup(int fd, char **cgroup) {
        struct ucred ucred;
        int r;

        assert_return(fd >= 0, -EBADF);
        assert_return(cgroup, -EINVAL);

        r = getpeercred(fd, &ucred);
        if (r < 0)
                return r;

        return sd_pid_get_cgroup(ucred.pid, cgroup);
}

static int file_of_uid(uid_t uid, char **p) {

        assert_return(uid_is_valid(uid), -EINVAL);
        assert(p);

        if (asprintf(p, "/run/systemd/users/" UID_FMT, uid) < 0)
                return -ENOMEM;

        return 0;
}

_public_ int sd_uid_get_state(uid_t uid, char**state) {
        _cleanup_free_ char *p = NULL, *s = NULL;
        int r;

        assert_return(state, -EINVAL);

        r = file_of_uid(uid, &p);
        if (r < 0)
                return r;

        r = parse_env_file(NULL, p, "STATE", &s);
        if (r == -ENOENT)
                r = free_and_strdup(&s, "offline");
        if (r < 0)
                return r;
        if (isempty(s))
                return -EIO;

        *state = TAKE_PTR(s);
        return 0;
}

_public_ int sd_uid_get_display(uid_t uid, char **session) {
        _cleanup_free_ char *p = NULL, *s = NULL;
        int r;

        assert_return(session, -EINVAL);

        r = file_of_uid(uid, &p);
        if (r < 0)
                return r;

        r = parse_env_file(NULL, p, "DISPLAY", &s);
        if (r == -ENOENT)
                return -ENODATA;
        if (r < 0)
                return r;
        if (isempty(s))
                return -ENODATA;

        *session = TAKE_PTR(s);

        return 0;
}

_public_ int sd_uid_get_login_time(uid_t uid, uint64_t *usec) {
        _cleanup_free_ char *p = NULL, *s = NULL, *rt = NULL;
        usec_t t;
        int r;

        assert_return(usec, -EINVAL);

        r = file_of_uid(uid, &p);
        if (r < 0)
                return r;

        r = parse_env_file(NULL, p, "STATE", &s, "REALTIME", &rt);
        if (r == -ENOENT)
                return -ENXIO;
        if (r < 0)
                return r;
        if (isempty(s) || isempty(rt))
                return -EIO;

        if (!STR_IN_SET(s, "active", "online"))
                return -ENXIO;

        r = safe_atou64(rt, &t);
        if (r < 0)
                return r;

        *usec = t;
        return 0;
}

static int file_of_seat(const char *seat, char **_p) {
        char *p;
        int r;

        assert(_p);

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

        *_p = TAKE_PTR(p);
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

        return string_contains_word(content, NULL, FORMAT_UID(uid));
}

static int uid_get_array(uid_t uid, const char *variable, char ***array) {
        _cleanup_free_ char *p = NULL, *s = NULL;
        char **a;
        int r;

        assert(variable);

        r = file_of_uid(uid, &p);
        if (r < 0)
                return r;

        r = parse_env_file(NULL, p, variable, &s);
        if (r == -ENOENT || (r >= 0 && isempty(s))) {
                if (array)
                        *array = NULL;
                return 0;
        }
        if (r < 0)
                return r;

        a = strv_split(s, NULL);
        if (!a)
                return -ENOMEM;

        strv_uniq(a);
        r = (int) strv_length(a);

        if (array)
                *array = a;
        else
                strv_free(a);

        return r;
}

_public_ int sd_uid_get_sessions(uid_t uid, int require_active, char ***sessions) {
        return uid_get_array(
                        uid,
                        require_active == 0 ? "ONLINE_SESSIONS" :
                        require_active > 0  ? "ACTIVE_SESSIONS" :
                                              "SESSIONS",
                        sessions);
}

_public_ int sd_uid_get_seats(uid_t uid, int require_active, char ***seats) {
        return uid_get_array(
                        uid,
                        require_active == 0 ? "ONLINE_SEATS" :
                        require_active > 0  ? "ACTIVE_SEATS" :
                                              "SEATS",
                        seats);
}

static int file_of_session(const char *session, char **_p) {
        char *p;
        int r;

        assert(_p);

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

        *_p = p;
        return 0;
}

_public_ int sd_session_is_active(const char *session) {
        _cleanup_free_ char *p = NULL, *s = NULL;
        int r;

        r = file_of_session(session, &p);
        if (r < 0)
                return r;

        r = parse_env_file(NULL, p, "ACTIVE", &s);
        if (r == -ENOENT)
                return -ENXIO;
        if (r < 0)
                return r;
        if (isempty(s))
                return -EIO;

        return parse_boolean(s);
}

_public_ int sd_session_is_remote(const char *session) {
        _cleanup_free_ char *p = NULL, *s = NULL;
        int r;

        r = file_of_session(session, &p);
        if (r < 0)
                return r;

        r = parse_env_file(NULL, p, "REMOTE", &s);
        if (r == -ENOENT)
                return -ENXIO;
        if (r < 0)
                return r;
        if (isempty(s))
                return -ENODATA;

        return parse_boolean(s);
}

_public_ int sd_session_get_state(const char *session, char **state) {
        _cleanup_free_ char *p = NULL, *s = NULL;
        int r;

        assert_return(state, -EINVAL);

        r = file_of_session(session, &p);
        if (r < 0)
                return r;

        r = parse_env_file(NULL, p, "STATE", &s);
        if (r == -ENOENT)
                return -ENXIO;
        if (r < 0)
                return r;
        if (isempty(s))
                return -EIO;

        *state = TAKE_PTR(s);

        return 0;
}

_public_ int sd_session_get_uid(const char *session, uid_t *uid) {
        int r;
        _cleanup_free_ char *p = NULL, *s = NULL;

        assert_return(uid, -EINVAL);

        r = file_of_session(session, &p);
        if (r < 0)
                return r;

        r = parse_env_file(NULL, p, "UID", &s);
        if (r == -ENOENT)
                return -ENXIO;
        if (r < 0)
                return r;
        if (isempty(s))
                return -EIO;

        return parse_uid(s, uid);
}

static int session_get_string(const char *session, const char *field, char **value) {
        _cleanup_free_ char *p = NULL, *s = NULL;
        int r;

        assert_return(value, -EINVAL);
        assert(field);

        r = file_of_session(session, &p);
        if (r < 0)
                return r;

        r = parse_env_file(NULL, p, field, &s);
        if (r == -ENOENT)
                return -ENXIO;
        if (r < 0)
                return r;
        if (isempty(s))
                return -ENODATA;

        *value = TAKE_PTR(s);
        return 0;
}

_public_ int sd_session_get_username(const char *session, char **username) {
        return session_get_string(session, "USER", username);
}

_public_ int sd_session_get_seat(const char *session, char **seat) {
        return session_get_string(session, "SEAT", seat);
}

_public_ int sd_session_get_start_time(const char *session, uint64_t *usec) {
        _cleanup_free_ char *p = NULL, *s = NULL;
        usec_t t;
        int r;

        assert_return(usec, -EINVAL);

        r = file_of_session(session, &p);
        if (r < 0)
                return r;

        r = parse_env_file(NULL, p, "REALTIME", &s);
        if (r == -ENOENT)
                return -ENXIO;
        if (r < 0)
                return r;
        if (isempty(s))
                return -EIO;

        r = safe_atou64(s, &t);
        if (r < 0)
                return r;

        *usec = t;
        return 0;
}

_public_ int sd_session_get_tty(const char *session, char **tty) {
        return session_get_string(session, "TTY", tty);
}

_public_ int sd_session_get_vt(const char *session, unsigned *vtnr) {
        _cleanup_free_ char *vtnr_string = NULL;
        unsigned u;
        int r;

        assert_return(vtnr, -EINVAL);

        r = session_get_string(session, "VTNR", &vtnr_string);
        if (r < 0)
                return r;

        r = safe_atou(vtnr_string, &u);
        if (r < 0)
                return r;

        *vtnr = u;
        return 0;
}

_public_ int sd_session_get_service(const char *session, char **service) {
        return session_get_string(session, "SERVICE", service);
}

_public_ int sd_session_get_type(const char *session, char **type) {
        return session_get_string(session, "TYPE", type);
}

_public_ int sd_session_get_class(const char *session, char **class) {
        return session_get_string(session, "CLASS", class);
}

_public_ int sd_session_get_desktop(const char *session, char **desktop) {
        _cleanup_free_ char *escaped = NULL;
        int r;
        ssize_t l;

        assert_return(desktop, -EINVAL);

        r = session_get_string(session, "DESKTOP", &escaped);
        if (r < 0)
                return r;

        l = cunescape(escaped, 0, desktop);
        if (l < 0)
                return l;
        return 0;
}

_public_ int sd_session_get_display(const char *session, char **display) {
        return session_get_string(session, "DISPLAY", display);
}

_public_ int sd_session_get_remote_user(const char *session, char **remote_user) {
        return session_get_string(session, "REMOTE_USER", remote_user);
}

_public_ int sd_session_get_remote_host(const char *session, char **remote_host) {
        return session_get_string(session, "REMOTE_HOST", remote_host);
}

_public_ int sd_session_get_leader(const char *session, pid_t *leader) {
        _cleanup_free_ char *leader_string = NULL;
        pid_t pid;
        int r;

        assert_return(leader, -EINVAL);

        r = session_get_string(session, "LEADER", &leader_string);
        if (r < 0)
                return r;

        r = parse_pid(leader_string, &pid);
        if (r < 0)
                return r;

        *leader = pid;
        return 0;
}

_public_ int sd_seat_get_active(const char *seat, char **session, uid_t *uid) {
        _cleanup_free_ char *p = NULL, *s = NULL, *t = NULL;
        int r;

        assert_return(session || uid, -EINVAL);

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

        if (session && !s)
                return -ENODATA;

        if (uid && !t)
                return -ENODATA;

        if (uid && t) {
                r = parse_uid(t, uid);
                if (r < 0)
                        return r;
        }

        if (session && s)
                *session = TAKE_PTR(s);

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

_public_ int sd_get_seats(char ***seats) {
        int r;

        r = get_files_in_directory("/run/systemd/seats/", seats);
        if (r == -ENOENT) {
                if (seats)
                        *seats = NULL;
                return 0;
        }
        return r;
}

_public_ int sd_get_sessions(char ***sessions) {
        int r;

        r = get_files_in_directory("/run/systemd/sessions/", sessions);
        if (r == -ENOENT) {
                if (sessions)
                        *sessions = NULL;
                return 0;
        }
        return r;
}

_public_ int sd_get_uids(uid_t **users) {
        _cleanup_closedir_ DIR *d = NULL;
        _cleanup_free_ uid_t *l = NULL;
        size_t n = 0;

        d = opendir("/run/systemd/users/");
        if (!d) {
                if (errno == ENOENT) {
                        if (users)
                                *users = NULL;
                        return 0;
                }
                return -errno;
        }

        FOREACH_DIRENT_ALL(de, d, return -errno) {
                uid_t uid;

                if (!dirent_is_file(de))
                        continue;

                if (parse_uid(de->d_name, &uid) < 0)
                        continue;

                if (users) {
                        if (!GREEDY_REALLOC(l, n + 1))
                                return -ENOMEM;

                        l[n] = uid;
                }

                n++;
        }

        if (n > INT_MAX)
                return -EOVERFLOW;

        if (users)
                *users = TAKE_PTR(l);

        return (int) n;
}

_public_ int sd_get_machine_names(char ***machines) {
        _cleanup_strv_free_ char **l = NULL;
        char **a, **b;
        int r;

        r = get_files_in_directory("/run/systemd/machines/", &l);
        if (r == -ENOENT) {
                if (machines)
                        *machines = NULL;
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

        if (machines)
                *machines = TAKE_PTR(l);

        return r;
}

_public_ int sd_machine_get_class(const char *machine, char **class) {
        _cleanup_free_ char *c = NULL;
        const char *p;
        int r;

        assert_return(class, -EINVAL);

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

        *class = TAKE_PTR(c);
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

_public_ int sd_login_monitor_new(const char *category, sd_login_monitor **m) {
        _cleanup_close_ int fd = -EBADF;
        bool good = false;
        int k;

        assert_return(m, -EINVAL);

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

        *m = FD_TO_MONITOR(TAKE_FD(fd));
        return 0;
}

_public_ sd_login_monitor* sd_login_monitor_unref(sd_login_monitor *m) {
        if (m)
                (void) close(MONITOR_TO_FD(m));

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

_public_ int sd_login_monitor_get_timeout(sd_login_monitor *m, uint64_t *timeout_usec) {

        assert_return(m, -EINVAL);
        assert_return(timeout_usec, -EINVAL);

        /* For now we will only return UINT64_MAX, since we don't
         * need any timeout. However, let's have this API to keep our
         * options open should we later on need it. */
        *timeout_usec = UINT64_MAX;
        return 0;
}
