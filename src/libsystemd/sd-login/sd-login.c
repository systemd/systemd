/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <poll.h>
#include <sys/inotify.h>
#include <unistd.h>

#include "sd-login.h"

#include "alloc-util.h"
#include "cgroup-util.h"
#include "dirent-util.h"
#include "env-file.h"
#include "extract-word.h"
#include "fd-util.h"
#include "format-util.h"
#include "fs-util.h"
#include "hostname-util.h"
#include "io-util.h"
#include "login-util.h"
#include "parse-util.h"
#include "path-util.h"
#include "pidfd-util.h"
#include "pidref.h"
#include "socket-util.h"
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

_public_ int sd_pid_get_session(pid_t pid, char **ret_session) {
        int r;

        assert_return(pid >= 0, -EINVAL);

        r = cg_pid_get_session(pid, ret_session);
        return IN_SET(r, -ENXIO, -ENOMEDIUM) ? -ENODATA : r;
}

_public_ int sd_pid_get_unit(pid_t pid, char **ret_unit) {
        int r;

        assert_return(pid >= 0, -EINVAL);

        r = cg_pid_get_unit(pid, ret_unit);
        return IN_SET(r, -ENXIO, -ENOMEDIUM) ? -ENODATA : r;
}

_public_ int sd_pid_get_user_unit(pid_t pid, char **ret_unit) {
        int r;

        assert_return(pid >= 0, -EINVAL);

        r = cg_pid_get_user_unit(pid, ret_unit);
        return IN_SET(r, -ENXIO, -ENOMEDIUM) ? -ENODATA : r;
}

_public_ int sd_pid_get_machine_name(pid_t pid, char **ret_machine) {
        int r;

        assert_return(pid >= 0, -EINVAL);

        r = cg_pid_get_machine_name(pid, ret_machine);
        return IN_SET(r, -ENXIO, -ENOMEDIUM) ? -ENODATA : r;
}

_public_ int sd_pid_get_slice(pid_t pid, char **ret_slice) {
        int r;

        assert_return(pid >= 0, -EINVAL);

        r = cg_pid_get_slice(pid, ret_slice);
        return IN_SET(r, -ENXIO, -ENOMEDIUM) ? -ENODATA : r;
}

_public_ int sd_pid_get_user_slice(pid_t pid, char **ret_slice) {
        int r;

        assert_return(pid >= 0, -EINVAL);

        r = cg_pid_get_user_slice(pid, ret_slice);
        return IN_SET(r, -ENXIO, -ENOMEDIUM) ? -ENODATA : r;
}

_public_ int sd_pid_get_owner_uid(pid_t pid, uid_t *ret_uid) {
        int r;

        assert_return(pid >= 0, -EINVAL);

        r = cg_pid_get_owner_uid(pid, ret_uid);
        return IN_SET(r, -ENXIO, -ENOMEDIUM) ? -ENODATA : r;
}

_public_ int sd_pid_get_cgroup(pid_t pid, char **ret_cgroup) {
        int r;

        assert_return(pid >= 0, -EINVAL);

        _cleanup_free_ char *c = NULL;
        r = cg_pid_get_path(pid, &c);
        if (r < 0)
                return r;

        if (ret_cgroup) {
                /* The internal APIs return the empty string for the root cgroup, let's return the "/" in the
                 * public APIs instead, as that's easier and less ambiguous for people to grok. */
                if (isempty(c)) {
                        r = free_and_strdup(&c, "/");
                        if (r < 0)
                                return r;
                }

                *ret_cgroup = TAKE_PTR(c);
        }

        return 0;
}

_public_ int sd_pidfd_get_session(int pidfd, char **ret_session) {
        _cleanup_free_ char *session = NULL;
        pid_t pid;
        int r;

        assert_return(pidfd >= 0, -EBADF);

        r = pidfd_get_pid(pidfd, &pid);
        if (r < 0)
                return r;

        r = sd_pid_get_session(pid, &session);
        if (r < 0)
                return r;

        r = pidfd_verify_pid(pidfd, pid);
        if (r < 0)
                return r;

        if (ret_session)
                *ret_session = TAKE_PTR(session);
        return 0;
}

_public_ int sd_pidfd_get_unit(int pidfd, char **ret_unit) {
        _cleanup_free_ char *unit = NULL;
        pid_t pid;
        int r;

        assert_return(pidfd >= 0, -EBADF);

        r = pidfd_get_pid(pidfd, &pid);
        if (r < 0)
                return r;

        r = sd_pid_get_unit(pid, &unit);
        if (r < 0)
                return r;

        r = pidfd_verify_pid(pidfd, pid);
        if (r < 0)
                return r;

        if (ret_unit)
                *ret_unit = TAKE_PTR(unit);
        return 0;
}

_public_ int sd_pidfd_get_user_unit(int pidfd, char **ret_unit) {
        _cleanup_free_ char *unit = NULL;
        pid_t pid;
        int r;

        assert_return(pidfd >= 0, -EBADF);

        r = pidfd_get_pid(pidfd, &pid);
        if (r < 0)
                return r;

        r = sd_pid_get_user_unit(pid, &unit);
        if (r < 0)
                return r;

        r = pidfd_verify_pid(pidfd, pid);
        if (r < 0)
                return r;

        if (ret_unit)
                *ret_unit = TAKE_PTR(unit);
        return 0;
}

_public_ int sd_pidfd_get_machine_name(int pidfd, char **ret_machine) {
        _cleanup_free_ char *name = NULL;
        pid_t pid;
        int r;

        assert_return(pidfd >= 0, -EBADF);

        r = pidfd_get_pid(pidfd, &pid);
        if (r < 0)
                return r;

        r = sd_pid_get_machine_name(pid, &name);
        if (r < 0)
                return r;

        r = pidfd_verify_pid(pidfd, pid);
        if (r < 0)
                return r;

        if (ret_machine)
                *ret_machine = TAKE_PTR(name);
        return 0;
}

_public_ int sd_pidfd_get_slice(int pidfd, char **ret_slice) {
        _cleanup_free_ char *slice = NULL;
        pid_t pid;
        int r;

        assert_return(pidfd >= 0, -EBADF);

        r = pidfd_get_pid(pidfd, &pid);
        if (r < 0)
                return r;

        r = sd_pid_get_slice(pid, &slice);
        if (r < 0)
                return r;

        r = pidfd_verify_pid(pidfd, pid);
        if (r < 0)
                return r;

        if (ret_slice)
                *ret_slice = TAKE_PTR(slice);
        return 0;
}

_public_ int sd_pidfd_get_user_slice(int pidfd, char **ret_slice) {
        _cleanup_free_ char *slice = NULL;
        pid_t pid;
        int r;

        assert_return(pidfd >= 0, -EBADF);

        r = pidfd_get_pid(pidfd, &pid);
        if (r < 0)
                return r;

        r = sd_pid_get_user_slice(pid, &slice);
        if (r < 0)
                return r;

        r = pidfd_verify_pid(pidfd, pid);
        if (r < 0)
                return r;

        if (ret_slice)
                *ret_slice = TAKE_PTR(slice);
        return 0;
}

_public_ int sd_pidfd_get_owner_uid(int pidfd, uid_t *ret_uid) {
        uid_t uid;
        pid_t pid;
        int r;

        assert_return(pidfd >= 0, -EBADF);

        r = pidfd_get_pid(pidfd, &pid);
        if (r < 0)
                return r;

        r = sd_pid_get_owner_uid(pid, &uid);
        if (r < 0)
                return r;

        r = pidfd_verify_pid(pidfd, pid);
        if (r < 0)
                return r;

        if (ret_uid)
                *ret_uid = uid;
        return 0;
}

_public_ int sd_pidfd_get_cgroup(int pidfd, char **ret_cgroup) {
        _cleanup_free_ char *cgroup = NULL;
        pid_t pid;
        int r;

        assert_return(pidfd >= 0, -EBADF);

        r = pidfd_get_pid(pidfd, &pid);
        if (r < 0)
                return r;

        r = sd_pid_get_cgroup(pid, &cgroup);
        if (r < 0)
                return r;

        r = pidfd_verify_pid(pidfd, pid);
        if (r < 0)
                return r;

        if (ret_cgroup)
                *ret_cgroup = TAKE_PTR(cgroup);
        return 0;
}

_public_ int sd_peer_get_session(int fd, char **ret_session) {
        int r;

        assert_return(fd >= 0, -EBADF);

        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        r = getpeerpidref(fd, &pidref);
        if (r < 0)
                return r;

        return cg_pidref_get_session(&pidref, ret_session);
}

_public_ int sd_peer_get_owner_uid(int fd, uid_t *ret_uid) {
        int r;

        assert_return(fd >= 0, -EBADF);

        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        r = getpeerpidref(fd, &pidref);
        if (r < 0)
                return r;

        return cg_pidref_get_owner_uid(&pidref, ret_uid);
}

_public_ int sd_peer_get_unit(int fd, char **ret_unit) {
        int r;

        assert_return(fd >= 0, -EBADF);

        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        r = getpeerpidref(fd, &pidref);
        if (r < 0)
                return r;

        return cg_pidref_get_unit(&pidref, ret_unit);
}

_public_ int sd_peer_get_user_unit(int fd, char **ret_unit) {
        struct ucred ucred;
        int r;

        assert_return(fd >= 0, -EBADF);

        r = getpeercred(fd, &ucred);
        if (r < 0)
                return r;

        return cg_pid_get_user_unit(ucred.pid, ret_unit);
}

_public_ int sd_peer_get_machine_name(int fd, char **ret_machine) {
        struct ucred ucred;
        int r;

        assert_return(fd >= 0, -EBADF);

        r = getpeercred(fd, &ucred);
        if (r < 0)
                return r;

        return cg_pid_get_machine_name(ucred.pid, ret_machine);
}

_public_ int sd_peer_get_slice(int fd, char **ret_slice) {
        struct ucred ucred;
        int r;

        assert_return(fd >= 0, -EBADF);

        r = getpeercred(fd, &ucred);
        if (r < 0)
                return r;

        return cg_pid_get_slice(ucred.pid, ret_slice);
}

_public_ int sd_peer_get_user_slice(int fd, char **ret_slice) {
        struct ucred ucred;
        int r;

        assert_return(fd >= 0, -EBADF);

        r = getpeercred(fd, &ucred);
        if (r < 0)
                return r;

        return cg_pid_get_user_slice(ucred.pid, ret_slice);
}

_public_ int sd_peer_get_cgroup(int fd, char **ret_cgroup) {
        int r;

        assert_return(fd >= 0, -EBADF);

        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        r = getpeerpidref(fd, &pidref);
        if (r < 0)
                return r;

        _cleanup_free_ char *c = NULL;
        r = cg_pidref_get_path(&pidref, &c);
        if (r < 0)
                return r;

        if (ret_cgroup) {
                /* The internal APIs return the empty string for the root cgroup, let's return the "/" in the
                 * public APIs instead, as that's easier and less ambiguous for people to grok. */
                if (isempty(c)) {
                        r = free_and_strdup(&c, "/");
                        if (r < 0)
                                return r;
                }

                *ret_cgroup = TAKE_PTR(c);
        }

        return 0;
}

static int file_of_uid(uid_t uid, char **ret) {

        assert_return(uid_is_valid(uid), -EINVAL);
        assert(ret);

        if (asprintf(ret, "/run/systemd/users/" UID_FMT, uid) < 0)
                return -ENOMEM;

        return 0;
}

_public_ int sd_uid_get_state(uid_t uid, char **ret_state) {
        _cleanup_free_ char *p = NULL, *s = NULL;
        int r;

        r = file_of_uid(uid, &p);
        if (r < 0)
                return r;

        r = parse_env_file(/* f= */ NULL, p, "STATE", &s);
        if (r == -ENOENT)
                r = free_and_strdup(&s, "offline");
        if (r < 0)
                return r;
        if (isempty(s))
                return -EIO;

        if (ret_state)
                *ret_state = TAKE_PTR(s);
        return 0;
}

_public_ int sd_uid_get_display(uid_t uid, char **ret_display) {
        _cleanup_free_ char *p = NULL, *s = NULL;
        int r;

        r = file_of_uid(uid, &p);
        if (r < 0)
                return r;

        r = parse_env_file(/* f= */ NULL, p, "DISPLAY", &s);
        if (r == -ENOENT)
                return -ENODATA;
        if (r < 0)
                return r;
        if (isempty(s))
                return -ENODATA;

        if (ret_display)
                *ret_display = TAKE_PTR(s);
        return 0;
}

_public_ int sd_uid_get_login_time(uid_t uid, uint64_t *ret_usec) {
        _cleanup_free_ char *p = NULL, *s = NULL, *rt = NULL;
        int r;

        r = file_of_uid(uid, &p);
        if (r < 0)
                return r;

        r = parse_env_file(/* f= */ NULL, p, "STATE", &s, "REALTIME", &rt);
        if (r == -ENOENT)
                return -ENXIO;
        if (r < 0)
                return r;
        if (isempty(s) || isempty(rt))
                return -EIO;

        if (!STR_IN_SET(s, "active", "online"))
                return -ENXIO;

        return safe_atou64(rt, ret_usec);
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

        r = parse_env_file(/* f= */ NULL, filename,
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

static int uid_get_array(uid_t uid, const char *variable, char ***ret_array) {
        _cleanup_free_ char *p = NULL, *s = NULL;
        int r;

        assert(variable);

        r = file_of_uid(uid, &p);
        if (r < 0)
                return r;

        r = parse_env_file(/* f= */ NULL, p, variable, &s);
        if (r == -ENOENT || (r >= 0 && isempty(s))) {
                if (ret_array)
                        *ret_array = NULL;
                return 0;
        }
        if (r < 0)
                return r;

        _cleanup_strv_free_ char **a = strv_split(s, NULL);
        if (!a)
                return -ENOMEM;

        strv_uniq(a);
        r = (int) strv_length(a);

        if (ret_array)
                *ret_array = TAKE_PTR(a);

        return r;
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

static int file_of_session(const char *session, char **ret) {
        char *p;
        int r;

        assert(ret);

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

        *ret = p;
        return 0;
}

_public_ int sd_session_is_active(const char *session) {
        _cleanup_free_ char *p = NULL, *s = NULL;
        int r;

        r = file_of_session(session, &p);
        if (r < 0)
                return r;

        r = parse_env_file(/* f= */ NULL, p, "ACTIVE", &s);
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

        r = parse_env_file(/* f= */ NULL, p, "REMOTE", &s);
        if (r == -ENOENT)
                return -ENXIO;
        if (r < 0)
                return r;
        if (isempty(s))
                return -ENODATA;

        return parse_boolean(s);
}

_public_ int sd_session_get_extra_device_access(const char *session, char ***ret_ids) {
        _cleanup_free_ char *p = NULL, *s = NULL;
        int r;

        r = file_of_session(session, &p);
        if (r < 0)
                return r;

        r = parse_env_file(/* f= */ NULL, p, "EXTRA_DEVICE_ACCESS", &s);
        if (r == -ENOENT)
                return -ENXIO;
        if (r < 0)
                return r;

        _cleanup_strv_free_ char **ids = NULL;
        size_t n_ids = 0;
        if (!isempty(s)) {
                ids = strv_split(s, /* separators= */ NULL);
                if (!ids)
                        return -ENOMEM;

                n_ids = strv_length(ids);
        }

        if (ret_ids)
                *ret_ids = TAKE_PTR(ids);

        return n_ids;
}

_public_ int sd_session_get_state(const char *session, char **ret_state) {
        _cleanup_free_ char *p = NULL, *s = NULL;
        int r;

        r = file_of_session(session, &p);
        if (r < 0)
                return r;

        r = parse_env_file(/* f= */ NULL, p, "STATE", &s);
        if (r == -ENOENT)
                return -ENXIO;
        if (r < 0)
                return r;
        if (isempty(s))
                return -EIO;

        if (ret_state)
                *ret_state = TAKE_PTR(s);
        return 0;
}

_public_ int sd_session_get_uid(const char *session, uid_t *ret_uid) {
        int r;
        _cleanup_free_ char *p = NULL, *s = NULL;

        r = file_of_session(session, &p);
        if (r < 0)
                return r;

        r = parse_env_file(/* f= */ NULL, p, "UID", &s);
        if (r == -ENOENT)
                return -ENXIO;
        if (r < 0)
                return r;
        if (isempty(s))
                return -EIO;

        return parse_uid(s, ret_uid);
}

static int session_get_string(const char *session, const char *field, char **ret_value) {
        _cleanup_free_ char *p = NULL, *s = NULL;
        int r;

        assert(field);

        r = file_of_session(session, &p);
        if (r < 0)
                return r;

        r = parse_env_file(/* f= */ NULL, p, field, &s);
        if (r == -ENOENT)
                return -ENXIO;
        if (r < 0)
                return r;
        if (isempty(s))
                return -ENODATA;

        if (ret_value)
                *ret_value = TAKE_PTR(s);
        return 0;
}

_public_ int sd_session_get_username(const char *session, char **ret_username) {
        return session_get_string(session, "USER", ret_username);
}

_public_ int sd_session_get_seat(const char *session, char **ret_seat) {
        return session_get_string(session, "SEAT", ret_seat);
}

_public_ int sd_session_get_start_time(const char *session, uint64_t *ret_usec) {
        _cleanup_free_ char *p = NULL, *s = NULL;
        int r;

        r = file_of_session(session, &p);
        if (r < 0)
                return r;

        r = parse_env_file(/* f= */ NULL, p, "REALTIME", &s);
        if (r == -ENOENT)
                return -ENXIO;
        if (r < 0)
                return r;
        if (isempty(s))
                return -EIO;

        return safe_atou64(s, ret_usec);
}

_public_ int sd_session_get_tty(const char *session, char **ret_tty) {
        return session_get_string(session, "TTY", ret_tty);
}

_public_ int sd_session_get_vt(const char *session, unsigned *ret_vtnr) {
        _cleanup_free_ char *vtnr_string = NULL;
        int r;

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

_public_ int sd_session_get_class(const char *session, char **ret_clazz) {
        return session_get_string(session, "CLASS", ret_clazz);
}

_public_ int sd_session_get_desktop(const char *session, char **ret_desktop) {
        return session_get_string(session, "DESKTOP", ret_desktop);
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

_public_ int sd_session_get_leader(const char *session, pid_t *ret_leader) {
        _cleanup_free_ char *leader_string = NULL;
        int r;

        r = session_get_string(session, "LEADER", &leader_string);
        if (r < 0)
                return r;

        return parse_pid(leader_string, ret_leader);
}

_public_ int sd_seat_get_active(const char *seat, char **ret_session, uid_t *ret_uid) {
        _cleanup_free_ char *p = NULL, *s = NULL, *t = NULL;
        int r;

        r = file_of_seat(seat, &p);
        if (r < 0)
                return r;

        r = parse_env_file(/* f= */ NULL, p,
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

        r = parse_env_file(/* f= */ NULL, fname,
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

        r = parse_env_file(/* f= */ NULL, p,
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
        _cleanup_free_ uid_t *l = NULL;
        size_t n = 0;

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
                uid_t uid;

                if (!dirent_is_file(de))
                        continue;

                if (parse_uid(de->d_name, &uid) < 0)
                        continue;

                if (ret_users) {
                        if (!GREEDY_REALLOC(l, n + 1))
                                return -ENOMEM;

                        l[n] = uid;
                }

                n++;
        }

        if (n > INT_MAX)
                return -EOVERFLOW;

        if (ret_users)
                *ret_users = TAKE_PTR(l);

        return (int) n;
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

_public_ int sd_machine_get_class(const char *machine, char **ret_clazz) {
        _cleanup_free_ char *c = NULL;
        int r;

        if (streq_ptr(machine, ".host")) {
                c = strdup("host");
                if (!c)
                        return -ENOMEM;
        } else {
                if (!hostname_is_valid(machine, 0))
                        return -EINVAL;

                _cleanup_free_ char *p = path_join("/run/systemd/machines/", machine);
                if (!p)
                        return -ENOMEM;

                r = parse_env_file(/* f= */ NULL, p, "CLASS", &c);
                if (r == -ENOENT)
                        return -ENXIO;
                if (r < 0)
                        return r;
                if (!c)
                        return -EIO;
        }

        if (ret_clazz)
                *ret_clazz = TAKE_PTR(c);

        return 0;
}

_public_ int sd_machine_get_ifindices(const char *machine, int **ret_ifindices) {
        _cleanup_free_ char *netif_line = NULL, *p = NULL;
        int r;

        assert_return(hostname_is_valid(machine, 0), -EINVAL);

        p = path_join("/run/systemd/machines/", machine);
        if (!p)
                return -ENOMEM;

        r = parse_env_file(/* f= */ NULL, p, "NETIF", &netif_line);
        if (r == -ENOENT)
                return -ENXIO;
        if (r < 0)
                return r;
        if (!netif_line) {
                if (ret_ifindices)
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

_public_ int sd_login_monitor_new(const char *category, sd_login_monitor **ret) {
        _cleanup_close_ int fd = -EBADF;

        assert_return(ret, -EINVAL);

        fd = inotify_init1(IN_NONBLOCK|IN_CLOEXEC);
        if (fd < 0)
                return -errno;

        static const struct {
                const char *name;
                const char *path;
        } categories[] = {
                { "seat",     "/run/systemd/seats/"    },
                { "session",  "/run/systemd/sessions/" },
                { "uid",      "/run/systemd/users/"    },
                { "machine",  "/run/systemd/machines/" },
        };

        bool good = false;
        FOREACH_ELEMENT(c, categories) {
                if (category && !streq(category, c->name))
                        continue;

                if (inotify_add_watch(fd, c->path, IN_MOVED_TO|IN_DELETE) < 0)
                        return -errno;

                good = true;
        }

        if (!good)
                return -EINVAL;

        *ret = FD_TO_MONITOR(TAKE_FD(fd));
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

_public_ int sd_login_monitor_get_timeout(sd_login_monitor *m, uint64_t *ret_timeout_usec) {

        assert_return(m, -EINVAL);
        assert_return(ret_timeout_usec, -EINVAL);

        /* For now we will only return UINT64_MAX, since we don't
         * need any timeout. However, let's have this API to keep our
         * options open should we later on need it. */
        *ret_timeout_usec = UINT64_MAX;
        return 0;
}
