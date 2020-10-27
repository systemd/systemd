/* SPDX-License-Identifier: LGPL-2.1+ */

#include <alloca.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <utmp.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "format-util.h"
#include "macro.h"
#include "missing.h"
#include "parse-util.h"
#include "path-util.h"
#include "string-util.h"
#include "strv.h"
#include "user-util.h"
#include "utf8.h"

bool uid_is_valid(uid_t uid) {

        /* Also see POSIX IEEE Std 1003.1-2008, 2016 Edition, 3.436. */

        /* Some libc APIs use UID_INVALID as special placeholder */
        if (uid == (uid_t) UINT32_C(0xFFFFFFFF))
                return false;

        /* A long time ago UIDs where 16bit, hence explicitly avoid the 16bit -1 too */
        if (uid == (uid_t) UINT32_C(0xFFFF))
                return false;

        return true;
}

int parse_uid(const char *s, uid_t *ret) {
        uint32_t uid = 0;
        int r;

        assert(s);

        assert_cc(sizeof(uid_t) == sizeof(uint32_t));

        /* We are very strict when parsing UIDs, and prohibit +/- as prefix, leading zero as prefix, and
         * whitespace. We do this, since this call is often used in a context where we parse things as UID
         * first, and if that doesn't work we fall back to NSS. Thus we really want to make sure that UIDs
         * are parsed as UIDs only if they really really look like UIDs. */
        r = safe_atou32_full(s, 10
                             | SAFE_ATO_REFUSE_PLUS_MINUS
                             | SAFE_ATO_REFUSE_LEADING_ZERO
                             | SAFE_ATO_REFUSE_LEADING_WHITESPACE, &uid);
        if (r < 0)
                return r;

        if (!uid_is_valid(uid))
                return -ENXIO; /* we return ENXIO instead of EINVAL
                                * here, to make it easy to distuingish
                                * invalid numeric uids from invalid
                                * strings. */

        if (ret)
                *ret = uid;

        return 0;
}

char* getlogname_malloc(void) {
        uid_t uid;
        struct stat st;

        if (isatty(STDIN_FILENO) && fstat(STDIN_FILENO, &st) >= 0)
                uid = st.st_uid;
        else
                uid = getuid();

        return uid_to_name(uid);
}

char *getusername_malloc(void) {
        const char *e;

        e = getenv("USER");
        if (e)
                return strdup(e);

        return uid_to_name(getuid());
}

int get_user_creds(
                const char **username,
                uid_t *uid, gid_t *gid,
                const char **home,
                const char **shell) {

        struct passwd *p;
        uid_t u;

        assert(username);
        assert(*username);

        /* We enforce some special rules for uid=0 and uid=65534: in order to avoid NSS lookups for root we hardcode
         * their user record data. */

        if (STR_IN_SET(*username, "root", "0")) {
                *username = "root";

                if (uid)
                        *uid = 0;
                if (gid)
                        *gid = 0;

                if (home)
                        *home = "/root";

                if (shell)
                        *shell = "/bin/sh";

                return 0;
        }

        if (synthesize_nobody() &&
            STR_IN_SET(*username, NOBODY_USER_NAME, "65534")) {
                *username = NOBODY_USER_NAME;

                if (uid)
                        *uid = UID_NOBODY;
                if (gid)
                        *gid = GID_NOBODY;

                if (home)
                        *home = "/";

                if (shell)
                        *shell = "/sbin/nologin";

                return 0;
        }

        if (parse_uid(*username, &u) >= 0) {
                errno = 0;
                p = getpwuid(u);

                /* If there are multiple users with the same id, make
                 * sure to leave $USER to the configured value instead
                 * of the first occurrence in the database. However if
                 * the uid was configured by a numeric uid, then let's
                 * pick the real username from /etc/passwd. */
                if (p)
                        *username = p->pw_name;
        } else {
                errno = 0;
                p = getpwnam(*username);
        }

        if (!p)
                return errno > 0 ? -errno : -ESRCH;

        if (uid) {
                if (!uid_is_valid(p->pw_uid))
                        return -EBADMSG;

                *uid = p->pw_uid;
        }

        if (gid) {
                if (!gid_is_valid(p->pw_gid))
                        return -EBADMSG;

                *gid = p->pw_gid;
        }

        if (home)
                *home = p->pw_dir;

        if (shell)
                *shell = p->pw_shell;

        return 0;
}

static inline bool is_nologin_shell(const char *shell) {

        return PATH_IN_SET(shell,
                           /* 'nologin' is the friendliest way to disable logins for a user account. It prints a nice
                            * message and exits. Different distributions place the binary at different places though,
                            * hence let's list them all. */
                           "/bin/nologin",
                           "/sbin/nologin",
                           "/usr/bin/nologin",
                           "/usr/sbin/nologin",
                           /* 'true' and 'false' work too for the same purpose, but are less friendly as they don't do
                            * any message printing. Different distributions place the binary at various places but at
                            * least not in the 'sbin' directory. */
                           "/bin/false",
                           "/usr/bin/false",
                           "/bin/true",
                           "/usr/bin/true");
}

int get_user_creds_clean(
                const char **username,
                uid_t *uid, gid_t *gid,
                const char **home,
                const char **shell) {

        int r;

        /* Like get_user_creds(), but resets home/shell to NULL if they don't contain anything relevant. */

        r = get_user_creds(username, uid, gid, home, shell);
        if (r < 0)
                return r;

        if (shell &&
            (isempty(*shell) || is_nologin_shell(*shell)))
                *shell = NULL;

        if (home && empty_or_root(*home))
                *home = NULL;

        return 0;
}

int get_group_creds(const char **groupname, gid_t *gid) {
        struct group *g;
        gid_t id;

        assert(groupname);

        /* We enforce some special rules for gid=0: in order to avoid
         * NSS lookups for root we hardcode its data. */

        if (STR_IN_SET(*groupname, "root", "0")) {
                *groupname = "root";

                if (gid)
                        *gid = 0;

                return 0;
        }

        if (synthesize_nobody() &&
            STR_IN_SET(*groupname, NOBODY_GROUP_NAME, "65534")) {
                *groupname = NOBODY_GROUP_NAME;

                if (gid)
                        *gid = GID_NOBODY;

                return 0;
        }

        if (parse_gid(*groupname, &id) >= 0) {
                errno = 0;
                g = getgrgid(id);

                if (g)
                        *groupname = g->gr_name;
        } else {
                errno = 0;
                g = getgrnam(*groupname);
        }

        if (!g)
                return errno > 0 ? -errno : -ESRCH;

        if (gid) {
                if (!gid_is_valid(g->gr_gid))
                        return -EBADMSG;

                *gid = g->gr_gid;
        }

        return 0;
}

char* uid_to_name(uid_t uid) {
        char *ret;
        int r;

        /* Shortcut things to avoid NSS lookups */
        if (uid == 0)
                return strdup("root");
        if (synthesize_nobody() &&
            uid == UID_NOBODY)
                return strdup(NOBODY_USER_NAME);

        if (uid_is_valid(uid)) {
                long bufsize;

                bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
                if (bufsize <= 0)
                        bufsize = 4096;

                for (;;) {
                        struct passwd pwbuf, *pw = NULL;
                        _cleanup_free_ char *buf = NULL;

                        buf = malloc(bufsize);
                        if (!buf)
                                return NULL;

                        r = getpwuid_r(uid, &pwbuf, buf, (size_t) bufsize, &pw);
                        if (r == 0 && pw)
                                return strdup(pw->pw_name);
                        if (r != ERANGE)
                                break;

                        bufsize *= 2;
                }
        }

        if (asprintf(&ret, UID_FMT, uid) < 0)
                return NULL;

        return ret;
}

char* gid_to_name(gid_t gid) {
        char *ret;
        int r;

        if (gid == 0)
                return strdup("root");
        if (synthesize_nobody() &&
            gid == GID_NOBODY)
                return strdup(NOBODY_GROUP_NAME);

        if (gid_is_valid(gid)) {
                long bufsize;

                bufsize = sysconf(_SC_GETGR_R_SIZE_MAX);
                if (bufsize <= 0)
                        bufsize = 4096;

                for (;;) {
                        struct group grbuf, *gr = NULL;
                        _cleanup_free_ char *buf = NULL;

                        buf = malloc(bufsize);
                        if (!buf)
                                return NULL;

                        r = getgrgid_r(gid, &grbuf, buf, (size_t) bufsize, &gr);
                        if (r == 0 && gr)
                                return strdup(gr->gr_name);
                        if (r != ERANGE)
                                break;

                        bufsize *= 2;
                }
        }

        if (asprintf(&ret, GID_FMT, gid) < 0)
                return NULL;

        return ret;
}

int in_gid(gid_t gid) {
        gid_t *gids;
        int ngroups, r, i;

        if (getgid() == gid)
                return 1;

        if (getegid() == gid)
                return 1;

        if (!gid_is_valid(gid))
                return -EINVAL;

        ngroups = getgroups(0, NULL);
        if (ngroups < 0)
                return -errno;
        if (ngroups == 0)
                return 0;

        gids = newa(gid_t, ngroups);

        r = getgroups(ngroups, gids);
        if (r < 0)
                return -errno;

        for (i = 0; i < r; i++)
                if (gids[i] == gid)
                        return 1;

        return 0;
}

int in_group(const char *name) {
        int r;
        gid_t gid;

        r = get_group_creds(&name, &gid);
        if (r < 0)
                return r;

        return in_gid(gid);
}

int get_home_dir(char **_h) {
        struct passwd *p;
        const char *e;
        char *h;
        uid_t u;

        assert(_h);

        /* Take the user specified one */
        e = secure_getenv("HOME");
        if (e && path_is_absolute(e)) {
                h = strdup(e);
                if (!h)
                        return -ENOMEM;

                *_h = h;
                return 0;
        }

        /* Hardcode home directory for root and nobody to avoid NSS */
        u = getuid();
        if (u == 0) {
                h = strdup("/root");
                if (!h)
                        return -ENOMEM;

                *_h = h;
                return 0;
        }
        if (synthesize_nobody() &&
            u == UID_NOBODY) {
                h = strdup("/");
                if (!h)
                        return -ENOMEM;

                *_h = h;
                return 0;
        }

        /* Check the database... */
        errno = 0;
        p = getpwuid(u);
        if (!p)
                return errno > 0 ? -errno : -ESRCH;

        if (!path_is_absolute(p->pw_dir))
                return -EINVAL;

        h = strdup(p->pw_dir);
        if (!h)
                return -ENOMEM;

        *_h = h;
        return 0;
}

int get_shell(char **_s) {
        struct passwd *p;
        const char *e;
        char *s;
        uid_t u;

        assert(_s);

        /* Take the user specified one */
        e = getenv("SHELL");
        if (e) {
                s = strdup(e);
                if (!s)
                        return -ENOMEM;

                *_s = s;
                return 0;
        }

        /* Hardcode shell for root and nobody to avoid NSS */
        u = getuid();
        if (u == 0) {
                s = strdup("/bin/sh");
                if (!s)
                        return -ENOMEM;

                *_s = s;
                return 0;
        }
        if (synthesize_nobody() &&
            u == UID_NOBODY) {
                s = strdup("/sbin/nologin");
                if (!s)
                        return -ENOMEM;

                *_s = s;
                return 0;
        }

        /* Check the database... */
        errno = 0;
        p = getpwuid(u);
        if (!p)
                return errno > 0 ? -errno : -ESRCH;

        if (!path_is_absolute(p->pw_shell))
                return -EINVAL;

        s = strdup(p->pw_shell);
        if (!s)
                return -ENOMEM;

        *_s = s;
        return 0;
}

int reset_uid_gid(void) {
        int r;

        r = maybe_setgroups(0, NULL);
        if (r < 0)
                return r;

        if (setresgid(0, 0, 0) < 0)
                return -errno;

        if (setresuid(0, 0, 0) < 0)
                return -errno;

        return 0;
}

int take_etc_passwd_lock(const char *root) {

        struct flock flock = {
                .l_type = F_WRLCK,
                .l_whence = SEEK_SET,
                .l_start = 0,
                .l_len = 0,
        };

        const char *path;
        int fd, r;

        /* This is roughly the same as lckpwdf(), but not as awful. We
         * don't want to use alarm() and signals, hence we implement
         * our own trivial version of this.
         *
         * Note that shadow-utils also takes per-database locks in
         * addition to lckpwdf(). However, we don't given that they
         * are redundant as they invoke lckpwdf() first and keep
         * it during everything they do. The per-database locks are
         * awfully racy, and thus we just won't do them. */

        if (root)
                path = prefix_roota(root, ETC_PASSWD_LOCK_PATH);
        else
                path = ETC_PASSWD_LOCK_PATH;

        fd = open(path, O_WRONLY|O_CREAT|O_CLOEXEC|O_NOCTTY|O_NOFOLLOW, 0600);
        if (fd < 0)
                return log_debug_errno(errno, "Cannot open %s: %m", path);

        r = fcntl(fd, F_SETLKW, &flock);
        if (r < 0) {
                safe_close(fd);
                return log_debug_errno(errno, "Locking %s failed: %m", path);
        }

        return fd;
}

bool valid_user_group_name_full(const char *u, bool strict) {
        const char *i;
        long sz;

        /* Checks if the specified name is a valid user/group name. Also see POSIX IEEE Std 1003.1-2008, 2016 Edition,
         * 3.437. We are a bit stricter here however. Specifically we deviate from POSIX rules:
         *
         * - We require that names fit into the appropriate utmp field
         * - We don't allow empty user names
         * - No dots or digits in the first character
         *
         * If strict==true, additionally:
         * - We don't allow any dots (this conflicts with chown syntax which permits dots as user/group name separator)
         *
         * Note that other systems are even more restrictive, and don't permit underscores or uppercase characters.
         */

        if (isempty(u))
                return false;

        if (!(u[0] >= 'a' && u[0] <= 'z') &&
            !(u[0] >= 'A' && u[0] <= 'Z') &&
            u[0] != '_')
                return false;

        for (i = u+1; *i; i++)
                if (!((*i >= 'a' && *i <= 'z') ||
                      (*i >= 'A' && *i <= 'Z') ||
                      (*i >= '0' && *i <= '9') ||
                      IN_SET(*i, '_', '-') ||
                      (!strict && *i == '.')))
                        return false;

        sz = sysconf(_SC_LOGIN_NAME_MAX);
        assert_se(sz > 0);

        if ((size_t) (i-u) > (size_t) sz)
                return false;

        if ((size_t) (i-u) > UT_NAMESIZE - 1)
                return false;

        return true;
}

bool valid_user_group_name_or_id_full(const char *u, bool strict) {

        /* Similar as above, but is also fine with numeric UID/GID specifications, as long as they are in the
         * right range, and not the invalid user ids. */

        if (isempty(u))
                return false;

        if (valid_user_group_name_full(u, strict))
                return true;

        return parse_uid(u, NULL) >= 0;
}

bool valid_gecos(const char *d) {

        if (!d)
                return false;

        if (!utf8_is_valid(d))
                return false;

        if (string_has_cc(d, NULL))
                return false;

        /* Colons are used as field separators, and hence not OK */
        if (strchr(d, ':'))
                return false;

        return true;
}

bool valid_home(const char *p) {
        /* Note that this function is also called by valid_shell(), any
         * changes must account for that. */

        if (isempty(p))
                return false;

        if (!utf8_is_valid(p))
                return false;

        if (string_has_cc(p, NULL))
                return false;

        if (!path_is_absolute(p))
                return false;

        if (!path_is_normalized(p))
                return false;

        /* Colons are used as field separators, and hence not OK */
        if (strchr(p, ':'))
                return false;

        return true;
}

int maybe_setgroups(size_t size, const gid_t *list) {
        int r;

        /* Check if setgroups is allowed before we try to drop all the auxiliary groups */
        if (size == 0) { /* Dropping all aux groups? */
                _cleanup_free_ char *setgroups_content = NULL;
                bool can_setgroups;

                r = read_one_line_file("/proc/self/setgroups", &setgroups_content);
                if (r == -ENOENT)
                        /* Old kernels don't have /proc/self/setgroups, so assume we can use setgroups */
                        can_setgroups = true;
                else if (r < 0)
                        return r;
                else
                        can_setgroups = streq(setgroups_content, "allow");

                if (!can_setgroups) {
                        log_debug("Skipping setgroups(), /proc/self/setgroups is set to 'deny'");
                        return 0;
                }
        }

        if (setgroups(size, list) < 0)
                return -errno;

        return 0;
}

bool synthesize_nobody(void) {

#ifdef NOLEGACY
        return true;
#else
        /* Returns true when we shall synthesize the "nobody" user (which we do by default). This can be turned off by
         * touching /etc/systemd/dont-synthesize-nobody in order to provide upgrade compatibility with legacy systems
         * that used the "nobody" user name and group name for other UIDs/GIDs than 65534.
         *
         * Note that we do not employ any kind of synchronization on the following caching variable. If the variable is
         * accessed in multi-threaded programs in the worst case it might happen that we initialize twice, but that
         * shouldn't matter as each initialization should come to the same result. */
        static int cache = -1;

        if (cache < 0)
                cache = access("/etc/systemd/dont-synthesize-nobody", F_OK) < 0;

        return cache;
#endif
}

int putpwent_sane(const struct passwd *pw, FILE *stream) {
        assert(pw);
        assert(stream);

        errno = 0;
        if (putpwent(pw, stream) != 0)
                return errno > 0 ? -errno : -EIO;

        return 0;
}

int putspent_sane(const struct spwd *sp, FILE *stream) {
        assert(sp);
        assert(stream);

        errno = 0;
        if (putspent(sp, stream) != 0)
                return errno > 0 ? -errno : -EIO;

        return 0;
}

int putgrent_sane(const struct group *gr, FILE *stream) {
        assert(gr);
        assert(stream);

        errno = 0;
        if (putgrent(gr, stream) != 0)
                return errno > 0 ? -errno : -EIO;

        return 0;
}

#if ENABLE_GSHADOW
int putsgent_sane(const struct sgrp *sg, FILE *stream) {
        assert(sg);
        assert(stream);

        errno = 0;
        if (putsgent(sg, stream) != 0)
                return errno > 0 ? -errno : -EIO;

        return 0;
}
#endif

int fgetpwent_sane(FILE *stream, struct passwd **pw) {
        struct passwd *p;

        assert(pw);
        assert(stream);

        errno = 0;
        p = fgetpwent(stream);
        if (!p && errno != ENOENT)
                return errno > 0 ? -errno : -EIO;

        *pw = p;
        return !!p;
}

int fgetspent_sane(FILE *stream, struct spwd **sp) {
        struct spwd *s;

        assert(sp);
        assert(stream);

        errno = 0;
        s = fgetspent(stream);
        if (!s && errno != ENOENT)
                return errno > 0 ? -errno : -EIO;

        *sp = s;
        return !!s;
}

int fgetgrent_sane(FILE *stream, struct group **gr) {
        struct group *g;

        assert(gr);
        assert(stream);

        errno = 0;
        g = fgetgrent(stream);
        if (!g && errno != ENOENT)
                return errno > 0 ? -errno : -EIO;

        *gr = g;
        return !!g;
}

#if ENABLE_GSHADOW
int fgetsgent_sane(FILE *stream, struct sgrp **sg) {
        struct sgrp *s;

        assert(sg);
        assert(stream);

        errno = 0;
        s = fgetsgent(stream);
        if (!s && errno != ENOENT)
                return errno > 0 ? -errno : -EIO;

        *sg = s;
        return !!s;
}
#endif
