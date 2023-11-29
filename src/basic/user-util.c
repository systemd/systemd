/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#include <utmp.h>

#include "sd-messages.h"

#include "alloc-util.h"
#include "chase.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "format-util.h"
#include "lock-util.h"
#include "macro.h"
#include "mkdir.h"
#include "parse-util.h"
#include "path-util.h"
#include "random-util.h"
#include "string-util.h"
#include "strv.h"
#include "user-util.h"
#include "utf8.h"

bool uid_is_valid(uid_t uid) {

        /* Also see POSIX IEEE Std 1003.1-2008, 2016 Edition, 3.436. */

        /* Some libc APIs use UID_INVALID as special placeholder */
        if (uid == (uid_t) UINT32_C(0xFFFFFFFF))
                return false;

        /* A long time ago UIDs where 16 bit, hence explicitly avoid the 16-bit -1 too */
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
                                * here, to make it easy to distinguish
                                * invalid numeric uids from invalid
                                * strings. */

        if (ret)
                *ret = uid;

        return 0;
}

int parse_uid_range(const char *s, uid_t *ret_lower, uid_t *ret_upper) {
        _cleanup_free_ char *word = NULL;
        uid_t l, u;
        int r;

        assert(s);
        assert(ret_lower);
        assert(ret_upper);

        r = extract_first_word(&s, &word, "-", EXTRACT_DONT_COALESCE_SEPARATORS);
        if (r < 0)
                return r;
        if (r == 0)
                return -EINVAL;

        r = parse_uid(word, &l);
        if (r < 0)
                return r;

        /* Check for the upper bound and extract it if needed */
        if (!s)
                /* Single number with no dash. */
                u = l;
        else if (!*s)
                /* Trailing dash is an error. */
                return -EINVAL;
        else {
                r = parse_uid(s, &u);
                if (r < 0)
                        return r;

                if (l > u)
                        return -EINVAL;
        }

        *ret_lower = l;
        *ret_upper = u;
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

char* getusername_malloc(void) {
        const char *e;

        e = secure_getenv("USER");
        if (e)
                return strdup(e);

        return uid_to_name(getuid());
}

bool is_nologin_shell(const char *shell) {
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

const char* default_root_shell_at(int rfd) {
        /* We want to use the preferred shell, i.e. DEFAULT_USER_SHELL, which usually
         * will be /bin/bash. Fall back to /bin/sh if DEFAULT_USER_SHELL is not found,
         * or any access errors. */

        assert(rfd >= 0 || rfd == AT_FDCWD);

        int r = chaseat(rfd, DEFAULT_USER_SHELL, CHASE_AT_RESOLVE_IN_ROOT, NULL, NULL);
        if (r < 0 && r != -ENOENT)
                log_debug_errno(r, "Failed to look up shell '%s': %m", DEFAULT_USER_SHELL);
        if (r > 0)
                return DEFAULT_USER_SHELL;

        return "/bin/sh";
}

const char* default_root_shell(const char *root) {
        _cleanup_close_ int rfd = -EBADF;

        rfd = open(empty_to_root(root), O_CLOEXEC | O_DIRECTORY | O_PATH);
        if (rfd < 0)
                return "/bin/sh";

        return default_root_shell_at(rfd);
}

static int synthesize_user_creds(
                const char **username,
                uid_t *uid, gid_t *gid,
                const char **home,
                const char **shell,
                UserCredsFlags flags) {

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
                        *shell = default_root_shell(NULL);

                return 0;
        }

        if (STR_IN_SET(*username, NOBODY_USER_NAME, "65534") &&
            synthesize_nobody()) {
                *username = NOBODY_USER_NAME;

                if (uid)
                        *uid = UID_NOBODY;
                if (gid)
                        *gid = GID_NOBODY;

                if (home)
                        *home = FLAGS_SET(flags, USER_CREDS_CLEAN) ? NULL : "/";

                if (shell)
                        *shell = FLAGS_SET(flags, USER_CREDS_CLEAN) ? NULL : NOLOGIN;

                return 0;
        }

        return -ENOMEDIUM;
}

int get_user_creds(
                const char **username,
                uid_t *uid, gid_t *gid,
                const char **home,
                const char **shell,
                UserCredsFlags flags) {

        uid_t u = UID_INVALID;
        struct passwd *p;
        int r;

        assert(username);
        assert(*username);

        if (!FLAGS_SET(flags, USER_CREDS_PREFER_NSS) ||
            (!home && !shell)) {

                /* So here's the deal: normally, we'll try to synthesize all records we can synthesize, and override
                 * the user database with that. However, if the user specifies USER_CREDS_PREFER_NSS then the
                 * user database will override the synthetic records instead — except if the user is only interested in
                 * the UID and/or GID (but not the home directory, or the shell), in which case we'll always override
                 * the user database (i.e. the USER_CREDS_PREFER_NSS flag has no effect in this case). Why?
                 * Simply because there are valid usecase where the user might change the home directory or the shell
                 * of the relevant users, but changing the UID/GID mappings for them is something we explicitly don't
                 * support. */

                r = synthesize_user_creds(username, uid, gid, home, shell, flags);
                if (r >= 0)
                        return 0;
                if (r != -ENOMEDIUM) /* not a username we can synthesize */
                        return r;
        }

        if (parse_uid(*username, &u) >= 0) {
                errno = 0;
                p = getpwuid(u);

                /* If there are multiple users with the same id, make sure to leave $USER to the configured value
                 * instead of the first occurrence in the database. However if the uid was configured by a numeric uid,
                 * then let's pick the real username from /etc/passwd. */
                if (p)
                        *username = p->pw_name;
                else if (FLAGS_SET(flags, USER_CREDS_ALLOW_MISSING) && !gid && !home && !shell) {

                        /* If the specified user is a numeric UID and it isn't in the user database, and the caller
                         * passed USER_CREDS_ALLOW_MISSING and was only interested in the UID, then just return that
                         * and don't complain. */

                        if (uid)
                                *uid = u;

                        return 0;
                }
        } else {
                errno = 0;
                p = getpwnam(*username);
        }
        if (!p) {
                /* getpwnam() may fail with ENOENT if /etc/passwd is missing.
                 * For us that is equivalent to the name not being defined. */
                r = IN_SET(errno, 0, ENOENT) ? -ESRCH : -errno;

                /* If the user requested that we only synthesize as fallback, do so now */
                if (FLAGS_SET(flags, USER_CREDS_PREFER_NSS)) {
                        if (synthesize_user_creds(username, uid, gid, home, shell, flags) >= 0)
                                return 0;
                }

                return r;
        }

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

        if (home) {
                if (FLAGS_SET(flags, USER_CREDS_CLEAN) &&
                    (empty_or_root(p->pw_dir) ||
                     !path_is_valid(p->pw_dir) ||
                     !path_is_absolute(p->pw_dir)))
                        *home = NULL; /* Note: we don't insist on normalized paths, since there are setups that have /./ in the path */
                else
                        *home = p->pw_dir;
        }

        if (shell) {
                if (FLAGS_SET(flags, USER_CREDS_CLEAN) &&
                    (isempty(p->pw_shell) ||
                     !path_is_valid(p->pw_dir) ||
                     !path_is_absolute(p->pw_shell) ||
                     is_nologin_shell(p->pw_shell)))
                        *shell = NULL;
                else
                        *shell = p->pw_shell;
        }

        return 0;
}

int get_group_creds(const char **groupname, gid_t *gid, UserCredsFlags flags) {
        struct group *g;
        gid_t id;

        assert(groupname);

        /* We enforce some special rules for gid=0: in order to avoid NSS lookups for root we hardcode its data. */

        if (STR_IN_SET(*groupname, "root", "0")) {
                *groupname = "root";

                if (gid)
                        *gid = 0;

                return 0;
        }

        if (STR_IN_SET(*groupname, NOBODY_GROUP_NAME, "65534") &&
            synthesize_nobody()) {
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
                else if (FLAGS_SET(flags, USER_CREDS_ALLOW_MISSING)) {
                        if (gid)
                                *gid = id;

                        return 0;
                }
        } else {
                errno = 0;
                g = getgrnam(*groupname);
        }

        if (!g)
                /* getgrnam() may fail with ENOENT if /etc/group is missing.
                 * For us that is equivalent to the name not being defined. */
                return IN_SET(errno, 0, ENOENT) ? -ESRCH : -errno;

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
        if (uid == UID_NOBODY && synthesize_nobody())
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

                        if (bufsize > LONG_MAX/2) /* overflow check */
                                return NULL;

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
        if (gid == GID_NOBODY && synthesize_nobody())
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

                        if (bufsize > LONG_MAX/2) /* overflow check */
                                return NULL;

                        bufsize *= 2;
                }
        }

        if (asprintf(&ret, GID_FMT, gid) < 0)
                return NULL;

        return ret;
}

static bool gid_list_has(const gid_t *list, size_t size, gid_t val) {
        for (size_t i = 0; i < size; i++)
                if (list[i] == val)
                        return true;
        return false;
}

int in_gid(gid_t gid) {
        _cleanup_free_ gid_t *gids = NULL;
        int ngroups;

        if (getgid() == gid)
                return 1;

        if (getegid() == gid)
                return 1;

        if (!gid_is_valid(gid))
                return -EINVAL;

        ngroups = getgroups_alloc(&gids);
        if (ngroups < 0)
                return ngroups;

        return gid_list_has(gids, ngroups, gid);
}

int in_group(const char *name) {
        int r;
        gid_t gid;

        r = get_group_creds(&name, &gid, 0);
        if (r < 0)
                return r;

        return in_gid(gid);
}

int merge_gid_lists(const gid_t *list1, size_t size1, const gid_t *list2, size_t size2, gid_t **ret) {
        size_t nresult = 0;
        assert(ret);

        if (size2 > INT_MAX - size1)
                return -ENOBUFS;

        gid_t *buf = new(gid_t, size1 + size2);
        if (!buf)
                return -ENOMEM;

        /* Duplicates need to be skipped on merging, otherwise they'll be passed on and stored in the kernel. */
        for (size_t i = 0; i < size1; i++)
                if (!gid_list_has(buf, nresult, list1[i]))
                        buf[nresult++] = list1[i];
        for (size_t i = 0; i < size2; i++)
                if (!gid_list_has(buf, nresult, list2[i]))
                        buf[nresult++] = list2[i];
        *ret = buf;
        return (int)nresult;
}

int getgroups_alloc(gid_t** gids) {
        gid_t *allocated;
        _cleanup_free_  gid_t *p = NULL;
        int ngroups = 8;
        unsigned attempt = 0;

        allocated = new(gid_t, ngroups);
        if (!allocated)
                return -ENOMEM;
        p = allocated;

        for (;;) {
                ngroups = getgroups(ngroups, p);
                if (ngroups >= 0)
                        break;
                if (errno != EINVAL)
                        return -errno;

                /* Give up eventually */
                if (attempt++ > 10)
                        return -EINVAL;

                /* Get actual size needed, and size the array explicitly. Note that this is potentially racy
                 * to use (in multi-threaded programs), hence let's call this in a loop. */
                ngroups = getgroups(0, NULL);
                if (ngroups < 0)
                        return -errno;
                if (ngroups == 0)
                        return false;

                free(allocated);

                p = allocated = new(gid_t, ngroups);
                if (!allocated)
                        return -ENOMEM;
        }

        *gids = TAKE_PTR(p);
        return ngroups;
}

int get_home_dir(char **ret) {
        struct passwd *p;
        const char *e;
        uid_t u;

        assert(ret);

        /* Take the user specified one */
        e = secure_getenv("HOME");
        if (e && path_is_valid(e) && path_is_absolute(e))
                goto found;

        /* Hardcode home directory for root and nobody to avoid NSS */
        u = getuid();
        if (u == 0) {
                e = "/root";
                goto found;
        }

        if (u == UID_NOBODY && synthesize_nobody()) {
                e = "/";
                goto found;
        }

        /* Check the database... */
        errno = 0;
        p = getpwuid(u);
        if (!p)
                return errno_or_else(ESRCH);
        e = p->pw_dir;

        if (!path_is_valid(e) || !path_is_absolute(e))
                return -EINVAL;

 found:
        return path_simplify_alloc(e, ret);
}

int get_shell(char **ret) {
        struct passwd *p;
        const char *e;
        uid_t u;

        assert(ret);

        /* Take the user specified one */
        e = secure_getenv("SHELL");
        if (e && path_is_valid(e) && path_is_absolute(e))
                goto found;

        /* Hardcode shell for root and nobody to avoid NSS */
        u = getuid();
        if (u == 0) {
                e = default_root_shell(NULL);
                goto found;
        }
        if (u == UID_NOBODY && synthesize_nobody()) {
                e = NOLOGIN;
                goto found;
        }

        /* Check the database... */
        errno = 0;
        p = getpwuid(u);
        if (!p)
                return errno_or_else(ESRCH);
        e = p->pw_shell;

        if (!path_is_valid(e) || !path_is_absolute(e))
                return -EINVAL;

 found:
        return path_simplify_alloc(e, ret);
}

int fully_set_uid_gid(uid_t uid, gid_t gid, const gid_t supplementary_gids[], size_t n_supplementary_gids) {
        int r;

        assert(supplementary_gids || n_supplementary_gids == 0);

        /* Sets all UIDs and all GIDs to the specified ones. Drops all auxiliary GIDs */

        r = maybe_setgroups(n_supplementary_gids, supplementary_gids);
        if (r < 0)
                return r;

        if (gid_is_valid(gid))
                if (setresgid(gid, gid, gid) < 0)
                        return -errno;

        if (uid_is_valid(uid))
                if (setresuid(uid, uid, uid) < 0)
                        return -errno;

        return 0;
}

int take_etc_passwd_lock(const char *root) {
        int r;

        /* This is roughly the same as lckpwdf(), but not as awful. We don't want to use alarm() and signals,
         * hence we implement our own trivial version of this.
         *
         * Note that shadow-utils also takes per-database locks in addition to lckpwdf(). However, we don't,
         * given that they are redundant: they invoke lckpwdf() first and keep it during everything they do.
         * The per-database locks are awfully racy, and thus we just won't do them. */

        _cleanup_free_ char *path = path_join(root, ETC_PASSWD_LOCK_PATH);
        if (!path)
                return log_oom_debug();

        (void) mkdir_parents(path, 0755);

        _cleanup_close_ int fd = open(path, O_WRONLY|O_CREAT|O_CLOEXEC|O_NOCTTY|O_NOFOLLOW, 0600);
        if (fd < 0)
                return log_debug_errno(errno, "Cannot open %s: %m", path);

        r = unposix_lock(fd, LOCK_EX);
        if (r < 0)
                return log_debug_errno(r, "Locking %s failed: %m", path);

        return TAKE_FD(fd);
}

bool valid_user_group_name(const char *u, ValidUserFlags flags) {
        const char *i;

        /* Checks if the specified name is a valid user/group name. There are two flavours of this call:
         * strict mode is the default which is POSIX plus some extra rules; and relaxed mode where we accept
         * pretty much everything except the really worst offending names.
         *
         * Whenever we synthesize users ourselves we should use the strict mode. But when we process users
         * created by other stuff, let's be more liberal. */

        if (isempty(u)) /* An empty user name is never valid */
                return false;

        if (parse_uid(u, NULL) >= 0) /* Something that parses as numeric UID string is valid exactly when the
                                      * flag for it is set */
                return FLAGS_SET(flags, VALID_USER_ALLOW_NUMERIC);

        if (FLAGS_SET(flags, VALID_USER_RELAX)) {

                /* In relaxed mode we just check very superficially. Apparently SSSD and other stuff is
                 * extremely liberal (way too liberal if you ask me, even inserting "@" in user names, which
                 * is bound to cause problems for example when used with an MTA), hence only filter the most
                 * obvious cases, or where things would result in an invalid entry if such a user name would
                 * show up in /etc/passwd (or equivalent getent output).
                 *
                 * Note that we stepped far out of POSIX territory here. It's not our fault though, but
                 * SSSD's, Samba's and everybody else who ignored POSIX on this. (I mean, I am happy to step
                 * outside of POSIX' bounds any day, but I must say in this case I probably wouldn't
                 * have...) */

                if (startswith(u, " ") || endswith(u, " ")) /* At least expect whitespace padding is removed
                                                             * at front and back (accept in the middle, since
                                                             * that's apparently a thing on Windows). Note
                                                             * that this also blocks usernames consisting of
                                                             * whitespace only. */
                        return false;

                if (!utf8_is_valid(u)) /* We want to synthesize JSON from this, hence insist on UTF-8 */
                        return false;

                if (string_has_cc(u, NULL)) /* CC characters are just dangerous (and \n in particular is the
                                             * record separator in /etc/passwd), so we can't allow that. */
                        return false;

                if (strpbrk(u, ":/")) /* Colons are the field separator in /etc/passwd, we can't allow
                                       * that. Slashes are special to file systems paths and user names
                                       * typically show up in the file system as home directories, hence
                                       * don't allow slashes. */
                        return false;

                if (in_charset(u, "0123456789")) /* Don't allow fully numeric strings, they might be confused
                                                  * with UIDs (note that this test is more broad than
                                                  * the parse_uid() test above, as it will cover more than
                                                  * the 32-bit range, and it will detect 65535 (which is in
                                                  * invalid UID, even though in the unsigned 32 bit range) */
                        return false;

                if (u[0] == '-' && in_charset(u + 1, "0123456789")) /* Don't allow negative fully numeric
                                                                     * strings either. After all some people
                                                                     * write 65535 as -1 (even though that's
                                                                     * not even true on 32-bit uid_t
                                                                     * anyway) */
                        return false;

                if (dot_or_dot_dot(u)) /* User names typically become home directory names, and these two are
                                        * special in that context, don't allow that. */
                        return false;

                /* Compare with strict result and warn if result doesn't match */
                if (FLAGS_SET(flags, VALID_USER_WARN) && !valid_user_group_name(u, 0))
                        log_struct(LOG_NOTICE,
                                   LOG_MESSAGE("Accepting user/group name '%s', which does not match strict user/group name rules.", u),
                                   "USER_GROUP_NAME=%s", u,
                                   "MESSAGE_ID=" SD_MESSAGE_UNSAFE_USER_NAME_STR);

                /* Note that we make no restrictions on the length in relaxed mode! */
        } else {
                long sz;
                size_t l;

                /* Also see POSIX IEEE Std 1003.1-2008, 2016 Edition, 3.437. We are a bit stricter here
                 * however. Specifically we deviate from POSIX rules:
                 *
                 * - We don't allow empty user names (see above)
                 * - We require that names fit into the appropriate utmp field
                 * - We don't allow any dots (this conflicts with chown syntax which permits dots as user/group name separator)
                 * - We don't allow dashes or digit as the first character
                 *
                 * Note that other systems are even more restrictive, and don't permit underscores or uppercase characters.
                 */

                if (!ascii_isalpha(u[0]) &&
                    u[0] != '_')
                        return false;

                for (i = u+1; *i; i++)
                        if (!ascii_isalpha(*i) &&
                            !ascii_isdigit(*i) &&
                            !IN_SET(*i, '_', '-'))
                                return false;

                l = i - u;

                sz = sysconf(_SC_LOGIN_NAME_MAX);
                assert_se(sz > 0);

                if (l > (size_t) sz)
                        return false;
                if (l > NAME_MAX) /* must fit in a filename */
                        return false;
                if (l > UT_NAMESIZE - 1)
                        return false;
        }

        return true;
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

char* mangle_gecos(const char *d) {
        char *mangled;

        /* Makes sure the provided string becomes valid as a GEGOS field, by dropping bad chars. glibc's
         * putwent() only changes \n and : to spaces. We do more: replace all CC too, and remove invalid
         * UTF-8 */

        mangled = strdup(d);
        if (!mangled)
                return NULL;

        for (char *i = mangled; *i; i++) {
                int len;

                if ((uint8_t) *i < (uint8_t) ' ' || *i == ':') {
                        *i = ' ';
                        continue;
                }

                len = utf8_encoded_valid_unichar(i, SIZE_MAX);
                if (len < 0) {
                        *i = ' ';
                        continue;
                }

                i += len - 1;
        }

        return mangled;
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

        return RET_NERRNO(setgroups(size, list));
}

bool synthesize_nobody(void) {
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
}

int putpwent_sane(const struct passwd *pw, FILE *stream) {
        assert(pw);
        assert(stream);

        errno = 0;
        if (putpwent(pw, stream) != 0)
                return errno_or_else(EIO);

        return 0;
}

int putspent_sane(const struct spwd *sp, FILE *stream) {
        assert(sp);
        assert(stream);

        errno = 0;
        if (putspent(sp, stream) != 0)
                return errno_or_else(EIO);

        return 0;
}

int putgrent_sane(const struct group *gr, FILE *stream) {
        assert(gr);
        assert(stream);

        errno = 0;
        if (putgrent(gr, stream) != 0)
                return errno_or_else(EIO);

        return 0;
}

#if ENABLE_GSHADOW
int putsgent_sane(const struct sgrp *sg, FILE *stream) {
        assert(sg);
        assert(stream);

        errno = 0;
        if (putsgent(sg, stream) != 0)
                return errno_or_else(EIO);

        return 0;
}
#endif

int fgetpwent_sane(FILE *stream, struct passwd **pw) {
        assert(stream);
        assert(pw);

        errno = 0;
        struct passwd *p = fgetpwent(stream);
        if (!p && errno != ENOENT)
                return errno_or_else(EIO);

        *pw = p;
        return !!p;
}

int fgetspent_sane(FILE *stream, struct spwd **sp) {
        assert(stream);
        assert(sp);

        errno = 0;
        struct spwd *s = fgetspent(stream);
        if (!s && errno != ENOENT)
                return errno_or_else(EIO);

        *sp = s;
        return !!s;
}

int fgetgrent_sane(FILE *stream, struct group **gr) {
        assert(stream);
        assert(gr);

        errno = 0;
        struct group *g = fgetgrent(stream);
        if (!g && errno != ENOENT)
                return errno_or_else(EIO);

        *gr = g;
        return !!g;
}

#if ENABLE_GSHADOW
int fgetsgent_sane(FILE *stream, struct sgrp **sg) {
        assert(stream);
        assert(sg);

        errno = 0;
        struct sgrp *s = fgetsgent(stream);
        if (!s && errno != ENOENT)
                return errno_or_else(EIO);

        *sg = s;
        return !!s;
}
#endif

int is_this_me(const char *username) {
        uid_t uid;
        int r;

        /* Checks if the specified username is our current one. Passed string might be a UID or a user name. */

        r = get_user_creds(&username, &uid, NULL, NULL, NULL, USER_CREDS_ALLOW_MISSING);
        if (r < 0)
                return r;

        return uid == getuid();
}

const char* get_home_root(void) {
        const char *e;

        /* For debug purposes allow overriding where we look for home dirs */
        e = secure_getenv("SYSTEMD_HOME_ROOT");
        if (e && path_is_absolute(e) && path_is_normalized(e))
                return e;

        return "/home";
}
