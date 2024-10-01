/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <pwd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#include "alloc-util.h"
#include "dlfcn-util.h"
#include "errno-list.h"
#include "format-util.h"
#include "log.h"
#include "main-func.h"
#include "nss-test-util.h"
#include "nss-util.h"
#include "path-util.h"
#include "parse-util.h"
#include "stdio-util.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"
#include "user-util.h"

static size_t arg_bufsize = 1024;

static void print_struct_passwd(const struct passwd *pwd) {
        log_info("        \"%s\" / "UID_FMT":"GID_FMT,
                 pwd->pw_name, pwd->pw_uid, pwd->pw_gid);
        log_info("        passwd=\"%s\"", pwd->pw_passwd);
        log_info("        gecos=\"%s\"", pwd->pw_gecos);
        log_info("        dir=\"%s\"", pwd->pw_dir);
        log_info("        shell=\"%s\"", pwd->pw_shell);
}

static void print_struct_group(const struct group *gr) {
        _cleanup_free_ char *members = NULL;

        log_info("        \"%s\" / "GID_FMT,
                 gr->gr_name, gr->gr_gid);
        log_info("        passwd=\"%s\"", gr->gr_passwd);

        assert_se(members = strv_join(gr->gr_mem, ", "));
        // FIXME: use shell_maybe_quote(SHELL_ESCAPE_EMPTY) when it becomes available
        log_info("        members=%s", members);
}

static void test_getpwnam_r(void *handle, const char *module, const char *name) {
        const char *fname;
        _nss_getpwnam_r_t f;
        char buffer[arg_bufsize];
        int errno1 = 999; /* nss-dns doesn't set those */
        enum nss_status status;
        char pretty_status[DECIMAL_STR_MAX(enum nss_status)];
        struct passwd pwd;

        fname = strjoina("_nss_", module, "_getpwnam_r");
        f = dlsym(handle, fname);
        log_debug("dlsym(0x%p, %s) → 0x%p", handle, fname, f);
        if (!f) {
                log_info("%s not defined", fname);
                return;
        }

        status = f(name, &pwd, buffer, sizeof buffer, &errno1);
        log_info("%s(\"%s\") → status=%s%-20serrno=%d/%s",
                 fname, name,
                 nss_status_to_string(status, pretty_status, sizeof pretty_status), "\n",
                 errno1, errno_to_name(errno1) ?: "---");
        if (status == NSS_STATUS_SUCCESS)
                print_struct_passwd(&pwd);
}

static void test_getgrnam_r(void *handle, const char *module, const char *name) {
        const char *fname;
        _nss_getgrnam_r_t f;
        char buffer[arg_bufsize];
        int errno1 = 999; /* nss-dns doesn't set those */
        enum nss_status status;
        char pretty_status[DECIMAL_STR_MAX(enum nss_status)];
        struct group gr;

        fname = strjoina("_nss_", module, "_getgrnam_r");
        f = dlsym(handle, fname);
        log_debug("dlsym(0x%p, %s) → 0x%p", handle, fname, f);
        if (!f) {
                log_info("%s not defined", fname);
                return;
        }

        status = f(name, &gr, buffer, sizeof buffer, &errno1);
        log_info("%s(\"%s\") → status=%s%-20serrno=%d/%s",
                 fname, name,
                 nss_status_to_string(status, pretty_status, sizeof pretty_status), "\n",
                 errno1, errno_to_name(errno1) ?: "---");
        if (status == NSS_STATUS_SUCCESS)
                print_struct_group(&gr);
}

static void test_getpwuid_r(void *handle, const char *module, uid_t uid) {
        const char *fname;
        _nss_getpwuid_r_t f;
        char buffer[arg_bufsize];
        int errno1 = 999; /* nss-dns doesn't set those */
        enum nss_status status;
        char pretty_status[DECIMAL_STR_MAX(enum nss_status)];
        struct passwd pwd;

        fname = strjoina("_nss_", module, "_getpwuid_r");
        f = dlsym(handle, fname);
        log_debug("dlsym(0x%p, %s) → 0x%p", handle, fname, f);
        if (!f) {
                log_info("%s not defined", fname);
                return;
        }

        status = f(uid, &pwd, buffer, sizeof buffer, &errno1);
        log_info("%s("UID_FMT") → status=%s%-20serrno=%d/%s",
                 fname, uid,
                 nss_status_to_string(status, pretty_status, sizeof pretty_status), "\n",
                 errno1, errno_to_name(errno1) ?: "---");
        if (status == NSS_STATUS_SUCCESS)
                print_struct_passwd(&pwd);
}

static void test_getgrgid_r(void *handle, const char *module, gid_t gid) {
        const char *fname;
        _nss_getgrgid_r_t f;
        char buffer[arg_bufsize];
        int errno1 = 999; /* nss-dns doesn't set those */
        enum nss_status status;
        char pretty_status[DECIMAL_STR_MAX(enum nss_status)];
        struct group gr;

        fname = strjoina("_nss_", module, "_getgrgid_r");
        f = dlsym(handle, fname);
        log_debug("dlsym(0x%p, %s) → 0x%p", handle, fname, f);
        if (!f) {
                log_info("%s not defined", fname);
                return;
        }

        status = f(gid, &gr, buffer, sizeof buffer, &errno1);
        log_info("%s("GID_FMT") → status=%s%-20serrno=%d/%s",
                 fname, gid,
                 nss_status_to_string(status, pretty_status, sizeof pretty_status), "\n",
                 errno1, errno_to_name(errno1) ?: "---");
        if (status == NSS_STATUS_SUCCESS)
                print_struct_group(&gr);
}

static void test_byname(void *handle, const char *module, const char *name) {
        test_getpwnam_r(handle, module, name);
        test_getgrnam_r(handle, module, name);
        puts("");
}

static void test_byuid(void *handle, const char *module, uid_t uid) {
        test_getpwuid_r(handle, module, uid);
        test_getgrgid_r(handle, module, uid);
        puts("");
}

static int test_one_module(const char *dir,
                           const char *module,
                           char **names) {

        log_info("======== %s ========", module);

        _cleanup_(dlclosep) void *handle = nss_open_handle(dir, module, RTLD_NOW|RTLD_NODELETE);
        if (!handle)
                return -EINVAL;

        STRV_FOREACH(name, names)
                test_byname(handle, module, *name);

        STRV_FOREACH(name, names) {
                uid_t uid;

                assert_cc(sizeof(uid_t) == sizeof(uint32_t));
                /* We use safe_atou32 because we don't want to refuse invalid uids. */
                if (safe_atou32(*name, &uid) < 0)
                        continue;

                test_byuid(handle, module, uid);
        }

        log_info(" ");
        return 0;
}

static int parse_argv(int argc, char **argv,
                      char ***the_modules,
                      char ***the_names) {

        _cleanup_strv_free_ char **modules = NULL, **names = NULL;
        const char *p;
        int r;

        p = getenv("SYSTEMD_TEST_NSS_BUFSIZE");
        if (p) {
                r = safe_atozu(p, &arg_bufsize);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse $SYSTEMD_TEST_NSS_BUFSIZE");
        }

        if (argc > 1)
                modules = strv_new(argv[1]);
        else
                modules = strv_new(
#if ENABLE_NSS_SYSTEMD
                                "systemd",
#endif
#if ENABLE_NSS_MYMACHINES
                                "mymachines",
#endif
                                NULL);
        assert_se(modules);

        if (argc > 2)
                names = strv_copy(strv_skip(argv, 2));
        else
                names = strv_new("root",
                                 NOBODY_USER_NAME,
                                 "foo_no_such_user",
                                 "0",
                                 "65534");
        assert_se(names);

        *the_modules = TAKE_PTR(modules);
        *the_names = TAKE_PTR(names);
        return 0;
}

static int run(int argc, char **argv) {
        _cleanup_free_ char *dir = NULL;
        _cleanup_strv_free_ char **modules = NULL, **names = NULL;
        int r;

        test_setup_logging(LOG_INFO);

        r = parse_argv(argc, argv, &modules, &names);
        if (r < 0)
                return log_error_errno(r, "Failed to parse arguments: %m");

        assert_se(path_extract_directory(argv[0], &dir) >= 0);

        STRV_FOREACH(module, modules) {
                r = test_one_module(dir, *module, names);
                if (r < 0)
                        return r;
        }

        return 0;
}

DEFINE_MAIN_FUNCTION(run);
