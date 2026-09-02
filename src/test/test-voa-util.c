/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "alloc-util.h"
#include "conf-files.h"
#include "fd-util.h"
#include "fileio.h"
#include "mkdir.h"
#include "path-util.h"
#include "rm-rf.h"
#include "strv.h"
#include "tests.h"
#include "tmpfile-util.h"
#include "voa-util.h"

TEST(voa_identifier_is_valid) {
        ASSERT_TRUE(voa_identifier_is_valid("fedora", /* allow_colon= */ false));
        ASSERT_TRUE(voa_identifier_is_valid("repository-metadata", /* allow_colon= */ false));
        ASSERT_TRUE(voa_identifier_is_valid("x509", /* allow_colon= */ false));
        ASSERT_TRUE(voa_identifier_is_valid("1.0_a", /* allow_colon= */ false));
        ASSERT_FALSE(voa_identifier_is_valid("", /* allow_colon= */ false));
        ASSERT_FALSE(voa_identifier_is_valid(NULL, /* allow_colon= */ false));
        ASSERT_FALSE(voa_identifier_is_valid(".", /* allow_colon= */ false));
        ASSERT_FALSE(voa_identifier_is_valid("..", /* allow_colon= */ false));
        ASSERT_FALSE(voa_identifier_is_valid("Fedora", /* allow_colon= */ false));
        ASSERT_FALSE(voa_identifier_is_valid("a/b", /* allow_colon= */ false));
        ASSERT_FALSE(voa_identifier_is_valid("a b", /* allow_colon= */ false));
        char long_name[257];
        memset(long_name, 'a', sizeof(long_name) - 1);
        long_name[sizeof(long_name) - 1] = 0;
        ASSERT_FALSE(voa_identifier_is_valid(long_name, /* allow_colon= */ false));
        long_name[sizeof(long_name) - 2] = 0;
        ASSERT_TRUE(voa_identifier_is_valid(long_name, /* allow_colon= */ false));
        ASSERT_FALSE(voa_identifier_is_valid("a:b", /* allow_colon= */ false));
        ASSERT_TRUE(voa_identifier_is_valid("a:b", /* allow_colon= */ true));
}

TEST(voa_os_is_valid) {
        ASSERT_TRUE(voa_os_is_valid("arch"));
        ASSERT_TRUE(voa_os_is_valid("fedora:43:workstation"));
        ASSERT_TRUE(voa_os_is_valid("arch:::cashier-system:1.0.0"));
        ASSERT_FALSE(voa_os_is_valid(""));
        ASSERT_FALSE(voa_os_is_valid("arch:"));
        ASSERT_FALSE(voa_os_is_valid(":arch"));
        ASSERT_FALSE(voa_os_is_valid("a:b:c:d:e:f"));
        ASSERT_FALSE(voa_os_is_valid("Arch"));
}

static void write_os_release(const char *root, const char *contents) {
        _cleanup_free_ char *p = ASSERT_NOT_NULL(path_join(root, "/usr/lib/os-release"));

        ASSERT_OK(write_string_file(p, contents,
                                    WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_TRUNCATE|
                                    WRITE_STRING_FILE_MKDIR_0755));
}

TEST(voa_os_identifiers) {
        _cleanup_(rm_rf_physical_and_freep) char *root = NULL;
        _cleanup_strv_free_ char **l = NULL;
        _cleanup_close_ int root_fd = -EBADF;

        ASSERT_OK(mkdtemp_malloc(NULL, &root));
        ASSERT_OK_ERRNO(root_fd = open(root, O_PATH|O_DIRECTORY|O_CLOEXEC));

        /* No os-release at all yields the documented default */
        ASSERT_OK_ZERO(voa_os_identifiers(root_fd, &l));
        ASSERT_TRUE(strv_equal(l, STRV_MAKE("linux")));
        l = strv_free(l);

        write_os_release(root, "ID=testos\nVERSION_ID=1\nIMAGE_ID=img\n");
        ASSERT_OK_ZERO(voa_os_identifiers(root_fd, &l));
        ASSERT_TRUE(strv_equal(l, STRV_MAKE("testos:1::img", "testos")));
        l = strv_free(l);

        write_os_release(root,
                         "ID=testos\nVERSION_ID=1\nVARIANT_ID=server\nIMAGE_ID=img\nIMAGE_VERSION=2\n");
        ASSERT_OK_ZERO(voa_os_identifiers(root_fd, &l));
        ASSERT_TRUE(strv_equal(l, STRV_MAKE("testos:1:server:img:2", "testos")));
        l = strv_free(l);

        write_os_release(root, "ID=testos\n");
        ASSERT_OK_ZERO(voa_os_identifiers(root_fd, &l));
        ASSERT_TRUE(strv_equal(l, STRV_MAKE("testos")));
        l = strv_free(l);

        /* os-release permits characters VOA does not: the exact identifier is unusable then */
        write_os_release(root, "ID=testos\nVERSION_ID=1~rc1\n");
        ASSERT_OK_POSITIVE(voa_os_identifiers(root_fd, &l));
        ASSERT_TRUE(strv_equal(l, STRV_MAKE("testos")));
        l = strv_free(l);

        write_os_release(root, "NAME=Test\n");
        ASSERT_OK_ZERO(voa_os_identifiers(root_fd, &l));
        ASSERT_TRUE(strv_equal(l, STRV_MAKE("linux")));
        l = strv_free(l);

        write_os_release(root, "ID=\"Test OS\"\n");
        ASSERT_ERROR(voa_os_identifiers(root_fd, &l), EINVAL);
}

static void add_file(const char *root, const char *path) {
        _cleanup_free_ char *p = ASSERT_NOT_NULL(path_join(root, path));

        ASSERT_OK(write_string_file(p, "x", WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_MKDIR_0755));
}

static void add_symlink(const char *root, const char *path, const char *target) {
        _cleanup_free_ char *p = ASSERT_NOT_NULL(path_join(root, path));

        ASSERT_OK(mkdir_parents(p, 0755));
        ASSERT_OK_ERRNO(symlink(target, p));
}

static void add_dir(const char *root, const char *path) {
        _cleanup_free_ char *p = ASSERT_NOT_NULL(path_join(root, path));

        ASSERT_OK(mkdir_p(p, 0755));
}

#define X509_DIR "/image/default/x509/"

static char** file_paths(ConfFile **files, size_t n) {
        _cleanup_strv_free_ char **l = NULL;

        FOREACH_ARRAY(f, files, n) {
                ASSERT_TRUE((*f)->fd >= 0);
                ASSERT_TRUE(S_ISREG((*f)->st.st_mode));
                ASSERT_OK(strv_extend(&l, (*f)->original_path));
        }

        return TAKE_PTR(l);
}

static ConfFile** files_free(ConfFile **files, size_t *n) {
        conf_file_free_array(files, *n);
        *n = 0;
        return NULL;
}

TEST(voa_list_verifiers) {
        _cleanup_(rm_rf_physical_and_freep) char *root = NULL;
        _cleanup_strv_free_ char **l = NULL;
        _cleanup_close_ int root_fd = -EBADF;
        ConfFile **files = NULL;
        size_t n = 0;
        VoaLookup lookup = {
                .os = STRV_MAKE("testos"),
                .role = "image",
                .mode = VOA_MODE_ARTIFACT_VERIFIER,
                .context = "default",
                .technology = "x509",
                .suffix = "-certificate.pem",
        };

        ASSERT_OK(mkdtemp_malloc(NULL, &root));
        ASSERT_OK_ERRNO(root_fd = open(root, O_PATH|O_DIRECTORY|O_CLOEXEC));

        /* Every copy counts */
        add_file(root, "/usr/share/voa/testos" X509_DIR "a-certificate.pem");
        add_file(root, "/etc/voa/testos" X509_DIR "a-certificate.pem");
        /* A mask anywhere masks everywhere, whatever the priority */
        add_file(root, "/usr/share/voa/testos" X509_DIR "b-certificate.pem");
        add_symlink(root, "/etc/voa/testos" X509_DIR "b-certificate.pem", "/dev/null");
        add_file(root, "/etc/voa/testos" X509_DIR "c-certificate.pem");
        add_symlink(root, "/run/voa/testos" X509_DIR "c-certificate.pem", "/dev/null");
        /* Relative symlink to the same name in a load path of lower priority: fine, both copies count */
        add_file(root, "/usr/share/voa/testos" X509_DIR "d-certificate.pem");
        add_symlink(root, "/usr/local/share/voa/testos" X509_DIR "d-certificate.pem",
                    "../../../../../../../share/voa/testos" X509_DIR "d-certificate.pem");
        /* Rejected symlinks: different name, outside of the hierarchy, dangling, looping. Symlinks into a
         * load path of higher priority or into /run resolve to copies that are found anyway. */
        add_file(root, "/usr/share/voa/testos" X509_DIR "f-certificate.pem");
        add_symlink(root, "/etc/voa/testos" X509_DIR "e-certificate.pem",
                    "/usr/share/voa/testos" X509_DIR "f-certificate.pem");
        add_symlink(root, "/usr/share/voa/testos" X509_DIR "g-certificate.pem",
                    "/etc/voa/testos" X509_DIR "g-certificate.pem");
        add_file(root, "/etc/voa/testos" X509_DIR "g-certificate.pem");
        add_symlink(root, "/etc/voa/testos" X509_DIR "h-certificate.pem", "/tmp/h-certificate.pem");
        add_file(root, "/tmp/h-certificate.pem");
        add_symlink(root, "/etc/voa/testos" X509_DIR "i-certificate.pem",
                    "/run/voa/testos" X509_DIR "i-certificate.pem");
        add_file(root, "/run/voa/testos" X509_DIR "i-certificate.pem");
        add_symlink(root, "/etc/voa/testos" X509_DIR "j-certificate.pem",
                    "/usr/share/voa/testos" X509_DIR "j-certificate.pem");
        add_symlink(root, "/etc/voa/testos" X509_DIR "l-certificate.pem", "l-certificate.pem");
        /* Wrong type, wrong suffix */
        add_dir(root, "/etc/voa/testos" X509_DIR "x-certificate.pem");
        add_file(root, "/etc/voa/testos" X509_DIR "README");
        add_file(root, "/etc/voa/testos" X509_DIR "y-public-key.pem");
        /* Not valid VOA identifiers */
        add_file(root, "/etc/voa/testos" X509_DIR "-certificate.pem");
        add_file(root, "/etc/voa/testos" X509_DIR "UPPER-certificate.pem");

        ASSERT_OK(voa_list_verifiers(root_fd, &lookup, VOA_WARN, &files, &n));
        l = file_paths(files, n);
        ASSERT_TRUE(strv_equal(l, STRV_MAKE(
                                   "/etc/voa/testos" X509_DIR "a-certificate.pem",
                                   "/etc/voa/testos" X509_DIR "g-certificate.pem",
                                   "/etc/voa/testos" X509_DIR "i-certificate.pem",
                                   "/run/voa/testos" X509_DIR "i-certificate.pem",
                                   "/usr/local/share/voa/testos" X509_DIR "d-certificate.pem",
                                   "/usr/share/voa/testos" X509_DIR "a-certificate.pem",
                                   "/usr/share/voa/testos" X509_DIR "d-certificate.pem",
                                   "/usr/share/voa/testos" X509_DIR "f-certificate.pem",
                                   "/usr/share/voa/testos" X509_DIR "g-certificate.pem")));
        l = strv_free(l);
        files = files_free(files, &n);

        /* A context other than the default is a sibling directory */
        add_file(root, "/etc/voa/testos/image/ctx/x509/m-certificate.pem");
        lookup.context = "ctx";
        ASSERT_OK(voa_list_verifiers(root_fd, &lookup, VOA_WARN, &files, &n));
        l = file_paths(files, n);
        ASSERT_TRUE(strv_equal(l, STRV_MAKE("/etc/voa/testos/image/ctx/x509/m-certificate.pem")));
        l = strv_free(l);
        files = files_free(files, &n);
        lookup.context = "default";

        /* Trust anchors live in their own purpose directory */
        add_file(root, "/usr/share/voa/testos/trust-anchor-image/default/x509/ca-certificate.pem");
        lookup.mode = VOA_MODE_TRUST_ANCHOR;
        ASSERT_OK(voa_list_verifiers(root_fd, &lookup, VOA_WARN, &files, &n));
        l = file_paths(files, n);
        ASSERT_TRUE(strv_equal(l, STRV_MAKE("/usr/share/voa/testos/trust-anchor-image/default/x509/"
                                            "ca-certificate.pem")));
        l = strv_free(l);
        files = files_free(files, &n);
        lookup.mode = VOA_MODE_ARTIFACT_VERIFIER;

        /* Directories are not masked. Directory symlinks are resolved like the kernel does, but must stay
         * inside the hierarchy. */
        add_symlink(root, "/etc/voa/testos2", "../../usr/share/voa/testos4");
        add_file(root, "/usr/share/voa/testos2" X509_DIR "z-certificate.pem");
        add_file(root, "/usr/share/voa/testos4" X509_DIR "v-certificate.pem");
        add_symlink(root, "/etc/voa/testos3/image/default/x509",
                    "../../../../../usr/share/voa/testos3/image/default/x509");
        add_file(root, "/usr/share/voa/testos3" X509_DIR "w-certificate.pem");
        add_symlink(root, "/etc/voa/testos5", "../../var/voa-outside");
        add_file(root, "/var/voa-outside" X509_DIR "u-certificate.pem");
        add_symlink(root, "/etc/voa/testos6/image", "/dev/null");
        add_file(root, "/usr/share/voa/testos6" X509_DIR "o-certificate.pem");

        lookup.os = STRV_MAKE("testos2", "testos3", "testos5", "testos6");
        ASSERT_OK(voa_list_verifiers(root_fd, &lookup, VOA_WARN, &files, &n));
        l = file_paths(files, n);
        ASSERT_TRUE(strv_equal(l, STRV_MAKE(
                                   "/etc/voa/testos2" X509_DIR "v-certificate.pem",
                                   "/usr/share/voa/testos2" X509_DIR "z-certificate.pem",
                                   "/etc/voa/testos3" X509_DIR "w-certificate.pem",
                                   "/usr/share/voa/testos3" X509_DIR "w-certificate.pem",
                                   "/usr/share/voa/testos6" X509_DIR "o-certificate.pem")));
        l = strv_free(l);
        files = files_free(files, &n);

        /* Nothing there at all */
        lookup.os = STRV_MAKE("nosuchos");
        ASSERT_OK(voa_list_verifiers(root_fd, &lookup, VOA_WARN, &files, &n));
        l = file_paths(files, n);
        ASSERT_TRUE(strv_isempty(l));
        ASSERT_EQ(n, 0u);
        l = strv_free(l);
        files = files_free(files, &n);

        /* Invalid lookups */
        lookup.os = STRV_MAKE("Testos");
        ASSERT_ERROR(voa_list_verifiers(root_fd, &lookup, 0, &files, &n), EINVAL);
        lookup.os = NULL;
        ASSERT_ERROR(voa_list_verifiers(root_fd, &lookup, 0, &files, &n), EINVAL);
        lookup.os = STRV_MAKE("testos");
        lookup.role = "trust-anchor-image";
        ASSERT_ERROR(voa_list_verifiers(root_fd, &lookup, 0, &files, &n), EINVAL);
        lookup.role = "image";
        lookup.technology = "X509";
        ASSERT_ERROR(voa_list_verifiers(root_fd, &lookup, 0, &files, &n), EINVAL);
        lookup.technology = "x509";
        lookup.context = "CTX";
        ASSERT_ERROR(voa_list_verifiers(root_fd, &lookup, 0, &files, &n), EINVAL);
        lookup.context = "default";
        lookup.suffix = NULL;
        ASSERT_ERROR(voa_list_verifiers(root_fd, &lookup, 0, &files, &n), EINVAL);
        lookup.suffix = "-certificate.pem";
        lookup.mode = _VOA_MODE_MAX;
        ASSERT_ERROR(voa_list_verifiers(root_fd, &lookup, 0, &files, &n), EINVAL);
}

TEST(voa_list_verifiers_symlinked_load_path_parent) {
        _cleanup_(rm_rf_physical_and_freep) char *root = NULL;
        _cleanup_strv_free_ char **l = NULL;
        _cleanup_close_ int root_fd = -EBADF;
        ConfFile **files = NULL;
        size_t n = 0;
        VoaLookup lookup = {
                .os = STRV_MAKE("testos"),
                .role = "image",
                .mode = VOA_MODE_ARTIFACT_VERIFIER,
                .context = "default",
                .technology = "x509",
                .suffix = "-certificate.pem",
        };

        ASSERT_OK(mkdtemp_malloc(NULL, &root));
        ASSERT_OK_ERRNO(root_fd = open(root, O_PATH|O_DIRECTORY|O_CLOEXEC));

        /* rpm-ostree layout: /usr/local is a symlink to ../var/usrlocal */
        add_dir(root, "/usr");
        add_symlink(root, "/usr/local", "../var/usrlocal");
        add_file(root, "/var/usrlocal/share/voa/testos" X509_DIR "a-certificate.pem");
        add_symlink(root, "/etc/voa/testos" X509_DIR "a-certificate.pem",
                    "../../../../../../usr/local/share/voa/testos" X509_DIR "a-certificate.pem");

        ASSERT_OK(voa_list_verifiers(root_fd, &lookup, VOA_WARN, &files, &n));
        l = file_paths(files, n);
        ASSERT_TRUE(strv_equal(l, STRV_MAKE("/etc/voa/testos" X509_DIR "a-certificate.pem",
                                            "/usr/local/share/voa/testos" X509_DIR "a-certificate.pem")));
        ASSERT_TRUE(path_equal(skip_leading_slash(files[0]->resolved_path),
                               "var/usrlocal/share/voa/testos" X509_DIR "a-certificate.pem"));
        files = files_free(files, &n);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
