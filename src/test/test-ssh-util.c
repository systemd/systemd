/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include "alloc-util.h"
#include "crypto-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "hexdecoct.h"
#include "iovec-util.h"
#include "path-util.h"
#include "pidref.h"
#include "process-util.h"
#include "rm-rf.h"
#include "ssh-util.h"
#include "string-util.h"
#include "tests.h"
#include "tmpfile-util.h"

#define TEST_NAMESPACE "test"
#define TEST_HASH_ALG  "sha256"

static char *ssh_keygen_path = NULL;
static bool have_libcrypto = false;

STATIC_DESTRUCTOR_REGISTER(ssh_keygen_path, freep);

static bool skip_key_test(void) {
        if (!have_libcrypto) {
                log_tests_skipped("libcrypto is not available");
                return true;
        }

        if (!ssh_keygen_path) {
                log_tests_skipped("ssh-keygen is not available");
                return true;
        }

        return false;
}

/* Generates a key pair under `tmpdir` named `name`, returning the absolute paths to the
 * private key file (PEM/PKCS8) and to the .pub file. The caller frees both. */
static int generate_keypair(
                const char *tmpdir,
                const char *name,
                OpenSSHKeyType type,
                char **ret_priv,
                char **ret_pub) {

        _cleanup_free_ char *priv = NULL, *pub = NULL;
        int r;

        assert(tmpdir);
        assert(name);
        assert(ret_priv);
        assert(ret_pub);

        priv = path_join(tmpdir, name);
        if (!priv)
                return -ENOMEM;

        pub = strjoin(priv, ".pub");
        if (!pub)
                return -ENOMEM;

        r = openssh_key_generate(priv, type);
        if (r < 0)
                return r;

        *ret_priv = TAKE_PTR(priv);
        *ret_pub = TAKE_PTR(pub);
        return 0;
}

/* The "to-be-signed" blob — this is the byte string that gets fed to openssh_key_sign().
 *
 *   byte[6]  "SSHSIG"
 *   string   namespace
 *   string   reserved   (empty)
 *   string   hash_algorithm
 *   string   H(message) */
static int build_sshsig_tbs(const char *namespace, const struct iovec *msg, struct iovec *ret) {
        _cleanup_(iovec_done) struct iovec out = {}, hash = {};
        int r;

        r = openssl_digest(TEST_HASH_ALG, msg->iov_base, msg->iov_len, &hash.iov_base, &hash.iov_len);
        if (r < 0)
                return r;

        if (!iovec_append(&out, &CONST_IOVEC_MAKE_STRING("SSHSIG")))
                return -ENOMEM;

        r = ssh_wire_append_string(&out, &IOVEC_MAKE_STRING(namespace));
        if (r < 0)
                return r;

        r = ssh_wire_append_string(&out, &iovec_empty);
        if (r < 0)
                return r;

        r = ssh_wire_append_string(&out, &CONST_IOVEC_MAKE_STRING(TEST_HASH_ALG));
        if (r < 0)
                return r;

        r = ssh_wire_append_string(&out, &hash);
        if (r < 0)
                return r;

        *ret = TAKE_STRUCT(out);
        return 0;
}

/* The PEM-armored SSHSIG blob — accepted by `ssh-keygen -Y check-novalidate -s …`.
 *
 *   byte[6]  "SSHSIG"
 *   uint32   1
 *   string   publickey
 *   string   namespace
 *   string   reserved   (empty)
 *   string   hash_algorithm
 *   string   signature   (the raw blob produced by openssh_key_sign — passed through unchanged) */
static int build_sshsig_armored(
                const struct iovec *pubkey_blob,
                const char *namespace,
                const struct iovec *sig,
                char **ret) {

        _cleanup_(iovec_done) struct iovec inner = {};
        int r;

        if (!iovec_append(&inner, &CONST_IOVEC_MAKE_STRING("SSHSIG")))
                return -ENOMEM;

        r = ssh_wire_append_u32(&inner, 1);
        if (r < 0)
                return r;

        r = ssh_wire_append_string(&inner, pubkey_blob);
        if (r < 0)
                return r;

        r = ssh_wire_append_string(&inner, &IOVEC_MAKE_STRING(namespace));
        if (r < 0)
                return r;

        r = ssh_wire_append_string(&inner, &iovec_empty);
        if (r < 0)
                return r;

        r = ssh_wire_append_string(&inner, &CONST_IOVEC_MAKE_STRING(TEST_HASH_ALG));
        if (r < 0)
                return r;

        r = ssh_wire_append_string(&inner, sig);
        if (r < 0)
                return r;

        _cleanup_free_ char *b64 = NULL;
        if (base64mem_full(inner.iov_base, inner.iov_len, /* line_break= */ 76, &b64) < 0)
                return -ENOMEM;

        if (asprintf(ret,
                     "-----BEGIN SSH SIGNATURE-----\n"
                     "%s\n"
                     "-----END SSH SIGNATURE-----\n",
                     b64) < 0)
                return -ENOMEM;

        return 0;
}

/* Hands `armored_sig_path` + `msg` to `ssh-keygen -Y check-novalidate`. Returns 0 if
 * ssh-keygen accepted the signature, -EBADMSG otherwise. */
static int verify_with_ssh_keygen(
                const char *tmpdir,
                const char *armored_sig_path,
                const void *msg, size_t msg_size) {

        _cleanup_free_ char *msg_path = NULL;
        _cleanup_close_ int msg_fd = -EBADF;
        _cleanup_(pidref_done) PidRef child = PIDREF_NULL;
        int r;

        /* Stage the message in a temp file; ssh-keygen reads it from stdin. */
        msg_path = path_join(tmpdir, "message");
        if (!msg_path)
                return -ENOMEM;

        r = write_string_file(msg_path, "", WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_TRUNCATE);
        if (r < 0)
                return r;

        msg_fd = open(msg_path, O_WRONLY|O_CLOEXEC|O_TRUNC);
        if (msg_fd < 0)
                return -errno;

        if (write(msg_fd, msg, msg_size) != (ssize_t) msg_size)
                return -EIO;

        msg_fd = safe_close(msg_fd);

        msg_fd = open(msg_path, O_RDONLY|O_CLOEXEC);
        if (msg_fd < 0)
                return -errno;

        const char *cmdline[] = {
                ssh_keygen_path,
                "-Y", "check-novalidate",
                "-n", TEST_NAMESPACE,
                "-s", armored_sig_path,
                NULL,
        };

        r = pidref_safe_fork_full("(ssh-keygen-verify)",
                                  (int[3]) { msg_fd, STDOUT_FILENO, STDERR_FILENO },
                                  /* except_fds= */ NULL, /* n_except_fds= */ 0,
                                  FORK_RESET_SIGNALS|FORK_RLIMIT_NOFILE_SAFE|FORK_LOG|FORK_REARRANGE_STDIO,
                                  &child);
        if (r < 0)
                return r;
        if (r == 0) {
                execv(ssh_keygen_path, (char *const *) cmdline);
                _exit(EXIT_FAILURE);
        }

        r = pidref_wait_for_terminate_and_check("(ssh-keygen-verify)", &child, /* flags= */ 0);
        if (r < 0)
                return r;

        return r == EXIT_SUCCESS ? 0 : -EBADMSG;
}

/* End-to-end: build TBS, sign it, armor it, and have ssh-keygen verify. */
static int sign_and_verify_via_sshsig(
                const char *tmpdir,
                OpenSSHKey *k,
                uint32_t flags,
                const char *msg) {

        _cleanup_(iovec_done) struct iovec tbs = {}, sig = {};
        _cleanup_free_ char *armored = NULL, *armored_path = NULL;
        int r;

        r = build_sshsig_tbs(TEST_NAMESPACE, &IOVEC_MAKE_STRING(msg), &tbs);
        if (r < 0)
                return r;

        r = openssh_key_sign(k, flags, &tbs, &sig);
        if (r < 0)
                return r;

        r = build_sshsig_armored(&k->pubkey_blob, TEST_NAMESPACE, &sig, &armored);
        if (r < 0)
                return r;

        armored_path = path_join(tmpdir, "sig");
        if (!armored_path)
                return -ENOMEM;

        r = write_string_file(armored_path, armored, WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_TRUNCATE);
        if (r < 0)
                return r;

        return verify_with_ssh_keygen(tmpdir, armored_path, msg, strlen(msg));
}

TEST(load_and_sign_ed25519) {
        _cleanup_(rm_rf_physical_and_freep) char *tmp = NULL;
        _cleanup_free_ char *priv = NULL, *pub = NULL;
        _cleanup_(openssh_key_freep) OpenSSHKey *k = NULL;

        if (skip_key_test())
                return;

        ASSERT_OK(mkdtemp_malloc("/tmp/test-openssh-key-XXXXXX", &tmp));
        ASSERT_OK(generate_keypair(tmp, "ed25519", OPENSSH_KEY_TYPE_ED25519, &priv, &pub));

        /* ssh-keygen before OpenSSH 10.3 ignores "-m PKCS8" for ed25519 keys and writes the OpenSSH
         * native format. OpenSSL can't read that format. */
        _cleanup_free_ char *contents = NULL;
        ASSERT_OK(read_full_file(priv, &contents, /* ret_size= */ NULL));
        if (startswith(contents, "-----BEGIN OPENSSH PRIVATE KEY-----"))
                return (void) log_tests_skipped("ssh-keygen does not write ed25519 keys in PKCS#8 format (OpenSSH < 10.3)");

        ASSERT_OK(openssh_key_load(priv, pub, &k));
        ASSERT_EQ(k->type, OPENSSH_KEY_TYPE_ED25519);

        static const char msg[] = "this is the message to sign";
        ASSERT_OK(sign_and_verify_via_sshsig(tmp, k, 0, msg));
}

TEST(load_and_sign_rsa) {
        _cleanup_(rm_rf_physical_and_freep) char *tmp = NULL;
        _cleanup_free_ char *priv = NULL, *pub = NULL;
        _cleanup_(openssh_key_freep) OpenSSHKey *k = NULL;

        if (skip_key_test())
                return;

        ASSERT_OK(mkdtemp_malloc("/tmp/test-openssh-key-XXXXXX", &tmp));
        ASSERT_OK(generate_keypair(tmp, "rsa", OPENSSH_KEY_TYPE_RSA, &priv, &pub));
        ASSERT_OK(openssh_key_load(priv, pub, &k));
        ASSERT_EQ(k->type, OPENSSH_KEY_TYPE_RSA);

        static const char msg[] = "rsa-signed payload";

        /* SSHSIG only carries one signature, and the modern default is rsa-sha2-* —
         * exercise both SHA-256 and SHA-512 here. */
        ASSERT_OK(sign_and_verify_via_sshsig(tmp, k, SSH_AGENT_RSA_SHA2_256, msg));
        ASSERT_OK(sign_and_verify_via_sshsig(tmp, k, SSH_AGENT_RSA_SHA2_512, msg));
}

TEST(load_and_sign_ecdsa_p256) {
        _cleanup_(rm_rf_physical_and_freep) char *tmp = NULL;
        _cleanup_free_ char *priv = NULL, *pub = NULL;
        _cleanup_(openssh_key_freep) OpenSSHKey *k = NULL;

        if (skip_key_test())
                return;

        ASSERT_OK(mkdtemp_malloc("/tmp/test-openssh-key-XXXXXX", &tmp));
        ASSERT_OK(generate_keypair(tmp, "ecdsa", OPENSSH_KEY_TYPE_ECDSA_P256, &priv, &pub));
        ASSERT_OK(openssh_key_load(priv, pub, &k));
        ASSERT_EQ(k->type, OPENSSH_KEY_TYPE_ECDSA_P256);

        static const char msg[] = "the quick brown fox";
        ASSERT_OK(sign_and_verify_via_sshsig(tmp, k, 0, msg));
}

TEST(load_missing_files) {
        _cleanup_(rm_rf_physical_and_freep) char *tmp = NULL;
        _cleanup_(openssh_key_freep) OpenSSHKey *k = NULL;

        ASSERT_OK(mkdtemp_malloc("/tmp/test-openssh-key-XXXXXX", &tmp));

        _cleanup_free_ char *bogus_priv = ASSERT_NOT_NULL(path_join(tmp, "no-such"));
        _cleanup_free_ char *bogus_pub = ASSERT_NOT_NULL(path_join(tmp, "no-such.pub"));

        ASSERT_LT(openssh_key_load(bogus_priv, bogus_pub, &k), 0);
        ASSERT_NULL(k);
}

TEST(pubkey_load_unsupported_type) {
        _cleanup_(rm_rf_physical_and_freep) char *tmp = NULL;
        ASSERT_OK(mkdtemp_malloc("/tmp/test-openssh-key-XXXXXX", &tmp));

        _cleanup_free_ char *path = ASSERT_NOT_NULL(path_join(tmp, "bogus.pub"));
        ASSERT_OK(write_string_file(path,
                                    "ssh-dss AAAAB3NzaC1kc3MAAACBANk= someone@somewhere\n",
                                    WRITE_STRING_FILE_CREATE));

        _cleanup_(iovec_done) struct iovec blob = {};
        ASSERT_ERROR(openssh_pubkey_load(path, /* ret_type= */ NULL, &blob, /* ret_comment= */ NULL), EOPNOTSUPP);
}

TEST(wire_read_round_trip) {
        _cleanup_(iovec_done) struct iovec buf = {};
        struct iovec s;
        uint32_t v;

        ASSERT_OK(ssh_wire_append_u32(&buf, 0xdeadbeef));
        ASSERT_OK(ssh_wire_append_string(&buf, &CONST_IOVEC_MAKE_STRING("hello")));
        ASSERT_OK(ssh_wire_append_string(&buf, &iovec_empty));

        struct iovec i = buf;
        ASSERT_OK(ssh_wire_read_u32(&i, &v));
        ASSERT_EQ(v, 0xdeadbeefU);
        ASSERT_OK(ssh_wire_read_string(&i, &s));
        ASSERT_TRUE(iovec_equal(&s, &CONST_IOVEC_MAKE_STRING("hello")));
        ASSERT_OK(ssh_wire_read_string(&i, &s));
        ASSERT_EQ(s.iov_len, 0U);
        ASSERT_FALSE(iovec_is_set(&i));

        ASSERT_ERROR(ssh_wire_read_u32(&i, &v), EBADMSG);
        ASSERT_ERROR(ssh_wire_read_string(&i, &s), EBADMSG);
}

TEST(wire_read_truncated) {
        static const uint8_t short_u32[] = { 0x00, 0x00, 0x01 };
        static const uint8_t short_string[] = { 0x00, 0x00, 0x00, 0x05, 'a', 'b', 'c' };
        static const uint8_t huge_length[] = { 0xff, 0xff, 0xff, 0xff, 'a' };
        struct iovec i, s;
        uint32_t v;

        i = IOVEC_MAKE((void*) short_u32, sizeof(short_u32));
        ASSERT_ERROR(ssh_wire_read_u32(&i, &v), EBADMSG);
        ASSERT_PTR_EQ(i.iov_base, short_u32);
        ASSERT_EQ(i.iov_len, sizeof(short_u32));

        i = IOVEC_MAKE((void*) short_u32, sizeof(short_u32));
        ASSERT_ERROR(ssh_wire_read_string(&i, &s), EBADMSG);
        ASSERT_PTR_EQ(i.iov_base, short_u32);
        ASSERT_EQ(i.iov_len, sizeof(short_u32));

        i = IOVEC_MAKE((void*) short_string, sizeof(short_string));
        ASSERT_ERROR(ssh_wire_read_string(&i, &s), EBADMSG);
        ASSERT_PTR_EQ(i.iov_base, short_string);
        ASSERT_EQ(i.iov_len, sizeof(short_string));

        i = IOVEC_MAKE((void*) huge_length, sizeof(huge_length));
        ASSERT_ERROR(ssh_wire_read_string(&i, &s), EBADMSG);
        ASSERT_PTR_EQ(i.iov_base, huge_length);
        ASSERT_EQ(i.iov_len, sizeof(huge_length));
}

static int intro(void) {
        have_libcrypto = dlopen_libcrypto(LOG_DEBUG) >= 0;
        (void) find_executable("ssh-keygen", &ssh_keygen_path);
        return EXIT_SUCCESS;
}

DEFINE_TEST_MAIN_WITH_INTRO(LOG_DEBUG, intro);
