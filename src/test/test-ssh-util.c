/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include "alloc-util.h"
#include "crypto-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "hexdecoct.h"
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

STATIC_DESTRUCTOR_REGISTER(ssh_keygen_path, freep);

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
static int build_sshsig_tbs(
                const char *namespace,
                const void *msg,
                size_t msg_size,
                void **ret,
                size_t *ret_size) {

        _cleanup_(ssh_wire_buf_done) SshWireBuf out = {};
        int r;

        _cleanup_free_ void *hash = NULL;
        size_t hash_size = 0;
        r = openssl_digest(TEST_HASH_ALG, msg, msg_size, &hash, &hash_size);
        if (r < 0)
                return r;

        r = ssh_wire_buf_append_bytes(&out, "SSHSIG", 6);
        if (r < 0)
                return r;

        r = ssh_wire_buf_append_string(&out, namespace, SIZE_MAX);
        if (r < 0)
                return r;

        r = ssh_wire_buf_append_string(&out, "", 0);
        if (r < 0)
                return r;

        r = ssh_wire_buf_append_string(&out, TEST_HASH_ALG, SIZE_MAX);
        if (r < 0)
                return r;

        r = ssh_wire_buf_append_string(&out, hash, hash_size);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(out.data);
        *ret_size = out.size;
        out.size = 0;
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
                const void *pubkey_blob, size_t pubkey_size,
                const char *namespace,
                const void *sig_blob, size_t sig_size,
                char **ret) {

        _cleanup_(ssh_wire_buf_done) SshWireBuf inner = {};
        int r;

        r = ssh_wire_buf_append_bytes(&inner, "SSHSIG", 6);
        if (r < 0)
                return r;

        r = ssh_wire_buf_append_u32(&inner, 1);
        if (r < 0)
                return r;

        r = ssh_wire_buf_append_string(&inner, pubkey_blob, pubkey_size);
        if (r < 0)
                return r;

        r = ssh_wire_buf_append_string(&inner, namespace, SIZE_MAX);
        if (r < 0)
                return r;

        r = ssh_wire_buf_append_string(&inner, "", 0);
        if (r < 0)
                return r;

        r = ssh_wire_buf_append_string(&inner, TEST_HASH_ALG, SIZE_MAX);
        if (r < 0)
                return r;

        r = ssh_wire_buf_append_string(&inner, sig_blob, sig_size);
        if (r < 0)
                return r;

        _cleanup_free_ char *b64 = NULL;
        if (base64mem_full(inner.data, inner.size, /* line_break= */ 76, &b64) < 0)
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
                const void *msg,
                size_t msg_size) {

        _cleanup_free_ void *tbs = NULL, *sig = NULL;
        size_t tbs_size = 0, sig_size = 0;
        _cleanup_free_ char *armored = NULL, *armored_path = NULL;
        int r;

        if (msg_size == SIZE_MAX)
                msg_size = strlen(msg);

        r = build_sshsig_tbs(TEST_NAMESPACE, msg, msg_size, &tbs, &tbs_size);
        if (r < 0)
                return r;

        r = openssh_key_sign(k, flags, tbs, tbs_size, &sig, &sig_size);
        if (r < 0)
                return r;

        r = build_sshsig_armored(k->pubkey_blob, k->pubkey_blob_size,
                                 TEST_NAMESPACE, sig, sig_size, &armored);
        if (r < 0)
                return r;

        armored_path = path_join(tmpdir, "sig");
        if (!armored_path)
                return -ENOMEM;

        r = write_string_file(armored_path, armored, WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_TRUNCATE);
        if (r < 0)
                return r;

        return verify_with_ssh_keygen(tmpdir, armored_path, msg, msg_size);
}

TEST(load_and_sign_ed25519) {
        _cleanup_(rm_rf_physical_and_freep) char *tmp = NULL;
        _cleanup_free_ char *priv = NULL, *pub = NULL;
        _cleanup_(openssh_key_freep) OpenSSHKey *k = NULL;

        ASSERT_OK(mkdtemp_malloc("/tmp/test-openssh-key-XXXXXX", &tmp));
        ASSERT_OK(generate_keypair(tmp, "ed25519", OPENSSH_KEY_TYPE_ED25519, &priv, &pub));
        ASSERT_OK(openssh_key_load(priv, pub, &k));
        ASSERT_EQ(k->type, OPENSSH_KEY_TYPE_ED25519);

        static const char msg[] = "this is the message to sign";
        ASSERT_OK(sign_and_verify_via_sshsig(tmp, k, 0, msg, SIZE_MAX));
}

TEST(load_and_sign_rsa) {
        _cleanup_(rm_rf_physical_and_freep) char *tmp = NULL;
        _cleanup_free_ char *priv = NULL, *pub = NULL;
        _cleanup_(openssh_key_freep) OpenSSHKey *k = NULL;

        ASSERT_OK(mkdtemp_malloc("/tmp/test-openssh-key-XXXXXX", &tmp));
        ASSERT_OK(generate_keypair(tmp, "rsa", OPENSSH_KEY_TYPE_RSA, &priv, &pub));
        ASSERT_OK(openssh_key_load(priv, pub, &k));
        ASSERT_EQ(k->type, OPENSSH_KEY_TYPE_RSA);

        static const char msg[] = "rsa-signed payload";

        /* SSHSIG only carries one signature, and the modern default is rsa-sha2-* —
         * exercise both SHA-256 and SHA-512 here. */
        ASSERT_OK(sign_and_verify_via_sshsig(tmp, k, SSH_AGENT_RSA_SHA2_256, msg, SIZE_MAX));
        ASSERT_OK(sign_and_verify_via_sshsig(tmp, k, SSH_AGENT_RSA_SHA2_512, msg, SIZE_MAX));
}

TEST(load_and_sign_ecdsa_p256) {
        _cleanup_(rm_rf_physical_and_freep) char *tmp = NULL;
        _cleanup_free_ char *priv = NULL, *pub = NULL;
        _cleanup_(openssh_key_freep) OpenSSHKey *k = NULL;

        ASSERT_OK(mkdtemp_malloc("/tmp/test-openssh-key-XXXXXX", &tmp));
        ASSERT_OK(generate_keypair(tmp, "ecdsa", OPENSSH_KEY_TYPE_ECDSA_P256, &priv, &pub));
        ASSERT_OK(openssh_key_load(priv, pub, &k));
        ASSERT_EQ(k->type, OPENSSH_KEY_TYPE_ECDSA_P256);

        static const char msg[] = "the quick brown fox";
        ASSERT_OK(sign_and_verify_via_sshsig(tmp, k, 0, msg, SIZE_MAX));
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

        OpenSSHKeyType type;
        _cleanup_free_ void *blob = NULL;
        _cleanup_free_ char *comment = NULL;
        size_t blob_size = 0;
        ASSERT_EQ(openssh_pubkey_load(path, &type, &blob, &blob_size, &comment), -EOPNOTSUPP);
}

static int intro(void) {
        int r;

        if (dlopen_libcrypto(LOG_DEBUG) < 0)
                return log_tests_skipped("libcrypto is not available");

        r = find_executable("ssh-keygen", &ssh_keygen_path);
        if (r < 0)
                return log_tests_skipped("ssh-keygen is not available");

        /* ssh-keygen before OpenSSH 10.3 cannot write ed25519 keys in PKCS#8 format and falls back to the
         * OpenSSH native format, which openssh_key_load() rejects with -EOPNOTSUPP. Probe with a throwaway
         * key and skip the whole suite rather than fail when that's the case. */
        _cleanup_(rm_rf_physical_and_freep) char *tmp = NULL;
        if (mkdtemp_malloc("/tmp/test-openssh-key-XXXXXX", &tmp) < 0)
                return log_tests_skipped("Failed to create temporary directory");

        _cleanup_free_ char *priv = NULL, *pub = NULL;
        if (generate_keypair(tmp, "probe", OPENSSH_KEY_TYPE_ED25519, &priv, &pub) < 0)
                return log_tests_skipped("Failed to generate probe key");

        _cleanup_(openssh_key_freep) OpenSSHKey *k = NULL;
        if (openssh_key_load(priv, pub, &k) == -EOPNOTSUPP)
                return log_tests_skipped("ssh-keygen does not generate PKCS#8 private keys (OpenSSH < 10.3)");

        return EXIT_SUCCESS;
}

DEFINE_TEST_MAIN_WITH_INTRO(LOG_DEBUG, intro);
