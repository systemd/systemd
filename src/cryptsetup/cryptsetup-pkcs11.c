/* SPDX-License-Identifier: LGPL-2.1+ */

#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#include <p11-kit/p11-kit.h>
#include <p11-kit/uri.h>

#include "alloc-util.h"
#include "ask-password-api.h"
#include "cryptsetup-pkcs11.h"
#include "escape.h"
#include "fd-util.h"
#include "format-util.h"
#include "macro.h"
#include "memory-util.h"
#include "pkcs11-util.h"
#include "stat-util.h"
#include "strv.h"

#define KEY_FILE_SIZE_MAX (16U*1024U*1024U) /* 16 MiB */

static int load_key_file(
                const char *key_file,
                size_t key_file_size,
                uint64_t key_file_offset,
                void **ret_encrypted_key,
                size_t *ret_encrypted_key_size) {

        _cleanup_(erase_and_freep) char *buffer = NULL;
        _cleanup_close_ int fd = -1;
        ssize_t n;
        int r;

        assert(key_file);
        assert(ret_encrypted_key);
        assert(ret_encrypted_key_size);

        fd = open(key_file, O_RDONLY|O_CLOEXEC);
        if (fd < 0)
                return log_error_errno(errno, "Failed to load encrypted PKCS#11 key: %m");

        if (key_file_size == 0) {
                struct stat st;

                if (fstat(fd, &st) < 0)
                        return log_error_errno(errno, "Failed to stat key file: %m");

                r = stat_verify_regular(&st);
                if (r < 0)
                        return log_error_errno(r, "Key file is not a regular file: %m");

                if (st.st_size == 0)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Key file is empty, refusing.");
                if ((uint64_t) st.st_size > KEY_FILE_SIZE_MAX) {
                        char buf1[FORMAT_BYTES_MAX], buf2[FORMAT_BYTES_MAX];
                        return log_error_errno(SYNTHETIC_ERRNO(ERANGE),
                                               "Key file larger (%s) than allowed maximum size (%s), refusing.",
                                               format_bytes(buf1, sizeof(buf1), st.st_size),
                                               format_bytes(buf2, sizeof(buf2), KEY_FILE_SIZE_MAX));
                }

                if (key_file_offset >= (uint64_t) st.st_size)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Key file offset too large for file, refusing.");

                key_file_size = st.st_size - key_file_offset;
        }

        buffer = malloc(key_file_size);
        if (!buffer)
                return log_oom();

        if (key_file_offset > 0)
                n = pread(fd, buffer, key_file_size, key_file_offset);
        else
                n = read(fd, buffer, key_file_size);
        if (n < 0)
                return log_error_errno(errno, "Failed to read PKCS#11 key file: %m");
        if (n == 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Empty encrypted key found, refusing.");

        *ret_encrypted_key = TAKE_PTR(buffer);
        *ret_encrypted_key_size = (size_t) n;

        return 0;
}

struct pkcs11_callback_data {
        const char *friendly_name;
        usec_t until;
        void *encrypted_key;
        size_t encrypted_key_size;
        void *decrypted_key;
        size_t decrypted_key_size;
};

static void pkcs11_callback_data_release(struct pkcs11_callback_data *data) {
        free(data->decrypted_key);
        free(data->encrypted_key);
}

static int pkcs11_callback(
                CK_FUNCTION_LIST *m,
                CK_SESSION_HANDLE session,
                CK_SLOT_ID slot_id,
                const CK_SLOT_INFO *slot_info,
                const CK_TOKEN_INFO *token_info,
                P11KitUri *uri,
                void *userdata) {

        struct pkcs11_callback_data *data = userdata;
        CK_OBJECT_HANDLE object;
        int r;

        assert(m);
        assert(slot_info);
        assert(token_info);
        assert(uri);
        assert(data);

        /* Called for every token matching our URI */

        r = pkcs11_token_login(
                        m,
                        session,
                        slot_id,
                        token_info,
                        data->friendly_name,
                        "drive-harddisk",
                        "pkcs11-pin",
                        data->until,
                        NULL);
        if (r < 0)
                return r;

        /* We are likely called during early boot, where entropy is scarce. Mix some data from the PKCS#11
         * token, if it supports that. It should be cheap, given that we already are talking to it anyway and
         * shouldn't hurt. */
        (void) pkcs11_token_acquire_rng(m, session);

        r = pkcs11_token_find_private_key(m, session, uri, &object);
        if (r < 0)
                return r;

        r = pkcs11_token_decrypt_data(
                        m,
                        session,
                        object,
                        data->encrypted_key,
                        data->encrypted_key_size,
                        &data->decrypted_key,
                        &data->decrypted_key_size);
        if (r < 0)
                return r;

        return 0;
}

int decrypt_pkcs11_key(
                const char *friendly_name,
                const char *pkcs11_uri,
                const char *key_file,
                size_t key_file_size,
                uint64_t key_file_offset,
                usec_t until,
                void **ret_decrypted_key,
                size_t *ret_decrypted_key_size) {

        _cleanup_(pkcs11_callback_data_release) struct pkcs11_callback_data data = {
                .friendly_name = friendly_name,
                .until = until,
        };
        int r;

        assert(friendly_name);
        assert(pkcs11_uri);
        assert(key_file);
        assert(ret_decrypted_key);
        assert(ret_decrypted_key_size);

        /* The functions called here log about all errors, except for EAGAIN which means "token not found right now" */

        r = load_key_file(key_file, key_file_size, key_file_offset, &data.encrypted_key, &data.encrypted_key_size);
        if (r < 0)
                return r;

        r = pkcs11_find_token(pkcs11_uri, pkcs11_callback, &data);
        if (r < 0)
                return r;

        *ret_decrypted_key = TAKE_PTR(data.decrypted_key);
        *ret_decrypted_key_size = data.decrypted_key_size;

        return 0;
}
