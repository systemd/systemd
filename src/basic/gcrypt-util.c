/* SPDX-License-Identifier: LGPL-2.1-or-later */

#if HAVE_GCRYPT

#include "gcrypt-util.h"
#include "hexdecoct.h"

void initialize_libgcrypt(bool secmem) {
        if (gcry_control(GCRYCTL_INITIALIZATION_FINISHED_P))
                return;

        gcry_control(GCRYCTL_SET_PREFERRED_RNG_TYPE, GCRY_RNG_TYPE_SYSTEM);
        assert_se(gcry_check_version("1.4.5"));

        /* Turn off "secmem". Clients which wish to make use of this
         * feature should initialize the library manually */
        if (!secmem)
                gcry_control(GCRYCTL_DISABLE_SECMEM);

        gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
}

#  if !PREFER_OPENSSL
int string_hashsum(const char *s, size_t len, int md_algorithm, char **out) {
        _cleanup_(gcry_md_closep) gcry_md_hd_t md = NULL;
        gcry_error_t err;
        size_t hash_size;
        void *hash;
        char *enc;

        initialize_libgcrypt(false);

        hash_size = gcry_md_get_algo_dlen(md_algorithm);
        assert(hash_size > 0);

        err = gcry_md_open(&md, md_algorithm, 0);
        if (gcry_err_code(err) != GPG_ERR_NO_ERROR || !md)
                return -EIO;

        gcry_md_write(md, s, len);

        hash = gcry_md_read(md, 0);
        if (!hash)
                return -EIO;

        enc = hexmem(hash, hash_size);
        if (!enc)
                return -ENOMEM;

        *out = enc;
        return 0;
}
#  endif
#endif
