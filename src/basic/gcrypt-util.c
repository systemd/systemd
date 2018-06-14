/* SPDX-License-Identifier: LGPL-2.1+ */

#if HAVE_GCRYPT
#include <gcrypt.h>

#include "gcrypt-util.h"
#include "hexdecoct.h"

void initialize_libgcrypt(bool secmem) {
        const char *p;
        if (gcry_control(GCRYCTL_INITIALIZATION_FINISHED_P))
                return;

        p = gcry_check_version("1.4.5");
        assert(p);

        /* Turn off "secmem". Clients which wish to make use of this
         * feature should initialize the library manually */
        if (!secmem)
                gcry_control(GCRYCTL_DISABLE_SECMEM);
        gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
}

int string_hashsum(const char *s, size_t len, int md_algorithm, char **out) {
        _cleanup_(gcry_md_closep) gcry_md_hd_t md = NULL;
        size_t hash_size;
        void *hash;
        char *enc;

        initialize_libgcrypt(false);

        hash_size = gcry_md_get_algo_dlen(md_algorithm);
        assert(hash_size > 0);

        gcry_md_open(&md, md_algorithm, 0);
        if (!md)
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
#endif
