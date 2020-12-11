/* SPDX-License-Identifier: LGPL-2.1-or-later */

#if HAVE_GCRYPT

#include "gcrypt-util.h"
#include "hexdecoct.h"

void initialize_libgcrypt(bool secmem) {
        if (gcry_control(GCRYCTL_INITIALIZATION_FINISHED_P))
                return;

        assert_se(gcry_check_version("1.4.5"));

        /* Turn off "secmem". Clients which wish to make use of this
         * feature should initialize the library manually */
        if (!secmem)
                gcry_control(GCRYCTL_DISABLE_SECMEM);
        gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
}
#endif
