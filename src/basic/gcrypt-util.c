/* SPDX-License-Identifier: LGPL-2.1-or-later */

#if HAVE_GCRYPT

#include <sys/syslog.h>

#include "gcrypt-util.h"

static void *gcrypt_dl = NULL;

static DLSYM_PROTOTYPE(gcry_control) = NULL;
static DLSYM_PROTOTYPE(gcry_check_version) = NULL;
DLSYM_PROTOTYPE(gcry_md_close) = NULL;
DLSYM_PROTOTYPE(gcry_md_copy) = NULL;
DLSYM_PROTOTYPE(gcry_md_ctl) = NULL;
DLSYM_PROTOTYPE(gcry_md_get_algo_dlen) = NULL;
DLSYM_PROTOTYPE(gcry_md_open) = NULL;
DLSYM_PROTOTYPE(gcry_md_read) = NULL;
DLSYM_PROTOTYPE(gcry_md_reset) = NULL;
DLSYM_PROTOTYPE(gcry_md_setkey) = NULL;
DLSYM_PROTOTYPE(gcry_md_write) = NULL;
DLSYM_PROTOTYPE(gcry_mpi_add) = NULL;
DLSYM_PROTOTYPE(gcry_mpi_add_ui) = NULL;
DLSYM_PROTOTYPE(gcry_mpi_cmp) = NULL;
DLSYM_PROTOTYPE(gcry_mpi_cmp_ui) = NULL;
DLSYM_PROTOTYPE(gcry_mpi_get_nbits) = NULL;
DLSYM_PROTOTYPE(gcry_mpi_invm) = NULL;
DLSYM_PROTOTYPE(gcry_mpi_mod) = NULL;
DLSYM_PROTOTYPE(gcry_mpi_mul) = NULL;
DLSYM_PROTOTYPE(gcry_mpi_mulm) = NULL;
DLSYM_PROTOTYPE(gcry_mpi_new) = NULL;
DLSYM_PROTOTYPE(gcry_mpi_powm) = NULL;
DLSYM_PROTOTYPE(gcry_mpi_print) = NULL;
DLSYM_PROTOTYPE(gcry_mpi_release) = NULL;
DLSYM_PROTOTYPE(gcry_mpi_scan) = NULL;
DLSYM_PROTOTYPE(gcry_mpi_set_ui) = NULL;
DLSYM_PROTOTYPE(gcry_mpi_sub) = NULL;
DLSYM_PROTOTYPE(gcry_mpi_subm) = NULL;
DLSYM_PROTOTYPE(gcry_mpi_sub_ui) = NULL;
DLSYM_PROTOTYPE(gcry_prime_check) = NULL;
DLSYM_PROTOTYPE(gcry_randomize) = NULL;
DLSYM_PROTOTYPE(gcry_strerror) = NULL;

static int dlopen_gcrypt(void) {
        ELF_NOTE_DLOPEN("gcrypt",
                        "Support for journald forward-sealing",
                        ELF_NOTE_DLOPEN_PRIORITY_SUGGESTED,
                        "libgcrypt.so.20");

        return dlopen_many_sym_or_warn(
                        &gcrypt_dl,
                        "libgcrypt.so.20", LOG_DEBUG,
                        DLSYM_ARG(gcry_control),
                        DLSYM_ARG(gcry_check_version),
                        DLSYM_ARG(gcry_md_close),
                        DLSYM_ARG(gcry_md_copy),
                        DLSYM_ARG(gcry_md_ctl),
                        DLSYM_ARG(gcry_md_get_algo_dlen),
                        DLSYM_ARG(gcry_md_open),
                        DLSYM_ARG(gcry_md_read),
                        DLSYM_ARG(gcry_md_reset),
                        DLSYM_ARG(gcry_md_setkey),
                        DLSYM_ARG(gcry_md_write),
                        DLSYM_ARG(gcry_mpi_add),
                        DLSYM_ARG(gcry_mpi_add_ui),
                        DLSYM_ARG(gcry_mpi_cmp),
                        DLSYM_ARG(gcry_mpi_cmp_ui),
                        DLSYM_ARG(gcry_mpi_get_nbits),
                        DLSYM_ARG(gcry_mpi_invm),
                        DLSYM_ARG(gcry_mpi_mod),
                        DLSYM_ARG(gcry_mpi_mul),
                        DLSYM_ARG(gcry_mpi_mulm),
                        DLSYM_ARG(gcry_mpi_new),
                        DLSYM_ARG(gcry_mpi_powm),
                        DLSYM_ARG(gcry_mpi_print),
                        DLSYM_ARG(gcry_mpi_release),
                        DLSYM_ARG(gcry_mpi_scan),
                        DLSYM_ARG(gcry_mpi_set_ui),
                        DLSYM_ARG(gcry_mpi_sub),
                        DLSYM_ARG(gcry_mpi_subm),
                        DLSYM_ARG(gcry_mpi_sub_ui),
                        DLSYM_ARG(gcry_prime_check),
                        DLSYM_ARG(gcry_randomize),
                        DLSYM_ARG(gcry_strerror));
}

int initialize_libgcrypt(bool secmem) {
        int r;

        r = dlopen_gcrypt();
        if (r < 0)
                return r;

        if (sym_gcry_control(GCRYCTL_INITIALIZATION_FINISHED_P))
                return 0;

        sym_gcry_control(GCRYCTL_SET_PREFERRED_RNG_TYPE, GCRY_RNG_TYPE_SYSTEM);
        assert_se(sym_gcry_check_version("1.4.5"));

        /* Turn off "secmem". Clients which wish to make use of this
         * feature should initialize the library manually */
        if (!secmem)
                sym_gcry_control(GCRYCTL_DISABLE_SECMEM);

        sym_gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);

        return 0;
}
#endif
