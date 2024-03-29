/* SPDX-License-Identifier: LGPL-2.1-or-later */

#pragma once

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>

#if HAVE_GCRYPT
#include <gcrypt.h>

#include "dlfcn-util.h"
#include "macro.h"

DLSYM_PROTOTYPE(gcry_md_close);
DLSYM_PROTOTYPE(gcry_md_copy);
DLSYM_PROTOTYPE(gcry_md_ctl);
DLSYM_PROTOTYPE(gcry_md_get_algo_dlen);
DLSYM_PROTOTYPE(gcry_md_open);
DLSYM_PROTOTYPE(gcry_md_read);
DLSYM_PROTOTYPE(gcry_md_reset);
DLSYM_PROTOTYPE(gcry_md_setkey);
DLSYM_PROTOTYPE(gcry_md_write);
DLSYM_PROTOTYPE(gcry_mpi_add);
DLSYM_PROTOTYPE(gcry_mpi_add_ui);
DLSYM_PROTOTYPE(gcry_mpi_cmp);
DLSYM_PROTOTYPE(gcry_mpi_cmp_ui);
DLSYM_PROTOTYPE(gcry_mpi_get_nbits);
DLSYM_PROTOTYPE(gcry_mpi_invm);
DLSYM_PROTOTYPE(gcry_mpi_mod);
DLSYM_PROTOTYPE(gcry_mpi_mul);
DLSYM_PROTOTYPE(gcry_mpi_mulm);
DLSYM_PROTOTYPE(gcry_mpi_new);
DLSYM_PROTOTYPE(gcry_mpi_powm);
DLSYM_PROTOTYPE(gcry_mpi_print);
DLSYM_PROTOTYPE(gcry_mpi_release);
DLSYM_PROTOTYPE(gcry_mpi_scan);
DLSYM_PROTOTYPE(gcry_mpi_set_ui);
DLSYM_PROTOTYPE(gcry_mpi_sub);
DLSYM_PROTOTYPE(gcry_mpi_subm);
DLSYM_PROTOTYPE(gcry_mpi_sub_ui);
DLSYM_PROTOTYPE(gcry_prime_check);
DLSYM_PROTOTYPE(gcry_randomize);
DLSYM_PROTOTYPE(gcry_strerror);

int initialize_libgcrypt(bool secmem);

static inline gcry_md_hd_t* sym_gcry_md_closep(gcry_md_hd_t *md) {
        if (!md || !*md)
                return NULL;
        sym_gcry_md_close(*md);

        return NULL;
}
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(gcry_md_hd_t, gcry_md_close, NULL);

/* Copied from gcry_md_putc from gcrypt.h due to the need to call the sym_ variant */
#define sym_gcry_md_putc(h,c)                              \
        do {                                               \
                gcry_md_hd_t h__ = (h);                    \
                if ((h__)->bufpos == (h__)->bufsize)       \
                        sym_gcry_md_write((h__), NULL, 0); \
                (h__)->buf[(h__)->bufpos++] = (c) & 0xff;  \
        } while(false)
#endif

#if !PREFER_OPENSSL
#  if HAVE_GCRYPT
int string_hashsum(const char *s, size_t len, int md_algorithm, char **out);
#  endif

static inline int string_hashsum_sha224(const char *s, size_t len, char **out) {
#  if HAVE_GCRYPT
        return string_hashsum(s, len, GCRY_MD_SHA224, out);
#  else
        return -EOPNOTSUPP;
#  endif
}

static inline int string_hashsum_sha256(const char *s, size_t len, char **out) {
#  if HAVE_GCRYPT
        return string_hashsum(s, len, GCRY_MD_SHA256, out);
#  else
        return -EOPNOTSUPP;
#  endif
}
#endif
