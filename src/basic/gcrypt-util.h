/* SPDX-License-Identifier: LGPL-2.1-or-later */

#pragma once

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>

#if HAVE_GCRYPT
#include <gcrypt.h>

#include "dlfcn-util.h"
#include "macro.h"

extern DLSYM_PROTOTYPE(gcry_md_close);
extern DLSYM_PROTOTYPE(gcry_md_copy);
extern DLSYM_PROTOTYPE(gcry_md_ctl);
extern DLSYM_PROTOTYPE(gcry_md_get_algo_dlen);
extern DLSYM_PROTOTYPE(gcry_md_open);
extern DLSYM_PROTOTYPE(gcry_md_read);
extern DLSYM_PROTOTYPE(gcry_md_reset);
extern DLSYM_PROTOTYPE(gcry_md_setkey);
extern DLSYM_PROTOTYPE(gcry_md_write);
extern DLSYM_PROTOTYPE(gcry_mpi_add);
extern DLSYM_PROTOTYPE(gcry_mpi_add_ui);
extern DLSYM_PROTOTYPE(gcry_mpi_cmp);
extern DLSYM_PROTOTYPE(gcry_mpi_cmp_ui);
extern DLSYM_PROTOTYPE(gcry_mpi_get_nbits);
extern DLSYM_PROTOTYPE(gcry_mpi_invm);
extern DLSYM_PROTOTYPE(gcry_mpi_mod);
extern DLSYM_PROTOTYPE(gcry_mpi_mul);
extern DLSYM_PROTOTYPE(gcry_mpi_mulm);
extern DLSYM_PROTOTYPE(gcry_mpi_new);
extern DLSYM_PROTOTYPE(gcry_mpi_powm);
extern DLSYM_PROTOTYPE(gcry_mpi_print);
extern DLSYM_PROTOTYPE(gcry_mpi_release);
extern DLSYM_PROTOTYPE(gcry_mpi_scan);
extern DLSYM_PROTOTYPE(gcry_mpi_set_ui);
extern DLSYM_PROTOTYPE(gcry_mpi_sub);
extern DLSYM_PROTOTYPE(gcry_mpi_subm);
extern DLSYM_PROTOTYPE(gcry_mpi_sub_ui);
extern DLSYM_PROTOTYPE(gcry_prime_check);
extern DLSYM_PROTOTYPE(gcry_randomize);
extern DLSYM_PROTOTYPE(gcry_strerror);

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
