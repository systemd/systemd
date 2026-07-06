/* SPDX-License-Identifier: LGPL-2.1-or-later */

#pragma once

#include "basic-forward.h"

int dlopen_gcrypt(int log_level);

int initialize_libgcrypt(bool secmem);

#if HAVE_GCRYPT
#ifndef SYSTEMD_CFLAGS_MARKER_LIBGCRYPT
#  error "missing libgcrypt_cflags in meson dependency."
#endif

#include <gcrypt.h> /* IWYU pragma: export */

#include "dlfcn-util.h"

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

/* Copied from gcry_md_putc from gcrypt.h due to the need to call the sym_ variant */
#define sym_gcry_md_putc(h,c)                              \
        do {                                               \
                gcry_md_hd_t h__ = (h);                    \
                if ((h__)->bufpos == (h__)->bufsize)       \
                        sym_gcry_md_write((h__), NULL, 0); \
                (h__)->buf[(h__)->bufpos++] = (c) & 0xff;  \
        } while(false)

DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(gcry_md_hd_t, sym_gcry_md_close, NULL);
#endif
