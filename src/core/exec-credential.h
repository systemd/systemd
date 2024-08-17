/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>

#include "hash-funcs.h"

typedef struct ExecContext ExecContext;
typedef struct ExecParameters ExecParameters;

/* A credential configured with LoadCredential= */
typedef struct ExecLoadCredential {
        char *id;
        char *path;
        bool encrypted;
} ExecLoadCredential;

/* A credential configured with SetCredential= */
typedef struct ExecSetCredential {
        char *id;
        bool encrypted;
        void *data;
        size_t size;
} ExecSetCredential;

typedef struct ExecImportCredential {
        char *glob;
        char *rename;
} ExecImportCredential;

ExecSetCredential* exec_set_credential_free(ExecSetCredential *sc);
DEFINE_TRIVIAL_CLEANUP_FUNC(ExecSetCredential*, exec_set_credential_free);

ExecLoadCredential* exec_load_credential_free(ExecLoadCredential *lc);
DEFINE_TRIVIAL_CLEANUP_FUNC(ExecLoadCredential*, exec_load_credential_free);

ExecImportCredential* exec_import_credential_free(ExecImportCredential *lc);
DEFINE_TRIVIAL_CLEANUP_FUNC(ExecImportCredential*, exec_import_credential_free);

int exec_context_put_load_credential(ExecContext *c, const char *id, const char *path, bool encrypted);
int exec_context_put_set_credential(
                ExecContext *c,
                const char *id,
                void *data_consume,
                size_t size,
                bool encrypted);
int exec_context_put_import_credential(ExecContext *c, const char *glob, const char *rename);

bool exec_params_need_credentials(const ExecParameters *p);

bool exec_context_has_credentials(const ExecContext *c);
bool exec_context_has_encrypted_credentials(const ExecContext *c);

int exec_context_get_credential_directory(
                const ExecContext *context,
                const ExecParameters *params,
                const char *unit,
                char **ret);

int exec_context_destroy_credentials(const ExecContext *c, const char *runtime_root, const char *unit);

int exec_setup_credentials(
                const ExecContext *context,
                const ExecParameters *params,
                const char *unit,
                uid_t uid,
                gid_t gid);

bool mount_point_is_credentials(const char *runtime_prefix, const char *path);
