/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>

#include "hash-funcs.h"

typedef struct ExecContext ExecContext;
typedef struct ExecParameters ExecParameters;
typedef struct Unit Unit;

/* A credential configured with LoadCredential= */
typedef struct ExecLoadCredential {
        char *id, *path;
        bool encrypted;
} ExecLoadCredential;

/* A credential configured with SetCredential= */
typedef struct ExecSetCredential {
        char *id;
        bool encrypted;
        void *data;
        size_t size;
} ExecSetCredential;

ExecSetCredential *exec_set_credential_free(ExecSetCredential *sc);
DEFINE_TRIVIAL_CLEANUP_FUNC(ExecSetCredential*, exec_set_credential_free);

ExecLoadCredential *exec_load_credential_free(ExecLoadCredential *lc);
DEFINE_TRIVIAL_CLEANUP_FUNC(ExecLoadCredential*, exec_load_credential_free);

extern const struct hash_ops exec_set_credential_hash_ops;
extern const struct hash_ops exec_load_credential_hash_ops;

bool exec_context_has_encrypted_credentials(ExecContext *c);
bool exec_context_has_credentials(const ExecContext *c);

int exec_context_get_credential_directory(
                const ExecContext *context,
                const ExecParameters *params,
                const char *unit,
                char **ret);

int unit_add_default_credential_dependencies(Unit *u, const ExecContext *c);

int exec_context_destroy_credentials(Unit *u);
int exec_setup_credentials(
                const ExecContext *context,
                const ExecParameters *params,
                const char *unit,
                uid_t uid,
                gid_t gid);
