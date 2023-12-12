/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/types.h>

typedef struct MachineCredential {
        char *id;
        void *data;
        size_t size;
} MachineCredential;

typedef struct MachineCredentialContext {
        MachineCredential *credentials;
        size_t n_credentials;
} MachineCredentialContext;

void machine_credential_context_done(MachineCredentialContext *ctx);

bool machine_credentials_contains(const MachineCredentialContext *ctx, const char *id);

int machine_credential_set(MachineCredentialContext *ctx, const char *cred_str);
int machine_credential_load(MachineCredentialContext *ctx, const char *cred_path);
