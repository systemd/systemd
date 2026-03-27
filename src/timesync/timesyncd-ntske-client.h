/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "timesyncd-manager.h"

int ntske_tls_send_request(Manager *m);
int ntske_tls_receive_response(sd_event_source *source, int fd, uint32_t revents, void *userdata);

int ntske_tls_connect(Manager *manager);
void ntske_tls_bye(Manager *m);

int ntske_tls_manager_init(Manager *manager);
void ntske_tls_manager_free(Manager *manager);

int aead_ciphers_to_gnu_tls_cipher_algorithm(int c);
