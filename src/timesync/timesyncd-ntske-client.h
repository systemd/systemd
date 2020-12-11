/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "timesyncd-manager.h"

int get_record(unsigned char *data, int length, int *type, int *blength, void *ret);
int is_message_complete(unsigned char *data, int length);
int ntske_tls_send_request(Manager *m);
int ntske_tls_receive_response(sd_event_source *source, int fd, uint32_t revents, void *userdata);

int ntske_openssl_connect(Manager *manager);
void ntske_tls_bye(Manager *m);

ssize_t ntske_tls_write(Manager *m, const char *buf, size_t count);
ssize_t ntske_tls_read(Manager *m, void *buf, size_t count);

int ntske_tls_manager_init(Manager *manager);
void ntske_tls_manager_free(Manager *manager);
