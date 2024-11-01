/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

typedef struct Manager Manager;

int manager_serialize(Manager *manager);
int manager_set_serialization_fd(Manager *manager, int fd, const char *name);
int manager_deserialize(Manager *manager);
