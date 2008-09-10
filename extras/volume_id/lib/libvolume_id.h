/*
 * volume_id - reads volume label and uuid
 *
 * Copyright (C) 2005-2008 Kay Sievers <kay.sievers@vrfy.org>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _LIBVOLUME_ID_H_
#define _LIBVOLUME_ID_H_

#include <stdint.h>
#include <stddef.h>

struct volume_id;
typedef void (*volume_id_log_fn_t)(int priority, const char *file, int line, const char *format, ...)
	     __attribute__ ((format(printf, 4, 5)));
extern volume_id_log_fn_t volume_id_log_fn;

typedef int (*volume_id_probe_fn_t)(struct volume_id *id, uint64_t off, uint64_t size);
typedef int (*all_probers_fn_t)(volume_id_probe_fn_t probe_fn,
				struct volume_id *id, uint64_t off, uint64_t size,
				void *data);

extern struct volume_id *volume_id_open_fd(int fd);
extern void volume_id_close(struct volume_id *id);
extern int volume_id_probe_filesystem(struct volume_id *id, uint64_t off, uint64_t size);
extern int volume_id_probe_raid(struct volume_id *id, uint64_t off, uint64_t size);
extern int volume_id_probe_all(struct volume_id *id, uint64_t off, uint64_t size);
extern const volume_id_probe_fn_t *volume_id_get_prober_by_type(const char *type);
extern void volume_id_all_probers(all_probers_fn_t all_probers_fn,
				  struct volume_id *id, uint64_t off, uint64_t size,
				  void *data);
extern int volume_id_get_label(struct volume_id *id, const char **label);
extern int volume_id_get_label_raw(struct volume_id *id, const uint8_t **label, size_t *len);
extern int volume_id_get_uuid(struct volume_id *id, const char **uuid);
extern int volume_id_get_uuid_raw(struct volume_id *id, const uint8_t **uuid, size_t *len);
extern int volume_id_get_usage(struct volume_id *id, const char **usage);
extern int volume_id_get_type(struct volume_id *id, const char **type);
extern int volume_id_get_type_version(struct volume_id *id, const char **type_version);
extern int volume_id_encode_string(const char *str, char *str_enc, size_t len);

#endif
