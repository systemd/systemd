/* SPDX-License-Identifier: LGPL-2.1+ */

#include <sys/file.h>
#include <limits.h>
#include "rdtd-resctrl.h"
#include "string-util.h"
#include "fileio.h"
#include "dirent-util.h"
#include "parse-util.h"
#include "fd-util.h"
#include "extract-word.h"
#include "strv.h"

int resctrl_lock(void) {
        int fd;

        fd = open(RESCTRL_PATH, O_DIRECTORY | O_CLOEXEC);
        if (fd < 0) {
                log_warning("failed to open %s: %m", RESCTRL_PATH);
                return -errno;
        }

        if (flock(fd, LOCK_EX) < 0) {
                log_warning("failed to lock %s: %m", RESCTRL_PATH);
                close(fd);
                return -errno;
        }
        return fd;
}

int resctrl_unlock(int fd) {
        if (fd == -1)
                return 0;

        /* close fd will unlock */
        if (close(fd) < 0) {
                log_warning("failed to close %s: %m", RESCTRL_PATH);

                /* Trying to unlock again */
                if (flock(fd, LOCK_UN) < 0)
                        log_warning("failed to unlock %s: %m", RESCTRL_PATH);
                return -errno;
        }
        return 0;
}

static int resctrl_parse_l3_schemata(ResctrlAllocSchemata *used,
                                     char *schema, unsigned int *max_id) {
        char **s;
        _cleanup_strv_free_ char **word = NULL;
        unsigned int id_val;
        uint64_t mask_val;
        int ret;
        unsigned int max = 0;

        word = strv_split(schema, ";");
        STRV_FOREACH(s, word) {
                _cleanup_free_ char *id = NULL, *mask = NULL;
                max++;
                if (!used)
                        continue;

                ret = extract_many_words((const char **)s, "=", 0, &id, &mask, NULL);
                if (ret != 2)
                        return -EINVAL;

                ret = safe_atou(id, &id_val);
                if (ret < 0)
                        return ret;
                ret = safe_atox64(mask, &mask_val);
                if (ret < 0)
                        return ret;
                used->bits_mask[id_val] |= mask_val;
        }
        if (!used)
                *max_id = max;
        return 0;
}

static int resctrl_alloc_schemata_read(const char *name,
                                       ResctrlAllocSchemata *used,
                                       unsigned int *max_id) {
        _cleanup_free_ char *file = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        char line[LINE_MAX];
        int ret;

        file = strjoin(RESCTRL_PATH, "/", name, "/schemata");
        if (!file)
                return -ENOMEM;

        f = fopen(file, "re");
        if (!f)
                return log_warning_errno(errno, "Cannot open %s: %m", file);

        FOREACH_LINE(line, f, goto read_fail) {
                char *c;
                _cleanup_free_ char *type = NULL, *schema = NULL;

                c = skip_leading_chars(line, NULL);
                c = truncate_nl(c);

                if (extract_many_words((const char **)&c, ":", 0, &type, &schema, NULL) != 2)
                        continue;

                if (streq(type, RESCTRL_TYPE_L3)) {
                        ret = resctrl_parse_l3_schemata(used, schema, max_id);
                        if (ret < 0) {
                                log_warning("Failed to parse %s schemata", name);
                                return ret;
                        }
                }
        }
        return 0;
read_fail:
        return log_warning_errno(errno, "Failed to read %s: %m", file);
}

static ResctrlAllocSchemata *resctrl_get_alloc_schemata(void) {
        ResctrlAllocSchemata *alloc = NULL;

        alloc = new0(ResctrlAllocSchemata, 1);
        if (!alloc)
                return NULL;

        alloc->bits_mask = new0(uint64_t, alloc->max_ids);
        if (!alloc->bits_mask)
                return mfree(alloc);

        return alloc;
}

static void resctrl_put_alloc_schemata(ResctrlAllocSchemata *alloc) {
        if (!alloc)
                return;
        if (alloc->bits_mask)
                free(alloc->bits_mask);
        free(alloc);
}

static int resctrl_alloc_get_unused(RdtGroup *g,
                                    ResctrlAllocSchemata **alloc) {
        _cleanup_closedir_ DIR *d = NULL;
        struct dirent *de;
        int ret;
        ResctrlAllocSchemata *used;
        unsigned int i;
        RdtInfo *rinfo = g->manager->rdtinfo;

        d = opendir(RESCTRL_PATH);
        if (!d)
                return errno == ENOENT ? 0 : -errno;

        used = resctrl_get_alloc_schemata();
        if (!used)
                return -ENOMEM;
        used->max_ids = rinfo->l3_info.max_ids;

        FOREACH_DIRENT(de, d, return -errno) {
                if (dirent_is_file(de))
                        continue;
                if (streq(de->d_name, "info") || streq(de->d_name, "mon_data") ||
                    streq(de->d_name, "mon_groups") || streq(de->d_name, g->name))
                        continue;
                ret = resctrl_alloc_schemata_read(de->d_name, used, NULL);
                if (ret < 0) {
                        log_warning_errno(errno, "Failed to read %s: %m", de->d_name);
                        return ret;
                }
        }

        for (i = 0; i < used->max_ids; i++) {
                /* ^ zeroes the used bits */
                used->bits_mask[i] ^= rinfo->l3_info.cbm_mask;
                log_debug("resctrl group %s: L3 free schemata: id=%u, schema=%lx",
                         g->name, i, used->bits_mask[i]);
        }

        *alloc = used;
        return 0;
}

static int resctrl_alloc_l3_count_need_bits(RdtGroup *g,
                                            uint64_t request_size,
                                            unsigned int *bits) {
        RdtInfo *rinfo = g->manager->rdtinfo;

        if (request_size > rinfo->l3_info.cache_bytes || !request_size)
                return -EINVAL;
        *bits = DIV_ROUND_UP(request_size, rinfo->l3_info.granularity);
        return 0;
}

static int resctrl_alloc_l3_set_mask(RdtGroup *g,
                                     ResctrlAllocSchemata *alloc,
                                     unsigned *ids_v) {
        unsigned int i, found, tmp_bits;
        RdtInfo *rinfo = g->manager->rdtinfo;
        unsigned int max_bits = rinfo->l3_info.cbm_bits;
        uint64_t mask;
        unsigned int bits;

        for (i = 0; i < alloc->max_ids; i++) {
                bits = ids_v[i]; /* bits to be set */
                mask = alloc->bits_mask[i]; /* unused mask for this id */

                if (bits == 0) { /* full cache access for this id */
                        alloc->bits_mask[i] = rinfo->l3_info.cbm_mask;
                        continue;
                }

                alloc->bits_mask[i] = 0; /* reinit mask */
                tmp_bits = max_bits;
                found = 0;
                while (tmp_bits) {
                        if (mask & 1) {
                                found++;
                                alloc->bits_mask[i] |= (1UL << (max_bits - tmp_bits));
                                if (found == bits)
                                        break;
                        } else {
                                found = 0;
                                alloc->bits_mask[i] = 0;
                        }
                        mask >>= 1;
                        tmp_bits--;
                }
                if (found != bits)
                        return -ENOSPC;
        }
        return 0;
}

static int resctrl_set_ids(unsigned int *ids_v, char *s, char *e,
                           unsigned max_id, unsigned int bits) {
        unsigned int i;
        int ret;
        unsigned int sid, eid;

        ret = safe_atou(s, &sid);
        if (ret < 0 || sid >= max_id) {
                log_warning("wrong id %s\n", s);
                return -EINVAL;
        }
        if (s == e) {
                eid = sid;
        } else {
                ret = safe_atou(e, &eid);
                if (ret < 0 || eid >= max_id) {
                        log_warning("wrong id %s\n", e);
                        return -EINVAL;
                }
        }
        for (i = sid; i <= eid; i++)
                ids_v[i] = bits;
        return 0;
}

static int resctrl_parse_ids(const char *ids, unsigned int *ids_v,
                             unsigned int max_id, unsigned int bits) {
        char **s;
        _cleanup_strv_free_ char **word = NULL;
        int ret;
        unsigned int i;

        if (!ids || streq(ids, "all")) {
                for (i = 0; i < max_id; i++)
                        ids_v[i] = bits;
                return 0;
        }

        word = strv_split(ids, ",");
        STRV_FOREACH(s, word) {
                _cleanup_free_ char *start = NULL, *end = NULL;

                ret = extract_many_words((const char **)s, "-", 0, &start, &end, NULL);
                if (ret == 2)
                        ret = resctrl_set_ids(ids_v, start, end, max_id, bits);
                else if (ret == 1)
                        ret = resctrl_set_ids(ids_v, start, start, max_id, bits);
                else
                        ret = -EINVAL;
                if (ret < 0)
                        return ret;
        }
        return 0;
}

static int resctrl_alloc_l3_schemata_reserve(RdtGroup *g,
                                             ResctrlAllocSchemata *alloc,
                                             const char *ids, uint64_t size) {
        int ret = 0;
        _cleanup_free_ unsigned int *ids_v = NULL; /* store the bits we need */
        unsigned int i;
        unsigned int bits;
        const char *name = g->name;

        ids_v = new0(unsigned int, alloc->max_ids);
        if (!ids_v)
                return -ENOMEM;

        ret = resctrl_alloc_l3_count_need_bits(g, size, &bits);
        if (ret < 0)
                return ret;
        log_debug("resctrl group %s: l3 request bits %u", name, bits);

        ret = resctrl_parse_ids(ids, ids_v, alloc->max_ids, bits);
        if (ret < 0) {
                log_warning("resctrl group %s: failed to parse ids.", name);
                return ret;
        }

        ret = resctrl_alloc_l3_set_mask(g, alloc, ids_v);
        if (ret < 0) {
                log_warning("resctrl group %s: No enough free schemata.", name);
                return ret;
        }

        for (i = 0; i < alloc->max_ids; i++)
                log_debug("resctrl group %s: L3 new schemata: id=%u, schema=%lx",
                          name, i, alloc->bits_mask[i]);

        return 0;
}

static int resctrl_alloc_schemata_write(RdtGroup *g,
                                        ResctrlAllocSchemata *alloc_to) {
        _cleanup_free_ char *path = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        char schema[LINE_MAX] = { 0 };
        char *p;
        unsigned int i;
        uint64_t mask;
        const char *name = g->name;

        path = strjoin(RESCTRL_PATH, "/", name, "/schemata");
        if (!path)
                return -ENOMEM;

        f = fopen(path, "w");
        if (!f)
                return -errno;

        p = schema;
        strcpy(p, "L3:");
        for (i = 0; i < alloc_to->max_ids; i++) {
                mask = alloc_to->bits_mask[i];
                p += strlen(p);
                sprintf(p, "%u=%lx;", i, mask);
        }
        p = schema;
        p = delete_trailing_chars(p, ";");

        log_debug("resctrl group %s: writing %s", name, p);
        /* Write schemata to file */
        if (fprintf(f, "%s\n", p) < 0) {
                return log_warning_errno(errno, "resctrl group %s: "
                                         "failed to write schemata %m", name);
        }
        return 0;
}

static int resctrl_alloc_l3_schemata_update(RdtGroup *g) {
        ResctrlAllocSchemata *alloc = NULL;
        int ret;
        const char *name = g->name;

        ret = resctrl_alloc_get_unused(g, &alloc);
        if (ret < 0) {
                log_warning("resctrl group %s: Failed to get free schemata.",
                            name);
                goto out;
        }

        ret = resctrl_alloc_l3_schemata_reserve(g, alloc, g->l3_id, g->l3_size);
        if (ret < 0) {
                log_warning("resctrl group %s: Failed to reserve L3 schemata.",
                            name);
                goto out;
        }

        ret = resctrl_alloc_schemata_write(g, alloc);
        if (ret < 0) {
                log_warning("resctrl group %s: Failed to write schemata.",
                            name);
                goto out;
        }

out:
        resctrl_put_alloc_schemata(alloc);
        return ret;
}

int resctrl_alloc_group_remove(const char *name) {
        _cleanup_free_ char *path = NULL;
        _cleanup_free_ char *task_file = NULL;
        _cleanup_free_ char *buf = NULL;
        size_t l = 0;
        int r;

        task_file = strjoin(RESCTRL_PATH, "/", name, "/tasks");
        if (!task_file)
                return -ENOMEM;

        r = read_full_file(task_file, &buf, &l);
        if (r < 0)
                return r;

        if (l > 0) {
                log_warning("There are tasks running in group %s,"
                            " not remove\n", name);
                return -EPERM;
        }

        path = strjoin(RESCTRL_PATH, "/", name);
        if (!path)
                return -ENOMEM;

        if (rmdir(path) == -1) {
                if (errno == ENOENT)
                        return 0;
                return log_warning_errno(errno, "Failed to remove "
                                         "resctrl group %s: %m", name);
        }
        log_debug("resctrl group %s removed\n", name);
        return 0;
}

static int resctrl_alloc_group_create(const char *name) {
        _cleanup_free_ char *path = NULL;
        int ret;

        path = strjoin(RESCTRL_PATH, "/", name);
        if (!path)
                return -ENOMEM;

        ret = mkdir(path, 0755);
        if (ret < 0) {
                if (errno == EEXIST)
                        return 0;
                return log_warning_errno(errno, "Failed to create "
                                         "resctrl group %s: %m", name);
        }
        log_debug("resctrl group %s created\n", name);
        return 0;
}

static int resctrl_get_l3_cache_size(RdtInfoL3 *l3_info) {
        _cleanup_free_ char *contents = NULL;
        int ret;

        ret = read_one_line_file(L3_CACHE_FILE, &contents);
        if (ret < 0)
                return log_warning_errno(errno, "Cannot open %s: %m", L3_CACHE_FILE);

        return parse_size(contents, 1024, &l3_info->cache_bytes);
}

static int resctrl_get_l3_cache_max_id(RdtInfoL3 *l3_info) {
        int ret;
        unsigned int max_id = 0;

        ret = resctrl_alloc_schemata_read(".", NULL, &max_id);
        if (ret < 0)
                return ret;

        l3_info->max_ids = max_id;
        return 0;
}

static void resctrl_cal_mask_bits(RdtInfoL3 *l3_info) {
        uint64_t tmp_mask;

        /* get CAT mask bits */
        tmp_mask = l3_info->cbm_mask;
        l3_info->cbm_bits = 0;
        while (tmp_mask) {
                tmp_mask >>= 1;
                l3_info->cbm_bits++;
        }
}

static int resctrl_read_file(const char *level, const char *filename,
                             const char *types, void *key) {
        _cleanup_free_ char *path = NULL;
        _cleanup_free_ char *value = NULL;
        int ret;

        path = strjoin(RESCTRL_PATH_INFO, "/", level, "/", filename);
        if (!path)
                return -ENOMEM;
        ret = read_one_line_file(path, &value);
        if (ret < 0)
                return ret;
        if (streq(types, "uint"))
                return safe_atou(value, (unsigned int *)key);
        else if (streq(types, "x64"))
                return safe_atox64(value, (uint64_t *)key);
        return 0;
}

int resctrl_get_l3_info(RdtInfoL3 *l3_info, const char *type) {
        int ret;

        ret = resctrl_read_file(type, "num_closids", "uint", &l3_info->num_closids);
        if (ret < 0)
                return ret;
        ret = resctrl_read_file(type, "min_cbm_bits", "uint", &l3_info->min_cbm_bits);
        if (ret < 0)
                return ret;
        ret = resctrl_read_file(type, "cbm_mask", "x64", &l3_info->cbm_mask);
        if (ret < 0)
                return ret;

        ret = resctrl_get_l3_cache_size(l3_info);
        if (ret < 0)
                return ret;

        resctrl_cal_mask_bits(l3_info);
        if (l3_info->cbm_bits == 0)
                return -EINVAL;

        l3_info->granularity = l3_info->cache_bytes / l3_info->cbm_bits;
        if (l3_info->granularity == 0)
                return -EINVAL;

        ret = resctrl_get_l3_cache_max_id(l3_info);
        if (ret < 0)
                return ret;

        log_info("RDT l3 cache info:\n num_closids=%u, "
                 "min_cbm_bits=%u, cbm_mask=%lx\n cache_bytes=%lu, "
                 "cbm_bits=%u, granularity=%lu, max_ids=%u\n",
                 l3_info->num_closids, l3_info->min_cbm_bits,
                 l3_info->cbm_mask, l3_info->cache_bytes,
                 l3_info->cbm_bits, l3_info->granularity,
                 l3_info->max_ids);

        return 0;
}

int resctrl_update_schemata(RdtGroup *g) {
        int r;

        r = resctrl_alloc_group_create(g->name);
        if (r < 0)
                goto out;

        r = resctrl_alloc_l3_schemata_update(g);
        if (r < 0)
                goto out;

        return 0;
out:
        resctrl_alloc_group_remove(g->name);
        return r;
}
