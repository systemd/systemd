/* SPDX-License-Identifier: LGPL-2.1-or-later */

#if HAVE_VALGRIND_MEMCHECK_H
#include <valgrind/memcheck.h>
#endif

#include <fcntl.h>
#include <getopt.h>
#include <libfdisk.h>
#include <linux/fs.h>
#include <linux/loop.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

#include <openssl/hmac.h>
#include <openssl/sha.h>

#include "sd-id128.h"

#include "alloc-util.h"
#include "blkid-util.h"
#include "blockdev-util.h"
#include "btrfs-util.h"
#include "conf-files.h"
#include "conf-parser.h"
#include "cryptsetup-util.h"
#include "def.h"
#include "dirent-util.h"
#include "efivars.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "format-table.h"
#include "format-util.h"
#include "fs-util.h"
#include "gpt.h"
#include "hexdecoct.h"
#include "id128-util.h"
#include "json.h"
#include "list.h"
#include "locale-util.h"
#include "loop-util.h"
#include "main-func.h"
#include "mkdir.h"
#include "mkfs-util.h"
#include "mount-util.h"
#include "mountpoint-util.h"
#include "parse-argument.h"
#include "parse-util.h"
#include "path-util.h"
#include "pretty-print.h"
#include "proc-cmdline.h"
#include "process-util.h"
#include "random-util.h"
#include "resize-fs.h"
#include "sort-util.h"
#include "specifier.h"
#include "stat-util.h"
#include "stdio-util.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "terminal-util.h"
#include "tpm2-util.h"
#include "user-util.h"
#include "utf8.h"

/* If not configured otherwise use a minimal partition size of 10M */
#define DEFAULT_MIN_SIZE (10*1024*1024)

/* Hard lower limit for new partition sizes */
#define HARD_MIN_SIZE 4096

/* libfdisk takes off slightly more than 1M of the disk size when creating a GPT disk label */
#define GPT_METADATA_SIZE (1044*1024)

/* LUKS2 takes off 16M of the partition size with its metadata by default */
#define LUKS2_METADATA_SIZE (16*1024*1024)

/* Note: When growing and placing new partitions we always align to 4K sector size. It's how newer hard disks
 * are designed, and if everything is aligned to that performance is best. And for older hard disks with 512B
 * sector size devices were generally assumed to have an even number of sectors, hence at the worst we'll
 * waste 3K per partition, which is probably fine. */

static enum {
        EMPTY_REFUSE,   /* refuse empty disks, never create a partition table */
        EMPTY_ALLOW,    /* allow empty disks, create partition table if necessary */
        EMPTY_REQUIRE,  /* require an empty disk, create a partition table */
        EMPTY_FORCE,    /* make disk empty, erase everything, create a partition table always */
        EMPTY_CREATE,   /* create disk as loopback file, create a partition table always */
} arg_empty = EMPTY_REFUSE;

static bool arg_dry_run = true;
static const char *arg_node = NULL;
static char *arg_root = NULL;
static char *arg_image = NULL;
static char *arg_definitions = NULL;
static bool arg_discard = true;
static bool arg_can_factory_reset = false;
static int arg_factory_reset = -1;
static sd_id128_t arg_seed = SD_ID128_NULL;
static bool arg_randomize = false;
static int arg_pretty = -1;
static uint64_t arg_size = UINT64_MAX;
static bool arg_size_auto = false;
static JsonFormatFlags arg_json_format_flags = JSON_FORMAT_OFF;
static PagerFlags arg_pager_flags = 0;
static bool arg_legend = true;
static void *arg_key = NULL;
static size_t arg_key_size = 0;
static char *arg_tpm2_device = NULL;
static uint32_t arg_tpm2_pcr_mask = UINT32_MAX;

STATIC_DESTRUCTOR_REGISTER(arg_root, freep);
STATIC_DESTRUCTOR_REGISTER(arg_image, freep);
STATIC_DESTRUCTOR_REGISTER(arg_definitions, freep);
STATIC_DESTRUCTOR_REGISTER(arg_key, erase_and_freep);
STATIC_DESTRUCTOR_REGISTER(arg_tpm2_device, freep);

typedef struct Partition Partition;
typedef struct FreeArea FreeArea;
typedef struct Context Context;

typedef enum EncryptMode {
        ENCRYPT_OFF,
        ENCRYPT_KEY_FILE,
        ENCRYPT_TPM2,
        ENCRYPT_KEY_FILE_TPM2,
        _ENCRYPT_MODE_MAX,
        _ENCRYPT_MODE_INVALID = -EINVAL,
} EncryptMode;

struct Partition {
        char *definition_path;

        sd_id128_t type_uuid;
        sd_id128_t current_uuid, new_uuid;
        char *current_label, *new_label;

        bool dropped;
        bool factory_reset;
        int32_t priority;

        uint32_t weight, padding_weight;

        uint64_t current_size, new_size;
        uint64_t size_min, size_max;

        uint64_t current_padding, new_padding;
        uint64_t padding_min, padding_max;

        uint64_t partno;
        uint64_t offset;

        struct fdisk_partition *current_partition;
        struct fdisk_partition *new_partition;
        FreeArea *padding_area;
        FreeArea *allocated_to_area;

        char *copy_blocks_path;
        bool copy_blocks_auto;
        int copy_blocks_fd;
        uint64_t copy_blocks_size;

        char *format;
        char **copy_files;
        char **make_directories;
        EncryptMode encrypt;

        uint64_t gpt_flags;
        int no_auto;
        int read_only;
        int growfs;

        LIST_FIELDS(Partition, partitions);
};

#define PARTITION_IS_FOREIGN(p) (!(p)->definition_path)
#define PARTITION_EXISTS(p) (!!(p)->current_partition)

struct FreeArea {
        Partition *after;
        uint64_t size;
        uint64_t allocated;
};

struct Context {
        LIST_HEAD(Partition, partitions);
        size_t n_partitions;

        FreeArea **free_areas;
        size_t n_free_areas;

        uint64_t start, end, total;

        struct fdisk_context *fdisk_context;

        sd_id128_t seed;
};

static const char *encrypt_mode_table[_ENCRYPT_MODE_MAX] = {
        [ENCRYPT_OFF] = "off",
        [ENCRYPT_KEY_FILE] = "key-file",
        [ENCRYPT_TPM2] = "tpm2",
        [ENCRYPT_KEY_FILE_TPM2] = "key-file+tpm2",
};

#if HAVE_LIBCRYPTSETUP
DEFINE_PRIVATE_STRING_TABLE_LOOKUP_WITH_BOOLEAN(encrypt_mode, EncryptMode, ENCRYPT_KEY_FILE);
#else
DEFINE_PRIVATE_STRING_TABLE_LOOKUP_FROM_STRING_WITH_BOOLEAN(encrypt_mode, EncryptMode, ENCRYPT_KEY_FILE);
#endif


static uint64_t round_down_size(uint64_t v, uint64_t p) {
        return (v / p) * p;
}

static uint64_t round_up_size(uint64_t v, uint64_t p) {

        v = DIV_ROUND_UP(v, p);

        if (v > UINT64_MAX / p)
                return UINT64_MAX; /* overflow */

        return v * p;
}

static Partition *partition_new(void) {
        Partition *p;

        p = new(Partition, 1);
        if (!p)
                return NULL;

        *p = (Partition) {
                .weight = 1000,
                .padding_weight = 0,
                .current_size = UINT64_MAX,
                .new_size = UINT64_MAX,
                .size_min = UINT64_MAX,
                .size_max = UINT64_MAX,
                .current_padding = UINT64_MAX,
                .new_padding = UINT64_MAX,
                .padding_min = UINT64_MAX,
                .padding_max = UINT64_MAX,
                .partno = UINT64_MAX,
                .offset = UINT64_MAX,
                .copy_blocks_fd = -1,
                .copy_blocks_size = UINT64_MAX,
                .no_auto = -1,
                .read_only = -1,
                .growfs = -1,
        };

        return p;
}

static Partition* partition_free(Partition *p) {
        if (!p)
                return NULL;

        free(p->current_label);
        free(p->new_label);
        free(p->definition_path);

        if (p->current_partition)
                fdisk_unref_partition(p->current_partition);
        if (p->new_partition)
                fdisk_unref_partition(p->new_partition);

        free(p->copy_blocks_path);
        safe_close(p->copy_blocks_fd);

        free(p->format);
        strv_free(p->copy_files);
        strv_free(p->make_directories);

        return mfree(p);
}

static Partition* partition_unlink_and_free(Context *context, Partition *p) {
        if (!p)
                return NULL;

        LIST_REMOVE(partitions, context->partitions, p);

        assert(context->n_partitions > 0);
        context->n_partitions--;

        return partition_free(p);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(Partition*, partition_free);

static Context *context_new(sd_id128_t seed) {
        Context *context;

        context = new(Context, 1);
        if (!context)
                return NULL;

        *context = (Context) {
                .start = UINT64_MAX,
                .end = UINT64_MAX,
                .total = UINT64_MAX,
                .seed = seed,
        };

        return context;
}

static void context_free_free_areas(Context *context) {
        assert(context);

        for (size_t i = 0; i < context->n_free_areas; i++)
                free(context->free_areas[i]);

        context->free_areas = mfree(context->free_areas);
        context->n_free_areas = 0;
}

static Context *context_free(Context *context) {
        if (!context)
                return NULL;

        while (context->partitions)
                partition_unlink_and_free(context, context->partitions);
        assert(context->n_partitions == 0);

        context_free_free_areas(context);

        if (context->fdisk_context)
                fdisk_unref_context(context->fdisk_context);

        return mfree(context);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(Context*, context_free);

static int context_add_free_area(
                Context *context,
                uint64_t size,
                Partition *after) {

        FreeArea *a;

        assert(context);
        assert(!after || !after->padding_area);

        if (!GREEDY_REALLOC(context->free_areas, context->n_free_areas + 1))
                return -ENOMEM;

        a = new(FreeArea, 1);
        if (!a)
                return -ENOMEM;

        *a = (FreeArea) {
                .size = size,
                .after = after,
        };

        context->free_areas[context->n_free_areas++] = a;

        if (after)
                after->padding_area = a;

        return 0;
}

static bool context_drop_one_priority(Context *context) {
        int32_t priority = 0;
        Partition *p;
        bool exists = false;

        LIST_FOREACH(partitions, p, context->partitions) {
                if (p->dropped)
                        continue;
                if (p->priority < priority)
                        continue;
                if (p->priority == priority) {
                        exists = exists || PARTITION_EXISTS(p);
                        continue;
                }

                priority = p->priority;
                exists = PARTITION_EXISTS(p);
        }

        /* Refuse to drop partitions with 0 or negative priorities or partitions of priorities that have at
         * least one existing priority */
        if (priority <= 0 || exists)
                return false;

        LIST_FOREACH(partitions, p, context->partitions) {
                if (p->priority < priority)
                        continue;

                if (p->dropped)
                        continue;

                p->dropped = true;
                log_info("Can't fit partition %s of priority %" PRIi32 ", dropping.", p->definition_path, p->priority);
        }

        return true;
}

static uint64_t partition_min_size(const Partition *p) {
        uint64_t sz;

        /* Calculate the disk space we really need at minimum for this partition. If the partition already
         * exists the current size is what we really need. If it doesn't exist yet refuse to allocate less
         * than 4K.
         *
         * DEFAULT_MIN_SIZE is the default SizeMin= we configure if nothing else is specified. */

        if (PARTITION_IS_FOREIGN(p)) {
                /* Don't allow changing size of partitions not managed by us */
                assert(p->current_size != UINT64_MAX);
                return p->current_size;
        }

        sz = p->current_size != UINT64_MAX ? p->current_size : HARD_MIN_SIZE;

        if (!PARTITION_EXISTS(p)) {
                uint64_t d = 0;

                if (p->encrypt != ENCRYPT_OFF)
                        d += round_up_size(LUKS2_METADATA_SIZE, 4096);

                if (p->copy_blocks_size != UINT64_MAX)
                        d += round_up_size(p->copy_blocks_size, 4096);
                else if (p->format || p->encrypt != ENCRYPT_OFF) {
                        uint64_t f;

                        /* If we shall synthesize a file system, take minimal fs size into account (assumed to be 4K if not known) */
                        f = p->format ? minimal_size_by_fs_name(p->format) : UINT64_MAX;
                        d += f == UINT64_MAX ? 4096 : f;
                }

                if (d > sz)
                        sz = d;
        }

        return MAX(p->size_min != UINT64_MAX ? p->size_min : DEFAULT_MIN_SIZE, sz);
}

static uint64_t partition_max_size(const Partition *p) {
        /* Calculate how large the partition may become at max. This is generally the configured maximum
         * size, except when it already exists and is larger than that. In that case it's the existing size,
         * since we never want to shrink partitions. */

        if (PARTITION_IS_FOREIGN(p)) {
                /* Don't allow changing size of partitions not managed by us */
                assert(p->current_size != UINT64_MAX);
                return p->current_size;
        }

        if (p->current_size != UINT64_MAX)
                return MAX(p->current_size, p->size_max);

        return p->size_max;
}

static uint64_t partition_min_size_with_padding(const Partition *p) {
        uint64_t sz;

        /* Calculate the disk space we need for this partition plus any free space coming after it. This
         * takes user configured padding into account as well as any additional whitespace needed to align
         * the next partition to 4K again. */

        sz = partition_min_size(p);

        if (p->padding_min != UINT64_MAX)
                sz += p->padding_min;

        if (PARTITION_EXISTS(p)) {
                /* If the partition wasn't aligned, add extra space so that any we might add will be aligned */
                assert(p->offset != UINT64_MAX);
                return round_up_size(p->offset + sz, 4096) - p->offset;
        }

        /* If this is a new partition we'll place it aligned, hence we just need to round up the required size here */
        return round_up_size(sz, 4096);
}

static uint64_t free_area_available(const FreeArea *a) {
        assert(a);

        /* Determines how much of this free area is not allocated yet */

        assert(a->size >= a->allocated);
        return a->size - a->allocated;
}

static uint64_t free_area_available_for_new_partitions(const FreeArea *a) {
        uint64_t avail;

        /* Similar to free_area_available(), but takes into account that the required size and padding of the
         * preceding partition is honoured. */

        avail = free_area_available(a);
        if (a->after) {
                uint64_t need, space;

                need = partition_min_size_with_padding(a->after);

                assert(a->after->offset != UINT64_MAX);
                assert(a->after->current_size != UINT64_MAX);

                space = round_up_size(a->after->offset + a->after->current_size, 4096) - a->after->offset + avail;
                if (need >= space)
                        return 0;

                return space - need;
        }

        return avail;
}

static int free_area_compare(FreeArea *const *a, FreeArea *const*b) {
        return CMP(free_area_available_for_new_partitions(*a),
                   free_area_available_for_new_partitions(*b));
}

static uint64_t charge_size(uint64_t total, uint64_t amount) {
        uint64_t rounded;

        assert(amount <= total);

        /* Subtract the specified amount from total, rounding up to multiple of 4K if there's room */
        rounded = round_up_size(amount, 4096);
        if (rounded >= total)
                return 0;

        return total - rounded;
}

static uint64_t charge_weight(uint64_t total, uint64_t amount) {
        assert(amount <= total);
        return total - amount;
}

static bool context_allocate_partitions(Context *context) {
        Partition *p;

        assert(context);

        /* A simple first-fit algorithm, assuming the array of free areas is sorted by size in decreasing
         * order. */

        LIST_FOREACH(partitions, p, context->partitions) {
                bool fits = false;
                uint64_t required;
                FreeArea *a = NULL;

                /* Skip partitions we already dropped or that already exist */
                if (p->dropped || PARTITION_EXISTS(p))
                        continue;

                /* Sort by size */
                typesafe_qsort(context->free_areas, context->n_free_areas, free_area_compare);

                /* How much do we need to fit? */
                required = partition_min_size_with_padding(p);
                assert(required % 4096 == 0);

                for (size_t i = 0; i < context->n_free_areas; i++) {
                        a = context->free_areas[i];

                        if (free_area_available_for_new_partitions(a) >= required) {
                                fits = true;
                                break;
                        }
                }

                if (!fits)
                        return false; /* 😢 Oh no! We can't fit this partition into any free area! */

                /* Assign the partition to this free area */
                p->allocated_to_area = a;

                /* Budget the minimal partition size */
                a->allocated += required;
        }

        return true;
}

static int context_sum_weights(Context *context, FreeArea *a, uint64_t *ret) {
        uint64_t weight_sum = 0;
        Partition *p;

        assert(context);
        assert(a);
        assert(ret);

        /* Determine the sum of the weights of all partitions placed in or before the specified free area */

        LIST_FOREACH(partitions, p, context->partitions) {
                if (p->padding_area != a && p->allocated_to_area != a)
                        continue;

                if (p->weight > UINT64_MAX - weight_sum)
                        goto overflow_sum;
                weight_sum += p->weight;

                if (p->padding_weight > UINT64_MAX - weight_sum)
                        goto overflow_sum;
                weight_sum += p->padding_weight;
        }

        *ret = weight_sum;
        return 0;

overflow_sum:
        return log_error_errno(SYNTHETIC_ERRNO(EOVERFLOW), "Combined weight of partition exceeds unsigned 64bit range, refusing.");
}

static int scale_by_weight(uint64_t value, uint64_t weight, uint64_t weight_sum, uint64_t *ret) {
        assert(weight_sum >= weight);
        assert(ret);

        if (weight == 0) {
                *ret = 0;
                return 0;
        }

        if (value > UINT64_MAX / weight)
                return log_error_errno(SYNTHETIC_ERRNO(EOVERFLOW), "Scaling by weight of partition exceeds unsigned 64bit range, refusing.");

        *ret = value * weight / weight_sum;
        return 0;
}

typedef enum GrowPartitionPhase {
        /* The first phase: we charge partitions which need more (according to constraints) than their weight-based share. */
        PHASE_OVERCHARGE,

        /* The second phase: we charge partitions which need less (according to constraints) than their weight-based share. */
        PHASE_UNDERCHARGE,

        /* The third phase: we distribute what remains among the remaining partitions, according to the weights */
        PHASE_DISTRIBUTE,
} GrowPartitionPhase;

static int context_grow_partitions_phase(
                Context *context,
                FreeArea *a,
                GrowPartitionPhase phase,
                uint64_t *span,
                uint64_t *weight_sum) {

        Partition *p;
        int r;

        assert(context);
        assert(a);

        /* Now let's look at the intended weights and adjust them taking the minimum space assignments into
         * account. i.e. if a partition has a small weight but a high minimum space value set it should not
         * get any additional room from the left-overs. Similar, if two partitions have the same weight they
         * should get the same space if possible, even if one has a smaller minimum size than the other. */
        LIST_FOREACH(partitions, p, context->partitions) {

                /* Look only at partitions associated with this free area, i.e. immediately
                 * preceding it, or allocated into it */
                if (p->allocated_to_area != a && p->padding_area != a)
                        continue;

                if (p->new_size == UINT64_MAX) {
                        bool charge = false, try_again = false;
                        uint64_t share, rsz, xsz;

                        /* Calculate how much this space this partition needs if everyone would get
                         * the weight based share */
                        r = scale_by_weight(*span, p->weight, *weight_sum, &share);
                        if (r < 0)
                                return r;

                        rsz = partition_min_size(p);
                        xsz = partition_max_size(p);

                        if (phase == PHASE_OVERCHARGE && rsz > share) {
                                /* This partition needs more than its calculated share. Let's assign
                                 * it that, and take this partition out of all calculations and start
                                 * again. */

                                p->new_size = rsz;
                                charge = try_again = true;

                        } else if (phase == PHASE_UNDERCHARGE && xsz != UINT64_MAX && xsz < share) {
                                /* This partition accepts less than its calculated
                                 * share. Let's assign it that, and take this partition out
                                 * of all calculations and start again. */

                                p->new_size = xsz;
                                charge = try_again = true;

                        } else if (phase == PHASE_DISTRIBUTE) {
                                /* This partition can accept its calculated share. Let's
                                 * assign it. There's no need to restart things here since
                                 * assigning this shouldn't impact the shares of the other
                                 * partitions. */

                                if (PARTITION_IS_FOREIGN(p))
                                        /* Never change of foreign partitions (i.e. those we don't manage) */
                                        p->new_size = p->current_size;
                                else
                                        p->new_size = MAX(round_down_size(share, 4096), rsz);

                                charge = true;
                        }

                        if (charge) {
                                *span = charge_size(*span, p->new_size);
                                *weight_sum = charge_weight(*weight_sum, p->weight);
                        }

                        if (try_again)
                                return 0; /* try again */
                }

                if (p->new_padding == UINT64_MAX) {
                        bool charge = false, try_again = false;
                        uint64_t share;

                        r = scale_by_weight(*span, p->padding_weight, *weight_sum, &share);
                        if (r < 0)
                                return r;

                        if (phase == PHASE_OVERCHARGE && p->padding_min != UINT64_MAX && p->padding_min > share) {
                                p->new_padding = p->padding_min;
                                charge = try_again = true;
                        } else if (phase == PHASE_UNDERCHARGE && p->padding_max != UINT64_MAX && p->padding_max < share) {
                                p->new_padding = p->padding_max;
                                charge = try_again = true;
                        } else if (phase == PHASE_DISTRIBUTE) {

                                p->new_padding = round_down_size(share, 4096);
                                if (p->padding_min != UINT64_MAX && p->new_padding < p->padding_min)
                                        p->new_padding = p->padding_min;

                                charge = true;
                        }

                        if (charge) {
                                *span = charge_size(*span, p->new_padding);
                                *weight_sum = charge_weight(*weight_sum, p->padding_weight);
                        }

                        if (try_again)
                                return 0; /* try again */
                }
        }

        return 1; /* done */
}

static int context_grow_partitions_on_free_area(Context *context, FreeArea *a) {
        uint64_t weight_sum = 0, span;
        int r;

        assert(context);
        assert(a);

        r = context_sum_weights(context, a, &weight_sum);
        if (r < 0)
                return r;

        /* Let's calculate the total area covered by this free area and the partition before it */
        span = a->size;
        if (a->after) {
                assert(a->after->offset != UINT64_MAX);
                assert(a->after->current_size != UINT64_MAX);

                span += round_up_size(a->after->offset + a->after->current_size, 4096) - a->after->offset;
        }

        GrowPartitionPhase phase = PHASE_OVERCHARGE;
        for (;;) {
                r = context_grow_partitions_phase(context, a, phase, &span, &weight_sum);
                if (r < 0)
                        return r;
                if (r == 0) /* not done yet, re-run this phase */
                        continue;

                if (phase == PHASE_OVERCHARGE)
                        phase = PHASE_UNDERCHARGE;
                else if (phase == PHASE_UNDERCHARGE)
                        phase = PHASE_DISTRIBUTE;
                else if (phase == PHASE_DISTRIBUTE)
                        break;
        }

        /* We still have space left over? Donate to preceding partition if we have one */
        if (span > 0 && a->after && !PARTITION_IS_FOREIGN(a->after)) {
                uint64_t m, xsz;

                assert(a->after->new_size != UINT64_MAX);
                m = a->after->new_size + span;

                xsz = partition_max_size(a->after);
                if (xsz != UINT64_MAX && m > xsz)
                        m = xsz;

                span = charge_size(span, m - a->after->new_size);
                a->after->new_size = m;
        }

        /* What? Even still some space left (maybe because there was no preceding partition, or it had a
         * size limit), then let's donate it to whoever wants it. */
        if (span > 0) {
                Partition *p;

                LIST_FOREACH(partitions, p, context->partitions) {
                        uint64_t m, xsz;

                        if (p->allocated_to_area != a)
                                continue;

                        if (PARTITION_IS_FOREIGN(p))
                                continue;

                        assert(p->new_size != UINT64_MAX);
                        m = p->new_size + span;

                        xsz = partition_max_size(p);
                        if (xsz != UINT64_MAX && m > xsz)
                                m = xsz;

                        span = charge_size(span, m - p->new_size);
                        p->new_size = m;

                        if (span == 0)
                                break;
                }
        }

        /* Yuck, still no one? Then make it padding */
        if (span > 0 && a->after) {
                assert(a->after->new_padding != UINT64_MAX);
                a->after->new_padding += span;
        }

        return 0;
}

static int context_grow_partitions(Context *context) {
        Partition *p;
        int r;

        assert(context);

        for (size_t i = 0; i < context->n_free_areas; i++) {
                r = context_grow_partitions_on_free_area(context, context->free_areas[i]);
                if (r < 0)
                        return r;
        }

        /* All existing partitions that have no free space after them can't change size */
        LIST_FOREACH(partitions, p, context->partitions) {
                if (p->dropped)
                        continue;

                if (!PARTITION_EXISTS(p) || p->padding_area) {
                        /* The algorithm above must have initialized this already */
                        assert(p->new_size != UINT64_MAX);
                        continue;
                }

                assert(p->new_size == UINT64_MAX);
                p->new_size = p->current_size;

                assert(p->new_padding == UINT64_MAX);
                p->new_padding = p->current_padding;
        }

        return 0;
}

static void context_place_partitions(Context *context) {
        uint64_t partno = 0;
        Partition *p;

        assert(context);

        /* Determine next partition number to assign */
        LIST_FOREACH(partitions, p, context->partitions) {
                if (!PARTITION_EXISTS(p))
                        continue;

                assert(p->partno != UINT64_MAX);
                if (p->partno >= partno)
                        partno = p->partno + 1;
        }

        for (size_t i = 0; i < context->n_free_areas; i++) {
                FreeArea *a = context->free_areas[i];
                uint64_t start, left;

                if (a->after) {
                        assert(a->after->offset != UINT64_MAX);
                        assert(a->after->new_size != UINT64_MAX);
                        assert(a->after->new_padding != UINT64_MAX);

                        start = a->after->offset + a->after->new_size + a->after->new_padding;
                } else
                        start = context->start;

                start = round_up_size(start, 4096);
                left = a->size;

                LIST_FOREACH(partitions, p, context->partitions) {
                        if (p->allocated_to_area != a)
                                continue;

                        p->offset = start;
                        p->partno = partno++;

                        assert(left >= p->new_size);
                        start += p->new_size;
                        left -= p->new_size;

                        assert(left >= p->new_padding);
                        start += p->new_padding;
                        left -= p->new_padding;
                }
        }
}

static int config_parse_type(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        sd_id128_t *type_uuid = data;
        int r;

        assert(rvalue);
        assert(type_uuid);

        r = gpt_partition_type_uuid_from_string(rvalue, type_uuid);
        if (r < 0)
                return log_syntax(unit, LOG_ERR, filename, line, r, "Failed to parse partition type: %s", rvalue);

        return 0;
}

static int config_parse_label(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        _cleanup_free_ char *resolved = NULL;
        char **label = data;
        int r;

        assert(rvalue);
        assert(label);

        /* Nota bene: the empty label is a totally valid one. Let's hence not follow our usual rule of
         * assigning the empty string to reset to default here, but really accept it as label to set. */

        r = specifier_printf(rvalue, GPT_LABEL_MAX, system_and_tmp_specifier_table, arg_root, NULL, &resolved);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to expand specifiers in Label=, ignoring: %s", rvalue);
                return 0;
        }

        if (!utf8_is_valid(resolved)) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Partition label not valid UTF-8, ignoring: %s", rvalue);
                return 0;
        }

        r = gpt_partition_label_valid(resolved);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to check if string is valid as GPT partition label, ignoring: \"%s\" (from \"%s\")",
                           resolved, rvalue);
                return 0;
        }
        if (!r) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Partition label too long for GPT table, ignoring: \"%s\" (from \"%s\")",
                           resolved, rvalue);
                return 0;
        }

        free_and_replace(*label, resolved);
        return 0;
}

static int config_parse_weight(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        uint32_t *priority = data, v;
        int r;

        assert(rvalue);
        assert(priority);

        r = safe_atou32(rvalue, &v);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse weight value, ignoring: %s", rvalue);
                return 0;
        }

        if (v > 1000U*1000U) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Weight needs to be in range 0…10000000, ignoring: %" PRIu32, v);
                return 0;
        }

        *priority = v;
        return 0;
}

static int config_parse_size4096(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        uint64_t *sz = data, parsed;
        int r;

        assert(rvalue);
        assert(data);

        r = parse_size(rvalue, 1024, &parsed);
        if (r < 0)
                return log_syntax(unit, LOG_ERR, filename, line, r,
                                  "Failed to parse size value: %s", rvalue);

        if (ltype > 0)
                *sz = round_up_size(parsed, 4096);
        else if (ltype < 0)
                *sz = round_down_size(parsed, 4096);
        else
                *sz = parsed;

        if (*sz != parsed)
                log_syntax(unit, LOG_NOTICE, filename, line, r, "Rounded %s= size %" PRIu64 " → %" PRIu64 ", a multiple of 4096.", lvalue, parsed, *sz);

        return 0;
}

static int config_parse_fstype(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        char **fstype = data;

        assert(rvalue);
        assert(data);

        if (!filename_is_valid(rvalue))
                return log_syntax(unit, LOG_ERR, filename, line, 0,
                                  "File system type is not valid, refusing: %s", rvalue);

        return free_and_strdup_warn(fstype, rvalue);
}

static int config_parse_copy_files(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        _cleanup_free_ char *source = NULL, *buffer = NULL, *resolved_source = NULL, *resolved_target = NULL;
        const char *p = rvalue, *target;
        Partition *partition = data;
        int r;

        assert(rvalue);
        assert(partition);

        r = extract_first_word(&p, &source, ":", EXTRACT_CUNESCAPE|EXTRACT_DONT_COALESCE_SEPARATORS);
        if (r < 0)
                return log_syntax(unit, LOG_ERR, filename, line, r, "Failed to extract source path: %s", rvalue);
        if (r == 0) {
                log_syntax(unit, LOG_WARNING, filename, line, 0, "No argument specified: %s", rvalue);
                return 0;
        }

        r = extract_first_word(&p, &buffer, ":", EXTRACT_CUNESCAPE|EXTRACT_DONT_COALESCE_SEPARATORS);
        if (r < 0)
                return log_syntax(unit, LOG_ERR, filename, line, r, "Failed to extract target path: %s", rvalue);
        if (r == 0)
                target = source; /* No target, then it's the same as the source */
        else
                target = buffer;

        if (!isempty(p))
                return log_syntax(unit, LOG_ERR, filename, line, SYNTHETIC_ERRNO(EINVAL), "Too many arguments: %s", rvalue);

        r = specifier_printf(source, PATH_MAX-1, system_and_tmp_specifier_table, arg_root, NULL, &resolved_source);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to expand specifiers in CopyFiles= source, ignoring: %s", rvalue);
                return 0;
        }

        r = path_simplify_and_warn(resolved_source, PATH_CHECK_ABSOLUTE, unit, filename, line, lvalue);
        if (r < 0)
                return 0;

        r = specifier_printf(target, PATH_MAX-1, system_and_tmp_specifier_table, arg_root, NULL, &resolved_target);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to expand specifiers in CopyFiles= target, ignoring: %s", resolved_target);
                return 0;
        }

        r = path_simplify_and_warn(resolved_target, PATH_CHECK_ABSOLUTE, unit, filename, line, lvalue);
        if (r < 0)
                return 0;

        r = strv_consume_pair(&partition->copy_files, TAKE_PTR(resolved_source), TAKE_PTR(resolved_target));
        if (r < 0)
                return log_oom();

        return 0;
}

static int config_parse_copy_blocks(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        _cleanup_free_ char *d = NULL;
        Partition *partition = data;
        int r;

        assert(rvalue);
        assert(partition);

        if (isempty(rvalue)) {
                partition->copy_blocks_path = mfree(partition->copy_blocks_path);
                partition->copy_blocks_auto = false;
                return 0;
        }

        if (streq(rvalue, "auto")) {
                partition->copy_blocks_path = mfree(partition->copy_blocks_path);
                partition->copy_blocks_auto = true;
                return 0;
        }

        r = specifier_printf(rvalue, PATH_MAX-1, system_and_tmp_specifier_table, arg_root, NULL, &d);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to expand specifiers in CopyBlocks= source path, ignoring: %s", rvalue);
                return 0;
        }

        r = path_simplify_and_warn(d, PATH_CHECK_ABSOLUTE, unit, filename, line, lvalue);
        if (r < 0)
                return 0;

        free_and_replace(partition->copy_blocks_path, d);
        partition->copy_blocks_auto = false;
        return 0;
}

static int config_parse_make_dirs(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        Partition *partition = data;
        const char *p = rvalue;
        int r;

        assert(rvalue);
        assert(partition);

        for (;;) {
                _cleanup_free_ char *word = NULL, *d = NULL;

                r = extract_first_word(&p, &word, NULL, EXTRACT_UNQUOTE);
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r, "Invalid syntax, ignoring: %s", rvalue);
                        return 0;
                }
                if (r == 0)
                        return 0;

                r = specifier_printf(word, PATH_MAX-1, system_and_tmp_specifier_table, arg_root, NULL, &d);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Failed to expand specifiers in MakeDirectories= parameter, ignoring: %s", word);
                        continue;
                }

                r = path_simplify_and_warn(d, PATH_CHECK_ABSOLUTE, unit, filename, line, lvalue);
                if (r < 0)
                        continue;

                r = strv_consume(&partition->make_directories, TAKE_PTR(d));
                if (r < 0)
                        return log_oom();
        }
}

static DEFINE_CONFIG_PARSE_ENUM_WITH_DEFAULT(config_parse_encrypt, encrypt_mode, EncryptMode, ENCRYPT_OFF, "Invalid encryption mode");

static int config_parse_gpt_flags(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        uint64_t *gpt_flags = data;
        int r;

        assert(rvalue);
        assert(gpt_flags);

        r = safe_atou64(rvalue, gpt_flags);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse Flags= value, ignoring: %s", rvalue);
                return 0;
        }

        return 0;
}

static int partition_read_definition(Partition *p, const char *path) {

        ConfigTableItem table[] = {
                { "Partition", "Type",            config_parse_type,        0, &p->type_uuid        },
                { "Partition", "Label",           config_parse_label,       0, &p->new_label        },
                { "Partition", "UUID",            config_parse_id128,       0, &p->new_uuid         },
                { "Partition", "Priority",        config_parse_int32,       0, &p->priority         },
                { "Partition", "Weight",          config_parse_weight,      0, &p->weight           },
                { "Partition", "PaddingWeight",   config_parse_weight,      0, &p->padding_weight   },
                { "Partition", "SizeMinBytes",    config_parse_size4096,    1, &p->size_min         },
                { "Partition", "SizeMaxBytes",    config_parse_size4096,   -1, &p->size_max         },
                { "Partition", "PaddingMinBytes", config_parse_size4096,    1, &p->padding_min      },
                { "Partition", "PaddingMaxBytes", config_parse_size4096,   -1, &p->padding_max      },
                { "Partition", "FactoryReset",    config_parse_bool,        0, &p->factory_reset    },
                { "Partition", "CopyBlocks",      config_parse_copy_blocks, 0, p                    },
                { "Partition", "Format",          config_parse_fstype,      0, &p->format           },
                { "Partition", "CopyFiles",       config_parse_copy_files,  0, p                    },
                { "Partition", "MakeDirectories", config_parse_make_dirs,   0, p                    },
                { "Partition", "Encrypt",         config_parse_encrypt,     0, &p->encrypt          },
                { "Partition", "Flags",           config_parse_gpt_flags,   0, &p->gpt_flags        },
                { "Partition", "ReadOnly",        config_parse_tristate,    0, &p->read_only        },
                { "Partition", "NoAuto",          config_parse_tristate,    0, &p->no_auto          },
                { "Partition", "GrowFileSystem",  config_parse_tristate,    0, &p->growfs           },
                {}
        };
        int r;

        r = config_parse(NULL, path, NULL,
                         "Partition\0",
                         config_item_table_lookup, table,
                         CONFIG_PARSE_WARN,
                         p,
                         NULL);
        if (r < 0)
                return r;

        if (p->size_min != UINT64_MAX && p->size_max != UINT64_MAX && p->size_min > p->size_max)
                return log_syntax(NULL, LOG_ERR, path, 1, SYNTHETIC_ERRNO(EINVAL),
                                  "SizeMinBytes= larger than SizeMaxBytes=, refusing.");

        if (p->padding_min != UINT64_MAX && p->padding_max != UINT64_MAX && p->padding_min > p->padding_max)
                return log_syntax(NULL, LOG_ERR, path, 1, SYNTHETIC_ERRNO(EINVAL),
                                  "PaddingMinBytes= larger than PaddingMaxBytes=, refusing.");

        if (sd_id128_is_null(p->type_uuid))
                return log_syntax(NULL, LOG_ERR, path, 1, SYNTHETIC_ERRNO(EINVAL),
                                  "Type= not defined, refusing.");

        if ((p->copy_blocks_path || p->copy_blocks_auto) &&
            (p->format || !strv_isempty(p->copy_files) || !strv_isempty(p->make_directories)))
                return log_syntax(NULL, LOG_ERR, path, 1, SYNTHETIC_ERRNO(EINVAL),
                                  "Format=/CopyFiles=/MakeDirectories= and CopyBlocks= cannot be combined, refusing.");

        if ((!strv_isempty(p->copy_files) || !strv_isempty(p->make_directories)) && streq_ptr(p->format, "swap"))
                return log_syntax(NULL, LOG_ERR, path, 1, SYNTHETIC_ERRNO(EINVAL),
                                  "Format=swap and CopyFiles= cannot be combined, refusing.");

        if (!p->format && (!strv_isempty(p->copy_files) || !strv_isempty(p->make_directories) || (p->encrypt != ENCRYPT_OFF && !(p->copy_blocks_path || p->copy_blocks_auto)))) {
                /* Pick "ext4" as file system if we are configured to copy files or encrypt the device */
                p->format = strdup("ext4");
                if (!p->format)
                        return log_oom();
        }

        /* Verity partitions are read only, let's imply the RO flag hence, unless explicitly configured otherwise. */
        if ((gpt_partition_type_is_root_verity(p->type_uuid) ||
             gpt_partition_type_is_usr_verity(p->type_uuid)) &&
            p->read_only < 0)
                p->read_only = true;

        /* Default to "growfs" on, unless read-only */
        if (gpt_partition_type_knows_growfs(p->type_uuid) &&
            p->read_only <= 0)
                p->growfs = true;

        return 0;
}

static int context_read_definitions(
                Context *context,
                const char *directory,
                const char *root) {

        _cleanup_strv_free_ char **files = NULL;
        Partition *last = NULL;
        char **f;
        int r;

        assert(context);

        if (directory)
                r = conf_files_list_strv(&files, ".conf", NULL, CONF_FILES_REGULAR|CONF_FILES_FILTER_MASKED, (const char**) STRV_MAKE(directory));
        else
                r = conf_files_list_strv(&files, ".conf", root, CONF_FILES_REGULAR|CONF_FILES_FILTER_MASKED, (const char**) CONF_PATHS_STRV("repart.d"));
        if (r < 0)
                return log_error_errno(r, "Failed to enumerate *.conf files: %m");

        STRV_FOREACH(f, files) {
                _cleanup_(partition_freep) Partition *p = NULL;

                p = partition_new();
                if (!p)
                        return log_oom();

                p->definition_path = strdup(*f);
                if (!p->definition_path)
                        return log_oom();

                r = partition_read_definition(p, *f);
                if (r < 0)
                        return r;

                LIST_INSERT_AFTER(partitions, context->partitions, last, p);
                last = TAKE_PTR(p);
                context->n_partitions++;
        }

        return 0;
}

DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(struct fdisk_context*, fdisk_unref_context, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(struct fdisk_partition*, fdisk_unref_partition, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(struct fdisk_parttype*, fdisk_unref_parttype, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(struct fdisk_table*, fdisk_unref_table, NULL);

static int determine_current_padding(
                struct fdisk_context *c,
                struct fdisk_table *t,
                struct fdisk_partition *p,
                uint64_t *ret) {

        size_t n_partitions;
        uint64_t offset, next = UINT64_MAX;

        assert(c);
        assert(t);
        assert(p);

        if (!fdisk_partition_has_end(p))
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Partition has no end!");

        offset = fdisk_partition_get_end(p);
        assert(offset < UINT64_MAX / 512);
        offset *= 512;

        n_partitions = fdisk_table_get_nents(t);
        for (size_t i = 0; i < n_partitions; i++)  {
                struct fdisk_partition *q;
                uint64_t start;

                q = fdisk_table_get_partition(t, i);
                if (!q)
                        return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to read partition metadata: %m");

                if (fdisk_partition_is_used(q) <= 0)
                        continue;

                if (!fdisk_partition_has_start(q))
                        continue;

                start = fdisk_partition_get_start(q);
                assert(start < UINT64_MAX / 512);
                start *= 512;

                if (start >= offset && (next == UINT64_MAX || next > start))
                        next = start;
        }

        if (next == UINT64_MAX) {
                /* No later partition? In that case check the end of the usable area */
                next = fdisk_get_last_lba(c);
                assert(next < UINT64_MAX);
                next++; /* The last LBA is one sector before the end */

                assert(next < UINT64_MAX / 512);
                next *= 512;

                if (offset > next)
                        return log_error_errno(SYNTHETIC_ERRNO(EIO), "Partition end beyond disk end.");
        }

        assert(next >= offset);
        offset = round_up_size(offset, 4096);
        next = round_down_size(next, 4096);

        if (next >= offset) /* Check again, rounding might have fucked things up */
                *ret = next - offset;
        else
                *ret = 0;

        return 0;
}

static int fdisk_ask_cb(struct fdisk_context *c, struct fdisk_ask *ask, void *data) {
        _cleanup_free_ char *ids = NULL;
        int r;

        if (fdisk_ask_get_type(ask) != FDISK_ASKTYPE_STRING)
                return -EINVAL;

        ids = new(char, ID128_UUID_STRING_MAX);
        if (!ids)
                return -ENOMEM;

        r = fdisk_ask_string_set_result(ask, id128_to_uuid_string(*(sd_id128_t*) data, ids));
        if (r < 0)
                return r;

        TAKE_PTR(ids);
        return 0;
}

static int fdisk_set_disklabel_id_by_uuid(struct fdisk_context *c, sd_id128_t id) {
        int r;

        r = fdisk_set_ask(c, fdisk_ask_cb, &id);
        if (r < 0)
                return r;

        r = fdisk_set_disklabel_id(c);
        if (r < 0)
                return r;

        return fdisk_set_ask(c, NULL, NULL);
}

static int derive_uuid(sd_id128_t base, const char *token, sd_id128_t *ret) {
        union {
                unsigned char md[SHA256_DIGEST_LENGTH];
                sd_id128_t id;
        } result;

        assert(token);
        assert(ret);

        /* Derive a new UUID from the specified UUID in a stable and reasonably safe way. Specifically, we
         * calculate the HMAC-SHA256 of the specified token string, keyed by the supplied base (typically the
         * machine ID). We use the machine ID as key (and not as cleartext!) of the HMAC operation since it's
         * the machine ID we don't want to leak. */

        if (!HMAC(EVP_sha256(),
                  &base, sizeof(base),
                  (const unsigned char*) token, strlen(token),
                  result.md, NULL))
                return log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE), "HMAC-SHA256 calculation failed.");

        /* Take the first half, mark it as v4 UUID */
        assert_cc(sizeof(result.md) == sizeof(result.id) * 2);
        *ret = id128_make_v4_uuid(result.id);
        return 0;
}

static int context_load_partition_table(
                Context *context,
                const char *node,
                int *backing_fd) {

        _cleanup_(fdisk_unref_contextp) struct fdisk_context *c = NULL;
        _cleanup_(fdisk_unref_tablep) struct fdisk_table *t = NULL;
        uint64_t left_boundary = UINT64_MAX, first_lba, last_lba, nsectors;
        _cleanup_free_ char *disk_uuid_string = NULL;
        bool from_scratch = false;
        sd_id128_t disk_uuid;
        size_t n_partitions;
        int r;

        assert(context);
        assert(node);
        assert(backing_fd);
        assert(!context->fdisk_context);
        assert(!context->free_areas);
        assert(context->start == UINT64_MAX);
        assert(context->end == UINT64_MAX);
        assert(context->total == UINT64_MAX);

        c = fdisk_new_context();
        if (!c)
                return log_oom();

        /* libfdisk doesn't have an API to operate on arbitrary fds, hence reopen the fd going via the
         * /proc/self/fd/ magic path if we have an existing fd. Open the original file otherwise. */
        if (*backing_fd < 0)
                r = fdisk_assign_device(c, node, arg_dry_run);
        else {
                char procfs_path[STRLEN("/proc/self/fd/") + DECIMAL_STR_MAX(int)];
                xsprintf(procfs_path, "/proc/self/fd/%i", *backing_fd);

                r = fdisk_assign_device(c, procfs_path, arg_dry_run);
        }
        if (r == -EINVAL && arg_size_auto) {
                struct stat st;

                /* libfdisk returns EINVAL if opening a file of size zero. Let's check for that, and accept
                 * it if automatic sizing is requested. */

                if (*backing_fd < 0)
                        r = stat(node, &st);
                else
                        r = fstat(*backing_fd, &st);
                if (r < 0)
                        return log_error_errno(errno, "Failed to stat block device '%s': %m", node);

                if (S_ISREG(st.st_mode) && st.st_size == 0)
                        return /* from_scratch = */ true;

                r = -EINVAL;
        }
        if (r < 0)
                return log_error_errno(r, "Failed to open device '%s': %m", node);

        if (*backing_fd < 0) {
                /* If we have no fd referencing the device yet, make a copy of the fd now, so that we have one */
                *backing_fd = fcntl(fdisk_get_devfd(c), F_DUPFD_CLOEXEC, 3);
                if (*backing_fd < 0)
                        return log_error_errno(errno, "Failed to duplicate fdisk fd: %m");
        }

        /* Tell udev not to interfere while we are processing the device */
        if (flock(fdisk_get_devfd(c), arg_dry_run ? LOCK_SH : LOCK_EX) < 0)
                return log_error_errno(errno, "Failed to lock block device: %m");

        switch (arg_empty) {

        case EMPTY_REFUSE:
                /* Refuse empty disks, insist on an existing GPT partition table */
                if (!fdisk_is_labeltype(c, FDISK_DISKLABEL_GPT))
                        return log_notice_errno(SYNTHETIC_ERRNO(EHWPOISON), "Disk %s has no GPT disk label, not repartitioning.", node);

                break;

        case EMPTY_REQUIRE:
                /* Require an empty disk, refuse any existing partition table */
                r = fdisk_has_label(c);
                if (r < 0)
                        return log_error_errno(r, "Failed to determine whether disk %s has a disk label: %m", node);
                if (r > 0)
                        return log_notice_errno(SYNTHETIC_ERRNO(EHWPOISON), "Disk %s already has a disk label, refusing.", node);

                from_scratch = true;
                break;

        case EMPTY_ALLOW:
                /* Allow both an empty disk and an existing partition table, but only GPT */
                r = fdisk_has_label(c);
                if (r < 0)
                        return log_error_errno(r, "Failed to determine whether disk %s has a disk label: %m", node);
                if (r > 0) {
                        if (!fdisk_is_labeltype(c, FDISK_DISKLABEL_GPT))
                                return log_notice_errno(SYNTHETIC_ERRNO(EHWPOISON), "Disk %s has non-GPT disk label, not repartitioning.", node);
                } else
                        from_scratch = true;

                break;

        case EMPTY_FORCE:
        case EMPTY_CREATE:
                /* Always reinitiaize the disk, don't consider what there was on the disk before */
                from_scratch = true;
                break;
        }

        if (from_scratch) {
                r = fdisk_create_disklabel(c, "gpt");
                if (r < 0)
                        return log_error_errno(r, "Failed to create GPT disk label: %m");

                r = derive_uuid(context->seed, "disk-uuid", &disk_uuid);
                if (r < 0)
                        return log_error_errno(r, "Failed to acquire disk GPT uuid: %m");

                r = fdisk_set_disklabel_id_by_uuid(c, disk_uuid);
                if (r < 0)
                        return log_error_errno(r, "Failed to set GPT disk label: %m");

                goto add_initial_free_area;
        }

        r = fdisk_get_disklabel_id(c, &disk_uuid_string);
        if (r < 0)
                return log_error_errno(r, "Failed to get current GPT disk label UUID: %m");

        r = sd_id128_from_string(disk_uuid_string, &disk_uuid);
        if (r < 0)
                return log_error_errno(r, "Failed to parse current GPT disk label UUID: %m");

        if (sd_id128_is_null(disk_uuid)) {
                r = derive_uuid(context->seed, "disk-uuid", &disk_uuid);
                if (r < 0)
                        return log_error_errno(r, "Failed to acquire disk GPT uuid: %m");

                r = fdisk_set_disklabel_id(c);
                if (r < 0)
                        return log_error_errno(r, "Failed to set GPT disk label: %m");
        }

        r = fdisk_get_partitions(c, &t);
        if (r < 0)
                return log_error_errno(r, "Failed to acquire partition table: %m");

        n_partitions = fdisk_table_get_nents(t);
        for (size_t i = 0; i < n_partitions; i++)  {
                _cleanup_free_ char *label_copy = NULL;
                Partition *pp, *last = NULL;
                struct fdisk_partition *p;
                struct fdisk_parttype *pt;
                const char *pts, *ids, *label;
                uint64_t sz, start;
                bool found = false;
                sd_id128_t ptid, id;
                size_t partno;

                p = fdisk_table_get_partition(t, i);
                if (!p)
                        return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to read partition metadata: %m");

                if (fdisk_partition_is_used(p) <= 0)
                        continue;

                if (fdisk_partition_has_start(p) <= 0 ||
                    fdisk_partition_has_size(p) <= 0 ||
                    fdisk_partition_has_partno(p) <= 0)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Found a partition without a position, size or number.");

                pt = fdisk_partition_get_type(p);
                if (!pt)
                        return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to acquire type of partition: %m");

                pts = fdisk_parttype_get_string(pt);
                if (!pts)
                        return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to acquire type of partition as string: %m");

                r = sd_id128_from_string(pts, &ptid);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse partition type UUID %s: %m", pts);

                ids = fdisk_partition_get_uuid(p);
                if (!ids)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Found a partition without a UUID.");

                r = sd_id128_from_string(ids, &id);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse partition UUID %s: %m", ids);

                label = fdisk_partition_get_name(p);
                if (!isempty(label)) {
                        label_copy = strdup(label);
                        if (!label_copy)
                                return log_oom();
                }

                sz = fdisk_partition_get_size(p);
                assert_se(sz <= UINT64_MAX/512);
                sz *= 512;

                start = fdisk_partition_get_start(p);
                assert_se(start <= UINT64_MAX/512);
                start *= 512;

                partno = fdisk_partition_get_partno(p);

                if (left_boundary == UINT64_MAX || left_boundary > start)
                        left_boundary = start;

                /* Assign this existing partition to the first partition of the right type that doesn't have
                 * an existing one assigned yet. */
                LIST_FOREACH(partitions, pp, context->partitions) {
                        last = pp;

                        if (!sd_id128_equal(pp->type_uuid, ptid))
                                continue;

                        if (!pp->current_partition) {
                                pp->current_uuid = id;
                                pp->current_size = sz;
                                pp->offset = start;
                                pp->partno = partno;
                                pp->current_label = TAKE_PTR(label_copy);

                                pp->current_partition = p;
                                fdisk_ref_partition(p);

                                r = determine_current_padding(c, t, p, &pp->current_padding);
                                if (r < 0)
                                        return r;

                                if (pp->current_padding > 0) {
                                        r = context_add_free_area(context, pp->current_padding, pp);
                                        if (r < 0)
                                                return r;
                                }

                                found = true;
                                break;
                        }
                }

                /* If we have no matching definition, create a new one. */
                if (!found) {
                        _cleanup_(partition_freep) Partition *np = NULL;

                        np = partition_new();
                        if (!np)
                                return log_oom();

                        np->current_uuid = id;
                        np->type_uuid = ptid;
                        np->current_size = sz;
                        np->offset = start;
                        np->partno = partno;
                        np->current_label = TAKE_PTR(label_copy);

                        np->current_partition = p;
                        fdisk_ref_partition(p);

                        r = determine_current_padding(c, t, p, &np->current_padding);
                        if (r < 0)
                                return r;

                        if (np->current_padding > 0) {
                                r = context_add_free_area(context, np->current_padding, np);
                                if (r < 0)
                                        return r;
                        }

                        LIST_INSERT_AFTER(partitions, context->partitions, last, TAKE_PTR(np));
                        context->n_partitions++;
                }
        }

add_initial_free_area:
        nsectors = fdisk_get_nsectors(c);
        assert(nsectors <= UINT64_MAX/512);
        nsectors *= 512;

        first_lba = fdisk_get_first_lba(c);
        assert(first_lba <= UINT64_MAX/512);
        first_lba *= 512;

        last_lba = fdisk_get_last_lba(c);
        assert(last_lba < UINT64_MAX);
        last_lba++;
        assert(last_lba <= UINT64_MAX/512);
        last_lba *= 512;

        assert(last_lba >= first_lba);

        if (left_boundary == UINT64_MAX) {
                /* No partitions at all? Then the whole disk is up for grabs. */

                first_lba = round_up_size(first_lba, 4096);
                last_lba = round_down_size(last_lba, 4096);

                if (last_lba > first_lba) {
                        r = context_add_free_area(context, last_lba - first_lba, NULL);
                        if (r < 0)
                                return r;
                }
        } else {
                /* Add space left of first partition */
                assert(left_boundary >= first_lba);

                first_lba = round_up_size(first_lba, 4096);
                left_boundary = round_down_size(left_boundary, 4096);
                last_lba = round_down_size(last_lba, 4096);

                if (left_boundary > first_lba) {
                        r = context_add_free_area(context, left_boundary - first_lba, NULL);
                        if (r < 0)
                                return r;
                }
        }

        context->start = first_lba;
        context->end = last_lba;
        context->total = nsectors;
        context->fdisk_context = TAKE_PTR(c);

        return from_scratch;
}

static void context_unload_partition_table(Context *context) {
        Partition *p, *next;

        assert(context);

        LIST_FOREACH_SAFE(partitions, p, next, context->partitions) {

                /* Entirely remove partitions that have no configuration */
                if (PARTITION_IS_FOREIGN(p)) {
                        partition_unlink_and_free(context, p);
                        continue;
                }

                /* Otherwise drop all data we read off the block device and everything we might have
                 * calculated based on it */

                p->dropped = false;
                p->current_size = UINT64_MAX;
                p->new_size = UINT64_MAX;
                p->current_padding = UINT64_MAX;
                p->new_padding = UINT64_MAX;
                p->partno = UINT64_MAX;
                p->offset = UINT64_MAX;

                if (p->current_partition) {
                        fdisk_unref_partition(p->current_partition);
                        p->current_partition = NULL;
                }

                if (p->new_partition) {
                        fdisk_unref_partition(p->new_partition);
                        p->new_partition = NULL;
                }

                p->padding_area = NULL;
                p->allocated_to_area = NULL;

                p->current_uuid = SD_ID128_NULL;
                p->current_label = mfree(p->current_label);
        }

        context->start = UINT64_MAX;
        context->end = UINT64_MAX;
        context->total = UINT64_MAX;

        if (context->fdisk_context) {
                fdisk_unref_context(context->fdisk_context);
                context->fdisk_context = NULL;
        }

        context_free_free_areas(context);
}

static int format_size_change(uint64_t from, uint64_t to, char **ret) {
        char format_buffer1[FORMAT_BYTES_MAX], format_buffer2[FORMAT_BYTES_MAX], *buf;

        if (from != UINT64_MAX)
                format_bytes(format_buffer1, sizeof(format_buffer1), from);
        if (to != UINT64_MAX)
                format_bytes(format_buffer2, sizeof(format_buffer2), to);

        if (from != UINT64_MAX) {
                if (from == to || to == UINT64_MAX)
                        buf = strdup(format_buffer1);
                else
                        buf = strjoin(format_buffer1, " ", special_glyph(SPECIAL_GLYPH_ARROW), " ", format_buffer2);
        } else if (to != UINT64_MAX)
                buf = strjoin(special_glyph(SPECIAL_GLYPH_ARROW), " ", format_buffer2);
        else {
                *ret = NULL;
                return 0;
        }

        if (!buf)
                return log_oom();

        *ret = TAKE_PTR(buf);
        return 1;
}

static const char *partition_label(const Partition *p) {
        assert(p);

        if (p->new_label)
                return p->new_label;

        if (p->current_label)
                return p->current_label;

        return gpt_partition_type_uuid_to_string(p->type_uuid);
}

static int context_dump_partitions(Context *context, const char *node) {
        _cleanup_(table_unrefp) Table *t = NULL;
        uint64_t sum_padding = 0, sum_size = 0;
        Partition *p;
        int r;

        if ((arg_json_format_flags & JSON_FORMAT_OFF) && context->n_partitions == 0) {
                log_info("Empty partition table.");
                return 0;
        }

        t = table_new("type", "label", "uuid", "file", "node", "offset", "old size", "raw size", "size", "old padding", "raw padding", "padding", "activity");
        if (!t)
                return log_oom();

        if (!DEBUG_LOGGING) {
                if (arg_json_format_flags & JSON_FORMAT_OFF)
                        (void) table_set_display(t, (size_t) 0, (size_t) 1, (size_t) 2, (size_t) 3, (size_t) 4,
                                                    (size_t) 8, (size_t) 11);
                else
                        (void) table_set_display(t, (size_t) 0, (size_t) 1, (size_t) 2, (size_t) 3, (size_t) 4,
                                                    (size_t) 5, (size_t) 6, (size_t) 7, (size_t) 9, (size_t) 10, (size_t) 12);
        }

        (void) table_set_align_percent(t, table_get_cell(t, 0, 5), 100);
        (void) table_set_align_percent(t, table_get_cell(t, 0, 6), 100);
        (void) table_set_align_percent(t, table_get_cell(t, 0, 7), 100);
        (void) table_set_align_percent(t, table_get_cell(t, 0, 8), 100);
        (void) table_set_align_percent(t, table_get_cell(t, 0, 9), 100);
        (void) table_set_align_percent(t, table_get_cell(t, 0, 10), 100);
        (void) table_set_align_percent(t, table_get_cell(t, 0, 11), 100);

        LIST_FOREACH(partitions, p, context->partitions) {
                _cleanup_free_ char *size_change = NULL, *padding_change = NULL, *partname = NULL;
                char uuid_buffer[ID128_UUID_STRING_MAX];
                const char *label, *activity = NULL;

                if (p->dropped)
                        continue;

                if (p->current_size == UINT64_MAX)
                        activity = "create";
                else if (p->current_size != p->new_size)
                        activity = "resize";

                label = partition_label(p);
                partname = p->partno != UINT64_MAX ? fdisk_partname(node, p->partno+1) : NULL;

                r = format_size_change(p->current_size, p->new_size, &size_change);
                if (r < 0)
                        return r;

                r = format_size_change(p->current_padding, p->new_padding, &padding_change);
                if (r < 0)
                        return r;

                if (p->new_size != UINT64_MAX)
                        sum_size += p->new_size;
                if (p->new_padding != UINT64_MAX)
                        sum_padding += p->new_padding;

                r = table_add_many(
                                t,
                                TABLE_STRING, gpt_partition_type_uuid_to_string_harder(p->type_uuid, uuid_buffer),
                                TABLE_STRING, empty_to_null(label) ?: "-", TABLE_SET_COLOR, empty_to_null(label) ? NULL : ansi_grey(),
                                TABLE_UUID, sd_id128_is_null(p->new_uuid) ? p->current_uuid : p->new_uuid,
                                TABLE_STRING, p->definition_path ? basename(p->definition_path) : "-", TABLE_SET_COLOR, p->definition_path ? NULL : ansi_grey(),
                                TABLE_STRING, partname ?: "-", TABLE_SET_COLOR, partname ? NULL : ansi_highlight(),
                                TABLE_UINT64, p->offset,
                                TABLE_UINT64, p->current_size == UINT64_MAX ? 0 : p->current_size,
                                TABLE_UINT64, p->new_size,
                                TABLE_STRING, size_change, TABLE_SET_COLOR, !p->partitions_next && sum_size > 0 ? ansi_underline() : NULL,
                                TABLE_UINT64, p->current_padding == UINT64_MAX ? 0 : p->current_padding,
                                TABLE_UINT64, p->new_padding,
                                TABLE_STRING, padding_change, TABLE_SET_COLOR, !p->partitions_next && sum_padding > 0 ? ansi_underline() : NULL,
                                TABLE_STRING, activity ?: "unchanged");
                if (r < 0)
                        return table_log_add_error(r);
        }

        if ((arg_json_format_flags & JSON_FORMAT_OFF) && (sum_padding > 0 || sum_size > 0)) {
                char s[FORMAT_BYTES_MAX];
                const char *a, *b;

                a = strjoina(special_glyph(SPECIAL_GLYPH_SIGMA), " = ", format_bytes(s, sizeof(s), sum_size));
                b = strjoina(special_glyph(SPECIAL_GLYPH_SIGMA), " = ", format_bytes(s, sizeof(s), sum_padding));

                r = table_add_many(
                                t,
                                TABLE_EMPTY,
                                TABLE_EMPTY,
                                TABLE_EMPTY,
                                TABLE_EMPTY,
                                TABLE_EMPTY,
                                TABLE_EMPTY,
                                TABLE_EMPTY,
                                TABLE_EMPTY,
                                TABLE_STRING, a,
                                TABLE_EMPTY,
                                TABLE_EMPTY,
                                TABLE_STRING, b,
                                TABLE_EMPTY);
                if (r < 0)
                        return table_log_add_error(r);
        }

        return table_print_with_pager(t, arg_json_format_flags, arg_pager_flags, arg_legend);
}

static void context_bar_char_process_partition(
                Context *context,
                Partition *bar[],
                size_t n,
                Partition *p,
                size_t *ret_start) {

        uint64_t from, to, total;
        size_t x, y;

        assert(context);
        assert(bar);
        assert(n > 0);
        assert(p);

        if (p->dropped)
                return;

        assert(p->offset != UINT64_MAX);
        assert(p->new_size != UINT64_MAX);

        from = p->offset;
        to = from + p->new_size;

        assert(context->end >= context->start);
        total = context->end - context->start;

        assert(from >= context->start);
        assert(from <= context->end);
        x = (from - context->start) * n / total;

        assert(to >= context->start);
        assert(to <= context->end);
        y = (to - context->start) * n / total;

        assert(x <= y);
        assert(y <= n);

        for (size_t i = x; i < y; i++)
                bar[i] = p;

        *ret_start = x;
}

static int partition_hint(const Partition *p, const char *node, char **ret) {
        _cleanup_free_ char *buf = NULL;
        char ids[ID128_UUID_STRING_MAX];
        const char *label;
        sd_id128_t id;

        /* Tries really hard to find a suitable description for this partition */

        if (p->definition_path) {
                buf = strdup(basename(p->definition_path));
                goto done;
        }

        label = partition_label(p);
        if (!isempty(label)) {
                buf = strdup(label);
                goto done;
        }

        if (p->partno != UINT64_MAX) {
                buf = fdisk_partname(node, p->partno+1);
                goto done;
        }

        if (!sd_id128_is_null(p->new_uuid))
                id = p->new_uuid;
        else if (!sd_id128_is_null(p->current_uuid))
                id = p->current_uuid;
        else
                id = p->type_uuid;

        buf = strdup(id128_to_uuid_string(id, ids));

done:
        if (!buf)
                return -ENOMEM;

        *ret = TAKE_PTR(buf);
        return 0;
}

static int context_dump_partition_bar(Context *context, const char *node) {
        _cleanup_free_ Partition **bar = NULL;
        _cleanup_free_ size_t *start_array = NULL;
        Partition *p, *last = NULL;
        bool z = false;
        size_t c, j = 0;

        assert_se((c = columns()) >= 2);
        c -= 2; /* We do not use the leftmost and rightmost character cell */

        bar = new0(Partition*, c);
        if (!bar)
                return log_oom();

        start_array = new(size_t, context->n_partitions);
        if (!start_array)
                return log_oom();

        LIST_FOREACH(partitions, p, context->partitions)
                context_bar_char_process_partition(context, bar, c, p, start_array + j++);

        putc(' ', stdout);

        for (size_t i = 0; i < c; i++) {
                if (bar[i]) {
                        if (last != bar[i])
                                z = !z;

                        fputs(z ? ansi_green() : ansi_yellow(), stdout);
                        fputs(special_glyph(SPECIAL_GLYPH_DARK_SHADE), stdout);
                } else {
                        fputs(ansi_normal(), stdout);
                        fputs(special_glyph(SPECIAL_GLYPH_LIGHT_SHADE), stdout);
                }

                last = bar[i];
        }

        fputs(ansi_normal(), stdout);
        putc('\n', stdout);

        for (size_t i = 0; i < context->n_partitions; i++) {
                _cleanup_free_ char **line = NULL;

                line = new0(char*, c);
                if (!line)
                        return log_oom();

                j = 0;
                LIST_FOREACH(partitions, p, context->partitions) {
                        _cleanup_free_ char *d = NULL;
                        j++;

                        if (i < context->n_partitions - j) {

                                if (line[start_array[j-1]]) {
                                        const char *e;

                                        /* Upgrade final corner to the right with a branch to the right */
                                        e = startswith(line[start_array[j-1]], special_glyph(SPECIAL_GLYPH_TREE_RIGHT));
                                        if (e) {
                                                d = strjoin(special_glyph(SPECIAL_GLYPH_TREE_BRANCH), e);
                                                if (!d)
                                                        return log_oom();
                                        }
                                }

                                if (!d) {
                                        d = strdup(special_glyph(SPECIAL_GLYPH_TREE_VERTICAL));
                                        if (!d)
                                                return log_oom();
                                }

                        } else if (i == context->n_partitions - j) {
                                _cleanup_free_ char *hint = NULL;

                                (void) partition_hint(p, node, &hint);

                                if (streq_ptr(line[start_array[j-1]], special_glyph(SPECIAL_GLYPH_TREE_VERTICAL)))
                                        d = strjoin(special_glyph(SPECIAL_GLYPH_TREE_BRANCH), " ", strna(hint));
                                else
                                        d = strjoin(special_glyph(SPECIAL_GLYPH_TREE_RIGHT), " ", strna(hint));

                                if (!d)
                                        return log_oom();
                        }

                        if (d)
                                free_and_replace(line[start_array[j-1]], d);
                }

                putc(' ', stdout);

                j = 0;
                while (j < c) {
                        if (line[j]) {
                                fputs(line[j], stdout);
                                j += utf8_console_width(line[j]);
                        } else {
                                putc(' ', stdout);
                                j++;
                        }
                }

                putc('\n', stdout);

                for (j = 0; j < c; j++)
                        free(line[j]);
        }

        return 0;
}

static bool context_changed(const Context *context) {
        Partition *p;

        LIST_FOREACH(partitions, p, context->partitions) {
                if (p->dropped)
                        continue;

                if (p->allocated_to_area)
                        return true;

                if (p->new_size != p->current_size)
                        return true;
        }

        return false;
}

static int context_wipe_range(Context *context, uint64_t offset, uint64_t size) {
        _cleanup_(blkid_free_probep) blkid_probe probe = NULL;
        int r;

        assert(context);
        assert(offset != UINT64_MAX);
        assert(size != UINT64_MAX);

        probe = blkid_new_probe();
        if (!probe)
                return log_oom();

        errno = 0;
        r = blkid_probe_set_device(probe, fdisk_get_devfd(context->fdisk_context), offset, size);
        if (r < 0)
                return log_error_errno(errno ?: SYNTHETIC_ERRNO(EIO), "Failed to allocate device probe for wiping.");

        errno = 0;
        if (blkid_probe_enable_superblocks(probe, true) < 0 ||
            blkid_probe_set_superblocks_flags(probe, BLKID_SUBLKS_MAGIC|BLKID_SUBLKS_BADCSUM) < 0 ||
            blkid_probe_enable_partitions(probe, true) < 0 ||
            blkid_probe_set_partitions_flags(probe, BLKID_PARTS_MAGIC) < 0)
                return log_error_errno(errno ?: SYNTHETIC_ERRNO(EIO), "Failed to enable superblock and partition probing.");

        for (;;) {
                errno = 0;
                r = blkid_do_probe(probe);
                if (r < 0)
                        return log_error_errno(errno ?: SYNTHETIC_ERRNO(EIO), "Failed to probe for file systems.");
                if (r > 0)
                        break;

                errno = 0;
                if (blkid_do_wipe(probe, false) < 0)
                        return log_error_errno(errno ?: SYNTHETIC_ERRNO(EIO), "Failed to wipe file system signature.");
        }

        return 0;
}

static int context_wipe_partition(Context *context, Partition *p) {
        int r;

        assert(context);
        assert(p);
        assert(!PARTITION_EXISTS(p)); /* Safety check: never wipe existing partitions */

        assert(p->offset != UINT64_MAX);
        assert(p->new_size != UINT64_MAX);

        r = context_wipe_range(context, p->offset, p->new_size);
        if (r < 0)
                return r;

        log_info("Successfully wiped file system signatures from future partition %" PRIu64 ".", p->partno);
        return 0;
}

static int context_discard_range(
                Context *context,
                uint64_t offset,
                uint64_t size) {

        struct stat st;
        int fd;

        assert(context);
        assert(offset != UINT64_MAX);
        assert(size != UINT64_MAX);

        if (size <= 0)
                return 0;

        assert_se((fd = fdisk_get_devfd(context->fdisk_context)) >= 0);

        if (fstat(fd, &st) < 0)
                return -errno;

        if (S_ISREG(st.st_mode)) {
                if (fallocate(fd, FALLOC_FL_PUNCH_HOLE|FALLOC_FL_KEEP_SIZE, offset, size) < 0) {
                        if (ERRNO_IS_NOT_SUPPORTED(errno))
                                return -EOPNOTSUPP;

                        return -errno;
                }

                return 1;
        }

        if (S_ISBLK(st.st_mode)) {
                uint64_t range[2], end;

                range[0] = round_up_size(offset, 512);

                if (offset > UINT64_MAX - size)
                        return -ERANGE;

                end = offset + size;
                if (end <= range[0])
                        return 0;

                range[1] = round_down_size(end - range[0], 512);
                if (range[1] <= 0)
                        return 0;

                if (ioctl(fd, BLKDISCARD, range) < 0) {
                        if (ERRNO_IS_NOT_SUPPORTED(errno))
                                return -EOPNOTSUPP;

                        return -errno;
                }

                return 1;
        }

        return -EOPNOTSUPP;
}

static int context_discard_partition(Context *context, Partition *p) {
        int r;

        assert(context);
        assert(p);

        assert(p->offset != UINT64_MAX);
        assert(p->new_size != UINT64_MAX);
        assert(!PARTITION_EXISTS(p)); /* Safety check: never discard existing partitions */

        if (!arg_discard)
                return 0;

        r = context_discard_range(context, p->offset, p->new_size);
        if (r == -EOPNOTSUPP) {
                log_info("Storage does not support discard, not discarding data in future partition %" PRIu64 ".", p->partno);
                return 0;
        }
        if (r == -EBUSY) {
                /* Let's handle this gracefully: https://bugzilla.kernel.org/show_bug.cgi?id=211167 */
                log_info("Block device is busy, not discarding partition %" PRIu64 " because it probably is mounted.", p->partno);
                return 0;
        }
        if (r == 0) {
                log_info("Partition %" PRIu64 " too short for discard, skipping.", p->partno);
                return 0;
        }
        if (r < 0)
                return log_error_errno(r, "Failed to discard data for future partition %" PRIu64 ".", p->partno);

        log_info("Successfully discarded data from future partition %" PRIu64 ".", p->partno);
        return 1;
}

static int context_discard_gap_after(Context *context, Partition *p) {
        uint64_t gap, next = UINT64_MAX;
        Partition *q;
        int r;

        assert(context);
        assert(!p || (p->offset != UINT64_MAX && p->new_size != UINT64_MAX));

        if (p)
                gap = p->offset + p->new_size;
        else
                gap = context->start;

        LIST_FOREACH(partitions, q, context->partitions) {
                if (q->dropped)
                        continue;

                assert(q->offset != UINT64_MAX);
                assert(q->new_size != UINT64_MAX);

                if (q->offset < gap)
                        continue;

                if (next == UINT64_MAX || q->offset < next)
                        next = q->offset;
        }

        if (next == UINT64_MAX) {
                next = context->end;
                if (gap > next)
                        return log_error_errno(SYNTHETIC_ERRNO(EIO), "Partition end beyond disk end.");
        }

        assert(next >= gap);
        r = context_discard_range(context, gap, next - gap);
        if (r == -EOPNOTSUPP) {
                if (p)
                        log_info("Storage does not support discard, not discarding gap after partition %" PRIu64 ".", p->partno);
                else
                        log_info("Storage does not support discard, not discarding gap at beginning of disk.");
                return 0;
        }
        if (r == 0)  /* Too short */
                return 0;
        if (r < 0) {
                if (p)
                        return log_error_errno(r, "Failed to discard gap after partition %" PRIu64 ".", p->partno);
                else
                        return log_error_errno(r, "Failed to discard gap at beginning of disk.");
        }

        if (p)
                log_info("Successfully discarded gap after partition %" PRIu64 ".", p->partno);
        else
                log_info("Successfully discarded gap at beginning of disk.");

        return 0;
}

static int context_wipe_and_discard(Context *context, bool from_scratch) {
        Partition *p;
        int r;

        assert(context);

        /* Wipe and discard the contents of all partitions we are about to create. We skip the discarding if
         * we were supposed to start from scratch anyway, as in that case we just discard the whole block
         * device in one go early on. */

        LIST_FOREACH(partitions, p, context->partitions) {

                if (!p->allocated_to_area)
                        continue;

                r = context_wipe_partition(context, p);
                if (r < 0)
                        return r;

                if (!from_scratch) {
                        r = context_discard_partition(context, p);
                        if (r < 0)
                                return r;

                        r = context_discard_gap_after(context, p);
                        if (r < 0)
                                return r;
                }
        }

        if (!from_scratch) {
                r = context_discard_gap_after(context, NULL);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int partition_encrypt(
                Partition *p,
                const char *node,
                struct crypt_device **ret_cd,
                char **ret_volume,
                int *ret_fd) {
#if HAVE_LIBCRYPTSETUP
        _cleanup_(sym_crypt_freep) struct crypt_device *cd = NULL;
        _cleanup_(erase_and_freep) void *volume_key = NULL;
        _cleanup_free_ char *dm_name = NULL, *vol = NULL;
        char suuid[ID128_UUID_STRING_MAX];
        size_t volume_key_size = 256 / 8;
        sd_id128_t uuid;
        int r;

        assert(p);
        assert(p->encrypt != ENCRYPT_OFF);

        log_debug("Encryption mode for partition %" PRIu64 ": %s", p->partno, encrypt_mode_to_string(p->encrypt));

        r = dlopen_cryptsetup();
        if (r < 0)
                return log_error_errno(r, "libcryptsetup not found, cannot encrypt: %m");

        if (asprintf(&dm_name, "luks-repart-%08" PRIx64, random_u64()) < 0)
                return log_oom();

        if (ret_volume) {
                vol = path_join("/dev/mapper/", dm_name);
                if (!vol)
                        return log_oom();
        }

        r = derive_uuid(p->new_uuid, "luks-uuid", &uuid);
        if (r < 0)
                return r;

        log_info("Encrypting future partition %" PRIu64 "...", p->partno);

        volume_key = malloc(volume_key_size);
        if (!volume_key)
                return log_oom();

        r = genuine_random_bytes(volume_key, volume_key_size, RANDOM_BLOCK);
        if (r < 0)
                return log_error_errno(r, "Failed to generate volume key: %m");

        r = sym_crypt_init(&cd, node);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate libcryptsetup context: %m");

        cryptsetup_enable_logging(cd);

        r = sym_crypt_format(cd,
                         CRYPT_LUKS2,
                         "aes",
                         "xts-plain64",
                         id128_to_uuid_string(uuid, suuid),
                         volume_key,
                         volume_key_size,
                         &(struct crypt_params_luks2) {
                                 .label = strempty(p->new_label),
                                 .sector_size = 512U,
                         });
        if (r < 0)
                return log_error_errno(r, "Failed to LUKS2 format future partition: %m");

        if (IN_SET(p->encrypt, ENCRYPT_KEY_FILE, ENCRYPT_KEY_FILE_TPM2)) {
                r = sym_crypt_keyslot_add_by_volume_key(
                                cd,
                                CRYPT_ANY_SLOT,
                                volume_key,
                                volume_key_size,
                                strempty(arg_key),
                                arg_key_size);
                if (r < 0)
                        return log_error_errno(r, "Failed to add LUKS2 key: %m");
        }

        if (IN_SET(p->encrypt, ENCRYPT_TPM2, ENCRYPT_KEY_FILE_TPM2)) {
#if HAVE_TPM2
                _cleanup_(erase_and_freep) char *base64_encoded = NULL;
                _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
                _cleanup_(erase_and_freep) void *secret = NULL;
                _cleanup_free_ void *blob = NULL, *hash = NULL;
                size_t secret_size, blob_size, hash_size;
                int keyslot;

                r = tpm2_seal(arg_tpm2_device, arg_tpm2_pcr_mask, &secret, &secret_size, &blob, &blob_size, &hash, &hash_size);
                if (r < 0)
                        return log_error_errno(r, "Failed to seal to TPM2: %m");

                r = base64mem(secret, secret_size, &base64_encoded);
                if (r < 0)
                        return log_error_errno(r, "Failed to base64 encode secret key: %m");

                r = cryptsetup_set_minimal_pbkdf(cd);
                if (r < 0)
                        return log_error_errno(r, "Failed to set minimal PBKDF: %m");

                keyslot = sym_crypt_keyslot_add_by_volume_key(
                                cd,
                                CRYPT_ANY_SLOT,
                                volume_key,
                                volume_key_size,
                                base64_encoded,
                                strlen(base64_encoded));
                if (keyslot < 0)
                        return log_error_errno(keyslot, "Failed to add new TPM2 key to %s: %m", node);

                r = tpm2_make_luks2_json(keyslot, arg_tpm2_pcr_mask, blob, blob_size, hash, hash_size, &v);
                if (r < 0)
                        return log_error_errno(r, "Failed to prepare TPM2 JSON token object: %m");

                r = cryptsetup_add_token_json(cd, v);
                if (r < 0)
                        return log_error_errno(r, "Failed to add TPM2 JSON token to LUKS2 header: %m");
#else
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                       "Support for TPM2 enrollment not enabled.");
#endif
        }

        r = sym_crypt_activate_by_volume_key(
                        cd,
                        dm_name,
                        volume_key,
                        volume_key_size,
                        arg_discard ? CRYPT_ACTIVATE_ALLOW_DISCARDS : 0);
        if (r < 0)
                return log_error_errno(r, "Failed to activate LUKS superblock: %m");

        log_info("Successfully encrypted future partition %" PRIu64 ".", p->partno);

        if (ret_fd) {
                _cleanup_close_ int dev_fd = -1;

                dev_fd = open(vol, O_RDWR|O_CLOEXEC|O_NOCTTY);
                if (dev_fd < 0)
                        return log_error_errno(errno, "Failed to open LUKS volume '%s': %m", vol);

                *ret_fd = TAKE_FD(dev_fd);
        }

        if (ret_cd)
                *ret_cd = TAKE_PTR(cd);
        if (ret_volume)
                *ret_volume = TAKE_PTR(vol);

        return 0;
#else
        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "libcryptsetup is not supported, cannot encrypt: %m");
#endif
}

static int deactivate_luks(struct crypt_device *cd, const char *node) {
#if HAVE_LIBCRYPTSETUP
        int r;

        if (!cd)
                return 0;

        assert(node);

        /* udev or so might access out block device in the background while we are done. Let's hence force
         * detach the volume. We sync'ed before, hence this should be safe. */

        r = sym_crypt_deactivate_by_name(cd, basename(node), CRYPT_DEACTIVATE_FORCE);
        if (r < 0)
                return log_error_errno(r, "Failed to deactivate LUKS device: %m");

        return 1;
#else
        return 0;
#endif
}

static int context_copy_blocks(Context *context) {
        Partition *p;
        int whole_fd = -1, r;

        assert(context);

        /* Copy in file systems on the block level */

        LIST_FOREACH(partitions, p, context->partitions) {
                _cleanup_(sym_crypt_freep) struct crypt_device *cd = NULL;
                _cleanup_(loop_device_unrefp) LoopDevice *d = NULL;
                _cleanup_free_ char *encrypted = NULL;
                _cleanup_close_ int encrypted_dev_fd = -1;
                char buf[FORMAT_BYTES_MAX];
                int target_fd;

                if (p->copy_blocks_fd < 0)
                        continue;

                if (p->dropped)
                        continue;

                if (PARTITION_EXISTS(p)) /* Never copy over existing partitions */
                        continue;

                assert(p->new_size != UINT64_MAX);
                assert(p->copy_blocks_size != UINT64_MAX);
                assert(p->new_size >= p->copy_blocks_size);

                if (whole_fd < 0)
                        assert_se((whole_fd = fdisk_get_devfd(context->fdisk_context)) >= 0);

                if (p->encrypt != ENCRYPT_OFF) {
                        r = loop_device_make(whole_fd, O_RDWR, p->offset, p->new_size, 0, &d);
                        if (r < 0)
                                return log_error_errno(r, "Failed to make loopback device of future partition %" PRIu64 ": %m", p->partno);

                        r = loop_device_flock(d, LOCK_EX);
                        if (r < 0)
                                return log_error_errno(r, "Failed to lock loopback device: %m");

                        r = partition_encrypt(p, d->node, &cd, &encrypted, &encrypted_dev_fd);
                        if (r < 0)
                                return log_error_errno(r, "Failed to encrypt device: %m");

                        if (flock(encrypted_dev_fd, LOCK_EX) < 0)
                                return log_error_errno(errno, "Failed to lock LUKS device: %m");

                        target_fd = encrypted_dev_fd;
                }  else {
                        if (lseek(whole_fd, p->offset, SEEK_SET) == (off_t) -1)
                                return log_error_errno(errno, "Failed to seek to partition offset: %m");

                        target_fd = whole_fd;
                }

                log_info("Copying in '%s' (%s) on block level into future partition %" PRIu64 ".", p->copy_blocks_path, format_bytes(buf, sizeof(buf), p->copy_blocks_size), p->partno);

                r = copy_bytes_full(p->copy_blocks_fd, target_fd, p->copy_blocks_size, 0, NULL, NULL, NULL, NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to copy in data from '%s': %m", p->copy_blocks_path);

                if (fsync(target_fd) < 0)
                        return log_error_errno(errno, "Failed to synchronize copied data blocks: %m");

                if (p->encrypt != ENCRYPT_OFF) {
                        encrypted_dev_fd = safe_close(encrypted_dev_fd);

                        r = deactivate_luks(cd, encrypted);
                        if (r < 0)
                                return r;

                        sym_crypt_free(cd);
                        cd = NULL;

                        r = loop_device_sync(d);
                        if (r < 0)
                                return log_error_errno(r, "Failed to sync loopback device: %m");
                }

                log_info("Copying in of '%s' on block level completed.", p->copy_blocks_path);
        }

        return 0;
}

static int do_copy_files(Partition *p, const char *fs) {
        char **source, **target;
        int r;

        assert(p);
        assert(fs);

        STRV_FOREACH_PAIR(source, target, p->copy_files) {
                _cleanup_close_ int sfd = -1, pfd = -1, tfd = -1;

                sfd = chase_symlinks_and_open(*source, arg_root, CHASE_PREFIX_ROOT|CHASE_WARN, O_CLOEXEC|O_NOCTTY, NULL);
                if (sfd < 0)
                        return log_error_errno(sfd, "Failed to open source file '%s%s': %m", strempty(arg_root), *source);

                r = fd_verify_regular(sfd);
                if (r < 0) {
                        if (r != -EISDIR)
                                return log_error_errno(r, "Failed to check type of source file '%s': %m", *source);

                        /* We are looking at a directory */
                        tfd = chase_symlinks_and_open(*target, fs, CHASE_PREFIX_ROOT|CHASE_WARN, O_RDONLY|O_DIRECTORY|O_CLOEXEC, NULL);
                        if (tfd < 0) {
                                _cleanup_free_ char *dn = NULL, *fn = NULL;

                                if (tfd != -ENOENT)
                                        return log_error_errno(tfd, "Failed to open target directory '%s': %m", *target);

                                r = path_extract_filename(*target, &fn);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to extract filename from '%s': %m", *target);

                                r = path_extract_directory(*target, &dn);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to extract directory from '%s': %m", *target);

                                r = mkdir_p_root(fs, dn, UID_INVALID, GID_INVALID, 0755);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to create parent directory '%s': %m", dn);

                                pfd = chase_symlinks_and_open(dn, fs, CHASE_PREFIX_ROOT|CHASE_WARN, O_RDONLY|O_DIRECTORY|O_CLOEXEC, NULL);
                                if (pfd < 0)
                                        return log_error_errno(pfd, "Failed to open parent directory of target: %m");

                                r = copy_tree_at(
                                                sfd, ".",
                                                pfd, fn,
                                                UID_INVALID, GID_INVALID,
                                                COPY_REFLINK|COPY_MERGE|COPY_REPLACE|COPY_SIGINT|COPY_HARDLINKS);
                        } else
                                r = copy_tree_at(
                                                sfd, ".",
                                                tfd, ".",
                                                UID_INVALID, GID_INVALID,
                                                COPY_REFLINK|COPY_MERGE|COPY_REPLACE|COPY_SIGINT|COPY_HARDLINKS);
                        if (r < 0)
                                return log_error_errno(r, "Failed to copy '%s' to '%s%s': %m", *source, strempty(arg_root), *target);
                } else {
                        _cleanup_free_ char *dn = NULL, *fn = NULL;

                        /* We are looking at a regular file */

                        r = path_extract_filename(*target, &fn);
                        if (r == -EADDRNOTAVAIL || r == O_DIRECTORY)
                                return log_error_errno(SYNTHETIC_ERRNO(EISDIR),
                                                       "Target path '%s' refers to a directory, but source path '%s' refers to regular file, can't copy.", *target, *source);
                        if (r < 0)
                                return log_error_errno(r, "Failed to extract filename from '%s': %m", *target);

                        r = path_extract_directory(*target, &dn);
                        if (r < 0)
                                return log_error_errno(r, "Failed to extract directory from '%s': %m", *target);

                        r = mkdir_p_root(fs, dn, UID_INVALID, GID_INVALID, 0755);
                        if (r < 0)
                                return log_error_errno(r, "Failed to create parent directory: %m");

                        pfd = chase_symlinks_and_open(dn, fs, CHASE_PREFIX_ROOT|CHASE_WARN, O_RDONLY|O_DIRECTORY|O_CLOEXEC, NULL);
                        if (pfd < 0)
                                return log_error_errno(pfd, "Failed to open parent directory of target: %m");

                        tfd = openat(pfd, fn, O_CREAT|O_EXCL|O_WRONLY|O_CLOEXEC, 0700);
                        if (tfd < 0)
                                return log_error_errno(errno, "Failed to create target file '%s': %m", *target);

                        r = copy_bytes(sfd, tfd, UINT64_MAX, COPY_REFLINK|COPY_SIGINT);
                        if (r < 0)
                                return log_error_errno(r, "Failed to copy '%s' to '%s%s': %m", *source, strempty(arg_root), *target);

                        (void) copy_xattr(sfd, tfd);
                        (void) copy_access(sfd, tfd);
                        (void) copy_times(sfd, tfd, 0);
                }
        }

        return 0;
}

static int do_make_directories(Partition *p, const char *fs) {
        char **d;
        int r;

        assert(p);
        assert(fs);

        STRV_FOREACH(d, p->make_directories) {

                r = mkdir_p_root(fs, *d, UID_INVALID, GID_INVALID, 0755);
                if (r < 0)
                        return log_error_errno(r, "Failed to create directory '%s' in file system: %m", *d);
        }

        return 0;
}

static int partition_populate(Partition *p, const char *node) {
        int r;

        assert(p);
        assert(node);

        if (strv_isempty(p->copy_files) && strv_isempty(p->make_directories))
                return 0;

        log_info("Populating partition %" PRIu64 " with files.", p->partno);

        /* We copy in a child process, since we have to mount the fs for that, and we don't want that fs to
         * appear in the host namespace. Hence we fork a child that has its own file system namespace and
         * detached mount propagation. */

        r = safe_fork("(sd-copy)", FORK_DEATHSIG|FORK_LOG|FORK_WAIT|FORK_NEW_MOUNTNS|FORK_MOUNTNS_SLAVE, NULL);
        if (r < 0)
                return r;
        if (r == 0) {
                static const char fs[] = "/run/systemd/mount-root";
                /* This is a child process with its own mount namespace and propagation to host turned off */

                r = mkdir_p(fs, 0700);
                if (r < 0) {
                        log_error_errno(r, "Failed to create mount point: %m");
                        _exit(EXIT_FAILURE);
                }

                if (mount_nofollow_verbose(LOG_ERR, node, fs, p->format, MS_NOATIME|MS_NODEV|MS_NOEXEC|MS_NOSUID, NULL) < 0)
                        _exit(EXIT_FAILURE);

                if (do_copy_files(p, fs) < 0)
                        _exit(EXIT_FAILURE);

                if (do_make_directories(p, fs) < 0)
                        _exit(EXIT_FAILURE);

                r = syncfs_path(AT_FDCWD, fs);
                if (r < 0) {
                        log_error_errno(r, "Failed to synchronize written files: %m");
                        _exit(EXIT_FAILURE);
                }

                _exit(EXIT_SUCCESS);
        }

        log_info("Successfully populated partition %" PRIu64 " with files.", p->partno);
        return 0;
}

static int context_mkfs(Context *context) {
        Partition *p;
        int fd = -1, r;

        assert(context);

        /* Make a file system */

        LIST_FOREACH(partitions, p, context->partitions) {
                _cleanup_(sym_crypt_freep) struct crypt_device *cd = NULL;
                _cleanup_(loop_device_unrefp) LoopDevice *d = NULL;
                _cleanup_free_ char *encrypted = NULL;
                _cleanup_close_ int encrypted_dev_fd = -1;
                const char *fsdev;
                sd_id128_t fs_uuid;

                if (p->dropped)
                        continue;

                if (PARTITION_EXISTS(p)) /* Never format existing partitions */
                        continue;

                if (!p->format)
                        continue;

                assert(p->offset != UINT64_MAX);
                assert(p->new_size != UINT64_MAX);

                if (fd < 0)
                        assert_se((fd = fdisk_get_devfd(context->fdisk_context)) >= 0);

                /* Loopback block devices are not only useful to turn regular files into block devices, but
                 * also to cut out sections of block devices into new block devices. */

                r = loop_device_make(fd, O_RDWR, p->offset, p->new_size, 0, &d);
                if (r < 0)
                        return log_error_errno(r, "Failed to make loopback device of future partition %" PRIu64 ": %m", p->partno);

                r = loop_device_flock(d, LOCK_EX);
                if (r < 0)
                        return log_error_errno(r, "Failed to lock loopback device: %m");

                if (p->encrypt != ENCRYPT_OFF) {
                        r = partition_encrypt(p, d->node, &cd, &encrypted, &encrypted_dev_fd);
                        if (r < 0)
                                return log_error_errno(r, "Failed to encrypt device: %m");

                        if (flock(encrypted_dev_fd, LOCK_EX) < 0)
                                return log_error_errno(errno, "Failed to lock LUKS device: %m");

                        fsdev = encrypted;
                } else
                        fsdev = d->node;

                log_info("Formatting future partition %" PRIu64 ".", p->partno);

                /* Calculate the UUID for the file system as HMAC-SHA256 of the string "file-system-uuid",
                 * keyed off the partition UUID. */
                r = derive_uuid(p->new_uuid, "file-system-uuid", &fs_uuid);
                if (r < 0)
                        return r;

                r = make_filesystem(fsdev, p->format, strempty(p->new_label), fs_uuid, arg_discard);
                if (r < 0) {
                        encrypted_dev_fd = safe_close(encrypted_dev_fd);
                        (void) deactivate_luks(cd, encrypted);
                        return r;
                }

                log_info("Successfully formatted future partition %" PRIu64 ".", p->partno);

                /* The file system is now created, no need to delay udev further */
                if (p->encrypt != ENCRYPT_OFF)
                        if (flock(encrypted_dev_fd, LOCK_UN) < 0)
                                return log_error_errno(errno, "Failed to unlock LUKS device: %m");

                r = partition_populate(p, fsdev);
                if (r < 0) {
                        encrypted_dev_fd = safe_close(encrypted_dev_fd);
                        (void) deactivate_luks(cd, encrypted);
                        return r;
                }

                /* Note that we always sync explicitly here, since mkfs.fat doesn't do that on its own, and
                 * if we don't sync before detaching a block device the in-flight sectors possibly won't hit
                 * the disk. */

                if (p->encrypt != ENCRYPT_OFF) {
                        if (fsync(encrypted_dev_fd) < 0)
                                return log_error_errno(errno, "Failed to synchronize LUKS volume: %m");
                        encrypted_dev_fd = safe_close(encrypted_dev_fd);

                        r = deactivate_luks(cd, encrypted);
                        if (r < 0)
                                return r;

                        sym_crypt_free(cd);
                        cd = NULL;
                }

                r = loop_device_sync(d);
                if (r < 0)
                        return log_error_errno(r, "Failed to sync loopback device: %m");
        }

        return 0;
}

static int partition_acquire_uuid(Context *context, Partition *p, sd_id128_t *ret) {
        struct {
                sd_id128_t type_uuid;
                uint64_t counter;
        } _packed_  plaintext = {};
        union {
                unsigned char md[SHA256_DIGEST_LENGTH];
                sd_id128_t id;
        } result;

        uint64_t k = 0;
        Partition *q;
        int r;

        assert(context);
        assert(p);
        assert(ret);

        /* Calculate a good UUID for the indicated partition. We want a certain degree of reproducibility,
         * hence we won't generate the UUIDs randomly. Instead we use a cryptographic hash (precisely:
         * HMAC-SHA256) to derive them from a single seed. The seed is generally the machine ID of the
         * installation we are processing, but if random behaviour is desired can be random, too. We use the
         * seed value as key for the HMAC (since the machine ID is something we generally don't want to leak)
         * and the partition type as plaintext. The partition type is suffixed with a counter (only for the
         * second and later partition of the same type) if we have more than one partition of the same
         * time. Or in other words:
         *
         * With:
         *     SEED := /etc/machine-id
         *
         * If first partition instance of type TYPE_UUID:
         *     PARTITION_UUID := HMAC-SHA256(SEED, TYPE_UUID)
         *
         * For all later partition instances of type TYPE_UUID with INSTANCE being the LE64 encoded instance number:
         *     PARTITION_UUID := HMAC-SHA256(SEED, TYPE_UUID || INSTANCE)
         */

        LIST_FOREACH(partitions, q, context->partitions) {
                if (p == q)
                        break;

                if (!sd_id128_equal(p->type_uuid, q->type_uuid))
                        continue;

                k++;
        }

        plaintext.type_uuid = p->type_uuid;
        plaintext.counter = htole64(k);

        if (!HMAC(EVP_sha256(),
                  &context->seed, sizeof(context->seed),
                  (const unsigned char*) &plaintext, k == 0 ? sizeof(sd_id128_t) : sizeof(plaintext),
                  result.md, NULL))
                return log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE), "SHA256 calculation failed.");

        /* Take the first half, mark it as v4 UUID */
        assert_cc(sizeof(result.md) == sizeof(result.id) * 2);
        result.id = id128_make_v4_uuid(result.id);

        /* Ensure this partition UUID is actually unique, and there's no remaining partition from an earlier run? */
        LIST_FOREACH(partitions, q, context->partitions) {
                if (p == q)
                        continue;

                if (sd_id128_in_set(result.id, q->current_uuid, q->new_uuid)) {
                        log_warning("Partition UUID calculated from seed for partition %" PRIu64 " already used, reverting to randomized UUID.", p->partno);

                        r = sd_id128_randomize(&result.id);
                        if (r < 0)
                                return log_error_errno(r, "Failed to generate randomized UUID: %m");

                        break;
                }
        }

        *ret = result.id;
        return 0;
}

static int partition_acquire_label(Context *context, Partition *p, char **ret) {
        _cleanup_free_ char *label = NULL;
        const char *prefix;
        unsigned k = 1;

        assert(context);
        assert(p);
        assert(ret);

        prefix = gpt_partition_type_uuid_to_string(p->type_uuid);
        if (!prefix)
                prefix = "linux";

        for (;;) {
                const char *ll = label ?: prefix;
                bool retry = false;
                Partition *q;

                LIST_FOREACH(partitions, q, context->partitions) {
                        if (p == q)
                                break;

                        if (streq_ptr(ll, q->current_label) ||
                            streq_ptr(ll, q->new_label)) {
                                retry = true;
                                break;
                        }
                }

                if (!retry)
                        break;

                label = mfree(label);
                if (asprintf(&label, "%s-%u", prefix, ++k) < 0)
                        return log_oom();
        }

        if (!label) {
                label = strdup(prefix);
                if (!label)
                        return log_oom();
        }

        *ret = TAKE_PTR(label);
        return 0;
}

static int context_acquire_partition_uuids_and_labels(Context *context) {
        Partition *p;
        int r;

        assert(context);

        LIST_FOREACH(partitions, p, context->partitions) {
                /* Never touch foreign partitions */
                if (PARTITION_IS_FOREIGN(p)) {
                        p->new_uuid = p->current_uuid;

                        if (p->current_label) {
                                r = free_and_strdup_warn(&p->new_label, strempty(p->current_label));
                                if (r < 0)
                                        return r;
                        }

                        continue;
                }

                if (!sd_id128_is_null(p->current_uuid))
                        p->new_uuid = p->current_uuid; /* Never change initialized UUIDs */
                else if (sd_id128_is_null(p->new_uuid)) {
                        /* Not explicitly set by user! */
                        r = partition_acquire_uuid(context, p, &p->new_uuid);
                        if (r < 0)
                                return r;
                }

                if (!isempty(p->current_label)) {
                        /* never change initialized labels */
                        r = free_and_strdup_warn(&p->new_label, p->current_label);
                        if (r < 0)
                                return r;
                } else if (!p->new_label) {
                        /* Not explicitly set by user! */

                        r = partition_acquire_label(context, p, &p->new_label);
                        if (r < 0)
                                return r;
                }
        }

        return 0;
}

static int set_gpt_flags(struct fdisk_partition *q, uint64_t flags) {
        _cleanup_free_ char *a = NULL;

        for (unsigned i = 0; i < sizeof(flags) * 8; i++) {
                uint64_t bit = UINT64_C(1) << i;
                char buf[DECIMAL_STR_MAX(unsigned)+1];

                if (!FLAGS_SET(flags, bit))
                        continue;

                xsprintf(buf, "%u", i);
                if (!strextend_with_separator(&a, ",", buf))
                        return -ENOMEM;
        }

        return fdisk_partition_set_attrs(q, a);
}

static uint64_t partition_merge_flags(Partition *p) {
        uint64_t f;

        assert(p);

        f = p->gpt_flags;

        if (p->no_auto >= 0) {
                if (gpt_partition_type_knows_no_auto(p->type_uuid))
                        SET_FLAG(f, GPT_FLAG_NO_AUTO, p->no_auto);
                else {
                        char buffer[ID128_UUID_STRING_MAX];
                        log_warning("Configured NoAuto=%s for partition type '%s' that doesn't support it, ignoring.",
                                    yes_no(p->no_auto),
                                    gpt_partition_type_uuid_to_string_harder(p->type_uuid, buffer));
                }
        }

        if (p->read_only >= 0) {
                if (gpt_partition_type_knows_read_only(p->type_uuid))
                        SET_FLAG(f, GPT_FLAG_READ_ONLY, p->read_only);
                else {
                        char buffer[ID128_UUID_STRING_MAX];
                        log_warning("Configured ReadOnly=%s for partition type '%s' that doesn't support it, ignoring.",
                                    yes_no(p->read_only),
                                    gpt_partition_type_uuid_to_string_harder(p->type_uuid, buffer));
                }
        }

        if (p->growfs >= 0) {
                if (gpt_partition_type_knows_growfs(p->type_uuid))
                        SET_FLAG(f, GPT_FLAG_GROWFS, p->growfs);
                else {
                        char buffer[ID128_UUID_STRING_MAX];
                        log_warning("Configured GrowFileSystem=%s for partition type '%s' that doesn't support it, ignoring.",
                                    yes_no(p->growfs),
                                    gpt_partition_type_uuid_to_string_harder(p->type_uuid, buffer));
                }
        }

        return f;
}

static int context_mangle_partitions(Context *context) {
        Partition *p;
        int r;

        assert(context);

        LIST_FOREACH(partitions, p, context->partitions) {
                if (p->dropped)
                        continue;

                assert(p->new_size != UINT64_MAX);
                assert(p->offset != UINT64_MAX);
                assert(p->partno != UINT64_MAX);

                if (PARTITION_EXISTS(p)) {
                        bool changed = false;

                        assert(p->current_partition);

                        if (p->new_size != p->current_size) {
                                assert(p->new_size >= p->current_size);
                                assert(p->new_size % 512 == 0);

                                r = fdisk_partition_size_explicit(p->current_partition, true);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to enable explicit sizing: %m");

                                r = fdisk_partition_set_size(p->current_partition, p->new_size / 512);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to grow partition: %m");

                                log_info("Growing existing partition %" PRIu64 ".", p->partno);
                                changed = true;
                        }

                        if (!sd_id128_equal(p->new_uuid, p->current_uuid)) {
                                char buf[ID128_UUID_STRING_MAX];

                                assert(!sd_id128_is_null(p->new_uuid));

                                r = fdisk_partition_set_uuid(p->current_partition, id128_to_uuid_string(p->new_uuid, buf));
                                if (r < 0)
                                        return log_error_errno(r, "Failed to set partition UUID: %m");

                                log_info("Initializing UUID of existing partition %" PRIu64 ".", p->partno);
                                changed = true;
                        }

                        if (!streq_ptr(p->new_label, p->current_label)) {
                                r = fdisk_partition_set_name(p->current_partition, strempty(p->new_label));
                                if (r < 0)
                                        return log_error_errno(r, "Failed to set partition label: %m");

                                log_info("Setting partition label of existing partition %" PRIu64 ".", p->partno);
                                changed = true;
                        }

                        if (changed) {
                                assert(!PARTITION_IS_FOREIGN(p)); /* never touch foreign partitions */

                                r = fdisk_set_partition(context->fdisk_context, p->partno, p->current_partition);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to update partition: %m");
                        }
                } else {
                        _cleanup_(fdisk_unref_partitionp) struct fdisk_partition *q = NULL;
                        _cleanup_(fdisk_unref_parttypep) struct fdisk_parttype *t = NULL;
                        char ids[ID128_UUID_STRING_MAX];

                        assert(!p->new_partition);
                        assert(p->offset % 512 == 0);
                        assert(p->new_size % 512 == 0);
                        assert(!sd_id128_is_null(p->new_uuid));
                        assert(p->new_label);

                        t = fdisk_new_parttype();
                        if (!t)
                                return log_oom();

                        r = fdisk_parttype_set_typestr(t, id128_to_uuid_string(p->type_uuid, ids));
                        if (r < 0)
                                return log_error_errno(r, "Failed to initialize partition type: %m");

                        q = fdisk_new_partition();
                        if (!q)
                                return log_oom();

                        r = fdisk_partition_set_type(q, t);
                        if (r < 0)
                                return log_error_errno(r, "Failed to set partition type: %m");

                        r = fdisk_partition_size_explicit(q, true);
                        if (r < 0)
                                return log_error_errno(r, "Failed to enable explicit sizing: %m");

                        r = fdisk_partition_set_start(q, p->offset / 512);
                        if (r < 0)
                                return log_error_errno(r, "Failed to position partition: %m");

                        r = fdisk_partition_set_size(q, p->new_size / 512);
                        if (r < 0)
                                return log_error_errno(r, "Failed to grow partition: %m");

                        r = fdisk_partition_set_partno(q, p->partno);
                        if (r < 0)
                                return log_error_errno(r, "Failed to set partition number: %m");

                        r = fdisk_partition_set_uuid(q, id128_to_uuid_string(p->new_uuid, ids));
                        if (r < 0)
                                return log_error_errno(r, "Failed to set partition UUID: %m");

                        r = fdisk_partition_set_name(q, strempty(p->new_label));
                        if (r < 0)
                                return log_error_errno(r, "Failed to set partition label: %m");

                        /* Merge the no auto + read only + growfs setting with the literal flags, and set them for the partition */
                        r = set_gpt_flags(q, partition_merge_flags(p));
                        if (r < 0)
                                return log_error_errno(r, "Failed to set GPT partition flags: %m");

                        log_info("Adding new partition %" PRIu64 " to partition table.", p->partno);

                        r = fdisk_add_partition(context->fdisk_context, q, NULL);
                        if (r < 0)
                                return log_error_errno(r, "Failed to add partition: %m");

                        assert(!p->new_partition);
                        p->new_partition = TAKE_PTR(q);
                }
        }

        return 0;
}

static int context_write_partition_table(
                Context *context,
                const char *node,
                bool from_scratch) {

        _cleanup_(fdisk_unref_tablep) struct fdisk_table *original_table = NULL;
        int capable, r;

        assert(context);

        if (arg_pretty > 0 ||
            (arg_pretty < 0 && isatty(STDOUT_FILENO) > 0) ||
            !FLAGS_SET(arg_json_format_flags, JSON_FORMAT_OFF)) {

                (void) context_dump_partitions(context, node);

                putc('\n', stdout);

                if (arg_json_format_flags & JSON_FORMAT_OFF)
                        (void) context_dump_partition_bar(context, node);
                putc('\n', stdout);
                fflush(stdout);
        }

        if (!from_scratch && !context_changed(context)) {
                log_info("No changes.");
                return 0;
        }

        if (arg_dry_run) {
                log_notice("Refusing to repartition, please re-run with --dry-run=no.");
                return 0;
        }

        log_info("Applying changes.");

        if (from_scratch) {
                r = context_wipe_range(context, 0, context->total);
                if (r < 0)
                        return r;

                log_info("Wiped block device.");

                r = context_discard_range(context, 0, context->total);
                if (r == -EOPNOTSUPP)
                        log_info("Storage does not support discard, not discarding entire block device data.");
                else if (r < 0)
                        return log_error_errno(r, "Failed to discard entire block device: %m");
                else if (r > 0)
                        log_info("Discarded entire block device.");
        }

        r = fdisk_get_partitions(context->fdisk_context, &original_table);
        if (r < 0)
                return log_error_errno(r, "Failed to acquire partition table: %m");

        /* Wipe fs signatures and discard sectors where the new partitions are going to be placed and in the
         * gaps between partitions, just to be sure. */
        r = context_wipe_and_discard(context, from_scratch);
        if (r < 0)
                return r;

        r = context_copy_blocks(context);
        if (r < 0)
                return r;

        r = context_mkfs(context);
        if (r < 0)
                return r;

        r = context_mangle_partitions(context);
        if (r < 0)
                return r;

        log_info("Writing new partition table.");

        r = fdisk_write_disklabel(context->fdisk_context);
        if (r < 0)
                return log_error_errno(r, "Failed to write partition table: %m");

        capable = blockdev_partscan_enabled(fdisk_get_devfd(context->fdisk_context));
        if (capable == -ENOTBLK)
                log_debug("Not telling kernel to reread partition table, since we are not operating on a block device.");
        else if (capable < 0)
                return log_error_errno(capable, "Failed to check if block device supports partition scanning: %m");
        else if (capable > 0) {
                log_info("Telling kernel to reread partition table.");

                if (from_scratch)
                        r = fdisk_reread_partition_table(context->fdisk_context);
                else
                        r = fdisk_reread_changes(context->fdisk_context, original_table);
                if (r < 0)
                        return log_error_errno(r, "Failed to reread partition table: %m");
        } else
                log_notice("Not telling kernel to reread partition table, because selected image does not support kernel partition block devices.");

        log_info("All done.");

        return 0;
}

static int context_read_seed(Context *context, const char *root) {
        int r;

        assert(context);

        if (!sd_id128_is_null(context->seed))
                return 0;

        if (!arg_randomize) {
                _cleanup_close_ int fd = -1;

                fd = chase_symlinks_and_open("/etc/machine-id", root, CHASE_PREFIX_ROOT, O_RDONLY|O_CLOEXEC, NULL);
                if (fd == -ENOENT)
                        log_info("No machine ID set, using randomized partition UUIDs.");
                else if (fd < 0)
                        return log_error_errno(fd, "Failed to determine machine ID of image: %m");
                else {
                        r = id128_read_fd(fd, ID128_PLAIN_OR_UNINIT, &context->seed);
                        if (r == -ENOMEDIUM)
                                log_info("No machine ID set, using randomized partition UUIDs.");
                        else if (r < 0)
                                return log_error_errno(r, "Failed to parse machine ID of image: %m");

                        return 0;
                }
        }

        r = sd_id128_randomize(&context->seed);
        if (r < 0)
                return log_error_errno(r, "Failed to generate randomized seed: %m");

        return 0;
}

static int context_factory_reset(Context *context, bool from_scratch) {
        Partition *p;
        size_t n = 0;
        int r;

        assert(context);

        if (arg_factory_reset <= 0)
                return 0;

        if (from_scratch) /* Nothing to reset if we start from scratch */
                return 0;

        if (arg_dry_run) {
                log_notice("Refusing to factory reset, please re-run with --dry-run=no.");
                return 0;
        }

        log_info("Applying factory reset.");

        LIST_FOREACH(partitions, p, context->partitions) {

                if (!p->factory_reset || !PARTITION_EXISTS(p))
                        continue;

                assert(p->partno != UINT64_MAX);

                log_info("Removing partition %" PRIu64 " for factory reset.", p->partno);

                r = fdisk_delete_partition(context->fdisk_context, p->partno);
                if (r < 0)
                        return log_error_errno(r, "Failed to remove partition %" PRIu64 ": %m", p->partno);

                n++;
        }

        if (n == 0) {
                log_info("Factory reset requested, but no partitions to delete found.");
                return 0;
        }

        r = fdisk_write_disklabel(context->fdisk_context);
        if (r < 0)
                return log_error_errno(r, "Failed to write disk label: %m");

        log_info("Successfully deleted %zu partitions.", n);
        return 1;
}

static int context_can_factory_reset(Context *context) {
        Partition *p;

        assert(context);

        LIST_FOREACH(partitions, p, context->partitions)
                if (p->factory_reset && PARTITION_EXISTS(p))
                        return true;

        return false;
}

static int resolve_copy_blocks_auto_candidate(
                dev_t partition_devno,
                sd_id128_t partition_type_uuid,
                dev_t restrict_devno,
                sd_id128_t *ret_uuid) {

        _cleanup_(blkid_free_probep) blkid_probe b = NULL;
        _cleanup_free_ char *p = NULL;
        _cleanup_close_ int fd = -1;
        const char *pttype, *t;
        sd_id128_t pt_parsed, u;
        blkid_partition pp;
        dev_t whole_devno;
        blkid_partlist pl;
        struct stat st;
        int r;

        /* Checks if the specified partition has the specified GPT type UUID, and is located on the specified
         * 'restrict_devno' device. The type check is particularly relevant if we have Verity volume which is
         * backed by two separate partitions: the data and the hash partitions, and we need to find the right
         * one of the two. */

        r = block_get_whole_disk(partition_devno, &whole_devno);
        if (r < 0)
                return log_error_errno(
                                r,
                                "Unable to determine containing block device of partition %u:%u: %m",
                                major(partition_devno), minor(partition_devno));

        if (restrict_devno != (dev_t) -1 &&
            restrict_devno != whole_devno)
                return log_error_errno(
                                SYNTHETIC_ERRNO(EPERM),
                                "Partition %u:%u is located outside of block device %u:%u, refusing.",
                                major(partition_devno), minor(partition_devno),
                                major(restrict_devno), minor(restrict_devno));

        r = device_path_make_major_minor(S_IFBLK, whole_devno, &p);
        if (r < 0)
                return log_error_errno(r, "Failed to convert block device to device node path: %m");

        fd = open(p, O_RDONLY|O_CLOEXEC|O_NONBLOCK);
        if (fd < 0)
                return log_error_errno(r, "Failed to open '%s': %m", p);

        if (fstat(fd, &st) < 0)
                return log_error_errno(r, "Failed to stat '%s': %m", p);

        if (!S_ISBLK(st.st_mode) || st.st_rdev != whole_devno)
                return log_error_errno(
                                SYNTHETIC_ERRNO(EPERM),
                                "Opened and determined block device don't match, refusing.");

        b = blkid_new_probe();
        if (!b)
                return log_oom();

        errno = 0;
        r = blkid_probe_set_device(b, fd, 0, 0);
        if (r != 0)
                return log_error_errno(errno_or_else(ENOMEM), "Failed to open block device '%s': %m", p);

        (void) blkid_probe_enable_partitions(b, 1);
        (void) blkid_probe_set_partitions_flags(b, BLKID_PARTS_ENTRY_DETAILS);

        errno = 0;
        r = blkid_do_safeprobe(b);
        if (IN_SET(r, -2, 1)) { /* nothing found or ambiguous result */
                log_debug("Didn't find partition table on block device '%s'.", p);
                return false;
        }
        if (r != 0)
                return log_error_errno(errno_or_else(EIO), "Unable to probe for partition table of '%s': %m", p);

        (void) blkid_probe_lookup_value(b, "PTTYPE", &pttype, NULL);
        if (!streq_ptr(pttype, "gpt")) {
                log_debug("Didn't find a GPT partition table on '%s'.", p);
                return false;
        }

        errno = 0;
        pl = blkid_probe_get_partitions(b);
        if (!pl)
                return log_error_errno(errno_or_else(EIO), "Unable read partition table of '%s': %m", p);
        errno = 0;

        pp = blkid_partlist_devno_to_partition(pl, partition_devno);
        if (!pp) {
                log_debug("Partition %u:%u has no matching partition table entry on '%s'.",
                          major(partition_devno), minor(partition_devno), p);
                return false;
        }

        t = blkid_partition_get_type_string(pp);
        if (isempty(t)) {
                log_debug("Partition %u:%u has no type on '%s'.",
                          major(partition_devno), minor(partition_devno), p);
                return false;
        }

        r = sd_id128_from_string(t, &pt_parsed);
        if (r < 0) {
                log_debug_errno(r, "Failed to parse partition type \"%s\": %m", t);
                return false;
        }

        if (!sd_id128_equal(pt_parsed, partition_type_uuid)) {
                log_debug("Partition %u:%u has non-matching partition type " SD_ID128_FORMAT_STR " (needed: " SD_ID128_FORMAT_STR "), ignoring.",
                          major(partition_devno), minor(partition_devno),
                          SD_ID128_FORMAT_VAL(pt_parsed), SD_ID128_FORMAT_VAL(partition_type_uuid));
                return false;
        }

        t = blkid_partition_get_uuid(pp);
        if (isempty(t)) {
                log_debug("Partition %u:%u has no UUID.",
                          major(partition_devno), minor(partition_devno));
                return false;
        }

        r = sd_id128_from_string(t, &u);
        if (r < 0) {
                log_debug_errno(r, "Failed to parse partition UUID \"%s\": %m", t);
                return false;
        }

        log_debug("Automatically found partition %u:%u of right type " SD_ID128_FORMAT_STR ".",
                  major(partition_devno), minor(partition_devno),
                  SD_ID128_FORMAT_VAL(pt_parsed));

        if (ret_uuid)
                *ret_uuid = u;

        return true;
}

static int find_backing_devno(
                const char *path,
                const char *root,
                dev_t *ret) {

        _cleanup_free_ char *resolved = NULL;
        int r;

        assert(path);

        r = chase_symlinks(path, root, CHASE_PREFIX_ROOT, &resolved, NULL);
        if (r < 0)
                return r;

        r = path_is_mount_point(resolved, NULL, 0);
        if (r < 0)
                return r;
        if (r == 0) /* Not a mount point, then it's not a partition of its own, let's not automatically use it. */
                return -ENOENT;

        r = get_block_device(resolved, ret);
        if (r < 0)
                return r;
        if (r == 0) /* Not backed by physical file system, we can't use this */
                return -ENOENT;

        return 0;
}

static int resolve_copy_blocks_auto(
                sd_id128_t type_uuid,
                const char *root,
                dev_t restrict_devno,
                char **ret_path,
                sd_id128_t *ret_uuid) {

        const char *try1 = NULL, *try2 = NULL;
        char p[SYS_BLOCK_PATH_MAX("/slaves")];
        _cleanup_(closedirp) DIR *d = NULL;
        sd_id128_t found_uuid = SD_ID128_NULL;
        dev_t devno, found = 0;
        int r;

        assert(ret_path);

        /* Enforce some security restrictions: CopyBlocks=auto should not be an avenue to get outside of the
         * --root=/--image= confinement. Specifically, refuse CopyBlocks= in combination with --root= at all,
         * and restrict block device references in the --image= case to loopback block device we set up.
         *
         * restrict_devno contain the dev_t of the loop back device we operate on in case of --image=, and
         * thus declares which device (and its partition subdevices) we shall limit access to. If
         * restrict_devno is zero no device probing access shall be allowed at all (used for --root=) and if
         * it is (dev_t) -1 then free access shall be allowed (if neither switch is used). */

        if (restrict_devno == 0)
                return log_error_errno(SYNTHETIC_ERRNO(EPERM),
                                       "Automatic discovery of backing block devices not permitted in --root= mode, refusing.");

        /* Handles CopyBlocks=auto, and finds the right source partition to copy from. We look for matching
         * partitions in the host, using the appropriate directory as key and ensuring that the partition
         * type matches. */

        if (gpt_partition_type_is_root(type_uuid))
                try1 = "/";
        else if (gpt_partition_type_is_usr(type_uuid))
                try1 = "/usr/";
        else if (gpt_partition_type_is_root_verity(type_uuid))
                try1 = "/";
        else if (gpt_partition_type_is_usr_verity(type_uuid))
                try1 = "/usr/";
        else if (sd_id128_equal(type_uuid, GPT_ESP)) {
                try1 = "/efi/";
                try2 = "/boot/";
        } else if (sd_id128_equal(type_uuid, GPT_XBOOTLDR))
                try1 = "/boot/";
        else
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                       "Partition type " SD_ID128_FORMAT_STR " not supported from automatic source block device discovery.",
                                       SD_ID128_FORMAT_VAL(type_uuid));

        r = find_backing_devno(try1, root, &devno);
        if (r == -ENOENT && try2)
                r = find_backing_devno(try2, root, &devno);
        if (r < 0)
                return log_error_errno(r, "Failed to resolve automatic CopyBlocks= path for partition type " SD_ID128_FORMAT_STR ", sorry: %m",
                                       SD_ID128_FORMAT_VAL(type_uuid));

        xsprintf_sys_block_path(p, "/slaves", devno);
        d = opendir(p);
        if (d) {
                struct dirent *de;

                for (;;) {
                        _cleanup_free_ char *q = NULL, *t = NULL;
                        sd_id128_t u;
                        dev_t sl;

                        errno = 0;
                        de = readdir_no_dot(d);
                        if (!de) {
                                if (errno != 0)
                                        return log_error_errno(errno, "Failed to read directory '%s': %m", p);

                                break;
                        }

                        if (!IN_SET(de->d_type, DT_LNK, DT_UNKNOWN))
                                continue;

                        q = path_join(p, de->d_name, "/dev");
                        if (!q)
                                return log_oom();

                        r = read_one_line_file(q, &t);
                        if (r < 0)
                                return log_error_errno(r, "Failed to read %s: %m", q);

                        r = parse_dev(t, &sl);
                        if (r < 0) {
                                log_debug_errno(r, "Failed to parse %s, ignoring: %m", q);
                                continue;
                        }
                        if (major(sl) == 0) {
                                log_debug_errno(r, "Device backing %s is special, ignoring: %m", q);
                                continue;
                        }

                        r = resolve_copy_blocks_auto_candidate(sl, type_uuid, restrict_devno, &u);
                        if (r < 0)
                                return r;
                        if (r > 0) {
                                /* We found a matching one! */
                                if (found != 0)
                                        return log_error_errno(SYNTHETIC_ERRNO(ENOTUNIQ),
                                                               "Multiple matching partitions found, refusing.");

                                found = sl;
                                found_uuid = u;
                        }
                }
        } else if (errno != ENOENT)
                return log_error_errno(errno, "Failed open %s: %m", p);
        else {
                r = resolve_copy_blocks_auto_candidate(devno, type_uuid, restrict_devno, &found_uuid);
                if (r < 0)
                        return r;
                if (r > 0)
                        found = devno;
        }

        if (found == 0)
                return log_error_errno(SYNTHETIC_ERRNO(ENXIO),
                                       "Unable to automatically discover suitable partition to copy blocks from.");

        r = device_path_make_major_minor(S_IFBLK, found, ret_path);
        if (r < 0)
                return log_error_errno(r, "Failed to convert dev_t to device node path: %m");

        if (ret_uuid)
                *ret_uuid = found_uuid;

        return 0;
}

static int context_open_copy_block_paths(
                Context *context,
                const char *root,
                dev_t restrict_devno) {

        Partition *p;
        int r;

        assert(context);

        LIST_FOREACH(partitions, p, context->partitions) {
                _cleanup_close_ int source_fd = -1;
                _cleanup_free_ char *opened = NULL;
                sd_id128_t uuid = SD_ID128_NULL;
                uint64_t size;
                struct stat st;

                assert(p->copy_blocks_fd < 0);
                assert(p->copy_blocks_size == UINT64_MAX);

                if (PARTITION_EXISTS(p)) /* Never copy over partitions that already exist! */
                        continue;

                if (p->copy_blocks_path) {

                        source_fd = chase_symlinks_and_open(p->copy_blocks_path, root, CHASE_PREFIX_ROOT, O_RDONLY|O_CLOEXEC|O_NONBLOCK, &opened);
                        if (source_fd < 0)
                                return log_error_errno(source_fd, "Failed to open '%s': %m", p->copy_blocks_path);

                        if (fstat(source_fd, &st) < 0)
                                return log_error_errno(errno, "Failed to stat block copy file '%s': %m", opened);

                        if (!S_ISREG(st.st_mode) && restrict_devno != (dev_t) -1)
                                return log_error_errno(SYNTHETIC_ERRNO(EPERM),
                                                       "Copying from block device node is not permitted in --image=/--root= mode, refusing.");

                } else if (p->copy_blocks_auto) {

                        r = resolve_copy_blocks_auto(p->type_uuid, root, restrict_devno, &opened, &uuid);
                        if (r < 0)
                                return r;

                        source_fd = open(opened, O_RDONLY|O_CLOEXEC|O_NOCTTY);
                        if (source_fd < 0)
                                return log_error_errno(errno, "Failed to open automatically determined source block copy device '%s': %m", opened);

                        if (fstat(source_fd, &st) < 0)
                                return log_error_errno(errno, "Failed to stat block copy file '%s': %m", opened);

                        /* If we found it automatically, it must be a block device, let's enforce that */
                        if (!S_ISBLK(st.st_mode))
                                return log_error_errno(SYNTHETIC_ERRNO(EBADF),
                                                       "Automatically detected source block copy device '%s' is not a block device, refusing: %m", opened);
                }  else
                        continue;

                if (S_ISDIR(st.st_mode)) {
                        _cleanup_free_ char *bdev = NULL;

                        /* If the file is a directory, automatically find the backing block device */

                        if (major(st.st_dev) != 0)
                                r = device_path_make_major_minor(S_IFBLK, st.st_dev, &bdev);
                        else {
                                dev_t devt;

                                /* Special support for btrfs */

                                r = btrfs_get_block_device_fd(source_fd, &devt);
                                if (r == -EUCLEAN)
                                        return btrfs_log_dev_root(LOG_ERR, r, opened);
                                if (r < 0)
                                        return log_error_errno(r, "Unable to determine backing block device of '%s': %m", opened);

                                r = device_path_make_major_minor(S_IFBLK, devt, &bdev);
                        }
                        if (r < 0)
                                return log_error_errno(r, "Failed to determine block device path for block device backing '%s': %m", opened);

                        safe_close(source_fd);

                        source_fd = open(bdev, O_RDONLY|O_CLOEXEC|O_NOCTTY);
                        if (source_fd < 0)
                                return log_error_errno(errno, "Failed to open block device '%s': %m", bdev);

                        if (fstat(source_fd, &st) < 0)
                                return log_error_errno(errno, "Failed to stat block device '%s': %m", bdev);

                        if (!S_ISBLK(st.st_mode))
                                return log_error_errno(SYNTHETIC_ERRNO(ENOTBLK), "Block device '%s' is not actually a block device, refusing.", bdev);
                }

                if (S_ISREG(st.st_mode))
                        size = st.st_size;
                else if (S_ISBLK(st.st_mode)) {
                        if (ioctl(source_fd, BLKGETSIZE64, &size) != 0)
                                return log_error_errno(errno, "Failed to determine size of block device to copy from: %m");
                } else
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Specified path to copy blocks from '%s' is not a regular file, block device or directory, refusing: %m", opened);

                if (size <= 0)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "File to copy bytes from '%s' has zero size, refusing.", opened);
                if (size % 512 != 0)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "File to copy bytes from '%s' has size that is not multiple of 512, refusing.", opened);

                p->copy_blocks_fd = TAKE_FD(source_fd);
                p->copy_blocks_size = size;

                free_and_replace(p->copy_blocks_path, opened);

                /* When copying from an existing partition copy that partitions UUID if none is configured explicitly */
                if (sd_id128_is_null(p->new_uuid) && !sd_id128_is_null(uuid))
                        p->new_uuid = uuid;
        }

        return 0;
}

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("systemd-repart", "1", &link);
        if (r < 0)
                return log_oom();

        printf("%s [OPTIONS...] [DEVICE]\n"
               "\n%sGrow and add partitions to partition table.%s\n\n"
               "  -h --help               Show this help\n"
               "     --version            Show package version\n"
               "     --no-pager           Do not pipe output into a pager\n"
               "     --no-legend          Do not show the headers and footers\n"
               "     --dry-run=BOOL       Whether to run dry-run operation\n"
               "     --empty=MODE         One of refuse, allow, require, force, create; controls\n"
               "                          how to handle empty disks lacking partition tables\n"
               "     --discard=BOOL       Whether to discard backing blocks for new partitions\n"
               "     --pretty=BOOL        Whether to show pretty summary before doing changes\n"
               "     --factory-reset=BOOL Whether to remove data partitions before recreating\n"
               "                          them\n"
               "     --can-factory-reset  Test whether factory reset is defined\n"
               "     --root=PATH          Operate relative to root path\n"
               "     --image=PATH         Operate relative to image file\n"
               "     --definitions=DIR    Find partition definitions in specified directory\n"
               "     --key-file=PATH      Key to use when encrypting partitions\n"
               "     --tpm2-device=PATH   Path to TPM2 device node to use\n"
               "     --tpm2-pcrs=PCR1+PCR2+PCR3+…\n"
               "                          TPM2 PCR indexes to use for TPM2 enrollment\n"
               "     --seed=UUID          128bit seed UUID to derive all UUIDs from\n"
               "     --size=BYTES         Grow loopback file to specified size\n"
               "     --json=pretty|short|off\n"
               "                          Generate JSON output\n"
               "\nSee the %s for details.\n",
               program_invocation_short_name,
               ansi_highlight(),
               ansi_normal(),
               link);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100,
                ARG_NO_PAGER,
                ARG_NO_LEGEND,
                ARG_DRY_RUN,
                ARG_EMPTY,
                ARG_DISCARD,
                ARG_FACTORY_RESET,
                ARG_CAN_FACTORY_RESET,
                ARG_ROOT,
                ARG_IMAGE,
                ARG_SEED,
                ARG_PRETTY,
                ARG_DEFINITIONS,
                ARG_SIZE,
                ARG_JSON,
                ARG_KEY_FILE,
                ARG_TPM2_DEVICE,
                ARG_TPM2_PCRS,
        };

        static const struct option options[] = {
                { "help",              no_argument,       NULL, 'h'                   },
                { "version",           no_argument,       NULL, ARG_VERSION           },
                { "no-pager",          no_argument,       NULL, ARG_NO_PAGER          },
                { "no-legend",         no_argument,       NULL, ARG_NO_LEGEND         },
                { "dry-run",           required_argument, NULL, ARG_DRY_RUN           },
                { "empty",             required_argument, NULL, ARG_EMPTY             },
                { "discard",           required_argument, NULL, ARG_DISCARD           },
                { "factory-reset",     required_argument, NULL, ARG_FACTORY_RESET     },
                { "can-factory-reset", no_argument,       NULL, ARG_CAN_FACTORY_RESET },
                { "root",              required_argument, NULL, ARG_ROOT              },
                { "image",             required_argument, NULL, ARG_IMAGE             },
                { "seed",              required_argument, NULL, ARG_SEED              },
                { "pretty",            required_argument, NULL, ARG_PRETTY            },
                { "definitions",       required_argument, NULL, ARG_DEFINITIONS       },
                { "size",              required_argument, NULL, ARG_SIZE              },
                { "json",              required_argument, NULL, ARG_JSON              },
                { "key-file",          required_argument, NULL, ARG_KEY_FILE          },
                { "tpm2-device",       required_argument, NULL, ARG_TPM2_DEVICE       },
                { "tpm2-pcrs",         required_argument, NULL, ARG_TPM2_PCRS         },
                {}
        };

        int c, r, dry_run = -1;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "h", options, NULL)) >= 0)

                switch (c) {

                case 'h':
                        return help();

                case ARG_VERSION:
                        return version();

                case ARG_NO_PAGER:
                        arg_pager_flags |= PAGER_DISABLE;
                        break;

                case ARG_NO_LEGEND:
                        arg_legend = false;
                        break;

                case ARG_DRY_RUN:
                        r = parse_boolean_argument("--dry-run=", optarg, &arg_dry_run);
                        if (r < 0)
                                return r;
                        break;

                case ARG_EMPTY:
                        if (isempty(optarg) || streq(optarg, "refuse"))
                                arg_empty = EMPTY_REFUSE;
                        else if (streq(optarg, "allow"))
                                arg_empty = EMPTY_ALLOW;
                        else if (streq(optarg, "require"))
                                arg_empty = EMPTY_REQUIRE;
                        else if (streq(optarg, "force"))
                                arg_empty = EMPTY_FORCE;
                        else if (streq(optarg, "create")) {
                                arg_empty = EMPTY_CREATE;

                                if (dry_run < 0)
                                        dry_run = false; /* Imply --dry-run=no if we create the loopback file
                                                          * anew. After all we cannot really break anyone's
                                                          * partition tables that way. */
                        } else
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Failed to parse --empty= parameter: %s", optarg);
                        break;

                case ARG_DISCARD:
                        r = parse_boolean_argument("--discard=", optarg, &arg_discard);
                        if (r < 0)
                                return r;
                        break;

                case ARG_FACTORY_RESET:
                        r = parse_boolean_argument("--factory-reset=", optarg, NULL);
                        if (r < 0)
                                return r;
                        arg_factory_reset = r;
                        break;

                case ARG_CAN_FACTORY_RESET:
                        arg_can_factory_reset = true;
                        break;

                case ARG_ROOT:
                        r = parse_path_argument(optarg, /* suppress_root= */ false, &arg_root);
                        if (r < 0)
                                return r;
                        break;

                case ARG_IMAGE:
                        r = parse_path_argument(optarg, /* suppress_root= */ false, &arg_image);
                        if (r < 0)
                                return r;
                        break;

                case ARG_SEED:
                        if (isempty(optarg)) {
                                arg_seed = SD_ID128_NULL;
                                arg_randomize = false;
                        } else if (streq(optarg, "random"))
                                arg_randomize = true;
                        else {
                                r = sd_id128_from_string(optarg, &arg_seed);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to parse seed: %s", optarg);

                                arg_randomize = false;
                        }

                        break;

                case ARG_PRETTY:
                        r = parse_boolean_argument("--pretty=", optarg, NULL);
                        if (r < 0)
                                return r;
                        arg_pretty = r;
                        break;

                case ARG_DEFINITIONS:
                        r = parse_path_argument(optarg, false, &arg_definitions);
                        if (r < 0)
                                return r;
                        break;

                case ARG_SIZE: {
                        uint64_t parsed, rounded;

                        if (streq(optarg, "auto")) {
                                arg_size = UINT64_MAX;
                                arg_size_auto = true;
                                break;
                        }

                        r = parse_size(optarg, 1024, &parsed);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --size= parameter: %s", optarg);

                        rounded = round_up_size(parsed, 4096);
                        if (rounded == 0)
                                return log_error_errno(SYNTHETIC_ERRNO(ERANGE), "Specified image size too small, refusing.");
                        if (rounded == UINT64_MAX)
                                return log_error_errno(SYNTHETIC_ERRNO(ERANGE), "Specified image size too large, refusing.");

                        if (rounded != parsed)
                                log_warning("Specified size is not a multiple of 4096, rounding up automatically. (%" PRIu64 " → %" PRIu64 ")",
                                            parsed, rounded);

                        arg_size = rounded;
                        arg_size_auto = false;
                        break;
                }

                case ARG_JSON:
                        r = parse_json_argument(optarg, &arg_json_format_flags);
                        if (r <= 0)
                                return r;

                        break;

                case ARG_KEY_FILE: {
                        _cleanup_(erase_and_freep) char *k = NULL;
                        size_t n = 0;

                        r = read_full_file_full(
                                        AT_FDCWD, optarg, UINT64_MAX, SIZE_MAX,
                                        READ_FULL_FILE_SECURE|READ_FULL_FILE_WARN_WORLD_READABLE|READ_FULL_FILE_CONNECT_SOCKET,
                                        NULL,
                                        &k, &n);
                        if (r < 0)
                                return log_error_errno(r, "Failed to read key file '%s': %m", optarg);

                        erase_and_free(arg_key);
                        arg_key = TAKE_PTR(k);
                        arg_key_size = n;
                        break;
                }

                case ARG_TPM2_DEVICE: {
                        _cleanup_free_ char *device = NULL;

                        if (streq(optarg, "list"))
                                return tpm2_list_devices();

                        if (!streq(optarg, "auto")) {
                                device = strdup(optarg);
                                if (!device)
                                        return log_oom();
                        }

                        free(arg_tpm2_device);
                        arg_tpm2_device = TAKE_PTR(device);
                        break;
                }

                case ARG_TPM2_PCRS: {
                        uint32_t mask;

                        if (isempty(optarg)) {
                                arg_tpm2_pcr_mask = 0;
                                break;
                        }

                        r = tpm2_parse_pcrs(optarg, &mask);
                        if (r < 0)
                                return r;

                        if (arg_tpm2_pcr_mask == UINT32_MAX)
                                arg_tpm2_pcr_mask = mask;
                        else
                                arg_tpm2_pcr_mask |= mask;

                        break;
                }

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached("Unhandled option");
                }

        if (argc - optind > 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Expected at most one argument, the path to the block device.");

        if (arg_factory_reset > 0 && IN_SET(arg_empty, EMPTY_FORCE, EMPTY_REQUIRE, EMPTY_CREATE))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Combination of --factory-reset=yes and --empty=force/--empty=require/--empty=create is invalid.");

        if (arg_can_factory_reset)
                arg_dry_run = true; /* When --can-factory-reset is specified we don't make changes, hence
                                     * non-dry-run mode makes no sense. Thus, imply dry run mode so that we
                                     * open things strictly read-only. */
        else if (dry_run >= 0)
                arg_dry_run = dry_run;

        if (arg_empty == EMPTY_CREATE && (arg_size == UINT64_MAX && !arg_size_auto))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "If --empty=create is specified, --size= must be specified, too.");

        if (arg_image && arg_root)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Please specify either --root= or --image=, the combination of both is not supported.");
        else if (!arg_image && !arg_root && in_initrd()) {

                /* By default operate on /sysusr/ or /sysroot/ when invoked in the initrd. We prefer the
                 * former, if it is mounted, so that we have deterministic behaviour on systems where /usr/
                 * is vendor-supplied but the root fs formatted on first boot. */
                r = path_is_mount_point("/sysusr/usr", NULL, 0);
                if (r <= 0) {
                        if (r < 0 && r != -ENOENT)
                                log_debug_errno(r, "Unable to determine whether /sysusr/usr is a mount point, assuming it is not: %m");

                        arg_root = strdup("/sysroot");
                } else
                        arg_root = strdup("/sysusr");
                if (!arg_root)
                        return log_oom();
        }

        arg_node = argc > optind ? argv[optind] : NULL;

        if (IN_SET(arg_empty, EMPTY_FORCE, EMPTY_REQUIRE, EMPTY_CREATE) && !arg_node && !arg_image)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "A path to a device node or loopback file must be specified when --empty=force, --empty=require or --empty=create are used.");

        if (arg_tpm2_pcr_mask == UINT32_MAX)
                arg_tpm2_pcr_mask = TPM2_PCR_MASK_DEFAULT;

        return 1;
}

static int parse_proc_cmdline_factory_reset(void) {
        bool b;
        int r;

        if (arg_factory_reset >= 0) /* Never override what is specified on the process command line */
                return 0;

        if (!in_initrd()) /* Never honour kernel command line factory reset request outside of the initrd */
                return 0;

        r = proc_cmdline_get_bool("systemd.factory_reset", &b);
        if (r < 0)
                return log_error_errno(r, "Failed to parse systemd.factory_reset kernel command line argument: %m");
        if (r > 0) {
                arg_factory_reset = b;

                if (b)
                        log_notice("Honouring factory reset requested via kernel command line.");
        }

        return 0;
}

static int parse_efi_variable_factory_reset(void) {
        _cleanup_free_ char *value = NULL;
        int r;

        if (arg_factory_reset >= 0) /* Never override what is specified on the process command line */
                return 0;

        if (!in_initrd()) /* Never honour EFI variable factory reset request outside of the initrd */
                return 0;

        r = efi_get_variable_string(EFI_SYSTEMD_VARIABLE(FactoryReset), &value);
        if (r == -ENOENT || ERRNO_IS_NOT_SUPPORTED(r))
                return 0;
        if (r < 0)
                return log_error_errno(r, "Failed to read EFI variable FactoryReset: %m");

        r = parse_boolean(value);
        if (r < 0)
                return log_error_errno(r, "Failed to parse EFI variable FactoryReset: %m");

        arg_factory_reset = r;
        if (r)
                log_notice("Factory reset requested via EFI variable FactoryReset.");

        return 0;
}

static int remove_efi_variable_factory_reset(void) {
        int r;

        r = efi_set_variable(EFI_SYSTEMD_VARIABLE(FactoryReset), NULL, 0);
        if (r == -ENOENT || ERRNO_IS_NOT_SUPPORTED(r))
                return 0;
        if (r < 0)
                return log_error_errno(r, "Failed to remove EFI variable FactoryReset: %m");

        log_info("Successfully unset EFI variable FactoryReset.");
        return 0;
}

static int acquire_root_devno(
                const char *p,
                const char *root,
                int mode,
                char **ret,
                int *ret_fd) {

        _cleanup_free_ char *found_path = NULL;
        dev_t devno, fd_devno = MODE_INVALID;
        _cleanup_close_ int fd = -1;
        struct stat st;
        int r;

        assert(p);
        assert(ret);
        assert(ret_fd);

        fd = chase_symlinks_and_open(p, root, CHASE_PREFIX_ROOT, mode, &found_path);
        if (fd < 0)
                return fd;

        if (fstat(fd, &st) < 0)
                return -errno;

        if (S_ISREG(st.st_mode)) {
                *ret = TAKE_PTR(found_path);
                *ret_fd = TAKE_FD(fd);
                return 0;
        }

        if (S_ISBLK(st.st_mode)) {
                /* Refuse referencing explicit block devices if a root dir is specified, after all we should
                 * not be able to leave the image the root path constrains us to. */
                if (root)
                        return -EPERM;

                fd_devno = devno = st.st_rdev;
        } else if (S_ISDIR(st.st_mode)) {

                devno = st.st_dev;
                if (major(devno) == 0) {
                        r = btrfs_get_block_device_fd(fd, &devno);
                        if (r == -ENOTTY) /* not btrfs */
                                return -ENODEV;
                        if (r < 0)
                                return r;
                }
        } else
                return -ENOTBLK;

        /* From dm-crypt to backing partition */
        r = block_get_originating(devno, &devno);
        if (r == -ENOENT)
                log_debug_errno(r, "Device '%s' has no dm-crypt/dm-verity device, no need to look for underlying block device.", p);
        else if (r < 0)
                log_debug_errno(r, "Failed to find underlying block device for '%s', ignoring: %m", p);

        /* From partition to whole disk containing it */
        r = block_get_whole_disk(devno, &devno);
        if (r < 0)
                log_debug_errno(r, "Failed to find whole disk block device for '%s', ignoring: %m", p);

        r = device_path_make_canonical(S_IFBLK, devno, ret);
        if (r < 0)
                return log_debug_errno(r, "Failed to determine canonical path for '%s': %m", p);

        /* Only if we still lock at the same block device we can reuse the fd. Otherwise return an
         * invalidated fd. */
        *ret_fd = fd_devno != MODE_INVALID && fd_devno == devno ? TAKE_FD(fd) : -1;
        return 0;
}

static int find_os_prefix(const char **ret) {
        int r;

        assert(ret);

        /* Searches for the right place to look for the OS root. This is relevant in the initrd: in the
         * initrd the host OS is typically mounted to /sysroot/ — except in setups where /usr/ is a separate
         * partition, in which case it is mounted to /sysusr/usr/ before being moved to /sysroot/usr/. */

        if (!in_initrd()) {
                *ret = NULL; /* no prefix */
                return 0;
        }

        r = path_is_mount_point("/sysroot", NULL, 0);
        if (r < 0 && r != -ENOENT)
                log_debug_errno(r, "Failed to determine whether /sysroot/ is a mount point, assuming it is not: %m");
        else if (r > 0) {
                log_debug("/sysroot/ is a mount point, assuming it's the prefix.");
                *ret = "/sysroot";
                return 0;
        }

        r = path_is_mount_point("/sysusr/usr", NULL, 0);
        if (r < 0 && r != -ENOENT)
                log_debug_errno(r, "Failed to determine whether /sysusr/usr is a mount point, assuming it is not: %m");
        else if (r > 0) {
                log_debug("/sysusr/usr/ is a mount point, assuming /sysusr/ is the prefix.");
                *ret = "/sysusr";
                return 0;
        }

        return -ENOENT;
}

static int find_root(char **ret, int *ret_fd) {
        const char *t, *prefix;
        int r;

        assert(ret);
        assert(ret_fd);

        if (arg_node) {
                if (arg_empty == EMPTY_CREATE) {
                        _cleanup_close_ int fd = -1;
                        _cleanup_free_ char *s = NULL;

                        s = strdup(arg_node);
                        if (!s)
                                return log_oom();

                        fd = open(arg_node, O_RDONLY|O_CREAT|O_EXCL|O_CLOEXEC|O_NOFOLLOW, 0666);
                        if (fd < 0)
                                return log_error_errno(errno, "Failed to create '%s': %m", arg_node);

                        *ret = TAKE_PTR(s);
                        *ret_fd = TAKE_FD(fd);
                        return 0;
                }

                /* Note that we don't specify a root argument here: if the user explicitly configured a node
                 * we'll take it relative to the host, not the image */
                r = acquire_root_devno(arg_node, NULL, O_RDONLY|O_CLOEXEC, ret, ret_fd);
                if (r == -EUCLEAN)
                        return btrfs_log_dev_root(LOG_ERR, r, arg_node);
                if (r < 0)
                        return log_error_errno(r, "Failed to open file or determine backing device of %s: %m", arg_node);

                return 0;
        }

        assert(IN_SET(arg_empty, EMPTY_REFUSE, EMPTY_ALLOW));

        /* Let's search for the root device. We look for two cases here: first in /, and then in /usr. The
         * latter we check for cases where / is a tmpfs and only /usr is an actual persistent block device
         * (think: volatile setups) */

        r = find_os_prefix(&prefix);
        if (r < 0)
                return log_error_errno(r, "Failed to determine OS prefix: %m");

        FOREACH_STRING(t, "/", "/usr") {
                _cleanup_free_ char *j = NULL;
                const char *p;

                if (prefix) {
                        j = path_join(prefix, t);
                        if (!j)
                                return log_oom();

                        p = j;
                } else
                        p = t;

                r = acquire_root_devno(p, arg_root, O_RDONLY|O_DIRECTORY|O_CLOEXEC, ret, ret_fd);
                if (r < 0) {
                        if (r == -EUCLEAN)
                                return btrfs_log_dev_root(LOG_ERR, r, p);
                        if (r != -ENODEV)
                                return log_error_errno(r, "Failed to determine backing device of %s: %m", p);
                } else
                        return 0;
        }

        return log_error_errno(SYNTHETIC_ERRNO(ENODEV), "Failed to discover root block device.");
}

static int resize_pt(int fd) {
        char procfs_path[STRLEN("/proc/self/fd/") + DECIMAL_STR_MAX(int)];
        _cleanup_(fdisk_unref_contextp) struct fdisk_context *c = NULL;
        int r;

        /* After resizing the backing file we need to resize the partition table itself too, so that it takes
         * possession of the enlarged backing file. For this it suffices to open the device with libfdisk and
         * immediately write it again, with no changes. */

        c = fdisk_new_context();
        if (!c)
                return log_oom();

        xsprintf(procfs_path, "/proc/self/fd/%i", fd);
        r = fdisk_assign_device(c, procfs_path, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to open device '%s': %m", procfs_path);

        r = fdisk_has_label(c);
        if (r < 0)
                return log_error_errno(r, "Failed to determine whether disk '%s' has a disk label: %m", procfs_path);
        if (r == 0) {
                log_debug("Not resizing partition table, as there currently is none.");
                return 0;
        }

        r = fdisk_write_disklabel(c);
        if (r < 0)
                return log_error_errno(r, "Failed to write resized partition table: %m");

        log_info("Resized partition table.");
        return 1;
}

static int resize_backing_fd(
                const char *node,           /* The primary way we access the disk image to operate on */
                int *fd,                    /* An O_RDONLY fd referring to that inode */
                const char *backing_file,   /* If the above refers to a loopback device, the backing regular file for that, which we can grow */
                LoopDevice *loop_device) {

        char buf1[FORMAT_BYTES_MAX], buf2[FORMAT_BYTES_MAX];
        _cleanup_close_ int writable_fd = -1;
        uint64_t current_size;
        struct stat st;
        int r;

        assert(node);
        assert(fd);

        if (arg_size == UINT64_MAX) /* Nothing to do */
                return 0;

        if (*fd < 0) {
                /* Open the file if we haven't opened it yet. Note that we open it read-only here, just to
                 * keep a reference to the file we can pass around. */
                *fd = open(node, O_RDONLY|O_CLOEXEC);
                if (*fd < 0)
                        return log_error_errno(errno, "Failed to open '%s' in order to adjust size: %m", node);
        }

        if (fstat(*fd, &st) < 0)
                return log_error_errno(errno, "Failed to stat '%s': %m", node);

        if (S_ISBLK(st.st_mode)) {
                if (!backing_file)
                        return log_error_errno(SYNTHETIC_ERRNO(EBADF), "Cannot resize block device '%s'.", node);

                assert(loop_device);

                if (ioctl(*fd, BLKGETSIZE64, &current_size) < 0)
                        return log_error_errno(errno, "Failed to determine size of block device %s: %m", node);
        } else {
                r = stat_verify_regular(&st);
                if (r < 0)
                        return log_error_errno(r, "Specified path '%s' is not a regular file or loopback block device, cannot resize: %m", node);

                assert(!backing_file);
                assert(!loop_device);
                current_size = st.st_size;
        }

        assert_se(format_bytes(buf1, sizeof(buf1), current_size));
        assert_se(format_bytes(buf2, sizeof(buf2), arg_size));

        if (current_size >= arg_size) {
                log_info("File '%s' already is of requested size or larger, not growing. (%s >= %s)", node, buf1, buf2);
                return 0;
        }

        if (S_ISBLK(st.st_mode)) {
                assert(backing_file);

                /* This is a loopback device. We can't really grow those directly, but we can grow the
                 * backing file, hence let's do that. */

                writable_fd = open(backing_file, O_WRONLY|O_CLOEXEC|O_NONBLOCK);
                if (writable_fd < 0)
                        return log_error_errno(errno, "Failed to open backing file '%s': %m", backing_file);

                if (fstat(writable_fd, &st) < 0)
                        return log_error_errno(errno, "Failed to stat() backing file '%s': %m", backing_file);

                r = stat_verify_regular(&st);
                if (r < 0)
                        return log_error_errno(r, "Backing file '%s' of block device is not a regular file: %m", backing_file);

                if ((uint64_t) st.st_size != current_size)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Size of backing file '%s' of loopback block device '%s' don't match, refusing.", node, backing_file);
        } else {
                assert(S_ISREG(st.st_mode));
                assert(!backing_file);

                /* The file descriptor is read-only. In order to grow the file we need to have a writable fd. We
                 * reopen the file for that temporarily. We keep the writable fd only open for this operation though,
                 * as fdisk can't accept it anyway. */

                writable_fd = fd_reopen(*fd, O_WRONLY|O_CLOEXEC);
                if (writable_fd < 0)
                        return log_error_errno(writable_fd, "Failed to reopen backing file '%s' writable: %m", node);
        }

        if (!arg_discard) {
                if (fallocate(writable_fd, 0, 0, arg_size) < 0) {
                        if (!ERRNO_IS_NOT_SUPPORTED(errno))
                                return log_error_errno(errno, "Failed to grow '%s' from %s to %s by allocation: %m",
                                                       node, buf1, buf2);

                        /* Fallback to truncation, if fallocate() is not supported. */
                        log_debug("Backing file system does not support fallocate(), falling back to ftruncate().");
                } else {
                        if (current_size == 0) /* Likely regular file just created by us */
                                log_info("Allocated %s for '%s'.", buf2, node);
                        else
                                log_info("File '%s' grown from %s to %s by allocation.", node, buf1, buf2);

                        goto done;
                }
        }

        if (ftruncate(writable_fd, arg_size) < 0)
                return log_error_errno(errno, "Failed to grow '%s' from %s to %s by truncation: %m",
                                       node, buf1, buf2);

        if (current_size == 0) /* Likely regular file just created by us */
                log_info("Sized '%s' to %s.", node, buf2);
        else
                log_info("File '%s' grown from %s to %s by truncation.", node, buf1, buf2);

done:
        r = resize_pt(writable_fd);
        if (r < 0)
                return r;

        if (loop_device) {
                r = loop_device_refresh_size(loop_device, UINT64_MAX, arg_size);
                if (r < 0)
                        return log_error_errno(r, "Failed to update loop device size: %m");
        }

        return 1;
}

static int determine_auto_size(Context *c) {
        uint64_t sum = round_up_size(GPT_METADATA_SIZE, 4096);
        char buf[FORMAT_BYTES_MAX];
        Partition *p;

        assert_se(c);

        LIST_FOREACH(partitions, p, c->partitions) {
                uint64_t m;

                if (p->dropped)
                        continue;

                m = partition_min_size_with_padding(p);
                if (m > UINT64_MAX - sum)
                        return log_error_errno(SYNTHETIC_ERRNO(EOVERFLOW), "Image would grow too large, refusing.");

                sum += m;
        }

        assert_se(format_bytes(buf, sizeof(buf), sum));
        log_info("Automatically determined minimal disk image size as %s.", buf);

        arg_size = sum;
        return 0;
}

static int run(int argc, char *argv[]) {
        _cleanup_(loop_device_unrefp) LoopDevice *loop_device = NULL;
        _cleanup_(decrypted_image_unrefp) DecryptedImage *decrypted_image = NULL;
        _cleanup_(umount_and_rmdir_and_freep) char *mounted_dir = NULL;
        _cleanup_(context_freep) Context* context = NULL;
        _cleanup_free_ char *node = NULL;
        _cleanup_close_ int backing_fd = -1;
        bool from_scratch, node_is_our_loop = false;
        int r;

        log_show_color(true);
        log_parse_environment();
        log_open();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        r = parse_proc_cmdline_factory_reset();
        if (r < 0)
                return r;

        r = parse_efi_variable_factory_reset();
        if (r < 0)
                return r;

        if (arg_image) {
                assert(!arg_root);

                /* Mount this strictly read-only: we shall modify the partition table, not the file
                 * systems */
                r = mount_image_privately_interactively(
                                arg_image,
                                DISSECT_IMAGE_MOUNT_READ_ONLY |
                                (arg_node ? DISSECT_IMAGE_DEVICE_READ_ONLY : 0) | /* If a different node to make changes to is specified let's open the device in read-only mode) */
                                DISSECT_IMAGE_GPT_ONLY |
                                DISSECT_IMAGE_RELAX_VAR_CHECK |
                                DISSECT_IMAGE_USR_NO_ROOT |
                                DISSECT_IMAGE_REQUIRE_ROOT,
                                &mounted_dir,
                                &loop_device,
                                &decrypted_image);
                if (r < 0)
                        return r;

                arg_root = strdup(mounted_dir);
                if (!arg_root)
                        return log_oom();

                if (!arg_node) {
                        arg_node = strdup(loop_device->node);
                        if (!arg_node)
                                return log_oom();

                        /* Remember that the device we are about to manipulate is actually the one we
                         * allocated here, and thus to increase its backing file we know what to do */
                        node_is_our_loop = true;
                }
        }

        context = context_new(arg_seed);
        if (!context)
                return log_oom();

        r = context_read_definitions(context, arg_definitions, arg_root);
        if (r < 0)
                return r;

        if (context->n_partitions <= 0 && arg_empty == EMPTY_REFUSE) {
                log_info("Didn't find any partition definition files, nothing to do.");
                return 0;
        }

        r = find_root(&node, &backing_fd);
        if (r < 0)
                return r;

        if (arg_size != UINT64_MAX) {
                r = resize_backing_fd(
                                node,
                                &backing_fd,
                                node_is_our_loop ? arg_image : NULL,
                                node_is_our_loop ? loop_device : NULL);
                if (r < 0)
                        return r;
        }

        r = context_load_partition_table(context, node, &backing_fd);
        if (r == -EHWPOISON)
                return 77; /* Special return value which means "Not GPT, so not doing anything". This isn't
                            * really an error when called at boot. */
        if (r < 0)
                return r;
        from_scratch = r > 0; /* Starting from scratch */

        if (arg_can_factory_reset) {
                r = context_can_factory_reset(context);
                if (r < 0)
                        return r;
                if (r == 0)
                        return EXIT_FAILURE;

                return 0;
        }

        r = context_factory_reset(context, from_scratch);
        if (r < 0)
                return r;
        if (r > 0) {
                /* We actually did a factory reset! */
                r = remove_efi_variable_factory_reset();
                if (r < 0)
                        return r;

                /* Reload the reduced partition table */
                context_unload_partition_table(context);
                r = context_load_partition_table(context, node, &backing_fd);
                if (r < 0)
                        return r;
        }

#if 0
        (void) context_dump_partitions(context, node);
        putchar('\n');
#endif

        r = context_read_seed(context, arg_root);
        if (r < 0)
                return r;

        /* Open all files to copy blocks from now, since we want to take their size into consideration */
        r = context_open_copy_block_paths(
                        context,
                        arg_root,
                        loop_device ? loop_device->devno :         /* if --image= is specified, only allow partitions on the loopback device */
                                      arg_root && !arg_image ? 0 : /* if --root= is specified, don't accept any block device */
                                      (dev_t) -1);                 /* if neither is specified, make no restrictions */
        if (r < 0)
                return r;

        if (arg_size_auto) {
                r = determine_auto_size(context);
                if (r < 0)
                        return r;

                /* Flush out everything again, and let's grow the file first, then start fresh */
                context_unload_partition_table(context);

                assert_se(arg_size != UINT64_MAX);
                r = resize_backing_fd(
                                node,
                                &backing_fd,
                                node_is_our_loop ? arg_image : NULL,
                                node_is_our_loop ? loop_device : NULL);
                if (r < 0)
                        return r;

                r = context_load_partition_table(context, node, &backing_fd);
                if (r < 0)
                        return r;
        }

        /* First try to fit new partitions in, dropping by priority until it fits */
        for (;;) {
                if (context_allocate_partitions(context))
                        break; /* Success! */

                if (!context_drop_one_priority(context)) {
                        r = log_error_errno(SYNTHETIC_ERRNO(ENOSPC),
                                            "Can't fit requested partitions into free space, refusing.");

                        determine_auto_size(context);
                        return r;
                }
        }

        /* Now assign free space according to the weight logic */
        r = context_grow_partitions(context);
        if (r < 0)
                return r;

        /* Now calculate where each partition gets placed */
        context_place_partitions(context);

        /* Make sure each partition has a unique UUID and unique label */
        r = context_acquire_partition_uuids_and_labels(context);
        if (r < 0)
                return r;

        r = context_write_partition_table(context, node, from_scratch);
        if (r < 0)
                return r;

        return 0;
}

DEFINE_MAIN_FUNCTION_WITH_POSITIVE_FAILURE(run);
