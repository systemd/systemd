/* SPDX-License-Identifier: LGPL-2.1+ */

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
#include "def.h"
#include "efivars.h"
#include "errno-util.h"
#include "fd-util.h"
#include "format-table.h"
#include "format-util.h"
#include "fs-util.h"
#include "gpt.h"
#include "id128-util.h"
#include "list.h"
#include "locale-util.h"
#include "main-func.h"
#include "parse-util.h"
#include "path-util.h"
#include "pretty-print.h"
#include "proc-cmdline.h"
#include "sort-util.h"
#include "specifier.h"
#include "stat-util.h"
#include "stdio-util.h"
#include "string-util.h"
#include "strv.h"
#include "terminal-util.h"
#include "utf8.h"

/* If not configured otherwise use a minimal partition size of 10M */
#define DEFAULT_MIN_SIZE (10*1024*1024)

/* Hard lower limit for new partition sizes */
#define HARD_MIN_SIZE 4096

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
static char *arg_definitions = NULL;
static bool arg_discard = true;
static bool arg_can_factory_reset = false;
static int arg_factory_reset = -1;
static sd_id128_t arg_seed = SD_ID128_NULL;
static bool arg_randomize = false;
static int arg_pretty = -1;
static uint64_t arg_size = UINT64_MAX;

STATIC_DESTRUCTOR_REGISTER(arg_root, freep);
STATIC_DESTRUCTOR_REGISTER(arg_definitions, freep);

typedef struct Partition Partition;
typedef struct FreeArea FreeArea;
typedef struct Context Context;

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
        int copy_blocks_fd;
        uint64_t copy_blocks_size;

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
        size_t n_free_areas, n_allocated_free_areas;

        uint64_t start, end, total;

        struct fdisk_context *fdisk_context;

        sd_id128_t seed;
};

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
        context->n_allocated_free_areas = 0;
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

        if (!GREEDY_REALLOC(context->free_areas, context->n_allocated_free_areas, context->n_free_areas + 1))
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

        if (p->copy_blocks_size != UINT64_MAX)
                sz = MAX(p->copy_blocks_size, sz);

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

        static const Specifier specifier_table[] = {
                { 'm', specifier_machine_id,      NULL },
                { 'b', specifier_boot_id,         NULL },
                { 'H', specifier_host_name,       NULL },
                { 'l', specifier_short_host_name, NULL },
                { 'v', specifier_kernel_release,  NULL },
                { 'a', specifier_architecture,    NULL },
                { 'o', specifier_os_id,           NULL },
                { 'w', specifier_os_version_id,   NULL },
                { 'B', specifier_os_build_id,     NULL },
                { 'W', specifier_os_variant_id,   NULL },
                {}
        };

        _cleanup_free_ char16_t *recoded = NULL;
        _cleanup_free_ char *resolved = NULL;
        char **label = data;
        int r;

        assert(rvalue);
        assert(label);

        r = specifier_printf(rvalue, specifier_table, NULL, &resolved);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r,
                           "Failed to expand specifiers in Label=, ignoring: %s", rvalue);
                return 0;
        }

        if (!utf8_is_valid(resolved)) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Partition label not valid UTF-8, ignoring: %s", rvalue);
                return 0;
        }

        recoded = utf8_to_utf16(resolved, strlen(resolved));
        if (!recoded)
                return log_oom();

        if (char16_strlen(recoded) > 36) {
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

static int partition_read_definition(Partition *p, const char *path) {

        ConfigTableItem table[] = {
                { "Partition", "Type",            config_parse_type,     0,  &p->type_uuid        },
                { "Partition", "Label",           config_parse_label,    0,  &p->new_label        },
                { "Partition", "UUID",            config_parse_id128,    0,  &p->new_uuid         },
                { "Partition", "Priority",        config_parse_int32,    0,  &p->priority         },
                { "Partition", "Weight",          config_parse_weight,   0,  &p->weight           },
                { "Partition", "PaddingWeight",   config_parse_weight,   0,  &p->padding_weight   },
                { "Partition", "SizeMinBytes",    config_parse_size4096, 1,  &p->size_min         },
                { "Partition", "SizeMaxBytes",    config_parse_size4096, -1, &p->size_max         },
                { "Partition", "PaddingMinBytes", config_parse_size4096, 1,  &p->padding_min      },
                { "Partition", "PaddingMaxBytes", config_parse_size4096, -1, &p->padding_max      },
                { "Partition", "FactoryReset",    config_parse_bool,     0,  &p->factory_reset    },
                { "Partition", "CopyBlocks",      config_parse_path,     0,  &p->copy_blocks_path },
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

DEFINE_TRIVIAL_CLEANUP_FUNC(struct fdisk_context*, fdisk_unref_context);
DEFINE_TRIVIAL_CLEANUP_FUNC(struct fdisk_partition*, fdisk_unref_partition);
DEFINE_TRIVIAL_CLEANUP_FUNC(struct fdisk_parttype*, fdisk_unref_parttype);
DEFINE_TRIVIAL_CLEANUP_FUNC(struct fdisk_table*, fdisk_unref_table);

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

#define DISK_UUID_TOKEN "disk-uuid"

static int disk_acquire_uuid(Context *context, sd_id128_t *ret) {
        union {
                unsigned char md[SHA256_DIGEST_LENGTH];
                sd_id128_t id;
        } result;

        assert(context);
        assert(ret);

        /* Calculate the HMAC-SHA256 of the string "disk-uuid", keyed off the machine ID. We use the machine
         * ID as key (and not as cleartext!) since it's the machine ID we don't want to leak. */

        if (!HMAC(EVP_sha256(),
                  &context->seed, sizeof(context->seed),
                  (const unsigned char*) DISK_UUID_TOKEN, strlen(DISK_UUID_TOKEN),
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
                r = fdisk_enable_wipe(c, true);
                if (r < 0)
                        return log_error_errno(r, "Failed to enable wiping of disk signature: %m");

                r = fdisk_create_disklabel(c, "gpt");
                if (r < 0)
                        return log_error_errno(r, "Failed to create GPT disk label: %m");

                r = disk_acquire_uuid(context, &disk_uuid);
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
                r = disk_acquire_uuid(context, &disk_uuid);
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

                p->current_uuid = p->new_uuid = SD_ID128_NULL;
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

        t = table_new("type", "label", "uuid", "file", "node", "offset", "raw size", "size", "raw padding", "padding");
        if (!t)
                return log_oom();

        if (!DEBUG_LOGGING)
                (void) table_set_display(t, (size_t) 0, (size_t) 1, (size_t) 2, (size_t) 3, (size_t) 4, (size_t) 7, (size_t) 9, (size_t) -1);

        (void) table_set_align_percent(t, table_get_cell(t, 0, 4), 100);
        (void) table_set_align_percent(t, table_get_cell(t, 0, 5), 100);

        LIST_FOREACH(partitions, p, context->partitions) {
                _cleanup_free_ char *size_change = NULL, *padding_change = NULL, *partname = NULL;
                char uuid_buffer[ID128_UUID_STRING_MAX];
                const char *label;

                if (p->dropped)
                        continue;

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
                                TABLE_STRING, label ?: "-", TABLE_SET_COLOR, label ? NULL : ansi_grey(),
                                TABLE_UUID, sd_id128_is_null(p->new_uuid) ? p->current_uuid : p->new_uuid,
                                TABLE_STRING, p->definition_path ? basename(p->definition_path) : "-", TABLE_SET_COLOR, p->definition_path ? NULL : ansi_grey(),
                                TABLE_STRING, partname ?: "no", TABLE_SET_COLOR, partname ? NULL : ansi_highlight(),
                                TABLE_UINT64, p->offset,
                                TABLE_UINT64, p->new_size,
                                TABLE_STRING, size_change, TABLE_SET_COLOR, !p->partitions_next && sum_size > 0 ? ansi_underline() : NULL,
                                TABLE_UINT64, p->new_padding,
                                TABLE_STRING, padding_change, TABLE_SET_COLOR, !p->partitions_next && sum_padding > 0 ? ansi_underline() : NULL);
                if (r < 0)
                        return table_log_add_error(r);
        }

        if (sum_padding > 0 || sum_size > 0) {
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
                                TABLE_STRING, a,
                                TABLE_EMPTY,
                                TABLE_STRING, b);
                if (r < 0)
                        return table_log_add_error(r);
        }

        r = table_print(t, stdout);
        if (r < 0)
                return log_error_errno(r, "Failed to dump table: %m");

        return 0;
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

static int context_wipe_partition(Context *context, Partition *p) {
        _cleanup_(blkid_free_probep) blkid_probe probe = NULL;
        int r;

        assert(context);
        assert(p);
        assert(!PARTITION_EXISTS(p)); /* Safety check: never wipe existing partitions */

        probe = blkid_new_probe();
        if (!probe)
                return log_oom();

        assert(p->offset != UINT64_MAX);
        assert(p->new_size != UINT64_MAX);

        errno = 0;
        r = blkid_probe_set_device(probe, fdisk_get_devfd(context->fdisk_context), p->offset, p->new_size);
        if (r < 0)
                return log_error_errno(errno ?: SYNTHETIC_ERRNO(EIO), "Failed to allocate device probe for partition %" PRIu64 ".", p->partno);

        errno = 0;
        if (blkid_probe_enable_superblocks(probe, true) < 0 ||
            blkid_probe_set_superblocks_flags(probe, BLKID_SUBLKS_MAGIC|BLKID_SUBLKS_BADCSUM) < 0 ||
            blkid_probe_enable_partitions(probe, true) < 0 ||
            blkid_probe_set_partitions_flags(probe, BLKID_PARTS_MAGIC) < 0)
                return log_error_errno(errno ?: SYNTHETIC_ERRNO(EIO), "Failed to enable superblock and partition probing for partition %" PRIu64 ".", p->partno);

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

        log_info("Successfully wiped file system signatures from partition %" PRIu64 ".", p->partno);
        return 0;
}

static int context_discard_range(Context *context, uint64_t offset, uint64_t size) {
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
                log_info("Storage does not support discarding, not discarding data in new partition %" PRIu64 ".", p->partno);
                return 0;
        }
        if (r == 0) {
                log_info("Partition %" PRIu64 " too short for discard, skipping.", p->partno);
                return 0;
        }
        if (r < 0)
                return log_error_errno(r, "Failed to discard data for new partition %" PRIu64 ".", p->partno);

        log_info("Successfully discarded data from partition %" PRIu64 ".", p->partno);
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
                        log_info("Storage does not support discarding, not discarding gap after partition %" PRIu64 ".", p->partno);
                else
                        log_info("Storage does not support discarding, not discarding gap at beginning of disk.");
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

                if (!from_scratch) {
                        r = context_discard_partition(context, p);
                        if (r < 0)
                                return r;
                }

                r = context_wipe_partition(context, p);
                if (r < 0)
                        return r;

                if (!from_scratch) {
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

static int context_copy_blocks(Context *context) {
        Partition *p;
        int fd = -1, r;

        assert(context);

        /* Copy in file systems on the block level */

        LIST_FOREACH(partitions, p, context->partitions) {
                char buf[FORMAT_BYTES_MAX];

                if (p->copy_blocks_fd < 0)
                        continue;

                if (p->dropped)
                        continue;

                if (PARTITION_EXISTS(p)) /* Never copy over existing partitions */
                        continue;

                assert(p->new_size != UINT64_MAX);
                assert(p->copy_blocks_size != UINT64_MAX);
                assert(p->new_size >= p->copy_blocks_size);

                if (fd < 0)
                        assert_se((fd = fdisk_get_devfd(context->fdisk_context)) >= 0);

                if (lseek(fd, p->offset, SEEK_SET) == (off_t) -1)
                        return log_error_errno(errno, "Failed to seek to partition offset: %m");

                log_info("Copying in '%s' (%s) on block level into partition %" PRIu64 ".", p->copy_blocks_path, format_bytes(buf, sizeof(buf), p->copy_blocks_size), p->partno);

                r = copy_bytes_full(p->copy_blocks_fd, fd, p->copy_blocks_size, 0, NULL, NULL, NULL, NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to copy in data from '%s': %m", p->copy_blocks_path);

                log_info("Copying in of '%s' on block level completed.", p->copy_blocks_path);
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

                if (sd_id128_equal(q->current_uuid, result.id) ||
                    sd_id128_equal(q->new_uuid, result.id)) {
                        log_warning("Partition UUID calculated from seed for partition %" PRIu64 " exists already, reverting to randomized UUID.", p->partno);

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
                                free(p->new_label);
                                p->new_label = strdup(p->current_label);
                                if (!p->new_label)
                                        return log_oom();
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
                        free(p->new_label);
                        p->new_label = strdup(p->current_label); /* never change initialized labels */
                        if (!p->new_label)
                                return log_oom();
                } else if (!p->new_label) {
                        /* Not explicitly set by user! */

                        r = partition_acquire_label(context, p, &p->new_label);
                        if (r < 0)
                                return r;
                }
        }

        return 0;
}

static int device_kernel_partitions_supported(int fd) {
        struct loop_info64 info;
        struct stat st;

        assert(fd >= 0);

        if (fstat(fd, &st) < 0)
                return log_error_errno(fd, "Failed to fstat() image file: %m");
        if (!S_ISBLK(st.st_mode))
                return -ENOTBLK; /* we do not log in this one special case about errors */

        if (ioctl(fd, LOOP_GET_STATUS64, &info) < 0) {

                if (ERRNO_IS_NOT_SUPPORTED(errno) || errno == EINVAL)
                        return true; /* not a loopback device, let's assume partition are supported */

                return log_error_errno(fd, "Failed to issue LOOP_GET_STATUS64 on block device: %m");
        }

#if HAVE_VALGRIND_MEMCHECK_H
        /* Valgrind currently doesn't know LOOP_GET_STATUS64. Remove this once it does */
        VALGRIND_MAKE_MEM_DEFINED(&info, sizeof(info));
#endif

        return FLAGS_SET(info.lo_flags, LO_FLAGS_PARTSCAN);
}

static int context_write_partition_table(
                Context *context,
                const char *node,
                bool from_scratch) {

        _cleanup_(fdisk_unref_tablep) struct fdisk_table *original_table = NULL;
        int capable, r;
        Partition *p;

        assert(context);

        if (arg_pretty > 0 ||
            (arg_pretty < 0 && isatty(STDOUT_FILENO) > 0)) {

                if (context->n_partitions == 0)
                        puts("Empty partition table.");
                else
                        (void) context_dump_partitions(context, node);

                putc('\n', stdout);

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
                r = context_discard_range(context, 0, context->total);
                if (r == -EOPNOTSUPP)
                        log_info("Storage does not support discarding, not discarding entire block device data.");
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
                                assert(!isempty(p->new_label));

                                r = fdisk_partition_set_name(p->current_partition, p->new_label);
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
                        assert(!isempty(p->new_label));

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

                        r = fdisk_partition_set_name(q, p->new_label);
                        if (r < 0)
                                return log_error_errno(r, "Failed to set partition label: %m");

                        log_info("Creating new partition %" PRIu64 ".", p->partno);

                        r = fdisk_add_partition(context->fdisk_context, q, NULL);
                        if (r < 0)
                                return log_error_errno(r, "Failed to add partition: %m");

                        assert(!p->new_partition);
                        p->new_partition = TAKE_PTR(q);
                }
        }

        log_info("Writing new partition table.");

        r = fdisk_write_disklabel(context->fdisk_context);
        if (r < 0)
                return log_error_errno(r, "Failed to write partition table: %m");

        capable = device_kernel_partitions_supported(fdisk_get_devfd(context->fdisk_context));
        if (capable == -ENOTBLK)
                log_debug("Not telling kernel to reread partition table, since we are not operating on a block device.");
        else if (capable < 0)
                return capable;
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
                        r = id128_read_fd(fd, ID128_PLAIN, &context->seed);
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

static int context_open_copy_block_paths(Context *context) {
        Partition *p;
        int r;

        assert(context);

        LIST_FOREACH(partitions, p, context->partitions) {
                _cleanup_close_ int source_fd = -1;
                uint64_t size;
                struct stat st;

                assert(p->copy_blocks_fd < 0);
                assert(p->copy_blocks_size == UINT64_MAX);

                if (PARTITION_EXISTS(p)) /* Never copy over partitions that already exist! */
                        continue;

                if (!p->copy_blocks_path)
                        continue;

                source_fd = open(p->copy_blocks_path, O_RDONLY|O_CLOEXEC|O_NOCTTY);
                if (source_fd < 0)
                        return log_error_errno(errno, "Failed to open block copy file '%s': %m", p->copy_blocks_path);

                if (fstat(source_fd, &st) < 0)
                        return log_error_errno(errno, "Failed to stat block copy file '%s': %m", p->copy_blocks_path);

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
                                        return btrfs_log_dev_root(LOG_ERR, r, p->copy_blocks_path);
                                if (r < 0)
                                        return log_error_errno(r, "Unable to determine backing block device of '%s': %m", p->copy_blocks_path);

                                r = device_path_make_major_minor(S_IFBLK, devt, &bdev);
                        }
                        if (r < 0)
                                return log_error_errno(r, "Failed to determine block device path for block device backing '%s': %m", p->copy_blocks_path);

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
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Specified path to copy blocks from '%s' is not a regular file, block device or directory, refusing: %m", p->copy_blocks_path);

                if (size <= 0)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "File to copy bytes from '%s' has zero size, refusing.", p->copy_blocks_path);
                if (size % 512 != 0)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "File to copy bytes from '%s' has size that is not multiple of 512, refusing.", p->copy_blocks_path);

                p->copy_blocks_fd = TAKE_FD(source_fd);
                p->copy_blocks_size = size;
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
               "     --dry-run=BOOL       Whether to run dry-run operation\n"
               "     --empty=MODE         One of refuse, allow, require, force, create; controls\n"
               "                          how to handle empty disks lacking partition tables\n"
               "     --discard=BOOL       Whether to discard backing blocks for new partitions\n"
               "     --pretty=BOOL        Whether to show pretty summary before executing operation\n"
               "     --factory-reset=BOOL Whether to remove data partitions before recreating\n"
               "                          them\n"
               "     --can-factory-reset  Test whether factory reset is defined\n"
               "     --root=PATH          Operate relative to root path\n"
               "     --definitions=DIR    Find partitions in specified directory\n"
               "     --seed=UUID          128bit seed UUID to derive all UUIDs from\n"
               "     --size=BYTES         Grow loopback file to specified size\n"
               "\nSee the %s for details.\n"
               , program_invocation_short_name
               , ansi_highlight(), ansi_normal()
               , link
        );

        return 0;
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100,
                ARG_DRY_RUN,
                ARG_EMPTY,
                ARG_DISCARD,
                ARG_FACTORY_RESET,
                ARG_CAN_FACTORY_RESET,
                ARG_ROOT,
                ARG_SEED,
                ARG_PRETTY,
                ARG_DEFINITIONS,
                ARG_SIZE,
        };

        static const struct option options[] = {
                { "help",              no_argument,       NULL, 'h'                   },
                { "version",           no_argument,       NULL, ARG_VERSION           },
                { "dry-run",           required_argument, NULL, ARG_DRY_RUN           },
                { "empty",             required_argument, NULL, ARG_EMPTY             },
                { "discard",           required_argument, NULL, ARG_DISCARD           },
                { "factory-reset",     required_argument, NULL, ARG_FACTORY_RESET     },
                { "can-factory-reset", no_argument,       NULL, ARG_CAN_FACTORY_RESET },
                { "root",              required_argument, NULL, ARG_ROOT              },
                { "seed",              required_argument, NULL, ARG_SEED              },
                { "pretty",            required_argument, NULL, ARG_PRETTY            },
                { "definitions",       required_argument, NULL, ARG_DEFINITIONS       },
                { "size",              required_argument, NULL, ARG_SIZE              },
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

                case ARG_DRY_RUN:
                        r = parse_boolean(optarg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --dry-run= parameter: %s", optarg);

                        dry_run = r;
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
                        r = parse_boolean(optarg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --discard= parameter: %s", optarg);

                        arg_discard = r;
                        break;

                case ARG_FACTORY_RESET:
                        r = parse_boolean(optarg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --factory-reset= parameter: %s", optarg);

                        arg_factory_reset = r;
                        break;

                case ARG_CAN_FACTORY_RESET:
                        arg_can_factory_reset = true;
                        break;

                case ARG_ROOT:
                        r = parse_path_argument_and_warn(optarg, false, &arg_root);
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
                        r = parse_boolean(optarg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --pretty= parameter: %s", optarg);

                        arg_pretty = r;
                        break;

                case ARG_DEFINITIONS:
                        r = parse_path_argument_and_warn(optarg, false, &arg_definitions);
                        if (r < 0)
                                return r;
                        break;

                case ARG_SIZE: {
                        uint64_t parsed, rounded;

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

        if (arg_empty == EMPTY_CREATE && arg_size == UINT64_MAX)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "If --empty=create is specified, --size= must be specified, too.");

        arg_node = argc > optind ? argv[optind] : NULL;

        if (IN_SET(arg_empty, EMPTY_FORCE, EMPTY_REQUIRE, EMPTY_CREATE) && !arg_node)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "A path to a device node or loopback file must be specified when --empty=force, --empty=require or --empty=create are used.");

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

        r = efi_get_variable_string(EFI_VENDOR_SYSTEMD, "FactoryReset", &value);
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

        r = efi_set_variable(EFI_VENDOR_SYSTEMD, "FactoryReset", NULL, 0);
        if (r == -ENOENT || ERRNO_IS_NOT_SUPPORTED(r))
                return 0;
        if (r < 0)
                return log_error_errno(r, "Failed to remove EFI variable FactoryReset: %m");

        log_info("Successfully unset EFI variable FactoryReset.");
        return 0;
}

static int acquire_root_devno(const char *p, int mode, char **ret, int *ret_fd) {
        _cleanup_close_ int fd = -1;
        struct stat st;
        dev_t devno, fd_devno = (mode_t) -1;
        int r;

        assert(p);
        assert(ret);
        assert(ret_fd);

        fd = open(p, mode);
        if (fd < 0)
                return -errno;

        if (fstat(fd, &st) < 0)
                return -errno;

        if (S_ISREG(st.st_mode)) {
                char *s;

                s = strdup(p);
                if (!s)
                        return log_oom();

                *ret = s;
                *ret_fd = TAKE_FD(fd);

                return 0;
        }

        if (S_ISBLK(st.st_mode))
                fd_devno = devno = st.st_rdev;
        else if (S_ISDIR(st.st_mode)) {

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
        if (r < 0)
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
        *ret_fd = fd_devno != (mode_t) -1 && fd_devno == devno ? TAKE_FD(fd) : -1;
        return 0;
}

static int find_root(char **ret, int *ret_fd) {
        const char *t;
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

                r = acquire_root_devno(arg_node, O_RDONLY|O_CLOEXEC, ret, ret_fd);
                if (r == -EUCLEAN)
                        return btrfs_log_dev_root(LOG_ERR, r, arg_node);
                if (r < 0)
                        return log_error_errno(r, "Failed to determine backing device of %s: %m", arg_node);

                return 0;
        }

        assert(IN_SET(arg_empty, EMPTY_REFUSE, EMPTY_ALLOW));

        /* Let's search for the root device. We look for two cases here: first in /, and then in /usr. The
         * latter we check for cases where / is a tmpfs and only /usr is an actual persistent block device
         * (think: volatile setups) */

        FOREACH_STRING(t, "/", "/usr") {
                _cleanup_free_ char *j = NULL;
                const char *p;

                if (in_initrd()) {
                        j = path_join("/sysroot", t);
                        if (!j)
                                return log_oom();

                        p = j;
                } else
                        p = t;

                r = acquire_root_devno(p, O_RDONLY|O_DIRECTORY|O_CLOEXEC, ret, ret_fd);
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

static int resize_backing_fd(const char *node, int *fd) {
        char buf1[FORMAT_BYTES_MAX], buf2[FORMAT_BYTES_MAX];
        _cleanup_close_ int writable_fd = -1;
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

        r = stat_verify_regular(&st);
        if (r < 0)
                return log_error_errno(r, "Specified path '%s' is not a regular file, cannot resize: %m", node);

        assert_se(format_bytes(buf1, sizeof(buf1), st.st_size));
        assert_se(format_bytes(buf2, sizeof(buf2), arg_size));

        if ((uint64_t) st.st_size >= arg_size) {
                log_info("File '%s' already is of requested size or larger, not growing. (%s >= %s)", node, buf1, buf2);
                return 0;
        }

        /* The file descriptor is read-only. In order to grow the file we need to have a writable fd. We
         * reopen the file for that temporarily. We keep the writable fd only open for this operation though,
         * as fdisk can't accept it anyway. */

        writable_fd = fd_reopen(*fd, O_WRONLY|O_CLOEXEC);
        if (writable_fd < 0)
                return log_error_errno(writable_fd, "Failed to reopen backing file '%s' writable: %m", node);

        if (!arg_discard) {
                if (fallocate(writable_fd, 0, 0, arg_size) < 0) {
                        if (!ERRNO_IS_NOT_SUPPORTED(errno))
                                return log_error_errno(errno, "Failed to grow '%s' from %s to %s by allocation: %m",
                                                       node, buf1, buf2);

                        /* Fallback to truncation, if fallocate() is not supported. */
                        log_debug("Backing file system does not support fallocate(), falling back to ftruncate().");
                } else {
                        r = resize_pt(writable_fd);
                        if (r < 0)
                                return r;

                        if (st.st_size == 0) /* Likely regular file just created by us */
                                log_info("Allocated %s for '%s'.", buf2, node);
                        else
                                log_info("File '%s' grown from %s to %s by allocation.", node, buf1, buf2);

                        return 1;
                }
        }

        if (ftruncate(writable_fd, arg_size) < 0)
                return log_error_errno(errno, "Failed to grow '%s' from %s to %s by truncation: %m",
                                       node, buf1, buf2);

        r = resize_pt(writable_fd);
        if (r < 0)
                return r;

        if (st.st_size == 0) /* Likely regular file just created by us */
                log_info("Sized '%s' to %s.", node, buf2);
        else
                log_info("File '%s' grown from %s to %s by truncation.", node, buf1, buf2);

        return 1;
}

static int run(int argc, char *argv[]) {
        _cleanup_(context_freep) Context* context = NULL;
        _cleanup_free_ char *node = NULL;
        _cleanup_close_ int backing_fd = -1;
        bool from_scratch;
        int r;

        log_show_color(true);
        log_parse_environment();
        log_open();

        if (in_initrd()) {
                /* Default to operation on /sysroot when invoked in the initrd! */
                arg_root = strdup("/sysroot");
                if (!arg_root)
                        return log_oom();
        }

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        r = parse_proc_cmdline_factory_reset();
        if (r < 0)
                return r;

        r = parse_efi_variable_factory_reset();
        if (r < 0)
                return r;

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
                r = resize_backing_fd(node, &backing_fd);
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
        r = context_open_copy_block_paths(context);
        if (r < 0)
                return r;

        /* First try to fit new partitions in, dropping by priority until it fits */
        for (;;) {
                if (context_allocate_partitions(context))
                        break; /* Success! */

                if (!context_drop_one_priority(context))
                        return log_error_errno(SYNTHETIC_ERRNO(ENOSPC),
                                               "Can't fit requested partitions into free space, refusing.");
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
