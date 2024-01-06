/* SPDX-License-Identifier: LGPL-2.1-or-later */

#if HAVE_VALGRIND_MEMCHECK_H
#include <valgrind/memcheck.h>
#endif

#include <fcntl.h>
#include <getopt.h>
#include <linux/fs.h>
#include <linux/loop.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

#include "sd-device.h"
#include "sd-id128.h"

#include "alloc-util.h"
#include "blkid-util.h"
#include "blockdev-util.h"
#include "btrfs-util.h"
#include "build.h"
#include "chase.h"
#include "conf-files.h"
#include "conf-parser.h"
#include "constants.h"
#include "cryptsetup-util.h"
#include "device-util.h"
#include "devnum-util.h"
#include "dirent-util.h"
#include "efivars.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fdisk-util.h"
#include "fileio.h"
#include "format-table.h"
#include "format-util.h"
#include "fs-util.h"
#include "glyph-util.h"
#include "gpt.h"
#include "hexdecoct.h"
#include "hmac.h"
#include "id128-util.h"
#include "initrd-util.h"
#include "io-util.h"
#include "json.h"
#include "list.h"
#include "loop-util.h"
#include "main-func.h"
#include "mkdir.h"
#include "mkfs-util.h"
#include "mount-util.h"
#include "mountpoint-util.h"
#include "nulstr-util.h"
#include "openssl-util.h"
#include "parse-argument.h"
#include "parse-helpers.h"
#include "pretty-print.h"
#include "proc-cmdline.h"
#include "process-util.h"
#include "random-util.h"
#include "resize-fs.h"
#include "rm-rf.h"
#include "sort-util.h"
#include "specifier.h"
#include "stdio-util.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "sync-util.h"
#include "terminal-util.h"
#include "tmpfile-util.h"
#include "tpm2-pcr.h"
#include "tpm2-util.h"
#include "user-util.h"
#include "utf8.h"

/* If not configured otherwise use a minimal partition size of 10M */
#define DEFAULT_MIN_SIZE (10ULL*1024ULL*1024ULL)

/* Hard lower limit for new partition sizes */
#define HARD_MIN_SIZE 4096ULL

/* We know up front we're never going to put more than this in a verity sig partition. */
#define VERITY_SIG_SIZE (HARD_MIN_SIZE*4ULL)

/* libfdisk takes off slightly more than 1M of the disk size when creating a GPT disk label */
#define GPT_METADATA_SIZE (1044ULL*1024ULL)

/* LUKS2 takes off 16M of the partition size with its metadata by default */
#define LUKS2_METADATA_SIZE (16ULL*1024ULL*1024ULL)

/* To do LUKS2 offline encryption, we need to keep some extra free space at the end of the partition. */
#define LUKS2_METADATA_KEEP_FREE (LUKS2_METADATA_SIZE*2ULL)

/* LUKS2 volume key size. */
#define VOLUME_KEY_SIZE (512ULL/8ULL)

/* Use 4K as the default filesystem sector size because as long as the partitions are aligned to 4K, the
 * filesystems will then also be compatible with sector sizes 512, 1024 and 2048. */
#define DEFAULT_FILESYSTEM_SECTOR_SIZE 4096ULL

#define APIVFS_TMP_DIRS_NULSTR "proc\0sys\0dev\0tmp\0run\0var/tmp\0"

/* Note: When growing and placing new partitions we always align to 4K sector size. It's how newer hard disks
 * are designed, and if everything is aligned to that performance is best. And for older hard disks with 512B
 * sector size devices were generally assumed to have an even number of sectors, hence at the worst we'll
 * waste 3K per partition, which is probably fine. */

typedef enum EmptyMode {
        EMPTY_UNSET,    /* no choice has been made yet */
        EMPTY_REFUSE,   /* refuse empty disks, never create a partition table */
        EMPTY_ALLOW,    /* allow empty disks, create partition table if necessary */
        EMPTY_REQUIRE,  /* require an empty disk, create a partition table */
        EMPTY_FORCE,    /* make disk empty, erase everything, create a partition table always */
        EMPTY_CREATE,   /* create disk as loopback file, create a partition table always */
        _EMPTY_MODE_MAX,
        _EMPTY_MODE_INVALID = -EINVAL,
} EmptyMode;

typedef enum FilterPartitionType {
        FILTER_PARTITIONS_NONE,
        FILTER_PARTITIONS_EXCLUDE,
        FILTER_PARTITIONS_INCLUDE,
        _FILTER_PARTITIONS_MAX,
        _FILTER_PARTITIONS_INVALID = -EINVAL,
} FilterPartitionsType;

static EmptyMode arg_empty = EMPTY_UNSET;
static bool arg_dry_run = true;
static const char *arg_node = NULL;
static char *arg_root = NULL;
static char *arg_image = NULL;
static char **arg_definitions = NULL;
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
static EVP_PKEY *arg_private_key = NULL;
static X509 *arg_certificate = NULL;
static char *arg_tpm2_device = NULL;
static uint32_t arg_tpm2_seal_key_handle = 0;
static char *arg_tpm2_device_key = NULL;
static Tpm2PCRValue *arg_tpm2_hash_pcr_values = NULL;
static size_t arg_tpm2_n_hash_pcr_values = 0;
static char *arg_tpm2_public_key = NULL;
static uint32_t arg_tpm2_public_key_pcr_mask = 0;
static char *arg_tpm2_pcrlock = NULL;
static bool arg_split = false;
static GptPartitionType *arg_filter_partitions = NULL;
static size_t arg_n_filter_partitions = 0;
static FilterPartitionsType arg_filter_partitions_type = FILTER_PARTITIONS_NONE;
static GptPartitionType *arg_defer_partitions = NULL;
static size_t arg_n_defer_partitions = 0;
static uint64_t arg_sector_size = 0;
static ImagePolicy *arg_image_policy = NULL;
static Architecture arg_architecture = _ARCHITECTURE_INVALID;
static int arg_offline = -1;
static char **arg_copy_from = NULL;
static char *arg_copy_source = NULL;
static char *arg_make_ddi = NULL;

STATIC_DESTRUCTOR_REGISTER(arg_root, freep);
STATIC_DESTRUCTOR_REGISTER(arg_image, freep);
STATIC_DESTRUCTOR_REGISTER(arg_definitions, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_key, erase_and_freep);
STATIC_DESTRUCTOR_REGISTER(arg_private_key, EVP_PKEY_freep);
STATIC_DESTRUCTOR_REGISTER(arg_certificate, X509_freep);
STATIC_DESTRUCTOR_REGISTER(arg_tpm2_device, freep);
STATIC_DESTRUCTOR_REGISTER(arg_tpm2_device_key, freep);
STATIC_DESTRUCTOR_REGISTER(arg_tpm2_hash_pcr_values, freep);
STATIC_DESTRUCTOR_REGISTER(arg_tpm2_public_key, freep);
STATIC_DESTRUCTOR_REGISTER(arg_tpm2_pcrlock, freep);
STATIC_DESTRUCTOR_REGISTER(arg_filter_partitions, freep);
STATIC_DESTRUCTOR_REGISTER(arg_image_policy, image_policy_freep);
STATIC_DESTRUCTOR_REGISTER(arg_copy_from, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_copy_source, freep);
STATIC_DESTRUCTOR_REGISTER(arg_make_ddi, freep);

typedef struct FreeArea FreeArea;

typedef enum EncryptMode {
        ENCRYPT_OFF,
        ENCRYPT_KEY_FILE,
        ENCRYPT_TPM2,
        ENCRYPT_KEY_FILE_TPM2,
        _ENCRYPT_MODE_MAX,
        _ENCRYPT_MODE_INVALID = -EINVAL,
} EncryptMode;

typedef enum VerityMode {
        VERITY_OFF,
        VERITY_DATA,
        VERITY_HASH,
        VERITY_SIG,
        _VERITY_MODE_MAX,
        _VERITY_MODE_INVALID = -EINVAL,
} VerityMode;

typedef enum MinimizeMode {
        MINIMIZE_OFF,
        MINIMIZE_BEST,
        MINIMIZE_GUESS,
        _MINIMIZE_MODE_MAX,
        _MINIMIZE_MODE_INVALID = -EINVAL,
} MinimizeMode;

typedef struct Partition {
        char *definition_path;
        char **drop_in_files;

        GptPartitionType type;
        sd_id128_t current_uuid, new_uuid;
        bool new_uuid_is_set;
        char *current_label, *new_label;
        sd_id128_t fs_uuid, luks_uuid, verity_uuid;
        uint8_t verity_salt[SHA256_DIGEST_SIZE];

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
        bool copy_blocks_path_is_our_file;
        bool copy_blocks_auto;
        const char *copy_blocks_root;
        int copy_blocks_fd;
        uint64_t copy_blocks_offset;
        uint64_t copy_blocks_size;

        char *format;
        char **copy_files;
        char **exclude_files_source;
        char **exclude_files_target;
        char **make_directories;
        char **subvolumes;
        EncryptMode encrypt;
        VerityMode verity;
        char *verity_match_key;
        MinimizeMode minimize;
        uint64_t verity_data_block_size;
        uint64_t verity_hash_block_size;

        uint64_t gpt_flags;
        int no_auto;
        int read_only;
        int growfs;

        struct iovec roothash;

        char *split_name_format;
        char *split_path;

        struct Partition *siblings[_VERITY_MODE_MAX];

        LIST_FIELDS(struct Partition, partitions);
} Partition;

#define PARTITION_IS_FOREIGN(p) (!(p)->definition_path)
#define PARTITION_EXISTS(p) (!!(p)->current_partition)

struct FreeArea {
        Partition *after;
        uint64_t size;
        uint64_t allocated;
};

typedef struct Context {
        LIST_HEAD(Partition, partitions);
        size_t n_partitions;

        FreeArea **free_areas;
        size_t n_free_areas;

        uint64_t start, end, total;

        struct fdisk_context *fdisk_context;
        uint64_t sector_size, grain_size, fs_sector_size;

        sd_id128_t seed;

        char *node;
        bool node_is_our_file;
        int backing_fd;

        bool from_scratch;
} Context;

static const char *empty_mode_table[_EMPTY_MODE_MAX] = {
        [EMPTY_UNSET]   = "unset",
        [EMPTY_REFUSE]  = "refuse",
        [EMPTY_ALLOW]   = "allow",
        [EMPTY_REQUIRE] = "require",
        [EMPTY_FORCE]   = "force",
        [EMPTY_CREATE]  = "create",
};

static const char *encrypt_mode_table[_ENCRYPT_MODE_MAX] = {
        [ENCRYPT_OFF] = "off",
        [ENCRYPT_KEY_FILE] = "key-file",
        [ENCRYPT_TPM2] = "tpm2",
        [ENCRYPT_KEY_FILE_TPM2] = "key-file+tpm2",
};

static const char *verity_mode_table[_VERITY_MODE_MAX] = {
        [VERITY_OFF]  = "off",
        [VERITY_DATA] = "data",
        [VERITY_HASH] = "hash",
        [VERITY_SIG]  = "signature",
};

static const char *minimize_mode_table[_MINIMIZE_MODE_MAX] = {
        [MINIMIZE_OFF]   = "off",
        [MINIMIZE_BEST]  = "best",
        [MINIMIZE_GUESS] = "guess",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP(empty_mode, EmptyMode);
DEFINE_PRIVATE_STRING_TABLE_LOOKUP_FROM_STRING_WITH_BOOLEAN(encrypt_mode, EncryptMode, ENCRYPT_KEY_FILE);
DEFINE_PRIVATE_STRING_TABLE_LOOKUP(verity_mode, VerityMode);
DEFINE_PRIVATE_STRING_TABLE_LOOKUP_FROM_STRING_WITH_BOOLEAN(minimize_mode, MinimizeMode, MINIMIZE_BEST);

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
                .copy_blocks_fd = -EBADF,
                .copy_blocks_offset = UINT64_MAX,
                .copy_blocks_size = UINT64_MAX,
                .no_auto = -1,
                .read_only = -1,
                .growfs = -1,
                .verity_data_block_size = UINT64_MAX,
                .verity_hash_block_size = UINT64_MAX,
        };

        return p;
}

static Partition* partition_free(Partition *p) {
        if (!p)
                return NULL;

        free(p->current_label);
        free(p->new_label);
        free(p->definition_path);
        strv_free(p->drop_in_files);

        if (p->current_partition)
                fdisk_unref_partition(p->current_partition);
        if (p->new_partition)
                fdisk_unref_partition(p->new_partition);

        if (p->copy_blocks_path_is_our_file)
                unlink_and_free(p->copy_blocks_path);
        else
                free(p->copy_blocks_path);
        safe_close(p->copy_blocks_fd);

        free(p->format);
        strv_free(p->copy_files);
        strv_free(p->exclude_files_source);
        strv_free(p->exclude_files_target);
        strv_free(p->make_directories);
        strv_free(p->subvolumes);
        free(p->verity_match_key);

        iovec_done(&p->roothash);

        free(p->split_name_format);
        unlink_and_free(p->split_path);

        return mfree(p);
}

static void partition_foreignize(Partition *p) {
        assert(p);
        assert(PARTITION_EXISTS(p));

        /* Reset several parameters set through definition file to make the partition foreign. */

        p->definition_path = mfree(p->definition_path);
        p->drop_in_files = strv_free(p->drop_in_files);

        p->copy_blocks_path = mfree(p->copy_blocks_path);
        p->copy_blocks_fd = safe_close(p->copy_blocks_fd);
        p->copy_blocks_root = NULL;

        p->format = mfree(p->format);
        p->copy_files = strv_free(p->copy_files);
        p->exclude_files_source = strv_free(p->exclude_files_source);
        p->exclude_files_target = strv_free(p->exclude_files_target);
        p->make_directories = strv_free(p->make_directories);
        p->subvolumes = strv_free(p->subvolumes);
        p->verity_match_key = mfree(p->verity_match_key);

        p->priority = 0;
        p->weight = 1000;
        p->padding_weight = 0;
        p->size_min = UINT64_MAX;
        p->size_max = UINT64_MAX;
        p->padding_min = UINT64_MAX;
        p->padding_max = UINT64_MAX;
        p->no_auto = -1;
        p->read_only = -1;
        p->growfs = -1;
        p->verity = VERITY_OFF;
}

static bool partition_type_exclude(const GptPartitionType *type) {
        if (arg_filter_partitions_type == FILTER_PARTITIONS_NONE)
                return false;

        for (size_t i = 0; i < arg_n_filter_partitions; i++)
                if (sd_id128_equal(type->uuid, arg_filter_partitions[i].uuid))
                        return arg_filter_partitions_type == FILTER_PARTITIONS_EXCLUDE;

        return arg_filter_partitions_type == FILTER_PARTITIONS_INCLUDE;
}

static bool partition_type_defer(const GptPartitionType *type) {
        for (size_t i = 0; i < arg_n_defer_partitions; i++)
                if (sd_id128_equal(type->uuid, arg_defer_partitions[i].uuid))
                        return true;

        return false;
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

        safe_close(context->backing_fd);
        if (context->node_is_our_file)
                unlink_and_free(context->node);
        else
                free(context->node);

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

static void partition_drop_or_foreignize(Partition *p) {
        if (!p || p->dropped || PARTITION_IS_FOREIGN(p))
                return;

        if (PARTITION_EXISTS(p)) {
                log_info("Can't grow existing partition %s of priority %" PRIi32 ", ignoring.",
                         strna(p->current_label ?: p->new_label), p->priority);

                /* Handle the partition as foreign. Do not set dropped flag. */
                partition_foreignize(p);
        } else {
                log_info("Can't fit partition %s of priority %" PRIi32 ", dropping.",
                         p->definition_path, p->priority);

                p->dropped = true;
                p->allocated_to_area = NULL;
        }
}

static bool context_drop_or_foreignize_one_priority(Context *context) {
        int32_t priority = 0;

        LIST_FOREACH(partitions, p, context->partitions) {
                if (p->dropped)
                        continue;

                priority = MAX(priority, p->priority);
        }

        /* Refuse to drop partitions with 0 or negative priorities or partitions of priorities that have at
         * least one existing priority */
        if (priority <= 0)
                return false;

        LIST_FOREACH(partitions, p, context->partitions) {
                if (p->priority < priority)
                        continue;

                partition_drop_or_foreignize(p);

                /* We ensure that all verity sibling partitions have the same priority, so it's safe
                 * to drop all siblings here as well. */

                for (VerityMode mode = VERITY_OFF + 1; mode < _VERITY_MODE_MAX; mode++)
                        partition_drop_or_foreignize(p->siblings[mode]);
        }

        return true;
}

static uint64_t partition_min_size(const Context *context, const Partition *p) {
        uint64_t sz;

        assert(context);
        assert(p);

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

        if (p->verity == VERITY_SIG)
                return VERITY_SIG_SIZE;

        sz = p->current_size != UINT64_MAX ? p->current_size : HARD_MIN_SIZE;

        if (!PARTITION_EXISTS(p)) {
                uint64_t d = 0;

                if (p->encrypt != ENCRYPT_OFF)
                        d += round_up_size(LUKS2_METADATA_KEEP_FREE, context->grain_size);

                if (p->copy_blocks_size != UINT64_MAX)
                        d += round_up_size(p->copy_blocks_size, context->grain_size);
                else if (p->format || p->encrypt != ENCRYPT_OFF) {
                        uint64_t f;

                        /* If we shall synthesize a file system, take minimal fs size into account (assumed to be 4K if not known) */
                        f = p->format ? round_up_size(minimal_size_by_fs_name(p->format), context->grain_size) : UINT64_MAX;
                        d += f == UINT64_MAX ? context->grain_size : f;
                }

                if (d > sz)
                        sz = d;
        }

        return MAX(round_up_size(p->size_min != UINT64_MAX ? p->size_min : DEFAULT_MIN_SIZE, context->grain_size), sz);
}

static uint64_t partition_max_size(const Context *context, const Partition *p) {
        uint64_t sm;

        /* Calculate how large the partition may become at max. This is generally the configured maximum
         * size, except when it already exists and is larger than that. In that case it's the existing size,
         * since we never want to shrink partitions. */

        assert(context);
        assert(p);

        if (PARTITION_IS_FOREIGN(p)) {
                /* Don't allow changing size of partitions not managed by us */
                assert(p->current_size != UINT64_MAX);
                return p->current_size;
        }

        if (p->verity == VERITY_SIG)
                return VERITY_SIG_SIZE;

        if (p->size_max == UINT64_MAX)
                return UINT64_MAX;

        sm = round_down_size(p->size_max, context->grain_size);

        if (p->current_size != UINT64_MAX)
                sm = MAX(p->current_size, sm);

        return MAX(partition_min_size(context, p), sm);
}

static uint64_t partition_min_padding(const Partition *p) {
        assert(p);
        return p->padding_min != UINT64_MAX ? p->padding_min : 0;
}

static uint64_t partition_max_padding(const Partition *p) {
        assert(p);
        return p->padding_max;
}

static uint64_t partition_min_size_with_padding(Context *context, const Partition *p) {
        uint64_t sz;

        /* Calculate the disk space we need for this partition plus any free space coming after it. This
         * takes user configured padding into account as well as any additional whitespace needed to align
         * the next partition to 4K again. */

        assert(context);
        assert(p);

        sz = partition_min_size(context, p) + partition_min_padding(p);

        if (PARTITION_EXISTS(p)) {
                /* If the partition wasn't aligned, add extra space so that any we might add will be aligned */
                assert(p->offset != UINT64_MAX);
                return round_up_size(p->offset + sz, context->grain_size) - p->offset;
        }

        /* If this is a new partition we'll place it aligned, hence we just need to round up the required size here */
        return round_up_size(sz, context->grain_size);
}

static uint64_t free_area_available(const FreeArea *a) {
        assert(a);

        /* Determines how much of this free area is not allocated yet */

        assert(a->size >= a->allocated);
        return a->size - a->allocated;
}

static uint64_t free_area_current_end(Context *context, const FreeArea *a) {
        assert(context);
        assert(a);

        if (!a->after)
                return free_area_available(a);

        assert(a->after->offset != UINT64_MAX);
        assert(a->after->current_size != UINT64_MAX);

        /* Calculate where the free area ends, based on the offset of the partition preceding it. */
        return round_up_size(a->after->offset + a->after->current_size, context->grain_size) + free_area_available(a);
}

static uint64_t free_area_min_end(Context *context, const FreeArea *a) {
        assert(context);
        assert(a);

        if (!a->after)
                return 0;

        assert(a->after->offset != UINT64_MAX);
        assert(a->after->current_size != UINT64_MAX);

        /* Calculate where the partition would end when we give it as much as it needs. */
        return round_up_size(a->after->offset + partition_min_size_with_padding(context, a->after), context->grain_size);
}

static uint64_t free_area_available_for_new_partitions(Context *context, const FreeArea *a) {
        assert(context);
        assert(a);

        /* Similar to free_area_available(), but takes into account that the required size and padding of the
         * preceding partition is honoured. */

        return LESS_BY(free_area_current_end(context, a), free_area_min_end(context, a));
}

static int free_area_compare(FreeArea *const *a, FreeArea *const*b, Context *context) {
        assert(context);

        return CMP(free_area_available_for_new_partitions(context, *a),
                   free_area_available_for_new_partitions(context, *b));
}

static uint64_t charge_size(Context *context, uint64_t total, uint64_t amount) {
        assert(context);
        /* Subtract the specified amount from total, rounding up to multiple of 4K if there's room */
        assert(amount <= total);
        return LESS_BY(total, round_up_size(amount, context->grain_size));
}

static uint64_t charge_weight(uint64_t total, uint64_t amount) {
        assert(amount <= total);
        return total - amount;
}

static bool context_allocate_partitions(Context *context, uint64_t *ret_largest_free_area) {
        assert(context);

        /* This may be called multiple times. Reset previous assignments. */
        for (size_t i = 0; i < context->n_free_areas; i++)
                context->free_areas[i]->allocated = 0;

        /* Sort free areas by size, putting smallest first */
        typesafe_qsort_r(context->free_areas, context->n_free_areas, free_area_compare, context);

        /* In any case return size of the largest free area (i.e. not the size of all free areas
         * combined!) */
        if (ret_largest_free_area)
                *ret_largest_free_area =
                        context->n_free_areas == 0 ? 0 :
                        free_area_available_for_new_partitions(context, context->free_areas[context->n_free_areas-1]);

        /* Check that each existing partition can fit its area. */
        for (size_t i = 0; i < context->n_free_areas; i++)
                if (free_area_current_end(context, context->free_areas[i]) <
                    free_area_min_end(context, context->free_areas[i]))
                        return false;

        /* A simple first-fit algorithm. We return true if we can fit the partitions in, otherwise false. */
        LIST_FOREACH(partitions, p, context->partitions) {
                bool fits = false;
                uint64_t required;
                FreeArea *a = NULL;

                /* Skip partitions we already dropped or that already exist */
                if (p->dropped || PARTITION_EXISTS(p))
                        continue;

                /* How much do we need to fit? */
                required = partition_min_size_with_padding(context, p);
                assert(required % context->grain_size == 0);

                for (size_t i = 0; i < context->n_free_areas; i++) {
                        a = context->free_areas[i];

                        if (free_area_available_for_new_partitions(context, a) >= required) {
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
        return log_error_errno(SYNTHETIC_ERRNO(EOVERFLOW), "Combined weight of partition exceeds unsigned 64-bit range, refusing.");
}

static uint64_t scale_by_weight(uint64_t value, uint64_t weight, uint64_t weight_sum) {
        assert(weight_sum >= weight);

        for (;;) {
                if (weight == 0)
                        return 0;
                if (weight == weight_sum)
                        return value;
                if (value <= UINT64_MAX / weight)
                        return value * weight / weight_sum;

                /* Rescale weight and weight_sum to make not the calculation overflow. To satisfy the
                 * following conditions, 'weight_sum' is rounded up but 'weight' is rounded down:
                 * - the sum of scale_by_weight() for all weights must not be larger than the input value,
                 * - scale_by_weight() must not be larger than the ideal value (i.e. calculated with uint128_t). */
                weight_sum = DIV_ROUND_UP(weight_sum, 2);
                weight /= 2;
        }
}

typedef enum GrowPartitionPhase {
        /* The zeroth phase: do not touch foreign partitions (i.e. those we don't manage). */
        PHASE_FOREIGN,

        /* The first phase: we charge partitions which need more (according to constraints) than their weight-based share. */
        PHASE_OVERCHARGE,

        /* The second phase: we charge partitions which need less (according to constraints) than their weight-based share. */
        PHASE_UNDERCHARGE,

        /* The third phase: we distribute what remains among the remaining partitions, according to the weights */
        PHASE_DISTRIBUTE,

        _GROW_PARTITION_PHASE_MAX,
} GrowPartitionPhase;

static bool context_grow_partitions_phase(
                Context *context,
                FreeArea *a,
                GrowPartitionPhase phase,
                uint64_t *span,
                uint64_t *weight_sum) {

        bool try_again = false;

        assert(context);
        assert(a);
        assert(span);
        assert(weight_sum);

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
                        uint64_t share, rsz, xsz;
                        bool charge = false;

                        /* Calculate how much this space this partition needs if everyone would get
                         * the weight based share */
                        share = scale_by_weight(*span, p->weight, *weight_sum);

                        rsz = partition_min_size(context, p);
                        xsz = partition_max_size(context, p);

                        if (phase == PHASE_FOREIGN && PARTITION_IS_FOREIGN(p)) {
                                /* Never change of foreign partitions (i.e. those we don't manage) */

                                p->new_size = p->current_size;
                                charge = true;

                        } else if (phase == PHASE_OVERCHARGE && rsz > share) {
                                /* This partition needs more than its calculated share. Let's assign
                                 * it that, and take this partition out of all calculations and start
                                 * again. */

                                p->new_size = rsz;
                                charge = try_again = true;

                        } else if (phase == PHASE_UNDERCHARGE && xsz < share) {
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

                                assert(share >= rsz);
                                p->new_size = CLAMP(round_down_size(share, context->grain_size), rsz, xsz);
                                charge = true;
                        }

                        if (charge) {
                                *span = charge_size(context, *span, p->new_size);
                                *weight_sum = charge_weight(*weight_sum, p->weight);
                        }
                }

                if (p->new_padding == UINT64_MAX) {
                        uint64_t share, rsz, xsz;
                        bool charge = false;

                        share = scale_by_weight(*span, p->padding_weight, *weight_sum);

                        rsz = partition_min_padding(p);
                        xsz = partition_max_padding(p);

                        if (phase == PHASE_OVERCHARGE && rsz > share) {
                                p->new_padding = rsz;
                                charge = try_again = true;
                        } else if (phase == PHASE_UNDERCHARGE && xsz < share) {
                                p->new_padding = xsz;
                                charge = try_again = true;
                        } else if (phase == PHASE_DISTRIBUTE) {
                                assert(share >= rsz);
                                p->new_padding = CLAMP(round_down_size(share, context->grain_size), rsz, xsz);
                                charge = true;
                        }

                        if (charge) {
                                *span = charge_size(context, *span, p->new_padding);
                                *weight_sum = charge_weight(*weight_sum, p->padding_weight);
                        }
                }
        }

        return !try_again;
}

static void context_grow_partition_one(Context *context, FreeArea *a, Partition *p, uint64_t *span) {
        uint64_t m;

        assert(context);
        assert(a);
        assert(p);
        assert(span);

        if (*span == 0)
                return;

        if (p->allocated_to_area != a)
                return;

        if (PARTITION_IS_FOREIGN(p))
                return;

        assert(p->new_size != UINT64_MAX);

        /* Calculate new size and align. */
        m = round_down_size(p->new_size + *span, context->grain_size);
        /* But ensure this doesn't shrink the size. */
        m = MAX(m, p->new_size);
        /* And ensure this doesn't exceed the maximum size. */
        m = MIN(m, partition_max_size(context, p));

        assert(m >= p->new_size);

        *span = charge_size(context, *span, m - p->new_size);
        p->new_size = m;
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

                span += round_up_size(a->after->offset + a->after->current_size, context->grain_size) - a->after->offset;
        }

        for (GrowPartitionPhase phase = 0; phase < _GROW_PARTITION_PHASE_MAX;)
                if (context_grow_partitions_phase(context, a, phase, &span, &weight_sum))
                        phase++; /* go to the next phase */

        /* We still have space left over? Donate to preceding partition if we have one */
        if (span > 0 && a->after)
                context_grow_partition_one(context, a, a->after, &span);

        /* What? Even still some space left (maybe because there was no preceding partition, or it had a
         * size limit), then let's donate it to whoever wants it. */
        if (span > 0)
                LIST_FOREACH(partitions, p, context->partitions) {
                        context_grow_partition_one(context, a, p, &span);
                        if (span == 0)
                                break;
                }

        /* Yuck, still no one? Then make it padding */
        if (span > 0 && a->after) {
                assert(a->after->new_padding != UINT64_MAX);
                a->after->new_padding += span;
        }

        return 0;
}

static int context_grow_partitions(Context *context) {
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

static uint64_t find_first_unused_partno(Context *context) {
        uint64_t partno = 0;

        assert(context);

        for (partno = 0;; partno++) {
                bool found = false;
                LIST_FOREACH(partitions, p, context->partitions)
                        if (p->partno != UINT64_MAX && p->partno == partno)
                                found = true;
                if (!found)
                        break;
        }

        return partno;
}

static void context_place_partitions(Context *context) {

        assert(context);

        for (size_t i = 0; i < context->n_free_areas; i++) {
                FreeArea *a = context->free_areas[i];
                _unused_ uint64_t left;
                uint64_t start;

                if (a->after) {
                        assert(a->after->offset != UINT64_MAX);
                        assert(a->after->new_size != UINT64_MAX);
                        assert(a->after->new_padding != UINT64_MAX);

                        start = a->after->offset + a->after->new_size + a->after->new_padding;
                } else
                        start = context->start;

                start = round_up_size(start, context->grain_size);
                left = a->size;

                LIST_FOREACH(partitions, p, context->partitions) {
                        if (p->allocated_to_area != a)
                                continue;

                        p->offset = start;
                        p->partno = find_first_unused_partno(context);

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

        GptPartitionType *type = ASSERT_PTR(data);
        int r;

        assert(rvalue);

        r = gpt_partition_type_from_string(rvalue, type);
        if (r < 0)
                return log_syntax(unit, LOG_ERR, filename, line, r, "Failed to parse partition type: %s", rvalue);

        if (arg_architecture >= 0)
                *type = gpt_partition_type_override_architecture(*type, arg_architecture);

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
        char **label = ASSERT_PTR(data);
        int r;

        assert(rvalue);

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

        uint32_t *w = ASSERT_PTR(data), v;
        int r;

        assert(rvalue);

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

        *w = v;
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
                log_syntax(unit, LOG_NOTICE, filename, line, r, "Rounded %s= size %" PRIu64 " %s %" PRIu64 ", a multiple of 4096.",
                           lvalue, parsed, special_glyph(SPECIAL_GLYPH_ARROW_RIGHT), *sz);

        return 0;
}

static int config_parse_block_size(
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

        uint64_t *blksz = ASSERT_PTR(data), parsed;
        int r;

        assert(rvalue);

        r = parse_size(rvalue, 1024, &parsed);
        if (r < 0)
                return log_syntax(unit, LOG_ERR, filename, line, r,
                                  "Failed to parse size value: %s", rvalue);

        if (parsed < 512 || parsed > 4096)
                return log_syntax(unit, LOG_ERR, filename, line, SYNTHETIC_ERRNO(EINVAL),
                                  "Value not between 512 and 4096: %s", rvalue);

        if (!ISPOWEROF2(parsed))
                return log_syntax(unit, LOG_ERR, filename, line, SYNTHETIC_ERRNO(EINVAL),
                                  "Value not a power of 2: %s", rvalue);

        *blksz = parsed;
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

        char **fstype = ASSERT_PTR(data);
        const char *e;

        assert(rvalue);

        /* Let's provide an easy way to override the chosen fstype for file system partitions */
        e = secure_getenv("SYSTEMD_REPART_OVERRIDE_FSTYPE");
        if (e && !streq(rvalue, e)) {
                log_syntax(unit, LOG_NOTICE, filename, line, 0,
                           "Overriding defined file system type '%s' with '%s'.", rvalue, e);
                rvalue = e;
        }

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
        char ***copy_files = ASSERT_PTR(data);
        int r;

        assert(rvalue);

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

        r = strv_consume_pair(copy_files, TAKE_PTR(resolved_source), TAKE_PTR(resolved_target));
        if (r < 0)
                return log_oom();

        return 0;
}

static int config_parse_exclude_files(
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
        char ***exclude_files = ASSERT_PTR(data);
        int r;

        if (isempty(rvalue)) {
                *exclude_files = strv_free(*exclude_files);
                return 0;
        }

        r = specifier_printf(rvalue, PATH_MAX-1, system_and_tmp_specifier_table, arg_root, NULL, &resolved);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to expand specifiers in ExcludeFiles= path, ignoring: %s", rvalue);
                return 0;
        }

        r = path_simplify_and_warn(resolved, PATH_CHECK_ABSOLUTE|PATH_KEEP_TRAILING_SLASH, unit, filename, line, lvalue);
        if (r < 0)
                return 0;

        if (strv_consume(exclude_files, TAKE_PTR(resolved)) < 0)
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
        Partition *partition = ASSERT_PTR(data);
        int r;

        assert(rvalue);

        if (isempty(rvalue)) {
                partition->copy_blocks_path = mfree(partition->copy_blocks_path);
                partition->copy_blocks_auto = false;
                return 0;
        }

        if (streq(rvalue, "auto")) {
                partition->copy_blocks_path = mfree(partition->copy_blocks_path);
                partition->copy_blocks_auto = true;
                partition->copy_blocks_root = arg_root;
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
        partition->copy_blocks_root = arg_root;
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

        char ***sv = ASSERT_PTR(data);
        const char *p = ASSERT_PTR(rvalue);
        int r;

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

                r = strv_consume(sv, TAKE_PTR(d));
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

        uint64_t *gpt_flags = ASSERT_PTR(data);
        int r;

        assert(rvalue);

        r = safe_atou64(rvalue, gpt_flags);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse Flags= value, ignoring: %s", rvalue);
                return 0;
        }

        return 0;
}

static int config_parse_uuid(
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

        Partition *partition = ASSERT_PTR(data);
        int r;

        if (isempty(rvalue)) {
                partition->new_uuid = SD_ID128_NULL;
                partition->new_uuid_is_set = false;
                return 0;
        }

        if (streq(rvalue, "null")) {
                partition->new_uuid = SD_ID128_NULL;
                partition->new_uuid_is_set = true;
                return 0;
        }

        r = sd_id128_from_string(rvalue, &partition->new_uuid);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to parse 128-bit ID/UUID, ignoring: %s", rvalue);
                return 0;
        }

        partition->new_uuid_is_set = true;

        return 0;
}

static DEFINE_CONFIG_PARSE_ENUM_WITH_DEFAULT(config_parse_verity, verity_mode, VerityMode, VERITY_OFF, "Invalid verity mode");
static DEFINE_CONFIG_PARSE_ENUM_WITH_DEFAULT(config_parse_minimize, minimize_mode, MinimizeMode, MINIMIZE_OFF, "Invalid minimize mode");

static int partition_read_definition(Partition *p, const char *path, const char *const *conf_file_dirs) {

        ConfigTableItem table[] = {
                { "Partition", "Type",                     config_parse_type,          0, &p->type                    },
                { "Partition", "Label",                    config_parse_label,         0, &p->new_label               },
                { "Partition", "UUID",                     config_parse_uuid,          0, p                           },
                { "Partition", "Priority",                 config_parse_int32,         0, &p->priority                },
                { "Partition", "Weight",                   config_parse_weight,        0, &p->weight                  },
                { "Partition", "PaddingWeight",            config_parse_weight,        0, &p->padding_weight          },
                { "Partition", "SizeMinBytes",             config_parse_size4096,     -1, &p->size_min                },
                { "Partition", "SizeMaxBytes",             config_parse_size4096,      1, &p->size_max                },
                { "Partition", "PaddingMinBytes",          config_parse_size4096,     -1, &p->padding_min             },
                { "Partition", "PaddingMaxBytes",          config_parse_size4096,      1, &p->padding_max             },
                { "Partition", "FactoryReset",             config_parse_bool,          0, &p->factory_reset           },
                { "Partition", "CopyBlocks",               config_parse_copy_blocks,   0, p                           },
                { "Partition", "Format",                   config_parse_fstype,        0, &p->format                  },
                { "Partition", "CopyFiles",                config_parse_copy_files,    0, &p->copy_files              },
                { "Partition", "ExcludeFiles",             config_parse_exclude_files, 0, &p->exclude_files_source    },
                { "Partition", "ExcludeFilesTarget",       config_parse_exclude_files, 0, &p->exclude_files_target    },
                { "Partition", "MakeDirectories",          config_parse_make_dirs,     0, &p->make_directories        },
                { "Partition", "Encrypt",                  config_parse_encrypt,       0, &p->encrypt                 },
                { "Partition", "Verity",                   config_parse_verity,        0, &p->verity                  },
                { "Partition", "VerityMatchKey",           config_parse_string,        0, &p->verity_match_key        },
                { "Partition", "Flags",                    config_parse_gpt_flags,     0, &p->gpt_flags               },
                { "Partition", "ReadOnly",                 config_parse_tristate,      0, &p->read_only               },
                { "Partition", "NoAuto",                   config_parse_tristate,      0, &p->no_auto                 },
                { "Partition", "GrowFileSystem",           config_parse_tristate,      0, &p->growfs                  },
                { "Partition", "SplitName",                config_parse_string,        0, &p->split_name_format       },
                { "Partition", "Minimize",                 config_parse_minimize,      0, &p->minimize                },
                { "Partition", "Subvolumes",               config_parse_make_dirs,     0, &p->subvolumes              },
                { "Partition", "VerityDataBlockSizeBytes", config_parse_block_size,    0, &p->verity_data_block_size  },
                { "Partition", "VerityHashBlockSizeBytes", config_parse_block_size,    0, &p->verity_hash_block_size  },
                {}
        };
        int r;
        _cleanup_free_ char *filename = NULL;
        const char* dropin_dirname;

        r = path_extract_filename(path, &filename);
        if (r < 0)
                return log_error_errno(r, "Failed to extract filename from path '%s': %m", path);

        dropin_dirname = strjoina(filename, ".d");

        r = config_parse_many(
                        STRV_MAKE_CONST(path),
                        conf_file_dirs,
                        dropin_dirname,
                        arg_definitions ? NULL : arg_root,
                        "Partition\0",
                        config_item_table_lookup, table,
                        CONFIG_PARSE_WARN,
                        p,
                        NULL,
                        &p->drop_in_files);
        if (r < 0)
                return r;

        if (partition_type_exclude(&p->type))
                return 0;

        if (p->size_min != UINT64_MAX && p->size_max != UINT64_MAX && p->size_min > p->size_max)
                return log_syntax(NULL, LOG_ERR, path, 1, SYNTHETIC_ERRNO(EINVAL),
                                  "SizeMinBytes= larger than SizeMaxBytes=, refusing.");

        if (p->padding_min != UINT64_MAX && p->padding_max != UINT64_MAX && p->padding_min > p->padding_max)
                return log_syntax(NULL, LOG_ERR, path, 1, SYNTHETIC_ERRNO(EINVAL),
                                  "PaddingMinBytes= larger than PaddingMaxBytes=, refusing.");

        if (sd_id128_is_null(p->type.uuid))
                return log_syntax(NULL, LOG_ERR, path, 1, SYNTHETIC_ERRNO(EINVAL),
                                  "Type= not defined, refusing.");

        if ((p->copy_blocks_path || p->copy_blocks_auto) &&
            (p->format || !strv_isempty(p->copy_files) || !strv_isempty(p->make_directories)))
                return log_syntax(NULL, LOG_ERR, path, 1, SYNTHETIC_ERRNO(EINVAL),
                                  "Format=/CopyFiles=/MakeDirectories= and CopyBlocks= cannot be combined, refusing.");

        if ((!strv_isempty(p->copy_files) || !strv_isempty(p->make_directories)) && streq_ptr(p->format, "swap"))
                return log_syntax(NULL, LOG_ERR, path, 1, SYNTHETIC_ERRNO(EINVAL),
                                  "Format=swap and CopyFiles= cannot be combined, refusing.");

        if (!p->format) {
                const char *format = NULL;

                if (!strv_isempty(p->copy_files) || !strv_isempty(p->make_directories) || (p->encrypt != ENCRYPT_OFF && !(p->copy_blocks_path || p->copy_blocks_auto)))
                        /* Pick "vfat" as file system for esp and xbootldr partitions, otherwise default to "ext4". */
                        format = IN_SET(p->type.designator, PARTITION_ESP, PARTITION_XBOOTLDR) ? "vfat" : "ext4";
                else if (p->type.designator == PARTITION_SWAP)
                        format = "swap";

                if (format) {
                        p->format = strdup(format);
                        if (!p->format)
                                return log_oom();
                }
        }

        if (p->minimize != MINIMIZE_OFF && !p->format && p->verity != VERITY_HASH)
                return log_syntax(NULL, LOG_ERR, path, 1, SYNTHETIC_ERRNO(EINVAL),
                                  "Minimize= can only be enabled if Format= or Verity=hash are set");

        if (p->minimize == MINIMIZE_BEST && (p->format && !fstype_is_ro(p->format)) && p->verity != VERITY_HASH)
                return log_syntax(NULL, LOG_ERR, path, 1, SYNTHETIC_ERRNO(EINVAL),
                                  "Minimize=best can only be used with read-only filesystems or Verity=hash");

        if ((!strv_isempty(p->copy_files) || !strv_isempty(p->make_directories)) && !mkfs_supports_root_option(p->format) && geteuid() != 0)
                return log_syntax(NULL, LOG_ERR, path, 1, SYNTHETIC_ERRNO(EPERM),
                                  "Need to be root to populate %s filesystems with CopyFiles=/MakeDirectories=",
                                  p->format);

        if (p->format && fstype_is_ro(p->format) && strv_isempty(p->copy_files) && strv_isempty(p->make_directories))
                return log_syntax(NULL, LOG_ERR, path, 1, SYNTHETIC_ERRNO(EINVAL),
                                  "Cannot format %s filesystem without source files, refusing", p->format);

        if (p->verity != VERITY_OFF || p->encrypt != ENCRYPT_OFF) {
                r = dlopen_cryptsetup();
                if (r < 0)
                        return log_syntax(NULL, LOG_ERR, path, 1, r,
                                          "libcryptsetup not found, Verity=/Encrypt= are not supported: %m");
        }

        if (p->verity != VERITY_OFF && !p->verity_match_key)
                return log_syntax(NULL, LOG_ERR, path, 1, SYNTHETIC_ERRNO(EINVAL),
                                  "VerityMatchKey= must be set if Verity=%s", verity_mode_to_string(p->verity));

        if (p->verity == VERITY_OFF && p->verity_match_key)
                return log_syntax(NULL, LOG_ERR, path, 1, SYNTHETIC_ERRNO(EINVAL),
                                  "VerityMatchKey= can only be set if Verity= is not \"%s\"",
                                  verity_mode_to_string(p->verity));

        if (IN_SET(p->verity, VERITY_HASH, VERITY_SIG) &&
                (p->copy_files || p->copy_blocks_path || p->copy_blocks_auto || p->format || p->make_directories))
                return log_syntax(NULL, LOG_ERR, path, 1, SYNTHETIC_ERRNO(EINVAL),
                                  "CopyBlocks=/CopyFiles=/Format=/MakeDirectories= cannot be used with Verity=%s",
                                  verity_mode_to_string(p->verity));

        if (p->verity != VERITY_OFF && p->encrypt != ENCRYPT_OFF)
                return log_syntax(NULL, LOG_ERR, path, 1, SYNTHETIC_ERRNO(EINVAL),
                                  "Encrypting verity hash/data partitions is not supported");

        if (p->verity == VERITY_SIG && !arg_private_key)
                return log_syntax(NULL, LOG_ERR, path, 1, SYNTHETIC_ERRNO(EINVAL),
                                  "Verity signature partition requested but no private key provided (--private-key=)");

        if (p->verity == VERITY_SIG && !arg_certificate)
                return log_syntax(NULL, LOG_ERR, path, 1, SYNTHETIC_ERRNO(EINVAL),
                                  "Verity signature partition requested but no PEM certificate provided (--certificate=)");

        if (p->verity == VERITY_SIG && (p->size_min != UINT64_MAX || p->size_max != UINT64_MAX))
                return log_syntax(NULL, LOG_ERR, path, 1, SYNTHETIC_ERRNO(EINVAL),
                                  "SizeMinBytes=/SizeMaxBytes= cannot be used with Verity=%s",
                                  verity_mode_to_string(p->verity));

        if (!strv_isempty(p->subvolumes) && arg_offline > 0)
                return log_syntax(NULL, LOG_ERR, path, 1, SYNTHETIC_ERRNO(EOPNOTSUPP),
                                  "Subvolumes= cannot be used with --offline=yes");

        /* Verity partitions are read only, let's imply the RO flag hence, unless explicitly configured otherwise. */
        if ((IN_SET(p->type.designator,
                    PARTITION_ROOT_VERITY,
                    PARTITION_USR_VERITY) || p->verity == VERITY_DATA) && p->read_only < 0)
                p->read_only = true;

        /* Default to "growfs" on, unless read-only */
        if (gpt_partition_type_knows_growfs(p->type) &&
            p->read_only <= 0)
                p->growfs = true;

        if (!p->split_name_format) {
                char *s = strdup("%t");
                if (!s)
                        return log_oom();

                p->split_name_format = s;
        } else if (streq(p->split_name_format, "-"))
                p->split_name_format = mfree(p->split_name_format);

        return 1;
}

static int find_verity_sibling(Context *context, Partition *p, VerityMode mode, Partition **ret) {
        Partition *s = NULL;

        assert(p);
        assert(p->verity != VERITY_OFF);
        assert(p->verity_match_key);
        assert(mode != VERITY_OFF);
        assert(p->verity != mode);
        assert(ret);

        /* Try to find the matching sibling partition of the given type for a verity partition. For a data
         * partition, this is the corresponding hash partition with the same verity name (and vice versa for
         * the hash partition). */

        LIST_FOREACH(partitions, q, context->partitions) {
                if (p == q)
                        continue;

                if (q->verity != mode)
                        continue;

                assert(q->verity_match_key);

                if (!streq(p->verity_match_key, q->verity_match_key))
                        continue;

                if (s)
                        return -ENOTUNIQ;

                s = q;
        }

        if (!s)
                return -ENXIO;

        *ret = s;

        return 0;
}

static int context_open_and_lock_backing_fd(const char *node, int operation, int *backing_fd) {
        _cleanup_close_ int fd = -EBADF;

        assert(node);
        assert(backing_fd);

        if (*backing_fd >= 0)
                return 0;

        fd = open(node, O_RDONLY|O_CLOEXEC);
        if (fd < 0)
                return log_error_errno(errno, "Failed to open device '%s': %m", node);

        /* Tell udev not to interfere while we are processing the device */
        if (flock(fd, operation) < 0)
                return log_error_errno(errno, "Failed to lock device '%s': %m", node);

        log_debug("Device %s opened and locked.", node);
        *backing_fd = TAKE_FD(fd);
        return 1;
}

static int determine_current_padding(
                struct fdisk_context *c,
                struct fdisk_table *t,
                struct fdisk_partition *p,
                uint64_t secsz,
                uint64_t grainsz,
                uint64_t *ret) {

        size_t n_partitions;
        uint64_t offset, next = UINT64_MAX;

        assert(c);
        assert(t);
        assert(p);
        assert(ret);

        if (!fdisk_partition_has_end(p))
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Partition has no end!");

        offset = fdisk_partition_get_end(p);
        assert(offset < UINT64_MAX);
        offset++; /* The end is one sector before the next partition or padding. */
        assert(offset < UINT64_MAX / secsz);
        offset *= secsz;

        n_partitions = fdisk_table_get_nents(t);
        for (size_t i = 0; i < n_partitions; i++) {
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
                assert(start < UINT64_MAX / secsz);
                start *= secsz;

                if (start >= offset && (next == UINT64_MAX || next > start))
                        next = start;
        }

        if (next == UINT64_MAX) {
                /* No later partition? In that case check the end of the usable area */
                next = fdisk_get_last_lba(c);
                assert(next < UINT64_MAX);
                next++; /* The last LBA is one sector before the end */

                assert(next < UINT64_MAX / secsz);
                next *= secsz;

                if (offset > next)
                        return log_error_errno(SYNTHETIC_ERRNO(EIO), "Partition end beyond disk end.");
        }

        assert(next >= offset);
        offset = round_up_size(offset, grainsz);
        next = round_down_size(next, grainsz);

        *ret = LESS_BY(next, offset); /* Saturated subtraction, rounding might have fucked things up */
        return 0;
}

static int context_copy_from_one(Context *context, const char *src) {
        _cleanup_close_ int fd = -EBADF;
        _cleanup_(fdisk_unref_contextp) struct fdisk_context *c = NULL;
        _cleanup_(fdisk_unref_tablep) struct fdisk_table *t = NULL;
        Partition *last = NULL;
        unsigned long secsz, grainsz;
        size_t n_partitions;
        int r;

        assert(src);

        r = context_open_and_lock_backing_fd(src, LOCK_SH, &fd);
        if (r < 0)
                return r;

        r = fd_verify_regular(fd);
        if (r < 0)
                return log_error_errno(r, "%s is not a file: %m", src);

        r = fdisk_new_context_at(fd, /* path = */ NULL, /* read_only = */ true, /* sector_size = */ UINT32_MAX, &c);
        if (r < 0)
                return log_error_errno(r, "Failed to create fdisk context: %m");

        secsz = fdisk_get_sector_size(c);
        grainsz = fdisk_get_grain_size(c);

        /* Insist on a power of two, and that it's a multiple of 512, i.e. the traditional sector size. */
        if (secsz < 512 || !ISPOWEROF2(secsz))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Sector size %lu is not a power of two larger than 512? Refusing.", secsz);

        if (!fdisk_is_labeltype(c, FDISK_DISKLABEL_GPT))
                return log_error_errno(SYNTHETIC_ERRNO(EHWPOISON), "Cannot copy from disk %s with no GPT disk label.", src);

        r = fdisk_get_partitions(c, &t);
        if (r < 0)
                return log_error_errno(r, "Failed to acquire partition table: %m");

        n_partitions = fdisk_table_get_nents(t);
        for (size_t i = 0; i < n_partitions; i++) {
                _cleanup_(partition_freep) Partition *np = NULL;
                _cleanup_free_ char *label_copy = NULL;
                struct fdisk_partition *p;
                const char *label;
                uint64_t sz, start, padding;
                sd_id128_t ptid, id;
                GptPartitionType type;

                p = fdisk_table_get_partition(t, i);
                if (!p)
                        return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to read partition metadata: %m");

                if (fdisk_partition_is_used(p) <= 0)
                        continue;

                if (fdisk_partition_has_start(p) <= 0 ||
                    fdisk_partition_has_size(p) <= 0 ||
                    fdisk_partition_has_partno(p) <= 0)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Found a partition without a position, size or number.");

                r = fdisk_partition_get_type_as_id128(p, &ptid);
                if (r < 0)
                        return log_error_errno(r, "Failed to query partition type UUID: %m");

                type = gpt_partition_type_from_uuid(ptid);

                r = fdisk_partition_get_uuid_as_id128(p, &id);
                if (r < 0)
                        return log_error_errno(r, "Failed to query partition UUID: %m");

                label = fdisk_partition_get_name(p);
                if (!isempty(label)) {
                        label_copy = strdup(label);
                        if (!label_copy)
                                return log_oom();
                }

                sz = fdisk_partition_get_size(p);
                assert(sz <= UINT64_MAX/secsz);
                sz *= secsz;

                start = fdisk_partition_get_start(p);
                assert(start <= UINT64_MAX/secsz);
                start *= secsz;

                if (partition_type_exclude(&type))
                        continue;

                np = partition_new();
                if (!np)
                        return log_oom();

                np->type = type;
                np->new_uuid = id;
                np->new_uuid_is_set = true;
                np->size_min = np->size_max = sz;
                np->new_label = TAKE_PTR(label_copy);

                np->definition_path = strdup(src);
                if (!np->definition_path)
                        return log_oom();

                r = determine_current_padding(c, t, p, secsz, grainsz, &padding);
                if (r < 0)
                        return r;

                np->padding_min = np->padding_max = padding;

                np->copy_blocks_path = strdup(src);
                if (!np->copy_blocks_path)
                        return log_oom();

                np->copy_blocks_fd = fcntl(fd, F_DUPFD_CLOEXEC, 3);
                if (np->copy_blocks_fd < 0)
                        return log_error_errno(r, "Failed to duplicate file descriptor of %s: %m", src);

                np->copy_blocks_offset = start;
                np->copy_blocks_size = sz;

                r = fdisk_partition_get_attrs_as_uint64(p, &np->gpt_flags);
                if (r < 0)
                        return log_error_errno(r, "Failed to get partition flags: %m");

                LIST_INSERT_AFTER(partitions, context->partitions, last, np);
                last = TAKE_PTR(np);
                context->n_partitions++;
        }

        return 0;
}

static int context_copy_from(Context *context) {
        int r;

        assert(context);

        STRV_FOREACH(src, arg_copy_from) {
                r = context_copy_from_one(context, *src);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int context_read_definitions(Context *context) {
        _cleanup_strv_free_ char **files = NULL;
        Partition *last = LIST_FIND_TAIL(partitions, context->partitions);
        const char *const *dirs;
        int r;

        assert(context);

        dirs = (const char* const*) (arg_definitions ?: CONF_PATHS_STRV("repart.d"));

        r = conf_files_list_strv(&files, ".conf", arg_definitions ? NULL : arg_root, CONF_FILES_REGULAR|CONF_FILES_FILTER_MASKED, dirs);
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

                r = partition_read_definition(p, *f, dirs);
                if (r < 0)
                        return r;
                if (r == 0)
                        continue;

                LIST_INSERT_AFTER(partitions, context->partitions, last, p);
                last = TAKE_PTR(p);
                context->n_partitions++;
        }

        /* Check that each configured verity hash/data partition has a matching verity data/hash partition. */

        LIST_FOREACH(partitions, p, context->partitions) {
                if (p->verity == VERITY_OFF)
                        continue;

                for (VerityMode mode = VERITY_OFF + 1; mode < _VERITY_MODE_MAX; mode++) {
                        Partition *q = NULL;

                        if (p->verity == mode)
                                continue;

                        if (p->siblings[mode])
                                continue;

                        r = find_verity_sibling(context, p, mode, &q);
                        if (r == -ENXIO) {
                                if (mode != VERITY_SIG)
                                        return log_syntax(NULL, LOG_ERR, p->definition_path, 1, SYNTHETIC_ERRNO(EINVAL),
                                                          "Missing verity %s partition for verity %s partition with VerityMatchKey=%s",
                                                          verity_mode_to_string(mode), verity_mode_to_string(p->verity), p->verity_match_key);
                        } else if (r == -ENOTUNIQ)
                                return log_syntax(NULL, LOG_ERR, p->definition_path, 1, SYNTHETIC_ERRNO(EINVAL),
                                                  "Multiple verity %s partitions found for verity %s partition with VerityMatchKey=%s",
                                                  verity_mode_to_string(mode), verity_mode_to_string(p->verity), p->verity_match_key);
                        else if (r < 0)
                                return log_syntax(NULL, LOG_ERR, p->definition_path, 1, r,
                                                  "Failed to find verity %s partition for verity %s partition with VerityMatchKey=%s",
                                                  verity_mode_to_string(mode), verity_mode_to_string(p->verity), p->verity_match_key);

                        if (q) {
                                if (q->priority != p->priority)
                                        return log_syntax(NULL, LOG_ERR, p->definition_path, 1, SYNTHETIC_ERRNO(EINVAL),
                                                          "Priority mismatch (%i != %i) for verity sibling partitions with VerityMatchKey=%s",
                                                          p->priority, q->priority, p->verity_match_key);

                                p->siblings[mode] = q;
                        }
                }
        }

        LIST_FOREACH(partitions, p, context->partitions) {
                Partition *dp;

                if (p->verity != VERITY_HASH)
                        continue;

                if (p->minimize == MINIMIZE_OFF)
                        continue;

                assert_se(dp = p->siblings[VERITY_DATA]);

                if (dp->minimize == MINIMIZE_OFF && !(dp->copy_blocks_path || dp->copy_blocks_auto))
                        return log_syntax(NULL, LOG_ERR, p->definition_path, 1, SYNTHETIC_ERRNO(EINVAL),
                                          "Minimize= set for verity hash partition but data partition does "
                                          "not set CopyBlocks= or Minimize=");

        }

        return 0;
}

static int fdisk_ask_cb(struct fdisk_context *c, struct fdisk_ask *ask, void *data) {
        _cleanup_free_ char *ids = NULL;
        int r;

        if (fdisk_ask_get_type(ask) != FDISK_ASKTYPE_STRING)
                return -EINVAL;

        ids = new(char, SD_ID128_UUID_STRING_MAX);
        if (!ids)
                return -ENOMEM;

        r = fdisk_ask_string_set_result(ask, sd_id128_to_uuid_string(*(sd_id128_t*) data, ids));
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
                uint8_t md[SHA256_DIGEST_SIZE];
                sd_id128_t id;
        } result;

        assert(token);
        assert(ret);

        /* Derive a new UUID from the specified UUID in a stable and reasonably safe way. Specifically, we
         * calculate the HMAC-SHA256 of the specified token string, keyed by the supplied base (typically the
         * machine ID). We use the machine ID as key (and not as cleartext!) of the HMAC operation since it's
         * the machine ID we don't want to leak. */

        hmac_sha256(base.bytes, sizeof(base.bytes), token, strlen(token), result.md);

        /* Take the first half, mark it as v4 UUID */
        assert_cc(sizeof(result.md) == sizeof(result.id) * 2);
        *ret = id128_make_v4_uuid(result.id);
        return 0;
}

static void derive_salt(sd_id128_t base, const char *token, uint8_t ret[static SHA256_DIGEST_SIZE]) {
        assert(token);

        hmac_sha256(base.bytes, sizeof(base.bytes), token, strlen(token), ret);
}

static int context_load_partition_table(Context *context) {
        _cleanup_(fdisk_unref_contextp) struct fdisk_context *c = NULL;
        _cleanup_(fdisk_unref_tablep) struct fdisk_table *t = NULL;
        uint64_t left_boundary = UINT64_MAX, first_lba, last_lba, nsectors;
        _cleanup_free_ char *disk_uuid_string = NULL;
        bool from_scratch = false;
        sd_id128_t disk_uuid;
        size_t n_partitions;
        unsigned long secsz;
        uint64_t grainsz, fs_secsz = DEFAULT_FILESYSTEM_SECTOR_SIZE;
        int r;

        assert(context);
        assert(!context->fdisk_context);
        assert(!context->free_areas);
        assert(context->start == UINT64_MAX);
        assert(context->end == UINT64_MAX);
        assert(context->total == UINT64_MAX);

        c = fdisk_new_context();
        if (!c)
                return log_oom();

        if (arg_sector_size > 0) {
                fs_secsz = arg_sector_size;
                r = fdisk_save_user_sector_size(c, /* phy= */ 0, arg_sector_size);
        } else {
                uint32_t ssz;
                struct stat st;

                r = context_open_and_lock_backing_fd(context->node, arg_dry_run ? LOCK_SH : LOCK_EX,
                                                     &context->backing_fd);
                if (r < 0)
                        return r;

                if (fstat(context->backing_fd, &st) < 0)
                        return log_error_errno(errno, "Failed to stat %s: %m", context->node);

                /* Auto-detect sector size if not specified. */
                r = probe_sector_size_prefer_ioctl(context->backing_fd, &ssz);
                if (r < 0)
                        return log_error_errno(r, "Failed to probe sector size of '%s': %m", context->node);

                /* If we found the sector size and we're operating on a block device, use it as the file
                 * system sector size as well, as we know its the sector size of the actual block device and
                 * not just the offset at which we found the GPT header. */
                if (r > 0 && S_ISBLK(st.st_mode))
                        fs_secsz = ssz;

                r = fdisk_save_user_sector_size(c, /* phy= */ 0, ssz);
        }
        if (r < 0)
                return log_error_errno(r, "Failed to set sector size: %m");

        /* libfdisk doesn't have an API to operate on arbitrary fds, hence reopen the fd going via the
         * /proc/self/fd/ magic path if we have an existing fd. Open the original file otherwise. */
        r = fdisk_assign_device(
                        c,
                        context->backing_fd >= 0 ? FORMAT_PROC_FD_PATH(context->backing_fd) : context->node,
                        arg_dry_run);
        if (r == -EINVAL && arg_size_auto) {
                struct stat st;

                /* libfdisk returns EINVAL if opening a file of size zero. Let's check for that, and accept
                 * it if automatic sizing is requested. */

                if (context->backing_fd < 0)
                        r = stat(context->node, &st);
                else
                        r = fstat(context->backing_fd, &st);
                if (r < 0)
                        return log_error_errno(errno, "Failed to stat block device '%s': %m", context->node);

                if (S_ISREG(st.st_mode) && st.st_size == 0) {
                        /* Use the fallback values if we have no better idea */
                        context->sector_size = fdisk_get_sector_size(c);
                        context->fs_sector_size = fs_secsz;
                        context->grain_size = 4096;
                        return /* from_scratch = */ true;
                }

                r = -EINVAL;
        }
        if (r < 0)
                return log_error_errno(r, "Failed to open device '%s': %m", context->node);

        if (context->backing_fd < 0) {
                /* If we have no fd referencing the device yet, make a copy of the fd now, so that we have one */
                r = context_open_and_lock_backing_fd(FORMAT_PROC_FD_PATH(fdisk_get_devfd(c)),
                                                     arg_dry_run ? LOCK_SH : LOCK_EX,
                                                     &context->backing_fd);
                if (r < 0)
                        return r;
        }

        /* The offsets/sizes libfdisk returns to us will be in multiple of the sector size of the
         * device. This is typically 512, and sometimes 4096. Let's query libfdisk once for it, and then use
         * it for all our needs. Note that the values we use ourselves always are in bytes though, thus mean
         * the same thing universally. Also note that regardless what kind of sector size is in use we'll
         * place partitions at multiples of 4K. */
        secsz = fdisk_get_sector_size(c);

        /* Insist on a power of two, and that it's a multiple of 512, i.e. the traditional sector size. */
        if (secsz < 512 || !ISPOWEROF2(secsz))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Sector size %lu is not a power of two larger than 512? Refusing.", secsz);

        /* Use at least 4K, and ensure it's a multiple of the sector size, regardless if that is smaller or
         * larger */
        grainsz = secsz < 4096 ? 4096 : secsz;

        log_debug("Sector size of device is %lu bytes. Using grain size of %" PRIu64 ".", secsz, grainsz);

        switch (arg_empty) {

        case EMPTY_REFUSE:
                /* Refuse empty disks, insist on an existing GPT partition table */
                if (!fdisk_is_labeltype(c, FDISK_DISKLABEL_GPT))
                        return log_notice_errno(SYNTHETIC_ERRNO(EHWPOISON), "Disk %s has no GPT disk label, not repartitioning.", context->node);

                break;

        case EMPTY_REQUIRE:
                /* Require an empty disk, refuse any existing partition table */
                r = fdisk_has_label(c);
                if (r < 0)
                        return log_error_errno(r, "Failed to determine whether disk %s has a disk label: %m", context->node);
                if (r > 0)
                        return log_notice_errno(SYNTHETIC_ERRNO(EHWPOISON), "Disk %s already has a disk label, refusing.", context->node);

                from_scratch = true;
                break;

        case EMPTY_ALLOW:
                /* Allow both an empty disk and an existing partition table, but only GPT */
                r = fdisk_has_label(c);
                if (r < 0)
                        return log_error_errno(r, "Failed to determine whether disk %s has a disk label: %m", context->node);
                if (r > 0) {
                        if (!fdisk_is_labeltype(c, FDISK_DISKLABEL_GPT))
                                return log_notice_errno(SYNTHETIC_ERRNO(EHWPOISON), "Disk %s has non-GPT disk label, not repartitioning.", context->node);
                } else
                        from_scratch = true;

                break;

        case EMPTY_FORCE:
        case EMPTY_CREATE:
                /* Always reinitiaize the disk, don't consider what there was on the disk before */
                from_scratch = true;
                break;

        default:
                assert_not_reached();
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

        r = id128_from_string_nonzero(disk_uuid_string, &disk_uuid);
        if (r == -ENXIO) {
                r = derive_uuid(context->seed, "disk-uuid", &disk_uuid);
                if (r < 0)
                        return log_error_errno(r, "Failed to acquire disk GPT uuid: %m");

                r = fdisk_set_disklabel_id(c);
                if (r < 0)
                        return log_error_errno(r, "Failed to set GPT disk label: %m");
        } else if (r < 0)
                return log_error_errno(r, "Failed to parse current GPT disk label UUID: %m");

        r = fdisk_get_partitions(c, &t);
        if (r < 0)
                return log_error_errno(r, "Failed to acquire partition table: %m");

        n_partitions = fdisk_table_get_nents(t);
        for (size_t i = 0; i < n_partitions; i++) {
                _cleanup_free_ char *label_copy = NULL;
                Partition *last = NULL;
                struct fdisk_partition *p;
                const char *label;
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

                r = fdisk_partition_get_type_as_id128(p, &ptid);
                if (r < 0)
                        return log_error_errno(r, "Failed to query partition type UUID: %m");

                r = fdisk_partition_get_uuid_as_id128(p, &id);
                if (r < 0)
                        return log_error_errno(r, "Failed to query partition UUID: %m");

                label = fdisk_partition_get_name(p);
                if (!isempty(label)) {
                        label_copy = strdup(label);
                        if (!label_copy)
                                return log_oom();
                }

                sz = fdisk_partition_get_size(p);
                assert(sz <= UINT64_MAX/secsz);
                sz *= secsz;

                start = fdisk_partition_get_start(p);
                assert(start <= UINT64_MAX/secsz);
                start *= secsz;

                partno = fdisk_partition_get_partno(p);

                if (left_boundary == UINT64_MAX || left_boundary > start)
                        left_boundary = start;

                /* Assign this existing partition to the first partition of the right type that doesn't have
                 * an existing one assigned yet. */
                LIST_FOREACH(partitions, pp, context->partitions) {
                        last = pp;

                        if (!sd_id128_equal(pp->type.uuid, ptid))
                                continue;

                        if (!pp->current_partition) {
                                pp->current_uuid = id;
                                pp->current_size = sz;
                                pp->offset = start;
                                pp->partno = partno;
                                pp->current_label = TAKE_PTR(label_copy);

                                pp->current_partition = p;
                                fdisk_ref_partition(p);

                                r = determine_current_padding(c, t, p, secsz, grainsz, &pp->current_padding);
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
                        np->type = gpt_partition_type_from_uuid(ptid);
                        np->current_size = sz;
                        np->offset = start;
                        np->partno = partno;
                        np->current_label = TAKE_PTR(label_copy);

                        np->current_partition = p;
                        fdisk_ref_partition(p);

                        r = determine_current_padding(c, t, p, secsz, grainsz, &np->current_padding);
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
        assert(nsectors <= UINT64_MAX/secsz);
        nsectors *= secsz;

        first_lba = fdisk_get_first_lba(c);
        assert(first_lba <= UINT64_MAX/secsz);
        first_lba *= secsz;

        last_lba = fdisk_get_last_lba(c);
        assert(last_lba < UINT64_MAX);
        last_lba++;
        assert(last_lba <= UINT64_MAX/secsz);
        last_lba *= secsz;

        assert(last_lba >= first_lba);

        if (left_boundary == UINT64_MAX) {
                /* No partitions at all? Then the whole disk is up for grabs. */

                first_lba = round_up_size(first_lba, grainsz);
                last_lba = round_down_size(last_lba, grainsz);

                if (last_lba > first_lba) {
                        r = context_add_free_area(context, last_lba - first_lba, NULL);
                        if (r < 0)
                                return r;
                }
        } else {
                /* Add space left of first partition */
                assert(left_boundary >= first_lba);

                first_lba = round_up_size(first_lba, grainsz);
                left_boundary = round_down_size(left_boundary, grainsz);
                last_lba = round_down_size(last_lba, grainsz);

                if (left_boundary > first_lba) {
                        r = context_add_free_area(context, left_boundary - first_lba, NULL);
                        if (r < 0)
                                return r;
                }
        }

        context->start = first_lba;
        context->end = last_lba;
        context->total = nsectors;
        context->sector_size = secsz;
        context->fs_sector_size = fs_secsz;
        context->grain_size = grainsz;
        context->fdisk_context = TAKE_PTR(c);

        return from_scratch;
}

static void context_unload_partition_table(Context *context) {
        assert(context);

        LIST_FOREACH(partitions, p, context->partitions) {

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
        char *t;

        if (from != UINT64_MAX) {
                if (from == to || to == UINT64_MAX)
                        t = strdup(FORMAT_BYTES(from));
                else
                        t = strjoin(FORMAT_BYTES(from), " ", special_glyph(SPECIAL_GLYPH_ARROW_RIGHT), " ", FORMAT_BYTES(to));
        } else if (to != UINT64_MAX)
                t = strjoin(special_glyph(SPECIAL_GLYPH_ARROW_RIGHT), " ", FORMAT_BYTES(to));
        else {
                *ret = NULL;
                return 0;
        }

        if (!t)
                return log_oom();

        *ret = t;
        return 1;
}

static const char *partition_label(const Partition *p) {
        assert(p);

        if (p->new_label)
                return p->new_label;

        if (p->current_label)
                return p->current_label;

        return gpt_partition_type_uuid_to_string(p->type.uuid);
}

static int context_dump_partitions(Context *context) {
        _cleanup_(table_unrefp) Table *t = NULL;
        uint64_t sum_padding = 0, sum_size = 0;
        int r;
        const size_t roothash_col = 14, dropin_files_col = 15, split_path_col = 16;
        bool has_roothash = false, has_dropin_files = false, has_split_path = false;

        if ((arg_json_format_flags & JSON_FORMAT_OFF) && context->n_partitions == 0) {
                log_info("Empty partition table.");
                return 0;
        }

        t = table_new("type",
                      "label",
                      "uuid",
                      "partno",
                      "file",
                      "node",
                      "offset",
                      "old size",
                      "raw size",
                      "size",
                      "old padding",
                      "raw padding",
                      "padding",
                      "activity",
                      "roothash",
                      "drop-in files",
                      "split path");
        if (!t)
                return log_oom();

        if (!DEBUG_LOGGING) {
                if (arg_json_format_flags & JSON_FORMAT_OFF)
                        (void) table_set_display(t, (size_t) 0, (size_t) 1, (size_t) 2, (size_t) 3, (size_t) 4,
                                                    (size_t) 8, (size_t) 9, (size_t) 12, roothash_col, dropin_files_col,
                                                    split_path_col);
                else
                        (void) table_set_display(t, (size_t) 0, (size_t) 1, (size_t) 2, (size_t) 3, (size_t) 4,
                                                    (size_t) 5, (size_t) 6, (size_t) 7, (size_t) 8, (size_t) 10,
                                                    (size_t) 11, (size_t) 13, roothash_col, dropin_files_col,
                                                    split_path_col);
        }

        (void) table_set_align_percent(t, table_get_cell(t, 0, 5), 100);
        (void) table_set_align_percent(t, table_get_cell(t, 0, 6), 100);
        (void) table_set_align_percent(t, table_get_cell(t, 0, 7), 100);
        (void) table_set_align_percent(t, table_get_cell(t, 0, 8), 100);
        (void) table_set_align_percent(t, table_get_cell(t, 0, 9), 100);
        (void) table_set_align_percent(t, table_get_cell(t, 0, 10), 100);
        (void) table_set_align_percent(t, table_get_cell(t, 0, 11), 100);

        LIST_FOREACH(partitions, p, context->partitions) {
                _cleanup_free_ char *size_change = NULL, *padding_change = NULL, *partname = NULL, *rh = NULL;
                char uuid_buffer[SD_ID128_UUID_STRING_MAX];
                const char *label, *activity = NULL;

                if (p->dropped)
                        continue;

                if (p->current_size == UINT64_MAX)
                        activity = "create";
                else if (p->current_size != p->new_size)
                        activity = "resize";

                label = partition_label(p);
                partname = p->partno != UINT64_MAX ? fdisk_partname(context->node, p->partno+1) : NULL;

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

                if (p->verity != VERITY_OFF) {
                        Partition *hp = p->verity == VERITY_HASH ? p : p->siblings[VERITY_HASH];

                        rh = iovec_is_set(&hp->roothash) ? hexmem(hp->roothash.iov_base, hp->roothash.iov_len) : strdup("TBD");
                        if (!rh)
                                return log_oom();
                }

                r = table_add_many(
                                t,
                                TABLE_STRING, gpt_partition_type_uuid_to_string_harder(p->type.uuid, uuid_buffer),
                                TABLE_STRING, empty_to_null(label) ?: "-", TABLE_SET_COLOR, empty_to_null(label) ? NULL : ansi_grey(),
                                TABLE_UUID, p->new_uuid_is_set ? p->new_uuid : p->current_uuid,
                                TABLE_UINT64, p->partno,
                                TABLE_PATH_BASENAME, p->definition_path, TABLE_SET_COLOR, p->definition_path ? NULL : ansi_grey(),
                                TABLE_STRING, partname ?: "-", TABLE_SET_COLOR, partname ? NULL : ansi_highlight(),
                                TABLE_UINT64, p->offset,
                                TABLE_UINT64, p->current_size == UINT64_MAX ? 0 : p->current_size,
                                TABLE_UINT64, p->new_size,
                                TABLE_STRING, size_change, TABLE_SET_COLOR, !p->partitions_next && sum_size > 0 ? ansi_underline() : NULL,
                                TABLE_UINT64, p->current_padding == UINT64_MAX ? 0 : p->current_padding,
                                TABLE_UINT64, p->new_padding,
                                TABLE_STRING, padding_change, TABLE_SET_COLOR, !p->partitions_next && sum_padding > 0 ? ansi_underline() : NULL,
                                TABLE_STRING, activity ?: "unchanged",
                                TABLE_STRING, rh,
                                TABLE_STRV, p->drop_in_files,
                                TABLE_STRING, empty_to_null(p->split_path) ?: "-");
                if (r < 0)
                        return table_log_add_error(r);

                has_roothash = has_roothash || !isempty(rh);
                has_dropin_files = has_dropin_files || !strv_isempty(p->drop_in_files);
                has_split_path = has_split_path || !isempty(p->split_path);
        }

        if ((arg_json_format_flags & JSON_FORMAT_OFF) && (sum_padding > 0 || sum_size > 0)) {
                const char *a, *b;

                a = strjoina(special_glyph(SPECIAL_GLYPH_SIGMA), " = ", FORMAT_BYTES(sum_size));
                b = strjoina(special_glyph(SPECIAL_GLYPH_SIGMA), " = ", FORMAT_BYTES(sum_padding));

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
                                TABLE_EMPTY,
                                TABLE_STRING, a,
                                TABLE_EMPTY,
                                TABLE_EMPTY,
                                TABLE_STRING, b,
                                TABLE_EMPTY,
                                TABLE_EMPTY,
                                TABLE_EMPTY,
                                TABLE_EMPTY);
                if (r < 0)
                        return table_log_add_error(r);
        }

        if (!has_roothash) {
                r = table_hide_column_from_display(t, roothash_col);
                if (r < 0)
                        return log_error_errno(r, "Failed to set columns to display: %m");
        }

        if (!has_dropin_files) {
                r = table_hide_column_from_display(t, dropin_files_col);
                if (r < 0)
                        return log_error_errno(r, "Failed to set columns to display: %m");
        }

        if (!has_split_path) {
                r = table_hide_column_from_display(t, split_path_col);
                if (r < 0)
                        return log_error_errno(r, "Failed to set columns to display: %m");
        }

        return table_print_with_pager(t, arg_json_format_flags, arg_pager_flags, arg_legend);
}

static int context_bar_char_process_partition(
                Context *context,
                Partition *bar[],
                size_t n,
                Partition *p,
                size_t **start_array,
                size_t *n_start_array) {

        uint64_t from, to, total;
        size_t x, y;

        assert(context);
        assert(bar);
        assert(n > 0);
        assert(p);
        assert(start_array);
        assert(n_start_array);

        if (p->dropped)
                return 0;

        assert(p->offset != UINT64_MAX);
        assert(p->new_size != UINT64_MAX);

        from = p->offset;
        to = from + p->new_size;

        assert(context->total > 0);
        total = context->total;

        assert(from <= total);
        x = from * n / total;

        assert(to <= total);
        y = to * n / total;

        assert(x <= y);
        assert(y <= n);

        for (size_t i = x; i < y; i++)
                bar[i] = p;

        if (!GREEDY_REALLOC_APPEND(*start_array, *n_start_array, &x, 1))
                return log_oom();

        return 1;
}

static int partition_hint(const Partition *p, const char *node, char **ret) {
        _cleanup_free_ char *buf = NULL;
        const char *label;
        sd_id128_t id;

        /* Tries really hard to find a suitable description for this partition */

        if (p->definition_path)
                return path_extract_filename(p->definition_path, ret);

        label = partition_label(p);
        if (!isempty(label)) {
                buf = strdup(label);
                goto done;
        }

        if (p->partno != UINT64_MAX) {
                buf = fdisk_partname(node, p->partno+1);
                goto done;
        }

        if (p->new_uuid_is_set)
                id = p->new_uuid;
        else if (!sd_id128_is_null(p->current_uuid))
                id = p->current_uuid;
        else
                id = p->type.uuid;

        buf = strdup(SD_ID128_TO_UUID_STRING(id));

done:
        if (!buf)
                return -ENOMEM;

        *ret = TAKE_PTR(buf);
        return 0;
}

static int context_dump_partition_bar(Context *context) {
        _cleanup_free_ Partition **bar = NULL;
        _cleanup_free_ size_t *start_array = NULL;
        size_t n_start_array = 0;
        Partition *last = NULL;
        bool z = false;
        size_t c, j = 0;
        int r;

        assert_se((c = columns()) >= 2);
        c -= 2; /* We do not use the leftmost and rightmost character cell */

        bar = new0(Partition*, c);
        if (!bar)
                return log_oom();

        LIST_FOREACH(partitions, p, context->partitions) {
                r = context_bar_char_process_partition(context, bar, c, p, &start_array, &n_start_array);
                if (r < 0)
                        return r;
        }

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

        for (size_t i = 0; i < n_start_array; i++) {
                _cleanup_free_ char **line = NULL;

                line = new0(char*, c);
                if (!line)
                        return log_oom();

                j = 0;
                LIST_FOREACH(partitions, p, context->partitions) {
                        _cleanup_free_ char *d = NULL;

                        if (p->dropped)
                                continue;

                        j++;

                        if (i < n_start_array - j) {

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

                        } else if (i == n_start_array - j) {
                                _cleanup_free_ char *hint = NULL;

                                (void) partition_hint(p, context->node, &hint);

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

static bool context_has_roothash(Context *context) {
        LIST_FOREACH(partitions, p, context->partitions)
                if (iovec_is_set(&p->roothash))
                        return true;

        return false;
}

static int context_dump(Context *context, bool late) {
        int r;

        assert(context);

        if (arg_pretty == 0 && FLAGS_SET(arg_json_format_flags, JSON_FORMAT_OFF))
                return 0;

        /* If we're outputting JSON, only dump after doing all operations so we can include the roothashes
         * in the output.  */
        if (!late && !FLAGS_SET(arg_json_format_flags, JSON_FORMAT_OFF))
                return 0;

        /* If we're not outputting JSON, only dump again after doing all operations if there are any
         * roothashes that we need to communicate to the user. */
        if (late && FLAGS_SET(arg_json_format_flags, JSON_FORMAT_OFF) && !context_has_roothash(context))
                return 0;

        r = context_dump_partitions(context);
        if (r < 0)
                return r;

        /* Make sure we only write the partition bar once, even if we're writing the partition table twice to
         * communicate roothashes. */
        if (FLAGS_SET(arg_json_format_flags, JSON_FORMAT_OFF) && !late) {
                putc('\n', stdout);

                r = context_dump_partition_bar(context);
                if (r < 0)
                        return r;

                putc('\n', stdout);
        }

        fflush(stdout);

        return 0;
}


static bool context_changed(const Context *context) {
        assert(context);

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
                        return log_error_errno(errno_or_else(EIO), "Failed to probe for file systems.");
                if (r > 0)
                        break;

                errno = 0;
                if (blkid_do_wipe(probe, false) < 0)
                        return log_error_errno(errno_or_else(EIO), "Failed to wipe file system signature.");
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

                range[0] = round_up_size(offset, context->sector_size);

                if (offset > UINT64_MAX - size)
                        return -ERANGE;

                end = offset + size;
                if (end <= range[0])
                        return 0;

                range[1] = round_down_size(end - range[0], context->sector_size);
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
        int r;

        assert(context);
        assert(!p || (p->offset != UINT64_MAX && p->new_size != UINT64_MAX));

        if (!arg_discard)
                return 0;

        if (p)
                gap = p->offset + p->new_size;
        else
                /* The context start gets rounded up to grain_size, however
                 * existing partitions may be before that so ensure the gap
                 * starts at the first actually usable lba
                 */
                gap = fdisk_get_first_lba(context->fdisk_context) * context->sector_size;

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
                next = (fdisk_get_last_lba(context->fdisk_context) + 1) * context->sector_size;
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

static int context_wipe_and_discard(Context *context) {
        int r;

        assert(context);

        if (arg_empty == EMPTY_CREATE) /* If we just created the image, no need to wipe */
                return 0;

        /* Wipe and discard the contents of all partitions we are about to create. We skip the discarding if
         * we were supposed to start from scratch anyway, as in that case we just discard the whole block
         * device in one go early on. */

        LIST_FOREACH(partitions, p, context->partitions) {

                if (!p->allocated_to_area)
                        continue;

                if (partition_type_defer(&p->type))
                        continue;

                r = context_wipe_partition(context, p);
                if (r < 0)
                        return r;

                if (!context->from_scratch) {
                        r = context_discard_partition(context, p);
                        if (r < 0)
                                return r;

                        r = context_discard_gap_after(context, p);
                        if (r < 0)
                                return r;
                }
        }

        if (!context->from_scratch) {
                r = context_discard_gap_after(context, NULL);
                if (r < 0)
                        return r;
        }

        return 0;
}

typedef struct DecryptedPartitionTarget {
        int fd;
        char *dm_name;
        char *volume;
        struct crypt_device *device;
} DecryptedPartitionTarget;

static DecryptedPartitionTarget* decrypted_partition_target_free(DecryptedPartitionTarget *t) {
#if HAVE_LIBCRYPTSETUP
        int r;

        if (!t)
                return NULL;

        safe_close(t->fd);

        /* udev or so might access out block device in the background while we are done. Let's hence
         * force detach the volume. We sync'ed before, hence this should be safe. */
        r = sym_crypt_deactivate_by_name(t->device, t->dm_name, CRYPT_DEACTIVATE_FORCE);
        if (r < 0)
                log_warning_errno(r, "Failed to deactivate LUKS device, ignoring: %m");

        sym_crypt_free(t->device);
        free(t->dm_name);
        free(t->volume);
        free(t);
#endif
        return NULL;
}

typedef struct {
        LoopDevice *loop;
        int fd;
        char *path;
        int whole_fd;
        DecryptedPartitionTarget *decrypted;
} PartitionTarget;

static int partition_target_fd(PartitionTarget *t) {
        assert(t);
        assert(t->loop || t->fd >= 0 || t->whole_fd >= 0);

        if (t->decrypted)
                return t->decrypted->fd;

        if (t->loop)
                return t->loop->fd;

        if (t->fd >= 0)
                return t->fd;

        return t->whole_fd;
}

static const char* partition_target_path(PartitionTarget *t) {
        assert(t);
        assert(t->loop || t->path);

        if (t->decrypted)
                return t->decrypted->volume;

        if (t->loop)
                return t->loop->node;

        return t->path;
}

static PartitionTarget *partition_target_free(PartitionTarget *t) {
        if (!t)
                return NULL;

        decrypted_partition_target_free(t->decrypted);
        loop_device_unref(t->loop);
        safe_close(t->fd);
        unlink_and_free(t->path);

        return mfree(t);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(PartitionTarget*, partition_target_free);

static int prepare_temporary_file(PartitionTarget *t, uint64_t size) {
        _cleanup_(unlink_and_freep) char *temp = NULL;
        _cleanup_close_ int fd = -EBADF;
        const char *vt;
        int r;

        assert(t);

        r = var_tmp_dir(&vt);
        if (r < 0)
                return log_error_errno(r, "Could not determine temporary directory: %m");

        temp = path_join(vt, "repart-XXXXXX");
        if (!temp)
                return log_oom();

        fd = mkostemp_safe(temp);
        if (fd < 0)
                return log_error_errno(fd, "Failed to create temporary file: %m");

        if (ftruncate(fd, size) < 0)
                return log_error_errno(errno, "Failed to truncate temporary file to %s: %m",
                                       FORMAT_BYTES(size));

        t->fd = TAKE_FD(fd);
        t->path = TAKE_PTR(temp);

        return 0;
}

static int partition_target_prepare(
                Context *context,
                Partition *p,
                uint64_t size,
                bool need_path,
                PartitionTarget **ret) {

        _cleanup_(partition_target_freep) PartitionTarget *t = NULL;
        _cleanup_(loop_device_unrefp) LoopDevice *d = NULL;
        int whole_fd, r;

        assert(context);
        assert(p);
        assert(ret);

        assert_se((whole_fd = fdisk_get_devfd(context->fdisk_context)) >= 0);

        t = new(PartitionTarget, 1);
        if (!t)
                return log_oom();
        *t = (PartitionTarget) {
                .fd = -EBADF,
                .whole_fd = -EBADF,
        };

        if (!need_path) {
                if (lseek(whole_fd, p->offset, SEEK_SET) < 0)
                        return log_error_errno(errno, "Failed to seek to partition offset: %m");

                t->whole_fd = whole_fd;
                *ret = TAKE_PTR(t);
                return 0;
        }

        /* Loopback block devices are not only useful to turn regular files into block devices, but
         * also to cut out sections of block devices into new block devices. */

        if (arg_offline <= 0) {
                r = loop_device_make(whole_fd, O_RDWR, p->offset, size, context->sector_size, 0, LOCK_EX, &d);
                if (r < 0 && (arg_offline == 0 || (r != -ENOENT && !ERRNO_IS_PRIVILEGE(r)) || !strv_isempty(p->subvolumes)))
                        return log_error_errno(r, "Failed to make loopback device of future partition %" PRIu64 ": %m", p->partno);
                if (r >= 0) {
                        t->loop = TAKE_PTR(d);
                        *ret = TAKE_PTR(t);
                        return 0;
                }

                log_debug_errno(r, "No access to loop devices, falling back to a regular file");
        }

        /* If we can't allocate a loop device, let's write to a regular file that we copy into the final
         * image so we can run in containers and without needing root privileges. On filesystems with
         * reflinking support, we can take advantage of this and just reflink the result into the image.
         */

        r = prepare_temporary_file(t, size);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(t);

        return 0;
}

static int partition_target_grow(PartitionTarget *t, uint64_t size) {
        int r;

        assert(t);
        assert(!t->decrypted);

        if (t->loop) {
                r = loop_device_refresh_size(t->loop, UINT64_MAX, size);
                if (r < 0)
                        return log_error_errno(r, "Failed to refresh loopback device size: %m");
        } else if (t->fd >= 0) {
                if (ftruncate(t->fd, size) < 0)
                        return log_error_errno(errno, "Failed to grow '%s' to %s by truncation: %m",
                                               t->path, FORMAT_BYTES(size));
        }

        return 0;
}

static int partition_target_sync(Context *context, Partition *p, PartitionTarget *t) {
        int whole_fd, r;

        assert(context);
        assert(p);
        assert(t);

        assert_se((whole_fd = fdisk_get_devfd(context->fdisk_context)) >= 0);

        if (t->decrypted && fsync(t->decrypted->fd) < 0)
                return log_error_errno(errno, "Failed to sync changes to '%s': %m", t->decrypted->volume);

        if (t->loop) {
                r = loop_device_sync(t->loop);
                if (r < 0)
                        return log_error_errno(r, "Failed to sync loopback device: %m");
        } else if (t->fd >= 0) {
                struct stat st;

                if (lseek(whole_fd, p->offset, SEEK_SET) < 0)
                        return log_error_errno(errno, "Failed to seek to partition offset: %m");

                if (lseek(t->fd, 0, SEEK_SET) < 0)
                        return log_error_errno(errno, "Failed to seek to start of temporary file: %m");

                if (fstat(t->fd, &st) < 0)
                        return log_error_errno(errno, "Failed to stat temporary file: %m");

                if (st.st_size > (off_t) p->new_size)
                        return log_error_errno(SYNTHETIC_ERRNO(ENOSPC),
                                               "Partition %" PRIu64 "'s contents (%s) don't fit in the partition (%s)",
                                               p->partno, FORMAT_BYTES(st.st_size), FORMAT_BYTES(p->new_size));

                r = copy_bytes(t->fd, whole_fd, UINT64_MAX, COPY_REFLINK|COPY_HOLES|COPY_FSYNC);
                if (r < 0)
                        return log_error_errno(r, "Failed to copy bytes to partition: %m");
        } else {
                if (fsync(t->whole_fd) < 0)
                        return log_error_errno(errno, "Failed to sync changes: %m");
        }

        return 0;
}

static int partition_encrypt(Context *context, Partition *p, PartitionTarget *target, bool offline) {
#if HAVE_LIBCRYPTSETUP && HAVE_CRYPT_SET_DATA_OFFSET && HAVE_CRYPT_REENCRYPT_INIT_BY_PASSPHRASE && HAVE_CRYPT_REENCRYPT
        const char *node = partition_target_path(target);
        struct crypt_params_luks2 luks_params = {
                .label = strempty(ASSERT_PTR(p)->new_label),
                .sector_size = ASSERT_PTR(context)->fs_sector_size,
                .data_device = offline ? node : NULL,
        };
        struct crypt_params_reencrypt reencrypt_params = {
                .mode = CRYPT_REENCRYPT_ENCRYPT,
                .direction = CRYPT_REENCRYPT_BACKWARD,
                .resilience = "datashift",
                .data_shift = LUKS2_METADATA_SIZE / 512,
                .luks2 = &luks_params,
                .flags = CRYPT_REENCRYPT_INITIALIZE_ONLY|CRYPT_REENCRYPT_MOVE_FIRST_SEGMENT,
        };
        _cleanup_(sym_crypt_freep) struct crypt_device *cd = NULL;
        _cleanup_(erase_and_freep) char *base64_encoded = NULL;
        _cleanup_fclose_ FILE *h = NULL;
        _cleanup_free_ char *hp = NULL, *vol = NULL, *dm_name = NULL;
        const char *passphrase = NULL;
        size_t passphrase_size = 0;
        const char *vt;
        int r;

        assert(context);
        assert(p);
        assert(p->encrypt != ENCRYPT_OFF);

        r = dlopen_cryptsetup();
        if (r < 0)
                return log_error_errno(r, "libcryptsetup not found, cannot encrypt: %m");

        log_info("Encrypting future partition %" PRIu64 "...", p->partno);

        if (offline) {
                r = var_tmp_dir(&vt);
                if (r < 0)
                        return log_error_errno(r, "Failed to determine temporary files directory: %m");

                r = fopen_temporary_child(vt, &h, &hp);
                if (r < 0)
                        return log_error_errno(r, "Failed to create temporary LUKS header file: %m");

                /* Weird cryptsetup requirement which requires the header file to be the size of at least one
                 * sector. */
                if (ftruncate(fileno(h), luks_params.sector_size) < 0)
                        return log_error_errno(errno, "Failed to grow temporary LUKS header file: %m");
        } else {
                if (asprintf(&dm_name, "luks-repart-%08" PRIx64, random_u64()) < 0)
                        return log_oom();

                vol = path_join("/dev/mapper/", dm_name);
                if (!vol)
                        return log_oom();
        }

        r = sym_crypt_init(&cd, offline ? hp : node);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate libcryptsetup context for %s: %m", hp);

        cryptsetup_enable_logging(cd);

        if (offline) {
                /* Disable kernel keyring usage by libcryptsetup as a workaround for
                 * https://gitlab.com/cryptsetup/cryptsetup/-/merge_requests/273. This makes sure that we can
                 * do offline encryption even when repart is running in a container. */
                r = sym_crypt_volume_key_keyring(cd, false);
                if (r < 0)
                        return log_error_errno(r, "Failed to disable kernel keyring: %m");

                r = sym_crypt_metadata_locking(cd, false);
                if (r < 0)
                        return log_error_errno(r, "Failed to disable metadata locking: %m");

                r = sym_crypt_set_data_offset(cd, LUKS2_METADATA_SIZE / 512);
                if (r < 0)
                        return log_error_errno(r, "Failed to set data offset: %m");
        }

        r = sym_crypt_format(
                        cd,
                        CRYPT_LUKS2,
                        "aes",
                        "xts-plain64",
                        SD_ID128_TO_UUID_STRING(p->luks_uuid),
                        NULL,
                        VOLUME_KEY_SIZE,
                        &luks_params);
        if (r < 0)
                return log_error_errno(r, "Failed to LUKS2 format future partition: %m");

        if (IN_SET(p->encrypt, ENCRYPT_KEY_FILE, ENCRYPT_KEY_FILE_TPM2)) {
                r = sym_crypt_keyslot_add_by_volume_key(
                                cd,
                                CRYPT_ANY_SLOT,
                                NULL,
                                VOLUME_KEY_SIZE,
                                strempty(arg_key),
                                arg_key_size);
                if (r < 0)
                        return log_error_errno(r, "Failed to add LUKS2 key: %m");

                passphrase = strempty(arg_key);
                passphrase_size = arg_key_size;
        }

        if (IN_SET(p->encrypt, ENCRYPT_TPM2, ENCRYPT_KEY_FILE_TPM2)) {
#if HAVE_TPM2
                _cleanup_(iovec_done) struct iovec pubkey = {}, blob = {}, srk = {};
                _cleanup_(iovec_done_erase) struct iovec secret = {};
                _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
                ssize_t base64_encoded_size;
                int keyslot;
                TPM2Flags flags = 0;

                if (arg_tpm2_public_key_pcr_mask != 0) {
                        r = tpm2_load_pcr_public_key(arg_tpm2_public_key, &pubkey.iov_base, &pubkey.iov_len);
                        if (r < 0) {
                                if (arg_tpm2_public_key || r != -ENOENT)
                                        return log_error_errno(r, "Failed to read TPM PCR public key: %m");

                                log_debug_errno(r, "Failed to read TPM2 PCR public key, proceeding without: %m");
                                arg_tpm2_public_key_pcr_mask = 0;
                        }
                }

                TPM2B_PUBLIC public;
                if (iovec_is_set(&pubkey)) {
                        r = tpm2_tpm2b_public_from_pem(pubkey.iov_base, pubkey.iov_len, &public);
                        if (r < 0)
                                return log_error_errno(r, "Could not convert public key to TPM2B_PUBLIC: %m");
                }

                _cleanup_(tpm2_pcrlock_policy_done) Tpm2PCRLockPolicy pcrlock_policy = {};
                if (arg_tpm2_pcrlock) {
                        r = tpm2_pcrlock_policy_load(arg_tpm2_pcrlock, &pcrlock_policy);
                        if (r < 0)
                                return r;

                        flags |= TPM2_FLAGS_USE_PCRLOCK;
                }

                _cleanup_(tpm2_context_unrefp) Tpm2Context *tpm2_context = NULL;
                TPM2B_PUBLIC device_key_public = {};
                if (arg_tpm2_device_key) {
                        r = tpm2_load_public_key_file(arg_tpm2_device_key, &device_key_public);
                        if (r < 0)
                                return r;

                        if (!tpm2_pcr_values_has_all_values(arg_tpm2_hash_pcr_values, arg_tpm2_n_hash_pcr_values))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Must provide all PCR values when using TPM2 device key.");
                } else {
                        r = tpm2_context_new(arg_tpm2_device, &tpm2_context);
                        if (r < 0)
                                return log_error_errno(r, "Failed to create TPM2 context: %m");

                        if (!tpm2_pcr_values_has_all_values(arg_tpm2_hash_pcr_values, arg_tpm2_n_hash_pcr_values)) {
                                r = tpm2_pcr_read_missing_values(tpm2_context, arg_tpm2_hash_pcr_values, arg_tpm2_n_hash_pcr_values);
                                if (r < 0)
                                        return log_error_errno(r, "Could not read pcr values: %m");
                        }
                }

                uint16_t hash_pcr_bank = 0;
                uint32_t hash_pcr_mask = 0;
                if (arg_tpm2_n_hash_pcr_values > 0) {
                        size_t hash_count;
                        r = tpm2_pcr_values_hash_count(arg_tpm2_hash_pcr_values, arg_tpm2_n_hash_pcr_values, &hash_count);
                        if (r < 0)
                                return log_error_errno(r, "Could not get hash count: %m");

                        if (hash_count > 1)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Multiple PCR banks selected.");

                        hash_pcr_bank = arg_tpm2_hash_pcr_values[0].hash;
                        r = tpm2_pcr_values_to_mask(arg_tpm2_hash_pcr_values, arg_tpm2_n_hash_pcr_values, hash_pcr_bank, &hash_pcr_mask);
                        if (r < 0)
                                return log_error_errno(r, "Could not get hash mask: %m");
                }

                TPM2B_DIGEST policy = TPM2B_DIGEST_MAKE(NULL, TPM2_SHA256_DIGEST_SIZE);
                r = tpm2_calculate_sealing_policy(
                                arg_tpm2_hash_pcr_values,
                                arg_tpm2_n_hash_pcr_values,
                                iovec_is_set(&pubkey) ? &public : NULL,
                                /* use_pin= */ false,
                                arg_tpm2_pcrlock ? &pcrlock_policy : NULL,
                                &policy);
                if (r < 0)
                        return log_error_errno(r, "Could not calculate sealing policy digest: %m");

                if (arg_tpm2_device_key)
                        r = tpm2_calculate_seal(
                                        arg_tpm2_seal_key_handle,
                                        &device_key_public,
                                        /* attributes= */ NULL,
                                        /* secret= */ NULL,
                                        &policy,
                                        /* pin= */ NULL,
                                        &secret,
                                        &blob,
                                        &srk);
                else
                        r = tpm2_seal(tpm2_context,
                                      arg_tpm2_seal_key_handle,
                                      &policy,
                                      /* pin= */ NULL,
                                      &secret,
                                      &blob,
                                      /* ret_primary_alg= */ NULL,
                                      &srk);
                if (r < 0)
                        return log_error_errno(r, "Failed to seal to TPM2: %m");

                base64_encoded_size = base64mem(secret.iov_base, secret.iov_len, &base64_encoded);
                if (base64_encoded_size < 0)
                        return log_error_errno(base64_encoded_size, "Failed to base64 encode secret key: %m");

                r = cryptsetup_set_minimal_pbkdf(cd);
                if (r < 0)
                        return log_error_errno(r, "Failed to set minimal PBKDF: %m");

                keyslot = sym_crypt_keyslot_add_by_volume_key(
                                cd,
                                CRYPT_ANY_SLOT,
                                /* volume_key= */ NULL,
                                /* volume_key_size= */ VOLUME_KEY_SIZE,
                                base64_encoded,
                                base64_encoded_size);
                if (keyslot < 0)
                        return log_error_errno(keyslot, "Failed to add new TPM2 key: %m");

                r = tpm2_make_luks2_json(
                                keyslot,
                                hash_pcr_mask,
                                hash_pcr_bank,
                                &pubkey,
                                arg_tpm2_public_key_pcr_mask,
                                /* primary_alg= */ 0,
                                &blob,
                                &IOVEC_MAKE(policy.buffer, policy.size),
                                /* salt= */ NULL, /* no salt because tpm2_seal has no pin */
                                &srk,
                                flags,
                                &v);
                if (r < 0)
                        return log_error_errno(r, "Failed to prepare TPM2 JSON token object: %m");

                r = cryptsetup_add_token_json(cd, v);
                if (r < 0)
                        return log_error_errno(r, "Failed to add TPM2 JSON token to LUKS2 header: %m");

                passphrase = base64_encoded;
                passphrase_size = strlen(base64_encoded);
#else
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                       "Support for TPM2 enrollment not enabled.");
#endif
        }

        if (offline) {
                r = sym_crypt_reencrypt_init_by_passphrase(
                                cd,
                                NULL,
                                passphrase,
                                passphrase_size,
                                CRYPT_ANY_SLOT,
                                0,
                                sym_crypt_get_cipher(cd),
                                sym_crypt_get_cipher_mode(cd),
                                &reencrypt_params);
                if (r < 0)
                        return log_error_errno(r, "Failed to prepare for reencryption: %m");

                /* crypt_reencrypt_init_by_passphrase() doesn't actually put the LUKS header at the front, we
                 * have to do that ourselves. */

                sym_crypt_free(cd);
                cd = NULL;

                r = sym_crypt_init(&cd, node);
                if (r < 0)
                        return log_error_errno(r, "Failed to allocate libcryptsetup context for %s: %m", node);

                r = sym_crypt_header_restore(cd, CRYPT_LUKS2, hp);
                if (r < 0)
                        return log_error_errno(r, "Failed to place new LUKS header at head of %s: %m", node);

                reencrypt_params.flags &= ~CRYPT_REENCRYPT_INITIALIZE_ONLY;

                r = sym_crypt_reencrypt_init_by_passphrase(
                                cd,
                                NULL,
                                passphrase,
                                passphrase_size,
                                CRYPT_ANY_SLOT,
                                0,
                                NULL,
                                NULL,
                                &reencrypt_params);
                if (r < 0)
                        return log_error_errno(r, "Failed to load reencryption context: %m");

                r = sym_crypt_reencrypt(cd, NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to encrypt %s: %m", node);
        } else {
                _cleanup_free_ DecryptedPartitionTarget *t = NULL;
                _cleanup_close_ int dev_fd = -1;

                r = sym_crypt_activate_by_volume_key(
                                cd,
                                dm_name,
                                NULL,
                                VOLUME_KEY_SIZE,
                                arg_discard ? CRYPT_ACTIVATE_ALLOW_DISCARDS : 0);
                if (r < 0)
                        return log_error_errno(r, "Failed to activate LUKS superblock: %m");

                dev_fd = open(vol, O_RDWR|O_CLOEXEC|O_NOCTTY);
                if (dev_fd < 0)
                        return log_error_errno(errno, "Failed to open LUKS volume '%s': %m", vol);

                if (flock(dev_fd, LOCK_EX) < 0)
                        return log_error_errno(errno, "Failed to lock '%s': %m", vol);

                t = new(DecryptedPartitionTarget, 1);
                if (!t)
                        return log_oom();

                *t = (DecryptedPartitionTarget) {
                        .fd = TAKE_FD(dev_fd),
                        .dm_name = TAKE_PTR(dm_name),
                        .volume = TAKE_PTR(vol),
                        .device = TAKE_PTR(cd),
                };

                target->decrypted = TAKE_PTR(t);
        }

        log_info("Successfully encrypted future partition %" PRIu64 ".", p->partno);

        return 0;
#else
        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                               "libcryptsetup is not supported or is missing required symbols, cannot encrypt: %m");
#endif
}

static int partition_format_verity_hash(
                Context *context,
                Partition *p,
                const char *node,
                const char *data_node) {

#if HAVE_LIBCRYPTSETUP
        Partition *dp;
        _cleanup_(partition_target_freep) PartitionTarget *t = NULL;
        _cleanup_(sym_crypt_freep) struct crypt_device *cd = NULL;
        _cleanup_free_ char *hint = NULL;
        int r;

        assert(context);
        assert(p);
        assert(p->verity == VERITY_HASH);
        assert(data_node);

        if (p->dropped)
                return 0;

        if (PARTITION_EXISTS(p)) /* Never format existing partitions */
                return 0;

        /* Minimized partitions will use the copy blocks logic so let's make sure to skip those here. */
        if (p->copy_blocks_fd >= 0)
                return 0;

        assert_se(dp = p->siblings[VERITY_DATA]);
        assert(!dp->dropped);

        (void) partition_hint(p, node, &hint);

        r = dlopen_cryptsetup();
        if (r < 0)
                return log_error_errno(r, "libcryptsetup not found, cannot setup verity: %m");

        if (!node) {
                r = partition_target_prepare(context, p, p->new_size, /*need_path=*/ true, &t);
                if (r < 0)
                        return r;

                node = partition_target_path(t);
        }

        if (p->verity_data_block_size == UINT64_MAX)
                p->verity_data_block_size = context->fs_sector_size;
        if (p->verity_hash_block_size == UINT64_MAX)
                p->verity_hash_block_size = context->fs_sector_size;

        r = sym_crypt_init(&cd, node);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate libcryptsetup context for %s: %m", node);

        cryptsetup_enable_logging(cd);

        r = sym_crypt_format(
                        cd, CRYPT_VERITY, NULL, NULL, SD_ID128_TO_UUID_STRING(p->verity_uuid), NULL, 0,
                        &(struct crypt_params_verity){
                                .data_device = data_node,
                                .flags = CRYPT_VERITY_CREATE_HASH,
                                .hash_name = "sha256",
                                .hash_type = 1,
                                .data_block_size = p->verity_data_block_size,
                                .hash_block_size = p->verity_hash_block_size,
                                .salt_size = sizeof(p->verity_salt),
                                .salt = (const char*)p->verity_salt,
                        });
        if (r < 0) {
                /* libcryptsetup reports non-descriptive EIO errors for every I/O failure. Luckily, it
                 * doesn't clobber errno so let's check for ENOSPC so we can report a better error if the
                 * partition is too small. */
                if (r == -EIO && errno == ENOSPC)
                        return log_error_errno(errno,
                                               "Verity hash data does not fit in partition %s with size %s",
                                               strna(hint), FORMAT_BYTES(p->new_size));

                return log_error_errno(r, "Failed to setup verity hash data of partition %s: %m", strna(hint));
        }

        if (t) {
                r = partition_target_sync(context, p, t);
                if (r < 0)
                        return r;
        }

        r = sym_crypt_get_volume_key_size(cd);
        if (r < 0)
                return log_error_errno(r, "Failed to determine verity root hash size of partition %s: %m", strna(hint));

        _cleanup_(iovec_done) struct iovec rh = {
                .iov_base = malloc(r),
                .iov_len = r,
        };
        if (!rh.iov_base)
                return log_oom();

        r = sym_crypt_volume_key_get(cd, CRYPT_ANY_SLOT, (char *) rh.iov_base, &rh.iov_len, NULL, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to get verity root hash of partition %s: %m", strna(hint));

        assert(rh.iov_len >= sizeof(sd_id128_t) * 2);

        if (!dp->new_uuid_is_set) {
                memcpy_safe(dp->new_uuid.bytes, rh.iov_base, sizeof(sd_id128_t));
                dp->new_uuid_is_set = true;
        }

        if (!p->new_uuid_is_set) {
                memcpy_safe(p->new_uuid.bytes, (uint8_t*) rh.iov_base + (rh.iov_len - sizeof(sd_id128_t)), sizeof(sd_id128_t));
                p->new_uuid_is_set = true;
        }

        p->roothash = TAKE_STRUCT(rh);

        return 0;
#else
        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "libcryptsetup is not supported, cannot setup verity hashes: %m");
#endif
}

static int sign_verity_roothash(
                const struct iovec *roothash,
                struct iovec *ret_signature) {

#if HAVE_OPENSSL
        _cleanup_(BIO_freep) BIO *rb = NULL;
        _cleanup_(PKCS7_freep) PKCS7 *p7 = NULL;
        _cleanup_free_ char *hex = NULL;
        _cleanup_free_ uint8_t *sig = NULL;
        int sigsz;

        assert(roothash);
        assert(iovec_is_set(roothash));
        assert(ret_signature);

        hex = hexmem(roothash->iov_base, roothash->iov_len);
        if (!hex)
                return log_oom();

        rb = BIO_new_mem_buf(hex, -1);
        if (!rb)
                return log_oom();

        p7 = PKCS7_sign(arg_certificate, arg_private_key, NULL, rb, PKCS7_DETACHED|PKCS7_NOATTR|PKCS7_BINARY);
        if (!p7)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to calculate PKCS7 signature: %s",
                                       ERR_error_string(ERR_get_error(), NULL));

        sigsz = i2d_PKCS7(p7, &sig);
        if (sigsz < 0)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to convert PKCS7 signature to DER: %s",
                                       ERR_error_string(ERR_get_error(), NULL));

        *ret_signature = IOVEC_MAKE(TAKE_PTR(sig), sigsz);

        return 0;
#else
        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "OpenSSL is not supported, cannot setup verity signature: %m");
#endif
}

static int partition_format_verity_sig(Context *context, Partition *p) {
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        _cleanup_(iovec_done) struct iovec sig = {};
        _cleanup_free_ char *text = NULL, *hint = NULL;
        Partition *hp;
        uint8_t fp[X509_FINGERPRINT_SIZE];
        int whole_fd, r;

        assert(p->verity == VERITY_SIG);

        if (p->dropped)
                return 0;

        if (PARTITION_EXISTS(p))
                return 0;

        (void) partition_hint(p, context->node, &hint);

        assert_se(hp = p->siblings[VERITY_HASH]);
        assert(!hp->dropped);

        assert(arg_certificate);

        assert_se((whole_fd = fdisk_get_devfd(context->fdisk_context)) >= 0);

        r = sign_verity_roothash(&hp->roothash, &sig);
        if (r < 0)
                return r;

        r = x509_fingerprint(arg_certificate, fp);
        if (r < 0)
                return log_error_errno(r, "Unable to calculate X509 certificate fingerprint: %m");

        r = json_build(&v,
                        JSON_BUILD_OBJECT(
                                JSON_BUILD_PAIR("rootHash", JSON_BUILD_HEX(hp->roothash.iov_base, hp->roothash.iov_len)),
                                JSON_BUILD_PAIR(
                                        "certificateFingerprint",
                                        JSON_BUILD_HEX(fp, sizeof(fp))
                                ),
                                JSON_BUILD_PAIR("signature", JSON_BUILD_IOVEC_BASE64(&sig))
                        )
        );
        if (r < 0)
                return log_error_errno(r, "Failed to build verity signature JSON object: %m");

        r = json_variant_format(v, 0, &text);
        if (r < 0)
                return log_error_errno(r, "Failed to format verity signature JSON object: %m");

        if (strlen(text)+1 > p->new_size)
                return log_error_errno(SYNTHETIC_ERRNO(E2BIG), "Verity signature too long for partition: %m");

        r = strgrowpad0(&text, p->new_size);
        if (r < 0)
                return log_error_errno(r, "Failed to pad string to %s", FORMAT_BYTES(p->new_size));

        if (lseek(whole_fd, p->offset, SEEK_SET) < 0)
                return log_error_errno(errno, "Failed to seek to partition %s offset: %m", strna(hint));

        r = loop_write(whole_fd, text, p->new_size);
        if (r < 0)
                return log_error_errno(r, "Failed to write verity signature to partition %s: %m", strna(hint));

        if (fsync(whole_fd) < 0)
                return log_error_errno(errno, "Failed to synchronize partition %s: %m", strna(hint));

        return 0;
}

static int context_copy_blocks(Context *context) {
        int r;

        assert(context);

        /* Copy in file systems on the block level */

        LIST_FOREACH(partitions, p, context->partitions) {
                _cleanup_(partition_target_freep) PartitionTarget *t = NULL;

                if (p->copy_blocks_fd < 0)
                        continue;

                if (p->dropped)
                        continue;

                if (PARTITION_EXISTS(p)) /* Never copy over existing partitions */
                        continue;

                if (partition_type_defer(&p->type))
                        continue;

                assert(p->new_size != UINT64_MAX);
                assert(p->copy_blocks_size != UINT64_MAX);
                assert(p->new_size >= p->copy_blocks_size + (p->encrypt != ENCRYPT_OFF ? LUKS2_METADATA_KEEP_FREE : 0));

                usec_t start_timestamp = now(CLOCK_MONOTONIC);

                r = partition_target_prepare(context, p, p->new_size,
                                             /*need_path=*/ p->encrypt != ENCRYPT_OFF || p->siblings[VERITY_HASH],
                                             &t);
                if (r < 0)
                        return r;

                if (p->encrypt != ENCRYPT_OFF && t->loop) {
                        r = partition_encrypt(context, p, t, /* offline = */ false);
                        if (r < 0)
                                return r;
                }

                if (p->copy_blocks_offset == UINT64_MAX)
                        log_info("Copying in '%s' (%s) on block level into future partition %" PRIu64 ".",
                                 p->copy_blocks_path, FORMAT_BYTES(p->copy_blocks_size), p->partno);
                else {
                        log_info("Copying in '%s' @ %" PRIu64 " (%s) on block level into future partition %" PRIu64 ".",
                                 p->copy_blocks_path, p->copy_blocks_offset, FORMAT_BYTES(p->copy_blocks_size), p->partno);

                        if (lseek(p->copy_blocks_fd, p->copy_blocks_offset, SEEK_SET) < 0)
                                return log_error_errno(errno, "Failed to seek to copy blocks offset in %s: %m", p->copy_blocks_path);
                }

                r = copy_bytes(p->copy_blocks_fd, partition_target_fd(t), p->copy_blocks_size, COPY_REFLINK);
                if (r < 0)
                        return log_error_errno(r, "Failed to copy in data from '%s': %m", p->copy_blocks_path);

                log_info("Copying in of '%s' on block level completed.", p->copy_blocks_path);

                if (p->encrypt != ENCRYPT_OFF && !t->loop) {
                        r = partition_encrypt(context, p, t, /* offline = */ true);
                        if (r < 0)
                                return r;
                }

                r = partition_target_sync(context, p, t);
                if (r < 0)
                        return r;

                usec_t time_spent = usec_sub_unsigned(now(CLOCK_MONOTONIC), start_timestamp);
                if (time_spent > 250 * USEC_PER_MSEC) /* Show throughput, but not if we spent too little time on it, since it's just noise then */
                        log_info("Block level copying and synchronization of partition %" PRIu64 " complete in %s (%s/s).",
                                 p->partno, FORMAT_TIMESPAN(time_spent, 0), FORMAT_BYTES((uint64_t) ((double) p->copy_blocks_size / time_spent * USEC_PER_SEC)));
                else
                        log_info("Block level copying and synchronization of partition %" PRIu64 " complete in %s.",
                                 p->partno, FORMAT_TIMESPAN(time_spent, 0));

                if (p->siblings[VERITY_HASH] && !partition_type_defer(&p->siblings[VERITY_HASH]->type)) {
                        r = partition_format_verity_hash(context, p->siblings[VERITY_HASH],
                                                         /* node = */ NULL, partition_target_path(t));
                        if (r < 0)
                                return r;
                }

                if (p->siblings[VERITY_SIG] && !partition_type_defer(&p->siblings[VERITY_SIG]->type)) {
                        r = partition_format_verity_sig(context, p->siblings[VERITY_SIG]);
                        if (r < 0)
                                return r;
                }
        }

        return 0;
}

static int add_exclude_path(const char *path, Hashmap **denylist, DenyType type) {
        _cleanup_free_ struct stat *st = NULL;
        int r;

        assert(path);
        assert(denylist);

        st = new(struct stat, 1);
        if (!st)
                return log_oom();

        r = chase_and_stat(path, arg_copy_source, CHASE_PREFIX_ROOT, NULL, st);
        if (r == -ENOENT)
                return 0;
        if (r < 0)
                return log_error_errno(r, "Failed to stat source file '%s/%s': %m", strempty(arg_copy_source), path);

        r = hashmap_ensure_put(denylist, &inode_hash_ops, st, INT_TO_PTR(type));
        if (r == -EEXIST)
                return 0;
        if (r < 0)
                return log_oom();
        if (r > 0)
                TAKE_PTR(st);

        return 0;
}

static int make_copy_files_denylist(
                Context *context,
                const Partition *p,
                const char *source,
                const char *target,
                Hashmap **ret) {

        _cleanup_hashmap_free_ Hashmap *denylist = NULL;
        int r;

        assert(context);
        assert(p);
        assert(source);
        assert(target);
        assert(ret);

        /* Always exclude the top level APIVFS and temporary directories since the contents of these
         * directories are almost certainly not intended to end up in an image. */

        NULSTR_FOREACH(s, APIVFS_TMP_DIRS_NULSTR) {
                r = add_exclude_path(s, &denylist, DENY_CONTENTS);
                if (r < 0)
                        return r;
        }

        /* Add the user configured excludes. */

        STRV_FOREACH(e, p->exclude_files_source) {
                r = add_exclude_path(*e, &denylist, endswith(*e, "/") ? DENY_CONTENTS : DENY_INODE);
                if (r < 0)
                        return r;
        }

        STRV_FOREACH(e, p->exclude_files_target) {
                _cleanup_free_ char *path = NULL;

                const char *s = path_startswith(*e, target);
                if (!s)
                        continue;

                path = path_join(source, s);
                if (!path)
                        return log_oom();

                r = add_exclude_path(path, &denylist, endswith(*e, "/") ? DENY_CONTENTS : DENY_INODE);
                if (r < 0)
                        return r;
        }

        /* If we're populating a root partition, we don't want any files to end up under the APIVFS mount
         * points. While we already exclude <source>/proc, users could still do something such as
         * "CopyFiles=/abc:/". Now, if /abc has a proc subdirectory with files in it, those will end up in
         * the top level proc directory in the root partition, which we want to avoid. To deal with these
         * cases, whenever we're populating a root partition and the target of CopyFiles= is the root
         * directory of the root partition, we exclude all directories under the source that are named after
         * APIVFS directories or named after mount points of other partitions that are also going to be part
         * of the image. */

        if (p->type.designator == PARTITION_ROOT && empty_or_root(target)) {
                LIST_FOREACH(partitions, q, context->partitions) {
                        if (q->type.designator == PARTITION_ROOT)
                                continue;

                        const char *sources = gpt_partition_type_mountpoint_nulstr(q->type);
                        if (!sources)
                                continue;

                        NULSTR_FOREACH(s, sources) {
                                _cleanup_free_ char *path = NULL;

                                /* Exclude only the children of partition mount points so that the nested
                                 * partition mount point itself still ends up in the upper partition. */

                                path = path_join(source, s);
                                if (!path)
                                        return -ENOMEM;

                                r = add_exclude_path(path, &denylist, DENY_CONTENTS);
                                if (r < 0)
                                        return r;
                        }
                }

                NULSTR_FOREACH(s, APIVFS_TMP_DIRS_NULSTR) {
                        _cleanup_free_ char *path = NULL;

                        path = path_join(source, s);
                        if (!path)
                                return -ENOMEM;

                        r = add_exclude_path(path, &denylist, DENY_CONTENTS);
                        if (r < 0)
                                return r;
                }
        }

        *ret = TAKE_PTR(denylist);
        return 0;
}

static int add_subvolume_path(const char *path, Set **subvolumes) {
        _cleanup_free_ struct stat *st = NULL;
        int r;

        assert(path);
        assert(subvolumes);

        st = new(struct stat, 1);
        if (!st)
                return log_oom();

        r = chase_and_stat(path, arg_copy_source, CHASE_PREFIX_ROOT, NULL, st);
        if (r == -ENOENT)
                return 0;
        if (r < 0)
                return log_error_errno(r, "Failed to stat source file '%s/%s': %m", strempty(arg_copy_source), path);

        r = set_ensure_consume(subvolumes, &inode_hash_ops, TAKE_PTR(st));
        if (r < 0)
                return log_oom();

        return 0;
}

static int make_subvolumes_set(
                Context *context,
                const Partition *p,
                const char *source,
                const char *target,
                Set **ret) {
        _cleanup_set_free_ Set *subvolumes = NULL;
        int r;

        assert(context);
        assert(p);
        assert(target);
        assert(ret);

        STRV_FOREACH(subvolume, p->subvolumes) {
                _cleanup_free_ char *path = NULL;

                const char *s = path_startswith(*subvolume, target);
                if (!s)
                        continue;

                path = path_join(source, s);
                if (!path)
                        return log_oom();

                r = add_subvolume_path(path, &subvolumes);
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(subvolumes);
        return 0;
}

static int do_copy_files(Context *context, Partition *p, const char *root) {
        int r;

        assert(p);
        assert(root);

        /* copy_tree_at() automatically copies the permissions of source directories to target directories if
         * it created them. However, the root directory is created by us, so we have to manually take care
         * that it is initialized. We use the first source directory targeting "/" as the metadata source for
         * the root directory. */
        STRV_FOREACH_PAIR(source, target, p->copy_files) {
                _cleanup_close_ int rfd = -EBADF, sfd = -EBADF;

                if (!path_equal(*target, "/"))
                        continue;

                rfd = open(root, O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
                if (rfd < 0)
                        return -errno;

                sfd = chase_and_open(*source, arg_copy_source, CHASE_PREFIX_ROOT, O_PATH|O_DIRECTORY|O_CLOEXEC|O_NOCTTY, NULL);
                if (sfd < 0)
                        return log_error_errno(sfd, "Failed to open source file '%s%s': %m", strempty(arg_copy_source), *source);

                (void) copy_xattr(sfd, NULL, rfd, NULL, COPY_ALL_XATTRS);
                (void) copy_access(sfd, rfd);
                (void) copy_times(sfd, rfd, 0);

                break;
        }

        STRV_FOREACH_PAIR(source, target, p->copy_files) {
                _cleanup_hashmap_free_ Hashmap *denylist = NULL;
                _cleanup_set_free_ Set *subvolumes_by_source_inode = NULL;
                _cleanup_close_ int sfd = -EBADF, pfd = -EBADF, tfd = -EBADF;

                r = make_copy_files_denylist(context, p, *source, *target, &denylist);
                if (r < 0)
                        return r;

                r = make_subvolumes_set(context, p, *source, *target, &subvolumes_by_source_inode);
                if (r < 0)
                        return r;

                sfd = chase_and_open(*source, arg_copy_source, CHASE_PREFIX_ROOT, O_CLOEXEC|O_NOCTTY, NULL);
                if (sfd == -ENOENT) {
                        log_notice_errno(sfd, "Failed to open source file '%s%s', skipping: %m", strempty(arg_copy_source), *source);
                        continue;
                }
                if (sfd < 0)
                        return log_error_errno(sfd, "Failed to open source file '%s%s': %m", strempty(arg_copy_source), *source);

                r = fd_verify_regular(sfd);
                if (r < 0) {
                        if (r != -EISDIR)
                                return log_error_errno(r, "Failed to check type of source file '%s': %m", *source);

                        /* We are looking at a directory */
                        tfd = chase_and_open(*target, root, CHASE_PREFIX_ROOT, O_RDONLY|O_DIRECTORY|O_CLOEXEC, NULL);
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

                                r = mkdir_p_root(root, dn, UID_INVALID, GID_INVALID, 0755, p->subvolumes);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to create parent directory '%s': %m", dn);

                                pfd = chase_and_open(dn, root, CHASE_PREFIX_ROOT, O_RDONLY|O_DIRECTORY|O_CLOEXEC, NULL);
                                if (pfd < 0)
                                        return log_error_errno(pfd, "Failed to open parent directory of target: %m");

                                r = copy_tree_at(
                                                sfd, ".",
                                                pfd, fn,
                                                UID_INVALID, GID_INVALID,
                                                COPY_REFLINK|COPY_HOLES|COPY_MERGE|COPY_REPLACE|COPY_SIGINT|COPY_HARDLINKS|COPY_ALL_XATTRS|COPY_GRACEFUL_WARN|COPY_TRUNCATE,
                                                denylist, subvolumes_by_source_inode);
                        } else
                                r = copy_tree_at(
                                                sfd, ".",
                                                tfd, ".",
                                                UID_INVALID, GID_INVALID,
                                                COPY_REFLINK|COPY_HOLES|COPY_MERGE|COPY_REPLACE|COPY_SIGINT|COPY_HARDLINKS|COPY_ALL_XATTRS|COPY_GRACEFUL_WARN|COPY_TRUNCATE,
                                                denylist, subvolumes_by_source_inode);
                        if (r < 0)
                                return log_error_errno(r, "Failed to copy '%s%s' to '%s%s': %m",
                                                       strempty(arg_copy_source), *source, strempty(root), *target);
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

                        r = mkdir_p_root(root, dn, UID_INVALID, GID_INVALID, 0755, p->subvolumes);
                        if (r < 0)
                                return log_error_errno(r, "Failed to create parent directory: %m");

                        pfd = chase_and_open(dn, root, CHASE_PREFIX_ROOT, O_RDONLY|O_DIRECTORY|O_CLOEXEC, NULL);
                        if (pfd < 0)
                                return log_error_errno(pfd, "Failed to open parent directory of target: %m");

                        tfd = openat(pfd, fn, O_CREAT|O_EXCL|O_WRONLY|O_CLOEXEC, 0700);
                        if (tfd < 0)
                                return log_error_errno(errno, "Failed to create target file '%s': %m", *target);

                        r = copy_bytes(sfd, tfd, UINT64_MAX, COPY_REFLINK|COPY_HOLES|COPY_SIGINT|COPY_TRUNCATE);
                        if (r < 0)
                                return log_error_errno(r, "Failed to copy '%s' to '%s%s': %m", *source, strempty(arg_copy_source), *target);

                        (void) copy_xattr(sfd, NULL, tfd, NULL, COPY_ALL_XATTRS);
                        (void) copy_access(sfd, tfd);
                        (void) copy_times(sfd, tfd, 0);
                }
        }

        return 0;
}

static int do_make_directories(Partition *p, const char *root) {
        int r;

        assert(p);
        assert(root);

        STRV_FOREACH(d, p->make_directories) {
                r = mkdir_p_root(root, *d, UID_INVALID, GID_INVALID, 0755, p->subvolumes);
                if (r < 0)
                        return log_error_errno(r, "Failed to create directory '%s' in file system: %m", *d);
        }

        return 0;
}

static bool partition_needs_populate(Partition *p) {
        assert(p);
        return !strv_isempty(p->copy_files) || !strv_isempty(p->make_directories);
}

static int partition_populate_directory(Context *context, Partition *p, char **ret) {
        _cleanup_(rm_rf_physical_and_freep) char *root = NULL;
        const char *vt;
        int r;

        assert(ret);

        log_info("Populating %s filesystem.", p->format);

        r = var_tmp_dir(&vt);
        if (r < 0)
                return log_error_errno(r, "Could not determine temporary directory: %m");

        r = tempfn_random_child(vt, "repart", &root);
        if (r < 0)
                return log_error_errno(r, "Failed to generate temporary directory: %m");

        r = mkdir(root, 0755);
        if (r < 0)
                return log_error_errno(errno, "Failed to create temporary directory: %m");

        r = do_copy_files(context, p, root);
        if (r < 0)
                return r;

        r = do_make_directories(p, root);
        if (r < 0)
                return r;

        log_info("Successfully populated %s filesystem.", p->format);

        *ret = TAKE_PTR(root);
        return 0;
}

static int partition_populate_filesystem(Context *context, Partition *p, const char *node) {
        int r;

        assert(p);
        assert(node);

        log_info("Populating %s filesystem.", p->format);

        /* We copy in a child process, since we have to mount the fs for that, and we don't want that fs to
         * appear in the host namespace. Hence we fork a child that has its own file system namespace and
         * detached mount propagation. */

        r = safe_fork("(sd-copy)", FORK_DEATHSIG_SIGTERM|FORK_LOG|FORK_WAIT|FORK_NEW_MOUNTNS|FORK_MOUNTNS_SLAVE, NULL);
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

                if (do_copy_files(context, p, fs) < 0)
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

        log_info("Successfully populated %s filesystem.", p->format);
        return 0;
}

static int context_mkfs(Context *context) {
        int r;

        assert(context);

        /* Make a file system */

        LIST_FOREACH(partitions, p, context->partitions) {
                _cleanup_(rm_rf_physical_and_freep) char *root = NULL;
                _cleanup_(partition_target_freep) PartitionTarget *t = NULL;
                _cleanup_strv_free_ char **extra_mkfs_options = NULL;

                if (p->dropped)
                        continue;

                if (PARTITION_EXISTS(p)) /* Never format existing partitions */
                        continue;

                if (!p->format)
                        continue;

                /* Minimized partitions will use the copy blocks logic so let's make sure to skip those here. */
                if (p->copy_blocks_fd >= 0)
                        continue;

                if (partition_type_defer(&p->type))
                        continue;

                assert(p->offset != UINT64_MAX);
                assert(p->new_size != UINT64_MAX);
                assert(p->new_size >= (p->encrypt != ENCRYPT_OFF ? LUKS2_METADATA_KEEP_FREE : 0));

                /* If we're doing encryption, we make sure we keep free space at the end which is required
                 * for cryptsetup's offline encryption. */
                r = partition_target_prepare(context, p,
                                             p->new_size - (p->encrypt != ENCRYPT_OFF ? LUKS2_METADATA_KEEP_FREE : 0),
                                             /*need_path=*/ true,
                                             &t);
                if (r < 0)
                        return r;

                if (p->encrypt != ENCRYPT_OFF && t->loop) {
                        r = partition_target_grow(t, p->new_size);
                        if (r < 0)
                                return r;

                        r = partition_encrypt(context, p, t, /* offline = */ false);
                        if (r < 0)
                                return log_error_errno(r, "Failed to encrypt device: %m");
                }

                log_info("Formatting future partition %" PRIu64 ".", p->partno);

                /* If we're not writing to a loop device or if we're populating a read-only filesystem, we
                 * have to populate using the filesystem's mkfs's --root (or equivalent) option. To do that,
                 * we need to set up the final directory tree beforehand. */

                if (partition_needs_populate(p) && (!t->loop || fstype_is_ro(p->format))) {
                        if (!mkfs_supports_root_option(p->format))
                                return log_error_errno(SYNTHETIC_ERRNO(ENODEV),
                                                        "Loop device access is required to populate %s filesystems.",
                                                        p->format);

                        r = partition_populate_directory(context, p, &root);
                        if (r < 0)
                                return r;
                }

                r = mkfs_options_from_env("REPART", p->format, &extra_mkfs_options);
                if (r < 0)
                        return log_error_errno(r,
                                               "Failed to determine mkfs command line options for '%s': %m",
                                               p->format);

                r = make_filesystem(partition_target_path(t), p->format, strempty(p->new_label), root,
                                    p->fs_uuid, arg_discard, /* quiet = */ false,
                                    context->fs_sector_size, extra_mkfs_options);
                if (r < 0)
                        return r;

                /* The mkfs binary we invoked might have removed our temporary file when we're not operating
                 * on a loop device, so let's make sure we open the file again to make sure our file
                 * descriptor points to any potential new file. */

                if (t->fd >= 0 && t->path && !t->loop) {
                        safe_close(t->fd);
                        t->fd = open(t->path, O_RDWR|O_CLOEXEC);
                        if (t->fd < 0)
                                return log_error_errno(errno, "Failed to reopen temporary file: %m");
                }

                log_info("Successfully formatted future partition %" PRIu64 ".", p->partno);

                /* If we're writing to a loop device, we can now mount the empty filesystem and populate it. */
                if (partition_needs_populate(p) && !root) {
                        assert(t->loop);

                        r = partition_populate_filesystem(context, p, partition_target_path(t));
                        if (r < 0)
                                return r;
                }

                if (p->encrypt != ENCRYPT_OFF && !t->loop) {
                        r = partition_target_grow(t, p->new_size);
                        if (r < 0)
                                return r;

                        r = partition_encrypt(context, p, t, /* offline = */ true);
                        if (r < 0)
                                return log_error_errno(r, "Failed to encrypt device: %m");
                }

                /* Note that we always sync explicitly here, since mkfs.fat doesn't do that on its own, and
                 * if we don't sync before detaching a block device the in-flight sectors possibly won't hit
                 * the disk. */

                r = partition_target_sync(context, p, t);
                if (r < 0)
                        return r;

                if (p->siblings[VERITY_HASH] && !partition_type_defer(&p->siblings[VERITY_HASH]->type)) {
                        r = partition_format_verity_hash(context, p->siblings[VERITY_HASH],
                                                         /* node = */ NULL, partition_target_path(t));
                        if (r < 0)
                                return r;
                }

                if (p->siblings[VERITY_SIG] && !partition_type_defer(&p->siblings[VERITY_SIG]->type)) {
                        r = partition_format_verity_sig(context, p->siblings[VERITY_SIG]);
                        if (r < 0)
                                return r;
                }
        }

        return 0;
}

static int parse_x509_certificate(const char *certificate, size_t certificate_size, X509 **ret) {
#if HAVE_OPENSSL
        _cleanup_(X509_freep) X509 *cert = NULL;
        _cleanup_(BIO_freep) BIO *cb = NULL;

        assert(certificate);
        assert(certificate_size > 0);
        assert(ret);

        cb = BIO_new_mem_buf(certificate, certificate_size);
        if (!cb)
                return log_oom();

        cert = PEM_read_bio_X509(cb, NULL, NULL, NULL);
        if (!cert)
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Failed to parse X.509 certificate: %s",
                                       ERR_error_string(ERR_get_error(), NULL));

        if (ret)
                *ret = TAKE_PTR(cert);

        return 0;
#else
        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "OpenSSL is not supported, cannot parse X509 certificate.");
#endif
}

static int parse_private_key(const char *key, size_t key_size, EVP_PKEY **ret) {
#if HAVE_OPENSSL
        _cleanup_(BIO_freep) BIO *kb = NULL;
        _cleanup_(EVP_PKEY_freep) EVP_PKEY *pk = NULL;

        assert(key);
        assert(key_size > 0);
        assert(ret);

        kb = BIO_new_mem_buf(key, key_size);
        if (!kb)
                return log_oom();

        pk = PEM_read_bio_PrivateKey(kb, NULL, NULL, NULL);
        if (!pk)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to parse PEM private key: %s",
                                       ERR_error_string(ERR_get_error(), NULL));

        if (ret)
                *ret = TAKE_PTR(pk);

        return 0;
#else
        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "OpenSSL is not supported, cannot parse private key.");
#endif
}

static int partition_acquire_uuid(Context *context, Partition *p, sd_id128_t *ret) {
        struct {
                sd_id128_t type_uuid;
                uint64_t counter;
        } _packed_ plaintext = {};
        union {
                uint8_t md[SHA256_DIGEST_SIZE];
                sd_id128_t id;
        } result;

        uint64_t k = 0;
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

                if (!sd_id128_equal(p->type.uuid, q->type.uuid))
                        continue;

                k++;
        }

        plaintext.type_uuid = p->type.uuid;
        plaintext.counter = htole64(k);

        hmac_sha256(context->seed.bytes, sizeof(context->seed.bytes),
                    &plaintext,
                    k == 0 ? sizeof(sd_id128_t) : sizeof(plaintext),
                    result.md);

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

        prefix = gpt_partition_type_uuid_to_string(p->type.uuid);
        if (!prefix)
                prefix = "linux";

        for (;;) {
                const char *ll = label ?: prefix;
                bool retry = false;

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
        int r;

        assert(context);

        LIST_FOREACH(partitions, p, context->partitions) {
                sd_id128_t uuid;

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
                        p->new_uuid = uuid = p->current_uuid; /* Never change initialized UUIDs */
                else if (p->new_uuid_is_set)
                        uuid = p->new_uuid;
                else {
                        /* Not explicitly set by user! */
                        r = partition_acquire_uuid(context, p, &uuid);
                        if (r < 0)
                                return r;

                        /* The final verity hash/data UUIDs can only be determined after formatting the
                         * verity hash partition. However, we still want to use the generated partition UUID
                         * to derive other UUIDs to keep things unique and reproducible, so we always
                         * generate a UUID if none is set, but we only use it as the actual partition UUID if
                         * verity is not configured. */
                        if (!IN_SET(p->verity, VERITY_DATA, VERITY_HASH)) {
                                p->new_uuid = uuid;
                                p->new_uuid_is_set = true;
                        }
                }

                /* Calculate the UUID for the file system as HMAC-SHA256 of the string "file-system-uuid",
                 * keyed off the partition UUID. */
                r = derive_uuid(uuid, "file-system-uuid", &p->fs_uuid);
                if (r < 0)
                        return r;

                if (p->encrypt != ENCRYPT_OFF) {
                        r = derive_uuid(uuid, "luks-uuid", &p->luks_uuid);
                        if (r < 0)
                                return r;
                }

                /* Derive the verity salt and verity superblock UUID from the seed to keep them reproducible */
                if (p->verity == VERITY_HASH) {
                        derive_salt(context->seed, "verity-salt", p->verity_salt);

                        r = derive_uuid(context->seed, "verity-uuid", &p->verity_uuid);
                        if (r < 0)
                                return log_error_errno(r, "Failed to acquire verity uuid: %m");
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
                if (gpt_partition_type_knows_no_auto(p->type))
                        SET_FLAG(f, SD_GPT_FLAG_NO_AUTO, p->no_auto);
                else {
                        char buffer[SD_ID128_UUID_STRING_MAX];
                        log_warning("Configured NoAuto=%s for partition type '%s' that doesn't support it, ignoring.",
                                    yes_no(p->no_auto),
                                    gpt_partition_type_uuid_to_string_harder(p->type.uuid, buffer));
                }
        }

        if (p->read_only >= 0) {
                if (gpt_partition_type_knows_read_only(p->type))
                        SET_FLAG(f, SD_GPT_FLAG_READ_ONLY, p->read_only);
                else {
                        char buffer[SD_ID128_UUID_STRING_MAX];
                        log_warning("Configured ReadOnly=%s for partition type '%s' that doesn't support it, ignoring.",
                                    yes_no(p->read_only),
                                    gpt_partition_type_uuid_to_string_harder(p->type.uuid, buffer));
                }
        }

        if (p->growfs >= 0) {
                if (gpt_partition_type_knows_growfs(p->type))
                        SET_FLAG(f, SD_GPT_FLAG_GROWFS, p->growfs);
                else {
                        char buffer[SD_ID128_UUID_STRING_MAX];
                        log_warning("Configured GrowFileSystem=%s for partition type '%s' that doesn't support it, ignoring.",
                                    yes_no(p->growfs),
                                    gpt_partition_type_uuid_to_string_harder(p->type.uuid, buffer));
                }
        }

        return f;
}

static int context_mangle_partitions(Context *context) {
        int r;

        assert(context);

        LIST_FOREACH(partitions, p, context->partitions) {
                if (p->dropped)
                        continue;

                if (partition_type_defer(&p->type))
                        continue;

                assert(p->new_size != UINT64_MAX);
                assert(p->offset != UINT64_MAX);
                assert(p->partno != UINT64_MAX);

                if (PARTITION_EXISTS(p)) {
                        bool changed = false;

                        assert(p->current_partition);

                        if (p->new_size != p->current_size) {
                                assert(p->new_size >= p->current_size);
                                assert(p->new_size % context->sector_size == 0);

                                r = fdisk_partition_size_explicit(p->current_partition, true);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to enable explicit sizing: %m");

                                r = fdisk_partition_set_size(p->current_partition, p->new_size / context->sector_size);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to grow partition: %m");

                                log_info("Growing existing partition %" PRIu64 ".", p->partno);
                                changed = true;
                        }

                        if (!sd_id128_equal(p->new_uuid, p->current_uuid)) {
                                r = fdisk_partition_set_uuid(p->current_partition, SD_ID128_TO_UUID_STRING(p->new_uuid));
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

                        assert(!p->new_partition);
                        assert(p->offset % context->sector_size == 0);
                        assert(p->new_size % context->sector_size == 0);
                        assert(p->new_label);

                        t = fdisk_new_parttype();
                        if (!t)
                                return log_oom();

                        r = fdisk_parttype_set_typestr(t, SD_ID128_TO_UUID_STRING(p->type.uuid));
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

                        r = fdisk_partition_set_start(q, p->offset / context->sector_size);
                        if (r < 0)
                                return log_error_errno(r, "Failed to position partition: %m");

                        r = fdisk_partition_set_size(q, p->new_size / context->sector_size);
                        if (r < 0)
                                return log_error_errno(r, "Failed to grow partition: %m");

                        r = fdisk_partition_set_partno(q, p->partno);
                        if (r < 0)
                                return log_error_errno(r, "Failed to set partition number: %m");

                        r = fdisk_partition_set_uuid(q, SD_ID128_TO_UUID_STRING(p->new_uuid));
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

static int split_name_printf(Partition *p, char **ret) {
        assert(p);

        const Specifier table[] = {
                { 't', specifier_string, GPT_PARTITION_TYPE_UUID_TO_STRING_HARDER(p->type.uuid) },
                { 'T', specifier_id128,  &p->type.uuid                                          },
                { 'U', specifier_id128,  &p->new_uuid                                           },
                { 'n', specifier_uint64, &p->partno                                             },

                COMMON_SYSTEM_SPECIFIERS,
                {}
        };

        return specifier_printf(p->split_name_format, NAME_MAX, table, arg_root, p, ret);
}

static int split_node(const char *node, char **ret_base, char **ret_ext) {
        _cleanup_free_ char *base = NULL, *ext = NULL;
        char *e;
        int r;

        assert(node);
        assert(ret_base);
        assert(ret_ext);

        r = path_extract_filename(node, &base);
        if (r == O_DIRECTORY || r == -EADDRNOTAVAIL)
                return log_error_errno(r, "Device node %s cannot be a directory", node);
        if (r < 0)
                return log_error_errno(r, "Failed to extract filename from %s: %m", node);

        e = endswith(base, ".raw");
        if (e) {
                ext = strdup(e);
                if (!ext)
                        return log_oom();

                *e = 0;
        }

        *ret_base = TAKE_PTR(base);
        *ret_ext = TAKE_PTR(ext);

        return 0;
}

static int split_name_resolve(Context *context) {
        _cleanup_free_ char *parent = NULL, *base = NULL, *ext = NULL;
        int r;

        assert(context);

        r = path_extract_directory(context->node, &parent);
        if (r < 0 && r != -EDESTADDRREQ)
                return log_error_errno(r, "Failed to extract directory from %s: %m", context->node);

        r = split_node(context->node, &base, &ext);
        if (r < 0)
                return r;

        LIST_FOREACH(partitions, p, context->partitions) {
                _cleanup_free_ char *resolved = NULL;

                if (p->dropped)
                        continue;

                if (!p->split_name_format)
                        continue;

                r = split_name_printf(p, &resolved);
                if (r < 0)
                        return log_error_errno(r, "Failed to resolve specifiers in %s: %m", p->split_name_format);

                if (parent)
                        p->split_path = strjoin(parent, "/", base, ".", resolved, ext);
                else
                        p->split_path = strjoin(base, ".", resolved, ext);
                if (!p->split_path)
                        return log_oom();
        }

        LIST_FOREACH(partitions, p, context->partitions) {
                if (!p->split_path)
                        continue;

                LIST_FOREACH(partitions, q, context->partitions) {
                        if (p == q)
                                continue;

                        if (!q->split_path)
                                continue;

                        if (!streq(p->split_path, q->split_path))
                                continue;

                        return log_error_errno(SYNTHETIC_ERRNO(ENOTUNIQ),
                                               "%s and %s have the same resolved split name \"%s\", refusing",
                                               p->definition_path, q->definition_path, p->split_path);
                }
        }

        return 0;
}

static int context_split(Context *context) {
        int fd = -EBADF, r;

        if (!arg_split)
                return 0;

        assert(context);

        /* We can't do resolution earlier because the partition UUIDs for verity partitions are only filled
         * in after they've been generated. */

        r = split_name_resolve(context);
        if (r < 0)
                return r;

        LIST_FOREACH(partitions, p, context->partitions) {
                _cleanup_close_ int fdt = -EBADF;

                if (p->dropped)
                        continue;

                if (!p->split_path)
                        continue;

                if (partition_type_defer(&p->type))
                        continue;

                fdt = open(p->split_path, O_WRONLY|O_NOCTTY|O_CLOEXEC|O_NOFOLLOW|O_CREAT|O_EXCL, 0666);
                if (fdt < 0)
                        return log_error_errno(fdt, "Failed to open split partition file %s: %m", p->split_path);

                if (fd < 0)
                        assert_se((fd = fdisk_get_devfd(context->fdisk_context)) >= 0);

                if (lseek(fd, p->offset, SEEK_SET) < 0)
                        return log_error_errno(errno, "Failed to seek to partition offset: %m");

                r = copy_bytes(fd, fdt, p->new_size, COPY_REFLINK|COPY_HOLES|COPY_TRUNCATE);
                if (r < 0)
                        return log_error_errno(r, "Failed to copy to split partition %s: %m", p->split_path);
        }

        return 0;
}

static int context_write_partition_table(Context *context) {
        _cleanup_(fdisk_unref_tablep) struct fdisk_table *original_table = NULL;
        int capable, r;

        assert(context);

        if (!context->from_scratch && !context_changed(context)) {
                log_info("No changes.");
                return 0;
        }

        if (arg_dry_run) {
                log_notice("Refusing to repartition, please re-run with --dry-run=no.");
                return 0;
        }

        log_info("Applying changes to %s.", context->node);

        if (context->from_scratch && arg_empty != EMPTY_CREATE) {
                /* Erase everything if we operate from scratch, except if the image was just created anyway, and thus is definitely empty. */
                r = context_wipe_range(context, 0, context->total);
                if (r < 0)
                        return r;

                log_info("Wiped block device.");

                if (arg_discard) {
                        r = context_discard_range(context, 0, context->total);
                        if (r == -EOPNOTSUPP)
                                log_info("Storage does not support discard, not discarding entire block device data.");
                        else if (r < 0)
                                return log_error_errno(r, "Failed to discard entire block device: %m");
                        else if (r > 0)
                                log_info("Discarded entire block device.");
                }
        }

        r = fdisk_get_partitions(context->fdisk_context, &original_table);
        if (r < 0)
                return log_error_errno(r, "Failed to acquire partition table: %m");

        /* Wipe fs signatures and discard sectors where the new partitions are going to be placed and in the
         * gaps between partitions, just to be sure. */
        r = context_wipe_and_discard(context);
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

                if (context->from_scratch)
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
                r = id128_get_machine(root, &context->seed);
                if (r >= 0)
                        return 0;

                if (!ERRNO_IS_MACHINE_ID_UNSET(r))
                        return log_error_errno(r, "Failed to parse machine ID of image: %m");

                log_info("No machine ID set, using randomized partition UUIDs.");
        }

        r = sd_id128_randomize(&context->seed);
        if (r < 0)
                return log_error_errno(r, "Failed to generate randomized seed: %m");

        return 0;
}

static int context_factory_reset(Context *context) {
        size_t n = 0;
        int r;

        assert(context);

        if (arg_factory_reset <= 0)
                return 0;

        if (context->from_scratch) /* Nothing to reset if we start from scratch */
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
        assert(context);

        LIST_FOREACH(partitions, p, context->partitions)
                if (p->factory_reset && PARTITION_EXISTS(p))
                        return true;

        return false;
}

static int resolve_copy_blocks_auto_candidate(
                dev_t partition_devno,
                GptPartitionType partition_type,
                dev_t restrict_devno,
                sd_id128_t *ret_uuid) {

        _cleanup_(blkid_free_probep) blkid_probe b = NULL;
        _cleanup_close_ int fd = -EBADF;
        _cleanup_free_ char *p = NULL;
        const char *pttype, *t;
        sd_id128_t pt_parsed, u;
        blkid_partition pp;
        dev_t whole_devno;
        blkid_partlist pl;
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

        fd = r = device_open_from_devnum(S_IFBLK, whole_devno, O_RDONLY|O_CLOEXEC|O_NONBLOCK, &p);
        if (r < 0)
                return log_error_errno(r, "Failed to open block device " DEVNUM_FORMAT_STR ": %m",
                                       DEVNUM_FORMAT_VAL(whole_devno));

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
        if (r == _BLKID_SAFEPROBE_ERROR)
                return log_error_errno(errno_or_else(EIO), "Unable to probe for partition table of '%s': %m", p);
        if (IN_SET(r, _BLKID_SAFEPROBE_AMBIGUOUS, _BLKID_SAFEPROBE_NOT_FOUND)) {
                log_debug("Didn't find partition table on block device '%s'.", p);
                return false;
        }

        assert(r == _BLKID_SAFEPROBE_FOUND);

        (void) blkid_probe_lookup_value(b, "PTTYPE", &pttype, NULL);
        if (!streq_ptr(pttype, "gpt")) {
                log_debug("Didn't find a GPT partition table on '%s'.", p);
                return false;
        }

        errno = 0;
        pl = blkid_probe_get_partitions(b);
        if (!pl)
                return log_error_errno(errno_or_else(EIO), "Unable read partition table of '%s': %m", p);

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

        if (!sd_id128_equal(pt_parsed, partition_type.uuid)) {
                log_debug("Partition %u:%u has non-matching partition type " SD_ID128_FORMAT_STR " (needed: " SD_ID128_FORMAT_STR "), ignoring.",
                          major(partition_devno), minor(partition_devno),
                          SD_ID128_FORMAT_VAL(pt_parsed), SD_ID128_FORMAT_VAL(partition_type.uuid));
                return false;
        }

        r = blkid_partition_get_uuid_id128(pp, &u);
        if (r == -ENXIO) {
                log_debug_errno(r, "Partition " DEVNUM_FORMAT_STR " has no UUID.", DEVNUM_FORMAT_VAL(partition_devno));
                return false;
        }
        if (r < 0) {
                log_debug_errno(r, "Failed to read partition UUID of " DEVNUM_FORMAT_STR ": %m", DEVNUM_FORMAT_VAL(partition_devno));
                return false;
        }

        log_debug("Automatically found partition " DEVNUM_FORMAT_STR " of right type " SD_ID128_FORMAT_STR ".",
                  DEVNUM_FORMAT_VAL(partition_devno),
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

        r = chase(path, root, CHASE_PREFIX_ROOT, &resolved, NULL);
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
                GptPartitionType type,
                const char *root,
                dev_t restrict_devno,
                dev_t *ret_devno,
                sd_id128_t *ret_uuid) {

        const char *try1 = NULL, *try2 = NULL;
        char p[SYS_BLOCK_PATH_MAX("/slaves")];
        _cleanup_closedir_ DIR *d = NULL;
        sd_id128_t found_uuid = SD_ID128_NULL;
        dev_t devno, found = 0;
        int r;

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

        if (type.designator == PARTITION_ROOT)
                try1 = "/";
        else if (type.designator == PARTITION_USR)
                try1 = "/usr/";
        else if (type.designator == PARTITION_ROOT_VERITY)
                try1 = "/";
        else if (type.designator == PARTITION_USR_VERITY)
                try1 = "/usr/";
        else if (type.designator == PARTITION_ESP) {
                try1 = "/efi/";
                try2 = "/boot/";
        } else if (type.designator == PARTITION_XBOOTLDR)
                try1 = "/boot/";
        else
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                       "Partition type " SD_ID128_FORMAT_STR " not supported from automatic source block device discovery.",
                                       SD_ID128_FORMAT_VAL(type.uuid));

        r = find_backing_devno(try1, root, &devno);
        if (r == -ENOENT && try2)
                r = find_backing_devno(try2, root, &devno);
        if (r < 0)
                return log_error_errno(r, "Failed to resolve automatic CopyBlocks= path for partition type " SD_ID128_FORMAT_STR ", sorry: %m",
                                       SD_ID128_FORMAT_VAL(type.uuid));

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

                        r = parse_devnum(t, &sl);
                        if (r < 0) {
                                log_debug_errno(r, "Failed to parse %s, ignoring: %m", q);
                                continue;
                        }
                        if (major(sl) == 0) {
                                log_debug("Device backing %s is special, ignoring.", q);
                                continue;
                        }

                        r = resolve_copy_blocks_auto_candidate(sl, type, restrict_devno, &u);
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
                r = resolve_copy_blocks_auto_candidate(devno, type, restrict_devno, &found_uuid);
                if (r < 0)
                        return r;
                if (r > 0)
                        found = devno;
        }

        if (found == 0)
                return log_error_errno(SYNTHETIC_ERRNO(ENXIO),
                                       "Unable to automatically discover suitable partition to copy blocks from.");

        if (ret_devno)
                *ret_devno = found;

        if (ret_uuid)
                *ret_uuid = found_uuid;

        return 0;
}

static int context_open_copy_block_paths(
                Context *context,
                dev_t restrict_devno) {

        int r;

        assert(context);

        LIST_FOREACH(partitions, p, context->partitions) {
                _cleanup_close_ int source_fd = -EBADF;
                _cleanup_free_ char *opened = NULL;
                sd_id128_t uuid = SD_ID128_NULL;
                uint64_t size;
                struct stat st;

                if (p->copy_blocks_fd >= 0)
                        continue;

                assert(p->copy_blocks_size == UINT64_MAX);

                if (PARTITION_EXISTS(p)) /* Never copy over partitions that already exist! */
                        continue;

                if (p->copy_blocks_path) {

                        source_fd = chase_and_open(p->copy_blocks_path, p->copy_blocks_root, CHASE_PREFIX_ROOT, O_RDONLY|O_CLOEXEC|O_NONBLOCK, &opened);
                        if (source_fd < 0)
                                return log_error_errno(source_fd, "Failed to open '%s': %m", p->copy_blocks_path);

                        if (fstat(source_fd, &st) < 0)
                                return log_error_errno(errno, "Failed to stat block copy file '%s': %m", opened);

                        if (!S_ISREG(st.st_mode) && restrict_devno != (dev_t) -1)
                                return log_error_errno(SYNTHETIC_ERRNO(EPERM),
                                                       "Copying from block device node is not permitted in --image=/--root= mode, refusing.");

                } else if (p->copy_blocks_auto) {
                        dev_t devno = 0;  /* Fake initialization to appease gcc. */

                        r = resolve_copy_blocks_auto(p->type, p->copy_blocks_root, restrict_devno, &devno, &uuid);
                        if (r < 0)
                                return r;
                        assert(devno != 0);

                        source_fd = r = device_open_from_devnum(S_IFBLK, devno, O_RDONLY|O_CLOEXEC|O_NONBLOCK, &opened);
                        if (r < 0)
                                return log_error_errno(r, "Failed to open automatically determined source block copy device " DEVNUM_FORMAT_STR ": %m",
                                                       DEVNUM_FORMAT_VAL(devno));

                        if (fstat(source_fd, &st) < 0)
                                return log_error_errno(errno, "Failed to stat block copy file '%s': %m", opened);
                } else
                        continue;

                if (S_ISDIR(st.st_mode)) {
                        _cleanup_free_ char *bdev = NULL;
                        dev_t devt;

                        /* If the file is a directory, automatically find the backing block device */

                        if (major(st.st_dev) != 0)
                                devt = st.st_dev;
                        else {
                                /* Special support for btrfs */
                                r = btrfs_get_block_device_fd(source_fd, &devt);
                                if (r == -EUCLEAN)
                                        return btrfs_log_dev_root(LOG_ERR, r, opened);
                                if (r < 0)
                                        return log_error_errno(r, "Unable to determine backing block device of '%s': %m", opened);
                        }

                        safe_close(source_fd);

                        source_fd = r = device_open_from_devnum(S_IFBLK, devt, O_RDONLY|O_CLOEXEC|O_NONBLOCK, &bdev);
                        if (r < 0)
                                return log_error_errno(r, "Failed to open block device backing '%s': %m", opened);

                        if (fstat(source_fd, &st) < 0)
                                return log_error_errno(errno, "Failed to stat block device '%s': %m", bdev);
                }

                if (S_ISREG(st.st_mode))
                        size = st.st_size;
                else if (S_ISBLK(st.st_mode)) {
                        r = blockdev_get_device_size(source_fd, &size);
                        if (r < 0)
                                return log_error_errno(r, "Failed to determine size of block device to copy from: %m");
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
                if (!p->new_uuid_is_set && !sd_id128_is_null(uuid)) {
                        p->new_uuid = uuid;
                        p->new_uuid_is_set = true;
                }
        }

        return 0;
}

static int fd_apparent_size(int fd, uint64_t *ret) {
        off_t initial = 0;
        uint64_t size = 0;

        assert(fd >= 0);
        assert(ret);

        initial = lseek(fd, 0, SEEK_CUR);
        if (initial < 0)
                return log_error_errno(errno, "Failed to get file offset: %m");

        for (off_t off = 0;;) {
                off_t r;

                r = lseek(fd, off, SEEK_DATA);
                if (r < 0 && errno == ENXIO)
                        /* If errno == ENXIO, that means we've reached the final hole of the file and
                         * that hole isn't followed by more data. */
                        break;
                if (r < 0)
                        return log_error_errno(errno, "Failed to seek data in file from offset %"PRIi64": %m", off);

                off = r; /* Set the offset to the start of the data segment. */

                /* After copying a potential hole, find the end of the data segment by looking for
                 * the next hole. If we get ENXIO, we're at EOF. */
                r = lseek(fd, off, SEEK_HOLE);
                if (r < 0) {
                        if (errno == ENXIO)
                                break;
                        return log_error_errno(errno, "Failed to seek hole in file from offset %"PRIi64": %m", off);
                }

                size += r - off;
                off = r;
        }

        if (lseek(fd, initial, SEEK_SET) < 0)
                return log_error_errno(errno, "Failed to reset file offset: %m");

        *ret = size;

        return 0;
}

static int context_minimize(Context *context) {
        const char *vt = NULL;
        int r;

        assert(context);

        LIST_FOREACH(partitions, p, context->partitions) {
                _cleanup_(rm_rf_physical_and_freep) char *root = NULL;
                _cleanup_(unlink_and_freep) char *temp = NULL;
                _cleanup_(loop_device_unrefp) LoopDevice *d = NULL;
                _cleanup_strv_free_ char **extra_mkfs_options = NULL;
                _cleanup_close_ int fd = -EBADF;
                _cleanup_free_ char *hint = NULL;
                sd_id128_t fs_uuid;
                struct stat st;
                uint64_t fsz;

                if (p->dropped)
                        continue;

                if (PARTITION_EXISTS(p)) /* Never format existing partitions */
                        continue;

                if (!p->format)
                        continue;

                if (p->copy_blocks_fd >= 0)
                        continue;

                if (p->minimize == MINIMIZE_OFF)
                        continue;

                if (!partition_needs_populate(p))
                        continue;

                assert(!p->copy_blocks_path);

                (void) partition_hint(p, context->node, &hint);

                log_info("Pre-populating %s filesystem of partition %s twice to calculate minimal partition size",
                         p->format, strna(hint));

                if (!vt) {
                        r = var_tmp_dir(&vt);
                        if (r < 0)
                                return log_error_errno(r, "Could not determine temporary directory: %m");
                }

                r = tempfn_random_child(vt, "repart", &temp);
                if (r < 0)
                        return log_error_errno(r, "Failed to generate temporary file path: %m");

                if (fstype_is_ro(p->format))
                        fs_uuid = p->fs_uuid;
                else {
                        fd = open(temp, O_CREAT|O_EXCL|O_CLOEXEC|O_RDWR|O_NOCTTY, 0600);
                        if (fd < 0)
                                return log_error_errno(errno, "Failed to open temporary file %s: %m", temp);

                        /* This may seem huge but it will be created sparse so it doesn't take up any space
                         * on disk until written to. */
                        if (ftruncate(fd, 1024ULL * 1024ULL * 1024ULL * 1024ULL) < 0)
                                return log_error_errno(errno, "Failed to truncate temporary file to %s: %m",
                                                       FORMAT_BYTES(1024ULL * 1024ULL * 1024ULL * 1024ULL));

                        if (arg_offline <= 0) {
                                r = loop_device_make(fd, O_RDWR, 0, UINT64_MAX, context->sector_size, 0, LOCK_EX, &d);
                                if (r < 0 && (arg_offline == 0 || (r != -ENOENT && !ERRNO_IS_PRIVILEGE(r)) || !strv_isempty(p->subvolumes)))
                                        return log_error_errno(r, "Failed to make loopback device of %s: %m", temp);
                        }

                        /* We're going to populate this filesystem twice so use a random UUID the first time
                         * to avoid UUID conflicts. */
                        r = sd_id128_randomize(&fs_uuid);
                        if (r < 0)
                                return r;
                }

                if (!d || fstype_is_ro(p->format)) {
                        if (!mkfs_supports_root_option(p->format))
                                return log_error_errno(SYNTHETIC_ERRNO(ENODEV),
                                                       "Loop device access is required to populate %s filesystems",
                                                       p->format);

                        r = partition_populate_directory(context, p, &root);
                        if (r < 0)
                                return r;
                }

                r = mkfs_options_from_env("REPART", p->format, &extra_mkfs_options);
                if (r < 0)
                        return log_error_errno(r,
                                               "Failed to determine mkfs command line options for '%s': %m",
                                               p->format);

                r = make_filesystem(d ? d->node : temp,
                                    p->format,
                                    strempty(p->new_label),
                                    root,
                                    fs_uuid,
                                    arg_discard, /* quiet = */ false,
                                    context->fs_sector_size,
                                    extra_mkfs_options);
                if (r < 0)
                        return r;

                /* Read-only filesystems are minimal from the first try because they create and size the
                 * loopback file for us. */
                if (fstype_is_ro(p->format)) {
                        assert(fd < 0);

                        fd = open(temp, O_RDONLY|O_CLOEXEC|O_NONBLOCK);
                        if (fd < 0)
                                return log_error_errno(errno, "Failed to open temporary file %s: %m", temp);

                        if (fstat(fd, &st) < 0)
                                return log_error_errno(errno, "Failed to stat temporary file: %m");

                        log_info("Minimal partition size of %s filesystem of partition %s is %s",
                                 p->format, strna(hint), FORMAT_BYTES(st.st_size));

                        p->copy_blocks_path = TAKE_PTR(temp);
                        p->copy_blocks_path_is_our_file = true;
                        p->copy_blocks_fd = TAKE_FD(fd);
                        p->copy_blocks_size = st.st_size;
                        continue;
                }

                if (!root) {
                        assert(d);

                        r = partition_populate_filesystem(context, p, d->node);
                        if (r < 0)
                                return r;
                }

                /* Other filesystems need to be provided with a pre-sized loopback file and will adapt to
                 * fully occupy it. Because we gave the filesystem a 1T sparse file, we need to shrink the
                 * filesystem down to a reasonable size again to fit it in the disk image. While there are
                 * some filesystems that support shrinking, it doesn't always work properly (e.g. shrinking
                 * btrfs gives us a 2.0G filesystem regardless of what we put in it). Instead, let's populate
                 * the filesystem again, but this time, instead of providing the filesystem with a 1T sparse
                 * loopback file, let's size the loopback file based on the actual data used by the
                 * filesystem in the sparse file after the first attempt. This should be a good guess of the
                 * minimal amount of space needed in the filesystem to fit all the required data.
                 */
                r = fd_apparent_size(fd, &fsz);
                if (r < 0)
                        return r;

                /* Massage the size a bit because just going by actual data used in the sparse file isn't
                 * fool-proof. */
                uint64_t heuristic = streq(p->format, "xfs") ? fsz : fsz / 2;
                fsz = round_up_size(fsz + heuristic, context->grain_size);
                if (minimal_size_by_fs_name(p->format) != UINT64_MAX)
                        fsz = MAX(minimal_size_by_fs_name(p->format), fsz);

                log_info("Minimal partition size of %s filesystem of partition %s is %s",
                         p->format, strna(hint), FORMAT_BYTES(fsz));

                d = loop_device_unref(d);

                /* Erase the previous filesystem first. */
                if (ftruncate(fd, 0) < 0)
                        return log_error_errno(errno, "Failed to erase temporary file: %m");

                if (ftruncate(fd, fsz) < 0)
                        return log_error_errno(errno, "Failed to truncate temporary file to %s: %m", FORMAT_BYTES(fsz));

                if (arg_offline <= 0) {
                        r = loop_device_make(fd, O_RDWR, 0, UINT64_MAX, context->sector_size, 0, LOCK_EX, &d);
                        if (r < 0 && (arg_offline == 0 || (r != -ENOENT && !ERRNO_IS_PRIVILEGE(r)) || !strv_isempty(p->subvolumes)))
                                return log_error_errno(r, "Failed to make loopback device of %s: %m", temp);
                }

                r = make_filesystem(d ? d->node : temp,
                                    p->format,
                                    strempty(p->new_label),
                                    root,
                                    p->fs_uuid,
                                    arg_discard,
                                    /* quiet = */ false,
                                    context->fs_sector_size,
                                    extra_mkfs_options);
                if (r < 0)
                        return r;

                if (!root) {
                        assert(d);

                        r = partition_populate_filesystem(context, p, d->node);
                        if (r < 0)
                                return r;
                }

                if (fstat(fd, &st) < 0)
                        return log_error_errno(errno, "Failed to stat temporary file: %m");

                p->copy_blocks_path = TAKE_PTR(temp);
                p->copy_blocks_path_is_our_file = true;
                p->copy_blocks_fd = TAKE_FD(fd);
                p->copy_blocks_size = st.st_size;
        }

        /* Now that we've done the data partitions, do the verity hash partitions. We do these in a separate
         * step because they might depend on data generated in the previous step. */

        LIST_FOREACH(partitions, p, context->partitions) {
                _cleanup_(unlink_and_freep) char *temp = NULL;
                _cleanup_free_ char *hint = NULL;
                _cleanup_close_ int fd = -EBADF;
                struct stat st;
                Partition *dp;

                if (p->dropped)
                        continue;

                if (PARTITION_EXISTS(p)) /* Never format existing partitions */
                        continue;

                if (p->minimize == MINIMIZE_OFF)
                        continue;

                if (p->verity != VERITY_HASH)
                        continue;

                assert_se(dp = p->siblings[VERITY_DATA]);
                assert(!dp->dropped);
                assert(dp->copy_blocks_path);

                (void) partition_hint(p, context->node, &hint);

                log_info("Pre-populating verity hash data of partition %s to calculate minimal partition size",
                         strna(hint));

                if (!vt) {
                        r = var_tmp_dir(&vt);
                        if (r < 0)
                                return log_error_errno(r, "Could not determine temporary directory: %m");
                }

                r = tempfn_random_child(vt, "repart", &temp);
                if (r < 0)
                        return log_error_errno(r, "Failed to generate temporary file path: %m");

                r = touch(temp);
                if (r < 0)
                        return log_error_errno(r, "Failed to create temporary file: %m");

                r = partition_format_verity_hash(context, p, temp, dp->copy_blocks_path);
                if (r < 0)
                        return r;

                fd = open(temp, O_RDONLY|O_CLOEXEC|O_NONBLOCK);
                if (fd < 0)
                        return log_error_errno(errno, "Failed to open temporary file %s: %m", temp);

                if (fstat(fd, &st) < 0)
                        return log_error_errno(errno, "Failed to stat temporary file: %m");

                log_info("Minimal partition size of verity hash partition %s is %s",
                         strna(hint), FORMAT_BYTES(st.st_size));

                p->copy_blocks_path = TAKE_PTR(temp);
                p->copy_blocks_path_is_our_file = true;
                p->copy_blocks_fd = TAKE_FD(fd);
                p->copy_blocks_size = st.st_size;
        }

        return 0;
}

static int parse_partition_types(const char *p, GptPartitionType **partitions, size_t *n_partitions) {
        int r;

        assert(partitions);
        assert(n_partitions);

        for (;;) {
                _cleanup_free_ char *name = NULL;
                GptPartitionType type;

                r = extract_first_word(&p, &name, ",", EXTRACT_CUNESCAPE|EXTRACT_DONT_COALESCE_SEPARATORS);
                if (r == 0)
                        break;
                if (r < 0)
                        return log_error_errno(r, "Failed to extract partition type identifier or GUID: %s", p);

                r = gpt_partition_type_from_string(name, &type);
                if (r < 0)
                        return log_error_errno(r, "'%s' is not a valid partition type identifier or GUID", name);

                if (!GREEDY_REALLOC(*partitions, *n_partitions + 1))
                        return log_oom();

                (*partitions)[(*n_partitions)++] = type;
        }

        return 0;
}

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("systemd-repart", "8", &link);
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
               "     --image-policy=POLICY\n"
               "                          Specify disk image dissection policy\n"
               "     --definitions=DIR    Find partition definitions in specified directory\n"
               "     --key-file=PATH      Key to use when encrypting partitions\n"
               "     --private-key=PATH   Private key to use when generating verity roothash\n"
               "                          signatures\n"
               "     --certificate=PATH   PEM certificate to use when generating verity\n"
               "                          roothash signatures\n"
               "     --tpm2-device=PATH   Path to TPM2 device node to use\n"
               "     --tpm2-device-key=PATH\n"
               "                          Enroll a TPM2 device using its public key\n"
               "     --tpm2-seal-key-handle=HANDLE\n"
               "                          Specify handle of key to use for sealing\n"
               "     --tpm2-pcrs=PCR1+PCR2+PCR3+…\n"
               "                          TPM2 PCR indexes to use for TPM2 enrollment\n"
               "     --tpm2-public-key=PATH\n"
               "                          Enroll signed TPM2 PCR policy against PEM public key\n"
               "     --tpm2-public-key-pcrs=PCR1+PCR2+PCR3+…\n"
               "                          Enroll signed TPM2 PCR policy for specified TPM2 PCRs\n"
               "     --tpm2-pcrlock=PATH\n"
               "                          Specify pcrlock policy to lock against\n"
               "     --seed=UUID          128-bit seed UUID to derive all UUIDs from\n"
               "     --size=BYTES         Grow loopback file to specified size\n"
               "     --json=pretty|short|off\n"
               "                          Generate JSON output\n"
               "     --split=BOOL         Whether to generate split artifacts\n"
               "     --include-partitions=PARTITION1,PARTITION2,PARTITION3,…\n"
               "                          Ignore partitions not of the specified types\n"
               "     --exclude-partitions=PARTITION1,PARTITION2,PARTITION3,…\n"
               "                          Ignore partitions of the specified types\n"
               "     --defer-partitions=PARTITION1,PARTITION2,PARTITION3,…\n"
               "                          Take partitions of the specified types into account\n"
               "                          but don't populate them yet\n"
               "     --sector-size=SIZE   Set the logical sector size for the image\n"
               "     --architecture=ARCH  Set the generic architecture for the image\n"
               "     --offline=BOOL       Whether to build the image offline\n"
               "  -s --copy-source=PATH   Specify the primary source tree to copy files from\n"
               "     --copy-from=IMAGE    Copy partitions from the given image(s)\n"
               "  -S --make-ddi=sysext    Make a system extension DDI\n"
               "  -C --make-ddi=confext   Make a configuration extension DDI\n"
               "  -P --make-ddi=portable  Make a portable service DDI\n"
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
                ARG_IMAGE_POLICY,
                ARG_SEED,
                ARG_PRETTY,
                ARG_DEFINITIONS,
                ARG_SIZE,
                ARG_JSON,
                ARG_KEY_FILE,
                ARG_PRIVATE_KEY,
                ARG_CERTIFICATE,
                ARG_TPM2_DEVICE,
                ARG_TPM2_DEVICE_KEY,
                ARG_TPM2_SEAL_KEY_HANDLE,
                ARG_TPM2_PCRS,
                ARG_TPM2_PUBLIC_KEY,
                ARG_TPM2_PUBLIC_KEY_PCRS,
                ARG_TPM2_PCRLOCK,
                ARG_SPLIT,
                ARG_INCLUDE_PARTITIONS,
                ARG_EXCLUDE_PARTITIONS,
                ARG_DEFER_PARTITIONS,
                ARG_SECTOR_SIZE,
                ARG_SKIP_PARTITIONS,
                ARG_ARCHITECTURE,
                ARG_OFFLINE,
                ARG_COPY_FROM,
                ARG_MAKE_DDI,
        };

        static const struct option options[] = {
                { "help",                 no_argument,       NULL, 'h'                      },
                { "version",              no_argument,       NULL, ARG_VERSION              },
                { "no-pager",             no_argument,       NULL, ARG_NO_PAGER             },
                { "no-legend",            no_argument,       NULL, ARG_NO_LEGEND            },
                { "dry-run",              required_argument, NULL, ARG_DRY_RUN              },
                { "empty",                required_argument, NULL, ARG_EMPTY                },
                { "discard",              required_argument, NULL, ARG_DISCARD              },
                { "factory-reset",        required_argument, NULL, ARG_FACTORY_RESET        },
                { "can-factory-reset",    no_argument,       NULL, ARG_CAN_FACTORY_RESET    },
                { "root",                 required_argument, NULL, ARG_ROOT                 },
                { "image",                required_argument, NULL, ARG_IMAGE                },
                { "image-policy",         required_argument, NULL, ARG_IMAGE_POLICY         },
                { "seed",                 required_argument, NULL, ARG_SEED                 },
                { "pretty",               required_argument, NULL, ARG_PRETTY               },
                { "definitions",          required_argument, NULL, ARG_DEFINITIONS          },
                { "size",                 required_argument, NULL, ARG_SIZE                 },
                { "json",                 required_argument, NULL, ARG_JSON                 },
                { "key-file",             required_argument, NULL, ARG_KEY_FILE             },
                { "private-key",          required_argument, NULL, ARG_PRIVATE_KEY          },
                { "certificate",          required_argument, NULL, ARG_CERTIFICATE          },
                { "tpm2-device",          required_argument, NULL, ARG_TPM2_DEVICE          },
                { "tpm2-device-key",      required_argument, NULL, ARG_TPM2_DEVICE_KEY      },
                { "tpm2-seal-key-handle", required_argument, NULL, ARG_TPM2_SEAL_KEY_HANDLE },
                { "tpm2-pcrs",            required_argument, NULL, ARG_TPM2_PCRS            },
                { "tpm2-public-key",      required_argument, NULL, ARG_TPM2_PUBLIC_KEY      },
                { "tpm2-public-key-pcrs", required_argument, NULL, ARG_TPM2_PUBLIC_KEY_PCRS },
                { "tpm2-pcrlock",         required_argument, NULL, ARG_TPM2_PCRLOCK         },
                { "split",                required_argument, NULL, ARG_SPLIT                },
                { "include-partitions",   required_argument, NULL, ARG_INCLUDE_PARTITIONS   },
                { "exclude-partitions",   required_argument, NULL, ARG_EXCLUDE_PARTITIONS   },
                { "defer-partitions",     required_argument, NULL, ARG_DEFER_PARTITIONS     },
                { "sector-size",          required_argument, NULL, ARG_SECTOR_SIZE          },
                { "architecture",         required_argument, NULL, ARG_ARCHITECTURE         },
                { "offline",              required_argument, NULL, ARG_OFFLINE              },
                { "copy-from",            required_argument, NULL, ARG_COPY_FROM            },
                { "copy-source",          required_argument, NULL, 's'                      },
                { "make-ddi",             required_argument, NULL, ARG_MAKE_DDI             },
                {}
        };

        bool auto_hash_pcr_values = true, auto_public_key_pcr_mask = true, auto_pcrlock = true;
        int c, r;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "hs:SCP", options, NULL)) >= 0)

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
                        if (isempty(optarg)) {
                                arg_empty = EMPTY_UNSET;
                                break;
                        }

                        arg_empty = empty_mode_from_string(optarg);
                        if (arg_empty < 0)
                                return log_error_errno(arg_empty, "Failed to parse --empty= parameter: %s", optarg);

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

                case ARG_IMAGE_POLICY:
                        r = parse_image_policy_argument(optarg, &arg_image_policy);
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

                case ARG_DEFINITIONS: {
                        _cleanup_free_ char *path = NULL;
                        r = parse_path_argument(optarg, false, &path);
                        if (r < 0)
                                return r;
                        if (strv_consume(&arg_definitions, TAKE_PTR(path)) < 0)
                                return log_oom();
                        break;
                }

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
                                log_warning("Specified size is not a multiple of 4096, rounding up automatically. (%" PRIu64 " %s %" PRIu64 ")",
                                            parsed, special_glyph(SPECIAL_GLYPH_ARROW_RIGHT), rounded);

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

                case ARG_PRIVATE_KEY: {
                        _cleanup_(erase_and_freep) char *k = NULL;
                        size_t n = 0;

                        r = read_full_file_full(
                                        AT_FDCWD, optarg, UINT64_MAX, SIZE_MAX,
                                        READ_FULL_FILE_SECURE|READ_FULL_FILE_WARN_WORLD_READABLE|READ_FULL_FILE_CONNECT_SOCKET,
                                        NULL,
                                        &k, &n);
                        if (r < 0)
                                return log_error_errno(r, "Failed to read key file '%s': %m", optarg);

                        EVP_PKEY_free(arg_private_key);
                        arg_private_key = NULL;
                        r = parse_private_key(k, n, &arg_private_key);
                        if (r < 0)
                                return r;
                        break;
                }

                case ARG_CERTIFICATE: {
                        _cleanup_free_ char *cert = NULL;
                        size_t n = 0;

                        r = read_full_file_full(
                                        AT_FDCWD, optarg, UINT64_MAX, SIZE_MAX,
                                        READ_FULL_FILE_CONNECT_SOCKET,
                                        NULL,
                                        &cert, &n);
                        if (r < 0)
                                return log_error_errno(r, "Failed to read certificate file '%s': %m", optarg);

                        X509_free(arg_certificate);
                        arg_certificate = NULL;
                        r = parse_x509_certificate(cert, n, &arg_certificate);
                        if (r < 0)
                                return r;
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

                case ARG_TPM2_DEVICE_KEY:
                        r = parse_path_argument(optarg, /* suppress_root= */ false, &arg_tpm2_device_key);
                        if (r < 0)
                                return r;

                        break;

                case ARG_TPM2_SEAL_KEY_HANDLE:
                        r = safe_atou32_full(optarg, 16, &arg_tpm2_seal_key_handle);
                        if (r < 0)
                                return log_error_errno(r, "Could not parse TPM2 seal key handle index '%s': %m", optarg);

                        break;

                case ARG_TPM2_PCRS:
                        auto_hash_pcr_values = false;
                        r = tpm2_parse_pcr_argument_append(optarg, &arg_tpm2_hash_pcr_values, &arg_tpm2_n_hash_pcr_values);
                        if (r < 0)
                                return r;

                        break;

                case ARG_TPM2_PUBLIC_KEY:
                        r = parse_path_argument(optarg, /* suppress_root= */ false, &arg_tpm2_public_key);
                        if (r < 0)
                                return r;

                        break;

                case ARG_TPM2_PUBLIC_KEY_PCRS:
                        auto_public_key_pcr_mask = false;
                        r = tpm2_parse_pcr_argument_to_mask(optarg, &arg_tpm2_public_key_pcr_mask);
                        if (r < 0)
                                return r;

                        break;

                case ARG_TPM2_PCRLOCK:
                        r = parse_path_argument(optarg, /* suppress_root= */ false, &arg_tpm2_pcrlock);
                        if (r < 0)
                                return r;

                        auto_pcrlock = false;
                        break;

                case ARG_SPLIT:
                        r = parse_boolean_argument("--split=", optarg, NULL);
                        if (r < 0)
                                return r;

                        arg_split = r;
                        break;

                case ARG_INCLUDE_PARTITIONS:
                        if (arg_filter_partitions_type == FILTER_PARTITIONS_EXCLUDE)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Combination of --include-partitions= and --exclude-partitions= is invalid.");

                        r = parse_partition_types(optarg, &arg_filter_partitions, &arg_n_filter_partitions);
                        if (r < 0)
                                return r;

                        arg_filter_partitions_type = FILTER_PARTITIONS_INCLUDE;

                        break;

                case ARG_EXCLUDE_PARTITIONS:
                        if (arg_filter_partitions_type == FILTER_PARTITIONS_INCLUDE)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Combination of --include-partitions= and --exclude-partitions= is invalid.");

                        r = parse_partition_types(optarg, &arg_filter_partitions, &arg_n_filter_partitions);
                        if (r < 0)
                                return r;

                        arg_filter_partitions_type = FILTER_PARTITIONS_EXCLUDE;

                        break;

                case ARG_DEFER_PARTITIONS:
                        r = parse_partition_types(optarg, &arg_defer_partitions, &arg_n_defer_partitions);
                        if (r < 0)
                                return r;

                        break;

                case ARG_SECTOR_SIZE:
                        r = parse_sector_size(optarg, &arg_sector_size);
                        if (r < 0)
                                return r;

                        break;

                case ARG_ARCHITECTURE:
                        r = architecture_from_string(optarg);
                        if (r < 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid architecture '%s'", optarg);

                        arg_architecture = r;
                        break;

                case ARG_OFFLINE:
                        if (streq(optarg, "auto"))
                                arg_offline = -1;
                        else {
                                r = parse_boolean_argument("--offline=", optarg, NULL);
                                if (r < 0)
                                        return r;

                                arg_offline = r;
                        }

                        break;

                case ARG_COPY_FROM: {
                        _cleanup_free_ char *p = NULL;

                        r = parse_path_argument(optarg, /* suppress_root= */ false, &p);
                        if (r < 0)
                                return r;

                        if (strv_consume(&arg_copy_from, TAKE_PTR(p)) < 0)
                                return log_oom();

                        break;
                }

                case 's':
                        r = parse_path_argument(optarg, /* suppress_root= */ false, &arg_copy_source);
                        if (r < 0)
                                return r;
                        break;

                case ARG_MAKE_DDI:
                        if (!filename_is_valid(optarg))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid DDI type: %s", optarg);

                        r = free_and_strdup_warn(&arg_make_ddi, optarg);
                        if (r < 0)
                                return r;
                        break;

                case 'S':
                        r = free_and_strdup_warn(&arg_make_ddi, "sysext");
                        if (r < 0)
                                return r;
                        break;

                case 'C':
                        r = free_and_strdup_warn(&arg_make_ddi, "confext");
                        if (r < 0)
                                return r;
                        break;

                case 'P':
                        r = free_and_strdup_warn(&arg_make_ddi, "portable");
                        if (r < 0)
                                return r;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }

        if (argc - optind > 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Expected at most one argument, the path to the block device or image file.");

        if (arg_make_ddi) {
                if (arg_definitions)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Combination of --make-ddi= and --definitions= is not supported.");
                if (!IN_SET(arg_empty, EMPTY_UNSET, EMPTY_CREATE))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Combination of --make-ddi= and --empty=%s is not supported.", empty_mode_to_string(arg_empty));

                /* Imply automatic sizing in DDI mode */
                if (arg_size == UINT64_MAX)
                        arg_size_auto = true;

                if (!arg_copy_source)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "No --copy-source= specified, refusing.");

                r = dir_is_empty(arg_copy_source, /* ignore_hidden_or_backup= */ false);
                if (r < 0)
                        return log_error_errno(r, "Failed to determine if '%s' is empty: %m", arg_copy_source);
                if (r > 0)
                        return log_error_errno(SYNTHETIC_ERRNO(ENOENT), "Source directory '%s' is empty, refusing to create empty image.", arg_copy_source);

                if (sd_id128_is_null(arg_seed) && !arg_randomize) {
                        /* We don't want that /etc/machine-id leaks into any image built this way, hence
                         * let's randomize the seed if not specified explicitly */
                        log_notice("No seed value specified, randomizing generated UUIDs, resulting image will not be reproducible.");
                        arg_randomize = true;
                }

                arg_empty = EMPTY_CREATE;
        }

        if (arg_empty == EMPTY_UNSET) /* default to refuse mode, if not otherwise specified */
                arg_empty = EMPTY_REFUSE;

        if (arg_factory_reset > 0 && IN_SET(arg_empty, EMPTY_FORCE, EMPTY_REQUIRE, EMPTY_CREATE))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Combination of --factory-reset=yes and --empty=force/--empty=require/--empty=create is invalid.");

        if (arg_can_factory_reset)
                arg_dry_run = true; /* When --can-factory-reset is specified we don't make changes, hence
                                     * non-dry-run mode makes no sense. Thus, imply dry run mode so that we
                                     * open things strictly read-only. */
        else if (arg_empty == EMPTY_CREATE)
                arg_dry_run = false; /* Imply --dry-run=no if we create the loopback file anew. After all we
                                      * cannot really break anyone's partition tables that way. */

        /* Disable pager once we are not just reviewing, but doing things. */
        if (!arg_dry_run)
                arg_pager_flags |= PAGER_DISABLE;

        if (arg_empty == EMPTY_CREATE && arg_size == UINT64_MAX && !arg_size_auto)
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
                                       "A path to a device node or image file must be specified when --make-ddi=, --empty=force, --empty=require or --empty=create are used.");

        if (arg_split && !arg_node)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "A path to an image file must be specified when --split is used.");

        if (auto_pcrlock) {
                assert(!arg_tpm2_pcrlock);

                r = tpm2_pcrlock_search_file(NULL, NULL, &arg_tpm2_pcrlock);
                if (r < 0) {
                        if (r != -ENOENT)
                                log_warning_errno(r, "Search for pcrlock.json failed, assuming it does not exist: %m");
                } else
                        log_debug("Automatically using pcrlock policy '%s'.", arg_tpm2_pcrlock);
        }

        if (auto_public_key_pcr_mask) {
                assert(arg_tpm2_public_key_pcr_mask == 0);
                arg_tpm2_public_key_pcr_mask = INDEX_TO_MASK(uint32_t, TPM2_PCR_KERNEL_BOOT);
        }

        if (auto_hash_pcr_values && !arg_tpm2_pcrlock) { /* Only lock to PCR 7 if no pcr policy is specified. */
                assert(arg_tpm2_n_hash_pcr_values == 0);

                if (!GREEDY_REALLOC_APPEND(
                                    arg_tpm2_hash_pcr_values,
                                    arg_tpm2_n_hash_pcr_values,
                                    &TPM2_PCR_VALUE_MAKE(TPM2_PCR_INDEX_DEFAULT, /* hash= */ 0, /* value= */ {}),
                                    1))
                        return log_oom();
        }

        if (arg_pretty < 0 && isatty(STDOUT_FILENO))
                arg_pretty = true;

        if (arg_architecture >= 0) {
                FOREACH_ARRAY(p, arg_filter_partitions, arg_n_filter_partitions)
                        *p = gpt_partition_type_override_architecture(*p, arg_architecture);

                FOREACH_ARRAY(p, arg_defer_partitions, arg_n_defer_partitions)
                        *p = gpt_partition_type_override_architecture(*p, arg_architecture);
        }

        return 1;
}

static int parse_proc_cmdline_factory_reset(void) {
        bool b;
        int r;

        if (arg_factory_reset >= 0) /* Never override what is specified on the process command line */
                return 0;

        if (!in_initrd()) /* Never honour kernel command line factory reset request outside of the initrd */
                return 0;

        r = proc_cmdline_get_bool("systemd.factory_reset", /* flags = */ 0, &b);
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
        if (r < 0) {
                if (r == -ENOENT || ERRNO_IS_NOT_SUPPORTED(r))
                        return 0;
                return log_error_errno(r, "Failed to read EFI variable FactoryReset: %m");
        }

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
        if (r < 0) {
                if (r == -ENOENT || ERRNO_IS_NOT_SUPPORTED(r))
                        return 0;
                return log_error_errno(r, "Failed to remove EFI variable FactoryReset: %m");
        }

        log_info("Successfully unset EFI variable FactoryReset.");
        return 0;
}

static int acquire_root_devno(
                const char *p,
                const char *root,
                int mode,
                char **ret,
                int *ret_fd) {

        _cleanup_free_ char *found_path = NULL, *node = NULL;
        dev_t devno, fd_devno = MODE_INVALID;
        _cleanup_close_ int fd = -EBADF;
        struct stat st;
        int r;

        assert(p);
        assert(ret);
        assert(ret_fd);

        fd = chase_and_open(p, root, CHASE_PREFIX_ROOT, mode, &found_path);
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

        r = devname_from_devnum(S_IFBLK, devno, &node);
        if (r < 0)
                return log_debug_errno(r, "Failed to determine canonical path for '%s': %m", p);

        /* Only if we still look at the same block device we can reuse the fd. Otherwise return an
         * invalidated fd. */
        if (fd_devno != MODE_INVALID && fd_devno == devno) {
                /* Tell udev not to interfere while we are processing the device */
                if (flock(fd, arg_dry_run ? LOCK_SH : LOCK_EX) < 0)
                        return log_error_errno(errno, "Failed to lock device '%s': %m", node);

                *ret_fd = TAKE_FD(fd);
        } else
                *ret_fd = -EBADF;

        *ret = TAKE_PTR(node);
        return 0;
}

static int find_root(Context *context) {
        _cleanup_free_ char *device = NULL;
        int r;

        assert(context);

        if (arg_node) {
                if (arg_empty == EMPTY_CREATE) {
                        _cleanup_close_ int fd = -EBADF;
                        _cleanup_free_ char *s = NULL;

                        s = strdup(arg_node);
                        if (!s)
                                return log_oom();

                        fd = open(arg_node, O_RDONLY|O_CREAT|O_EXCL|O_CLOEXEC|O_NOFOLLOW, 0666);
                        if (fd < 0)
                                return log_error_errno(errno, "Failed to create '%s': %m", arg_node);

                        context->node = TAKE_PTR(s);
                        context->node_is_our_file = true;
                        context->backing_fd = TAKE_FD(fd);
                        return 0;
                }

                /* Note that we don't specify a root argument here: if the user explicitly configured a node
                 * we'll take it relative to the host, not the image */
                r = acquire_root_devno(arg_node, NULL, O_RDONLY|O_CLOEXEC, &context->node, &context->backing_fd);
                if (r == -EUCLEAN)
                        return btrfs_log_dev_root(LOG_ERR, r, arg_node);
                if (r < 0)
                        return log_error_errno(r, "Failed to open file or determine backing device of %s: %m", arg_node);

                return 0;
        }

        assert(IN_SET(arg_empty, EMPTY_REFUSE, EMPTY_ALLOW));

        /* If the root mount has been replaced by some form of volatile file system (overlayfs), the
         * original root block device node is symlinked in /run/systemd/volatile-root. Let's read that
         * here. */
        r = readlink_malloc("/run/systemd/volatile-root", &device);
        if (r == -ENOENT) { /* volatile-root not found */
                /* Let's search for the root device. We look for two cases here: first in /, and then in /usr. The
                * latter we check for cases where / is a tmpfs and only /usr is an actual persistent block device
                * (think: volatile setups) */

                FOREACH_STRING(p, "/", "/usr") {

                        r = acquire_root_devno(p, arg_root, O_RDONLY|O_DIRECTORY|O_CLOEXEC, &context->node,
                                               &context->backing_fd);
                        if (r < 0) {
                                if (r == -EUCLEAN)
                                        return btrfs_log_dev_root(LOG_ERR, r, p);
                                if (r != -ENODEV)
                                        return log_error_errno(r, "Failed to determine backing device of %s: %m", p);
                        } else
                                return 0;
                }
        } else if (r < 0)
                return log_error_errno(r, "Failed to read symlink /run/systemd/volatile-root: %m");
        else {
                r = acquire_root_devno(device, NULL, O_RDONLY|O_CLOEXEC, &context->node, &context->backing_fd);
                if (r == -EUCLEAN)
                        return btrfs_log_dev_root(LOG_ERR, r, device);
                if (r < 0)
                        return log_error_errno(r, "Failed to open file or determine backing device of %s: %m", device);

                return 0;
        }

        return log_error_errno(SYNTHETIC_ERRNO(ENODEV), "Failed to discover root block device.");
}

static int resize_pt(int fd, uint64_t sector_size) {
        _cleanup_(fdisk_unref_contextp) struct fdisk_context *c = NULL;
        int r;

        /* After resizing the backing file we need to resize the partition table itself too, so that it takes
         * possession of the enlarged backing file. For this it suffices to open the device with libfdisk and
         * immediately write it again, with no changes. */

        r = fdisk_new_context_at(fd, /* path= */ NULL, /* read_only= */ false, sector_size, &c);
        if (r < 0)
                return log_error_errno(r, "Failed to open device '%s': %m", FORMAT_PROC_FD_PATH(fd));

        r = fdisk_has_label(c);
        if (r < 0)
                return log_error_errno(r, "Failed to determine whether disk '%s' has a disk label: %m", FORMAT_PROC_FD_PATH(fd));
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
                LoopDevice *loop_device,
                uint64_t sector_size) {

        _cleanup_close_ int writable_fd = -EBADF;
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

                r = blockdev_get_device_size(*fd, &current_size);
                if (r < 0)
                        return log_error_errno(r, "Failed to determine size of block device %s: %m", node);
        } else {
                r = stat_verify_regular(&st);
                if (r < 0)
                        return log_error_errno(r, "Specified path '%s' is not a regular file or loopback block device, cannot resize: %m", node);

                assert(!backing_file);
                assert(!loop_device);
                current_size = st.st_size;
        }

        if (current_size >= arg_size) {
                log_info("File '%s' already is of requested size or larger, not growing. (%s >= %s)",
                         node, FORMAT_BYTES(current_size), FORMAT_BYTES(arg_size));
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
                                               "Size of backing file '%s' of loopback block device '%s' don't match, refusing.",
                                               node, backing_file);
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
                                                       node, FORMAT_BYTES(current_size), FORMAT_BYTES(arg_size));

                        /* Fallback to truncation, if fallocate() is not supported. */
                        log_debug("Backing file system does not support fallocate(), falling back to ftruncate().");
                } else {
                        if (current_size == 0) /* Likely regular file just created by us */
                                log_info("Allocated %s for '%s'.", FORMAT_BYTES(arg_size), node);
                        else
                                log_info("File '%s' grown from %s to %s by allocation.",
                                         node, FORMAT_BYTES(current_size), FORMAT_BYTES(arg_size));

                        goto done;
                }
        }

        if (ftruncate(writable_fd, arg_size) < 0)
                return log_error_errno(errno, "Failed to grow '%s' from %s to %s by truncation: %m",
                                       node, FORMAT_BYTES(current_size), FORMAT_BYTES(arg_size));

        if (current_size == 0) /* Likely regular file just created by us */
                log_info("Sized '%s' to %s.", node, FORMAT_BYTES(arg_size));
        else
                log_info("File '%s' grown from %s to %s by truncation.",
                         node, FORMAT_BYTES(current_size), FORMAT_BYTES(arg_size));

done:
        r = resize_pt(writable_fd, sector_size);
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
        uint64_t sum;

        assert(c);

        sum = round_up_size(GPT_METADATA_SIZE, 4096);

        LIST_FOREACH(partitions, p, c->partitions) {
                uint64_t m;

                if (p->dropped)
                        continue;

                m = partition_min_size_with_padding(c, p);
                if (m > UINT64_MAX - sum)
                        return log_error_errno(SYNTHETIC_ERRNO(EOVERFLOW), "Image would grow too large, refusing.");

                sum += m;
        }

        if (c->total != UINT64_MAX)
                /* Image already allocated? Then show its size. */
                log_info("Automatically determined minimal disk image size as %s, current image size is %s.",
                         FORMAT_BYTES(sum), FORMAT_BYTES(c->total));
        else
                /* If the image is being created right now, then it has no previous size, suppress any comment about it hence. */
                log_info("Automatically determined minimal disk image size as %s.",
                         FORMAT_BYTES(sum));

        arg_size = sum;
        return 0;
}

static int run(int argc, char *argv[]) {
        _cleanup_(loop_device_unrefp) LoopDevice *loop_device = NULL;
        _cleanup_(umount_and_freep) char *mounted_dir = NULL;
        _cleanup_(context_freep) Context* context = NULL;
        bool node_is_our_loop = false;
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

#if HAVE_LIBCRYPTSETUP
        cryptsetup_enable_logging(NULL);
#endif

        if (arg_image) {
                assert(!arg_root);

                /* Mount this strictly read-only: we shall modify the partition table, not the file
                 * systems */
                r = mount_image_privately_interactively(
                                arg_image,
                                arg_image_policy,
                                DISSECT_IMAGE_MOUNT_READ_ONLY |
                                (arg_node ? DISSECT_IMAGE_DEVICE_READ_ONLY : 0) | /* If a different node to make changes to is specified let's open the device in read-only mode) */
                                DISSECT_IMAGE_GPT_ONLY |
                                DISSECT_IMAGE_RELAX_VAR_CHECK |
                                DISSECT_IMAGE_USR_NO_ROOT |
                                DISSECT_IMAGE_REQUIRE_ROOT,
                                &mounted_dir,
                                /* ret_dir_fd= */ NULL,
                                &loop_device);
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

        if (!arg_copy_source && arg_root) {
                /* If no explicit copy source is specified, then use --root=/--image= */
                arg_copy_source = strdup(arg_root);
                if (!arg_copy_source)
                        return log_oom();
        }

        context = context_new(arg_seed);
        if (!context)
                return log_oom();

        r = context_copy_from(context);
        if (r < 0)
                return r;

        if (arg_make_ddi) {
                _cleanup_free_ char *d = NULL, *dp = NULL;
                assert(!arg_definitions);

                d = strjoin(arg_make_ddi, ".repart.d/");
                if (!d)
                        return log_oom();

                r = search_and_access(d, F_OK, NULL, CONF_PATHS_USR_STRV("systemd/repart/definitions"), &dp);
                if (r < 0)
                        return log_error_errno(r, "DDI type '%s' is not defined: %m", arg_make_ddi);

                if (strv_consume(&arg_definitions, TAKE_PTR(dp)) < 0)
                        return log_oom();
        } else
                strv_uniq(arg_definitions);

        r = context_read_definitions(context);
        if (r < 0)
                return r;

        r = find_root(context);
        if (r == -ENODEV)
                return 76; /* Special return value which means "Root block device not found, so not doing
                            * anything". This isn't really an error when called at boot. */
        if (r < 0)
                return r;

        if (arg_size != UINT64_MAX) {
                r = resize_backing_fd(
                                context->node,
                                &context->backing_fd,
                                node_is_our_loop ? arg_image : NULL,
                                node_is_our_loop ? loop_device : NULL,
                                context->sector_size);
                if (r < 0)
                        return r;
        }

        r = context_load_partition_table(context);
        if (r == -EHWPOISON)
                return 77; /* Special return value which means "Not GPT, so not doing anything". This isn't
                            * really an error when called at boot. */
        if (r < 0)
                return r;
        context->from_scratch = r > 0; /* Starting from scratch */

        if (arg_can_factory_reset) {
                r = context_can_factory_reset(context);
                if (r < 0)
                        return r;
                if (r == 0)
                        return EXIT_FAILURE;

                return 0;
        }

        r = context_factory_reset(context);
        if (r < 0)
                return r;
        if (r > 0) {
                /* We actually did a factory reset! */
                r = remove_efi_variable_factory_reset();
                if (r < 0)
                        return r;

                /* Reload the reduced partition table */
                context_unload_partition_table(context);
                r = context_load_partition_table(context);
                if (r < 0)
                        return r;
        }

        r = context_read_seed(context, arg_root);
        if (r < 0)
                return r;

        /* Make sure each partition has a unique UUID and unique label */
        r = context_acquire_partition_uuids_and_labels(context);
        if (r < 0)
                return r;

        /* Open all files to copy blocks from now, since we want to take their size into consideration */
        r = context_open_copy_block_paths(
                        context,
                        loop_device ? loop_device->devno :         /* if --image= is specified, only allow partitions on the loopback device */
                                      arg_root && !arg_image ? 0 : /* if --root= is specified, don't accept any block device */
                                      (dev_t) -1);                 /* if neither is specified, make no restrictions */
        if (r < 0)
                return r;

        r = context_minimize(context);
        if (r < 0)
                return r;

        if (arg_size_auto) {
                r = determine_auto_size(context);
                if (r < 0)
                        return r;

                /* Flush out everything again, and let's grow the file first, then start fresh */
                context_unload_partition_table(context);

                assert(arg_size != UINT64_MAX);
                r = resize_backing_fd(
                                context->node,
                                &context->backing_fd,
                                node_is_our_loop ? arg_image : NULL,
                                node_is_our_loop ? loop_device : NULL,
                                context->sector_size);
                if (r < 0)
                        return r;

                r = context_load_partition_table(context);
                if (r < 0)
                        return r;
        }

        /* First try to fit new partitions in, dropping by priority until it fits */
        for (;;) {
                uint64_t largest_free_area;

                if (context_allocate_partitions(context, &largest_free_area))
                        break; /* Success! */

                if (!context_drop_or_foreignize_one_priority(context)) {
                        r = log_error_errno(SYNTHETIC_ERRNO(ENOSPC),
                                            "Can't fit requested partitions into available free space (%s), refusing.",
                                            FORMAT_BYTES(largest_free_area));
                        determine_auto_size(context);
                        return r;
                }
        }

        /* Now assign free space according to the weight logic */
        r = context_grow_partitions(context);
        if (r < 0)
                return r;

        /* Now calculate where each new partition gets placed */
        context_place_partitions(context);

        (void) context_dump(context, /*late=*/ false);

        r = context_write_partition_table(context);
        if (r < 0)
                return r;

        r = context_split(context);
        if (r < 0)
                return r;

        (void) context_dump(context, /*late=*/ true);

        context->node = mfree(context->node);

        LIST_FOREACH(partitions, p, context->partitions)
                p->split_path = mfree(p->split_path);

        return 0;
}

DEFINE_MAIN_FUNCTION_WITH_POSITIVE_FAILURE(run);
