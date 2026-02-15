/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <getopt.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "sd-daemon.h"
#include "sd-id128.h"
#include "sd-json.h"
#include "sd-varlink.h"

#include "alloc-util.h"
#include "ask-password-api.h"
#include "blkid-util.h"
#include "blockdev-list.h"
#include "blockdev-util.h"
#include "btrfs-util.h"
#include "build.h"
#include "chase.h"
#include "chattr-util.h"
#include "conf-files.h"
#include "conf-parser.h"
#include "constants.h"
#include "copy.h"
#include "cryptsetup-util.h"
#include "device-util.h"
#include "devnum-util.h"
#include "dirent-util.h"
#include "dissect-image.h"
#include "efivars.h"
#include "errno-util.h"
#include "extract-word.h"
#include "factory-reset.h"
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
#include "image-policy.h"
#include "initrd-util.h"
#include "install-file.h"
#include "io-util.h"
#include "json-util.h"
#include "libmount-util.h"
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
#include "parse-util.h"
#include "pretty-print.h"
#include "process-util.h"
#include "random-util.h"
#include "ratelimit.h"
#include "reread-partition-table.h"
#include "resize-fs.h"
#include "rm-rf.h"
#include "set.h"
#include "sort-util.h"
#include "specifier.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "sync-util.h"
#include "terminal-util.h"
#include "time-util.h"
#include "tmpfile-util.h"
#include "tpm2-pcr.h"
#include "tpm2-util.h"
#include "utf8.h"
#include "varlink-io.systemd.Repart.h"
#include "varlink-util.h"
#include "xattr-util.h"

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

/* LUKS2 default volume key size (no integrity). */
#define VOLUME_KEY_SIZE (512ULL/8ULL)

/* Use 4K as the default filesystem sector size because as long as the partitions are aligned to 4K, the
 * filesystems will then also be compatible with sector sizes 512, 1024 and 2048. */
#define DEFAULT_FILESYSTEM_SECTOR_SIZE 4096ULL

/* Minimum sizes for the ESP depending on sector size. What the minimum is, is severely underdocumented, but
 * it appears for 4K sector size it must be 260M, and otherwise 100M. This is what Microsoft says here:
 *
 * https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/configure-uefigpt-based-hard-drive-partitions?view=windows-11
 * https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/oem-deployment-of-windows-desktop-editions-sample-scripts?view=windows-11&preserve-view=true#-createpartitions-uefitxt
 */
#define ESP_MIN_SIZE (100 * U64_MB)
#define ESP_MIN_SIZE_4K (260 * U64_MB)

#define APIVFS_TMP_DIRS_NULSTR "proc\0sys\0dev\0tmp\0run\0var/tmp\0"

#define AUTOMATIC_FSTAB_HEADER_START "# Start section ↓ of automatically generated fstab by systemd-repart"
#define AUTOMATIC_FSTAB_HEADER_END   "# End section ↑ of automatically generated fstab by systemd-repart"

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

typedef enum AppendMode {
        APPEND_NO,
        APPEND_AUTO,
        APPEND_REPLACE,
        _APPEND_MODE_MAX,
        _APPEND_MODE_INVALID = -EINVAL,
} AppendMode;

static EmptyMode arg_empty = EMPTY_UNSET;
static bool arg_dry_run = true;
static char *arg_node = NULL;
static bool arg_node_none = false;
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
static sd_json_format_flags_t arg_json_format_flags = SD_JSON_FORMAT_OFF;
static PagerFlags arg_pager_flags = 0;
static bool arg_legend = true;
static struct iovec arg_key = {};
static char *arg_private_key = NULL;
static KeySourceType arg_private_key_source_type = OPENSSL_KEY_SOURCE_FILE;
static char *arg_private_key_source = NULL;
static char *arg_certificate = NULL;
static CertificateSourceType arg_certificate_source_type = OPENSSL_CERTIFICATE_SOURCE_FILE;
static char *arg_certificate_source = NULL;
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
static bool arg_defer_partitions_empty = false;
static bool arg_defer_partitions_factory_reset = false;
static uint64_t arg_sector_size = 0;
static ImagePolicy *arg_image_policy = NULL;
static Architecture arg_architecture = _ARCHITECTURE_INVALID;
static int arg_offline = -1;
static char **arg_copy_from = NULL;
static char *arg_copy_source = NULL;
static char *arg_make_ddi = NULL;
static AppendMode arg_append_fstab = APPEND_NO;
static char *arg_generate_fstab = NULL;
static char *arg_generate_crypttab = NULL;
static Set *arg_verity_settings = NULL;
static bool arg_relax_copy_block_security = false;
static bool arg_varlink = false;

STATIC_DESTRUCTOR_REGISTER(arg_node, freep);
STATIC_DESTRUCTOR_REGISTER(arg_root, freep);
STATIC_DESTRUCTOR_REGISTER(arg_image, freep);
STATIC_DESTRUCTOR_REGISTER(arg_definitions, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_key, iovec_done_erase);
STATIC_DESTRUCTOR_REGISTER(arg_private_key, freep);
STATIC_DESTRUCTOR_REGISTER(arg_private_key_source, freep);
STATIC_DESTRUCTOR_REGISTER(arg_certificate, freep);
STATIC_DESTRUCTOR_REGISTER(arg_certificate_source, freep);
STATIC_DESTRUCTOR_REGISTER(arg_tpm2_device, freep);
STATIC_DESTRUCTOR_REGISTER(arg_tpm2_device_key, freep);
STATIC_DESTRUCTOR_REGISTER(arg_tpm2_hash_pcr_values, freep);
STATIC_DESTRUCTOR_REGISTER(arg_tpm2_public_key, freep);
STATIC_DESTRUCTOR_REGISTER(arg_tpm2_pcrlock, freep);
STATIC_DESTRUCTOR_REGISTER(arg_filter_partitions, freep);
STATIC_DESTRUCTOR_REGISTER(arg_defer_partitions, freep);
STATIC_DESTRUCTOR_REGISTER(arg_image_policy, image_policy_freep);
STATIC_DESTRUCTOR_REGISTER(arg_copy_from, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_copy_source, freep);
STATIC_DESTRUCTOR_REGISTER(arg_make_ddi, freep);
STATIC_DESTRUCTOR_REGISTER(arg_generate_fstab, freep);
STATIC_DESTRUCTOR_REGISTER(arg_generate_crypttab, freep);
STATIC_DESTRUCTOR_REGISTER(arg_verity_settings, set_freep);

typedef enum ProgressPhase {
        PROGRESS_LOADING_DEFINITIONS,
        PROGRESS_LOADING_TABLE,
        PROGRESS_OPENING_COPY_BLOCK_SOURCES,
        PROGRESS_ACQUIRING_PARTITION_LABELS,
        PROGRESS_MINIMIZING,
        PROGRESS_PLACING,
        PROGRESS_WIPING_DISK,
        PROGRESS_WIPING_PARTITION,
        PROGRESS_COPYING_PARTITION,
        PROGRESS_FORMATTING_PARTITION,
        PROGRESS_ADJUSTING_PARTITION,
        PROGRESS_WRITING_TABLE,
        PROGRESS_REREADING_TABLE,
        _PROGRESS_PHASE_MAX,
        _PROGRESS_PHASE_INVALID = -EINVAL,
} ProgressPhase;

typedef struct FreeArea FreeArea;

typedef enum EncryptMode {
        ENCRYPT_OFF,
        ENCRYPT_KEY_FILE,
        ENCRYPT_TPM2,
        ENCRYPT_KEY_FILE_TPM2,
        _ENCRYPT_MODE_MAX,
        _ENCRYPT_MODE_INVALID = -EINVAL,
} EncryptMode;

typedef enum IntegrityMode {
        INTEGRITY_OFF,
        INTEGRITY_INLINE,
        _INTEGRITY_MODE_MAX,
        _INTEGRITY_MODE_INVALID = -EINVAL,
} IntegrityMode;

typedef enum IntegrityAlg {
        INTEGRITY_ALG_HMAC_SHA1,
        INTEGRITY_ALG_HMAC_SHA256,
        INTEGRITY_ALG_HMAC_SHA512,
        _INTEGRITY_ALG_MAX,
        _INTEGRITY_ALG_INVALID = -EINVAL,
} IntegrityAlg;

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

typedef struct PartitionMountPoint {
        char *where;
        char *options;
} PartitionMountPoint;

static void partition_mountpoint_free_many(PartitionMountPoint *f, size_t n) {
        assert(f || n == 0);

        FOREACH_ARRAY(i, f, n) {
                free(i->where);
                free(i->options);
        }

        free(f);
}

typedef struct PartitionEncryptedVolume {
        char *name;
        char *keyfile;
        char *options;
        bool fixate_volume_key;
} PartitionEncryptedVolume;

static PartitionEncryptedVolume* partition_encrypted_volume_free(PartitionEncryptedVolume *c) {
        if (!c)
                return NULL;

        free(c->name);
        free(c->keyfile);
        free(c->options);

        return mfree(c);
}

typedef struct CopyFiles {
        char *source;
        char *target;
        CopyFlags flags;
} CopyFiles;

static void copy_files_free_many(CopyFiles *f, size_t n) {
        assert(f || n == 0);

        FOREACH_ARRAY(i, f, n) {
                free(i->source);
                free(i->target);
        }

        free(f);
}

static BtrfsSubvolFlags subvolume_flags_from_string_one(const char *s) {
        /* This is a bitmask (i.e. not dense), hence we don't use the "string-table.h" stuff here. */

        assert(s);

        if (streq(s, "ro"))
                return BTRFS_SUBVOL_RO;

        if (streq(s, "nodatacow"))
                return BTRFS_SUBVOL_NODATACOW;

        return _BTRFS_SUBVOL_FLAGS_INVALID;
}

static BtrfsSubvolFlags subvolume_flags_from_string(const char *s) {
        BtrfsSubvolFlags flags = 0;
        int r;

        assert(s);

        for (;;) {
                _cleanup_free_ char *f = NULL;
                BtrfsSubvolFlags ff;

                r = extract_first_word(&s, &f, ",", EXTRACT_DONT_COALESCE_SEPARATORS);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                ff = subvolume_flags_from_string_one(f);
                if (ff < 0)
                        return -EBADRQC; /* recognizable error */

                flags |= ff;
        }

        return flags;
}

typedef struct Subvolume {
        char *path;
        BtrfsSubvolFlags flags;
} Subvolume;

static Subvolume* subvolume_free(Subvolume *s) {
        if (!s)
                return NULL;

        free(s->path);
        return mfree(s);
}

DEFINE_PRIVATE_HASH_OPS_WITH_VALUE_DESTRUCTOR(subvolume_hash_ops, char, path_hash_func, path_compare, Subvolume, subvolume_free);

typedef struct Context Context;

typedef struct Partition {
        Context *context;

        char *definition_path;
        char **drop_in_files;

        GptPartitionType type;
        sd_id128_t current_uuid, new_uuid;
        bool new_uuid_is_set;
        char *current_label, *new_label;      /* Used for the GPT partition label + fs superblock label */
        char *new_volume_label;               /* used for LUKS superblock */
        sd_id128_t fs_uuid, luks_uuid, verity_uuid;
        uint8_t verity_salt[SHA256_DIGEST_SIZE];

        bool dropped;
        bool factory_reset;
        bool discarded;
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
        uint64_t copy_blocks_done;

        char *format;
        char **exclude_files_source;
        char **exclude_files_target;
        char **make_directories;
        char **make_symlinks;
        OrderedHashmap *subvolumes;
        char *default_subvolume;
        EncryptMode encrypt;
        struct iovec key;
        Tpm2PCRValue *tpm2_hash_pcr_values;
        size_t tpm2_n_hash_pcr_values;
        IntegrityMode integrity;
        IntegrityAlg integrity_alg;
        VerityMode verity;
        char *verity_match_key;
        MinimizeMode minimize;
        uint64_t verity_data_block_size;
        uint64_t verity_hash_block_size;
        char *compression;
        char *compression_level;
        uint64_t fs_sector_size;

        int add_validatefs;
        CopyFiles *copy_files;
        size_t n_copy_files;

        uint64_t gpt_flags;
        int no_auto;
        int read_only;
        int growfs;

        struct iovec roothash;

        char *split_name_format;
        char *split_path;

        PartitionMountPoint *mountpoints;
        size_t n_mountpoints;

        PartitionEncryptedVolume *encrypted_volume;

        unsigned last_percent;
        RateLimit progress_ratelimit;

        char *supplement_for_name;
        struct Partition *supplement_for, *supplement_target_for;
        struct Partition *suppressing;

        struct Partition *siblings[_VERITY_MODE_MAX];

        LIST_FIELDS(struct Partition, partitions);
} Partition;

#define PARTITION_IS_FOREIGN(p) (!(p)->definition_path)
#define PARTITION_EXISTS(p) (!!(p)->current_partition)
#define PARTITION_SUPPRESSED(p) ((p)->supplement_for && (p)->supplement_for->suppressing == (p))

struct FreeArea {
        Partition *after;
        uint64_t size;
        uint64_t allocated;
};

struct Context {
        char **definitions;

        LIST_HEAD(Partition, partitions);
        size_t n_partitions;

        FreeArea **free_areas;
        size_t n_free_areas;

        uint64_t start, end, total;

        struct fdisk_context *fdisk_context;
        uint64_t sector_size, grain_size, default_fs_sector_size;

        sd_id128_t seed;

        char *node;
        bool node_is_our_file;
        int backing_fd;

        EmptyMode empty;
        bool dry_run;

        bool from_scratch;

#if HAVE_OPENSSL
        X509 *certificate;
        OpenSSLAskPasswordUI *ui;
        EVP_PKEY *private_key;
#endif

        bool defer_partitions_empty;
        bool defer_partitions_factory_reset;

        sd_varlink *link; /* If 'more' is used on the Varlink call, we'll send progress info over this link */
};

static const char *empty_mode_table[_EMPTY_MODE_MAX] = {
        [EMPTY_UNSET]   = "unset",
        [EMPTY_REFUSE]  = "refuse",
        [EMPTY_ALLOW]   = "allow",
        [EMPTY_REQUIRE] = "require",
        [EMPTY_FORCE]   = "force",
        [EMPTY_CREATE]  = "create",
};

static const char *append_mode_table[_APPEND_MODE_MAX] = {
        [APPEND_NO]      = "no",
        [APPEND_AUTO]    = "auto",
        [APPEND_REPLACE] = "replace",
};

static const char *encrypt_mode_table[_ENCRYPT_MODE_MAX] = {
        [ENCRYPT_OFF] = "off",
        [ENCRYPT_KEY_FILE] = "key-file",
        [ENCRYPT_TPM2] = "tpm2",
        [ENCRYPT_KEY_FILE_TPM2] = "key-file+tpm2",
};

/* Going forward, the plan is to add two more modes:
 * [INTEGRITY_DATA] = "data" (interleave data and integrity tags on the same device),
 * [INTEGRITY_META] = "meta" (use a separate device for storing integrity tags).
 * Also, INTEGRITY_INLINE will be using hardware sector integrity fields when used
 * without encryption. */
static const char *integrity_mode_table[_INTEGRITY_MODE_MAX] = {
        [INTEGRITY_OFF]    = "off",    /* no integrity protection */
        [INTEGRITY_INLINE] = "inline", /* luks2 storage when encrypted */
};

static const char *integrity_alg_table[_INTEGRITY_ALG_MAX] = {
        [INTEGRITY_ALG_HMAC_SHA1]   = "hmac-sha1",
        [INTEGRITY_ALG_HMAC_SHA256] = "hmac-sha256",
        [INTEGRITY_ALG_HMAC_SHA512] = "hmac-sha512",
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

static const char *progress_phase_table[_PROGRESS_PHASE_MAX] = {
        [PROGRESS_LOADING_DEFINITIONS]        = "loading-definitions",
        [PROGRESS_LOADING_TABLE]              = "loading-table",
        [PROGRESS_OPENING_COPY_BLOCK_SOURCES] = "opening-copy-block-sources",
        [PROGRESS_ACQUIRING_PARTITION_LABELS] = "acquiring-partition-labels",
        [PROGRESS_MINIMIZING]                 = "minimizing",
        [PROGRESS_PLACING]                    = "placing",
        [PROGRESS_WIPING_DISK]                = "wiping-disk",
        [PROGRESS_WIPING_PARTITION]           = "wiping-partition",
        [PROGRESS_COPYING_PARTITION]          = "copying-partition",
        [PROGRESS_FORMATTING_PARTITION]       = "formatting-partition",
        [PROGRESS_ADJUSTING_PARTITION]        = "adjusting-partition",
        [PROGRESS_WRITING_TABLE]              = "writing-table",
        [PROGRESS_REREADING_TABLE]            = "rereading-table",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP(empty_mode, EmptyMode);
DEFINE_PRIVATE_STRING_TABLE_LOOKUP(append_mode, AppendMode);
DEFINE_PRIVATE_STRING_TABLE_LOOKUP_FROM_STRING_WITH_BOOLEAN(encrypt_mode, EncryptMode, ENCRYPT_KEY_FILE);
DEFINE_PRIVATE_STRING_TABLE_LOOKUP_FROM_STRING_WITH_BOOLEAN(integrity_mode, IntegrityMode, INTEGRITY_INLINE);
DEFINE_PRIVATE_STRING_TABLE_LOOKUP(integrity_alg, IntegrityAlg);
DEFINE_PRIVATE_STRING_TABLE_LOOKUP(verity_mode, VerityMode);
DEFINE_PRIVATE_STRING_TABLE_LOOKUP_FROM_STRING_WITH_BOOLEAN(minimize_mode, MinimizeMode, MINIMIZE_BEST);
DEFINE_PRIVATE_STRING_TABLE_LOOKUP_TO_STRING(progress_phase, ProgressPhase);

static uint64_t round_down_size(uint64_t v, uint64_t p) {
        return (v / p) * p;
}

static uint64_t round_up_size(uint64_t v, uint64_t p) {

        v = DIV_ROUND_UP(v, p);

        if (v > UINT64_MAX / p)
                return UINT64_MAX; /* overflow */

        return v * p;
}

/* calculates the size of a dm-verity hash partition's contents */
static int calculate_verity_hash_size(
                uint64_t data_bytes,
                uint64_t hash_block_size,
                uint64_t data_block_size,
                uint64_t *ret_bytes) {

        /* The calculation here is based on the documented on-disk format of the dm-verity
         * https://docs.kernel.org/admin-guide/device-mapper/verity.html#hash-tree
         *
         * Upstream implementation:
         * https://gitlab.com/cryptsetup/cryptsetup/-/blob/v2.7.5/lib/verity/verity_hash.c */

        uint64_t data_blocks = DIV_ROUND_UP(data_bytes, data_block_size);
        if (data_blocks > UINT64_MAX / data_block_size)
                return -EOVERFLOW;

        /* hashes that fit in one hash block (node in the merkle tree) */
        uint64_t hashes_per_hash_block = hash_block_size / SHA256_DIGEST_SIZE;

        /* initialize with 2 for the root of the merkle tree + the superblock */
        uint64_t hash_blocks = 2;

        /* iterate through the levels of the merkle tree bottom up */
        uint64_t remaining_blocks = data_blocks;

        while (remaining_blocks > hashes_per_hash_block) {
                uint64_t hash_blocks_for_level;
                /* number of hash blocks required to reference the underlying blocks */
                hash_blocks_for_level = DIV_ROUND_UP(remaining_blocks, hashes_per_hash_block);

                if (hash_blocks > UINT64_MAX - hash_blocks_for_level)
                        return -EOVERFLOW;

                /* add current layer to the total number of hash blocks */
                hash_blocks += hash_blocks_for_level;
                /* hashes on this level serve as the blocks on which the next level is built */
                remaining_blocks = hash_blocks_for_level;
        }

        if (hash_blocks > UINT64_MAX / hash_block_size)
                return -EOVERFLOW;

        *ret_bytes = hash_blocks * hash_block_size;

        return 0;
}

static Partition *partition_new(Context *c) {
        Partition *p;

        p = new(Partition, 1);
        if (!p)
                return NULL;

        *p = (Partition) {
                .context = c,
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
                .add_validatefs = -1,
                .last_percent = UINT_MAX,
                .progress_ratelimit = { 100 * USEC_PER_MSEC, 1 },
                .fs_sector_size = UINT64_MAX,
        };

        return p;
}

static void partition_unlink_supplement(Partition *p) {
        assert(p);

        assert(!p->supplement_for || !p->supplement_target_for); /* Can't be both */

        if (p->supplement_target_for) {
                assert(p->supplement_target_for->supplement_for == p);

                p->supplement_target_for->supplement_for = NULL;
        }

        if (p->supplement_for) {
                assert(p->supplement_for->supplement_target_for == p);
                assert(!p->supplement_for->suppressing || p->supplement_for->suppressing == p);

                p->supplement_for->supplement_target_for = p->supplement_for->suppressing = NULL;
        }

        p->supplement_for_name = mfree(p->supplement_for_name);
        p->supplement_target_for = p->supplement_for = p->suppressing = NULL;
}

static Partition* partition_free(Partition *p) {
        if (!p)
                return NULL;

        free(p->current_label);
        free(p->new_label);
        free(p->new_volume_label);
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
        strv_free(p->exclude_files_source);
        strv_free(p->exclude_files_target);
        strv_free(p->make_directories);
        strv_free(p->make_symlinks);
        ordered_hashmap_free(p->subvolumes);
        free(p->default_subvolume);
        free(p->tpm2_hash_pcr_values);
        free(p->verity_match_key);
        free(p->compression);
        free(p->compression_level);

        iovec_done_erase(&p->key);

        copy_files_free_many(p->copy_files, p->n_copy_files);

        iovec_done(&p->roothash);

        free(p->split_name_format);
        unlink_and_free(p->split_path);
        partition_mountpoint_free_many(p->mountpoints, p->n_mountpoints);
        p->mountpoints = NULL;
        p->n_mountpoints = 0;

        partition_encrypted_volume_free(p->encrypted_volume);

        partition_unlink_supplement(p);

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
        p->exclude_files_source = strv_free(p->exclude_files_source);
        p->exclude_files_target = strv_free(p->exclude_files_target);
        p->make_directories = strv_free(p->make_directories);
        p->make_symlinks = strv_free(p->make_symlinks);
        p->subvolumes = ordered_hashmap_free(p->subvolumes);
        p->default_subvolume = mfree(p->default_subvolume);
        p->tpm2_hash_pcr_values = mfree(p->tpm2_hash_pcr_values);
        p->verity_match_key = mfree(p->verity_match_key);
        p->compression = mfree(p->compression);
        p->compression_level = mfree(p->compression_level);

        iovec_done_erase(&p->key);

        copy_files_free_many(p->copy_files, p->n_copy_files);
        p->copy_files = NULL;
        p->n_copy_files = 0;

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
        p->add_validatefs = false;
        p->fs_sector_size = UINT64_MAX;

        partition_mountpoint_free_many(p->mountpoints, p->n_mountpoints);
        p->mountpoints = NULL;
        p->n_mountpoints = 0;

        p->encrypted_volume = partition_encrypted_volume_free(p->encrypted_volume);

        partition_unlink_supplement(p);
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

static Context* context_new(
                char **definitions,
                EmptyMode empty,
                bool dry_run,
                sd_id128_t seed) {

        _cleanup_strv_free_ char **d = NULL;
        if (!strv_isempty(definitions)) {
                d = strv_copy(definitions);
                if (!d)
                        return NULL;
        }

        Context *context = new(Context, 1);
        if (!context)
                return NULL;

        *context = (Context) {
                .definitions = TAKE_PTR(d),
                .start = UINT64_MAX,
                .end = UINT64_MAX,
                .total = UINT64_MAX,
                .seed = seed,
                .empty = empty,
                .dry_run = dry_run,
                .backing_fd = -EBADF,
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

static Context* context_free(Context *context) {
        if (!context)
                return NULL;

        strv_free(context->definitions);

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

#if HAVE_OPENSSL
        X509_free(context->certificate);
        openssl_ask_password_ui_free(context->ui);
        EVP_PKEY_free(context->private_key);
#endif

        context->link = sd_varlink_unref(context->link);

        return mfree(context);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(Context*, context_free);

static void context_disarm_auto_removal(Context *context) {
        assert(context);

        /* Make sure automatic removal of half-written artifacts is disarmed */
        context->node = mfree(context->node);

        LIST_FOREACH(partitions, p, context->partitions)
                p->split_path = mfree(p->split_path);
}

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

                /* If a supplement partition is dropped, we don't want to merge in its settings. */
                if (PARTITION_SUPPRESSED(p))
                        p->supplement_for->suppressing = NULL;
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

static uint64_t partition_fs_sector_size(const Context *c, const Partition *p) {
        assert(c);
        assert(p);

        uint64_t ss;

        if (p->fs_sector_size != UINT64_MAX)
                /* Prefer explicitly configured value */
                ss = p->fs_sector_size;
        else
                /* Otherwise follow the default sector size */
                ss = c->default_fs_sector_size;

        /* never allow the fs sector size to be picked smaller than the physical sector size */
        return MAX(ss, c->sector_size);
}

static uint64_t partition_fstype_min_size(const Context *c, const Partition *p) {
        assert(c);
        assert(p);

        /* If a file system type is configured, then take it into consideration for the minimum partition
         * size */

        if (IN_SET(p->type.designator, PARTITION_ESP, PARTITION_XBOOTLDR) && streq_ptr(p->format, "vfat")) {
                uint64_t ss = partition_fs_sector_size(c, p);
                return ss >= 4096 ? ESP_MIN_SIZE_4K : ESP_MIN_SIZE;
        }

        return minimal_size_by_fs_name(p->format);
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

        if (partition_designator_is_verity_sig(p->type.designator))
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
                        f = partition_fstype_min_size(context, p);
                        d += f == UINT64_MAX ? context->grain_size : round_up_size(f, context->grain_size);
                }

                if (d > sz)
                        sz = d;
        }

        uint64_t min_size = p->size_min;
        if (p->suppressing && (min_size == UINT64_MAX || p->suppressing->size_min > min_size))
                min_size = p->suppressing->size_min;

        /* Default to 10M min size, except if the file system is read-only, in which case let's not enforce a
         * minimum size, because even if we wanted to we couldn't take possession of the extra space
         * allocated. */
        if (min_size == UINT64_MAX)
                min_size = (p->format && fstype_is_ro(p->format)) || p->verity != VERITY_OFF ? 1 : DEFAULT_MIN_SIZE;

        return MAX(round_up_size(min_size, context->grain_size), sz);
}

static uint64_t partition_max_size(const Context *context, const Partition *p) {
        uint64_t sm, override_max;

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

        if (partition_designator_is_verity_sig(p->type.designator))
                return VERITY_SIG_SIZE;

        override_max = p->suppressing ? MIN(p->size_max, p->suppressing->size_max) : p->size_max;
        if (override_max == UINT64_MAX)
                return UINT64_MAX;

        sm = round_down_size(override_max, context->grain_size);

        if (p->current_size != UINT64_MAX)
                sm = MAX(p->current_size, sm);

        return MAX(partition_min_size(context, p), sm);
}

static uint64_t partition_min_padding(const Partition *p) {
        uint64_t override_min;

        assert(p);

        override_min = p->suppressing ? MAX(p->padding_min, p->suppressing->padding_min) : p->padding_min;
        return override_min != UINT64_MAX ? override_min : 0;
}

static uint64_t partition_max_padding(const Partition *p) {
        assert(p);
        return p->suppressing ? MIN(p->padding_max, p->suppressing->padding_max) : p->padding_max;
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

                if (p->dropped || PARTITION_IS_FOREIGN(p) || PARTITION_SUPPRESSED(p))
                        continue;

                /* How much do we need to fit? */
                required = partition_min_size_with_padding(context, p);

                /* For existing partitions, we should verify that they'll actually fit */
                if (PARTITION_EXISTS(p)) {
                        if (p->current_size + p->current_padding < required)
                                return false; /* 😢 We won't be able to grow to the required min size! */

                        continue;
                }

                /* For new partitions, see if there's a free area big enough */
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

static bool context_unmerge_and_allocate_partitions(Context *context) {
        assert(context);

        /* This should only be called after plain context_allocate_partitions fails. This algorithm will
         * try, in the order that minimizes the number of created supplement partitions, all combinations of
         * un-suppressing supplement partitions until it finds one that works. */

        /* First, let's try to un-suppress just one supplement partition and see if that gets us anywhere */
        LIST_FOREACH(partitions, p, context->partitions) {
                Partition *unsuppressed;

                if (!p->suppressing)
                        continue;

                unsuppressed = TAKE_PTR(p->suppressing);

                if (context_allocate_partitions(context, NULL))
                        return true;

                p->suppressing = unsuppressed;
        }

        /* Looks like not. So we have to un-suppress at least two partitions. We can do this recursively */
        LIST_FOREACH(partitions, p, context->partitions) {
                Partition *unsuppressed;

                if (!p->suppressing)
                        continue;

                unsuppressed = TAKE_PTR(p->suppressing);

                if (context_unmerge_and_allocate_partitions(context))
                        return true;

                p->suppressing = unsuppressed;
        }

        /* No combination of un-suppressed supplements made it possible to fit the partitions */
        return false;
}

static uint32_t partition_weight(const Partition *p) {
        assert(p);
        return p->suppressing ? p->suppressing->weight : p->weight;
}

static uint32_t partition_padding_weight(const Partition *p) {
        assert(p);
        return p->suppressing ? p->suppressing->padding_weight : p->padding_weight;
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

                if (!INC_SAFE(&weight_sum, partition_weight(p)))
                        goto overflow_sum;

                if (!INC_SAFE(&weight_sum, partition_padding_weight(p)))
                        goto overflow_sum;
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
                        uint32_t weight;
                        bool charge = false;

                        weight = partition_weight(p);

                        /* Calculate how much this space this partition needs if everyone would get
                         * the weight based share */
                        share = scale_by_weight(*span, weight, *weight_sum);

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
                                *weight_sum = charge_weight(*weight_sum, weight);
                        }
                }

                if (p->new_padding == UINT64_MAX) {
                        uint64_t share, rsz, xsz;
                        uint32_t padding_weight;
                        bool charge = false;

                        padding_weight = partition_padding_weight(p);

                        share = scale_by_weight(*span, padding_weight, *weight_sum);

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
                                *weight_sum = charge_weight(*weight_sum, padding_weight);
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
                           lvalue, parsed, glyph(GLYPH_ARROW_RIGHT), *sz);

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

static int config_parse_fs_sector_size(
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

        uint64_t *fssecsz = ASSERT_PTR(data), parsed;
        int r;

        assert(rvalue);

        if (isempty(rvalue)) {
                *fssecsz = UINT64_MAX;
                return 0;
        }

        r = parse_size(rvalue, 1024, &parsed);
        if (r < 0)
                return log_syntax(unit, LOG_ERR, filename, line, r,
                                  "Failed to parse size value: %s", rvalue);

        if (!ISPOWEROF2(parsed))
                return log_syntax(unit, LOG_ERR, filename, line, SYNTHETIC_ERRNO(EINVAL),
                                  "Value not a power of 2: %s", rvalue);

        /* NB: we make no upper restriction here, since the maximum logical sector sizes file systems support
         * vary greatly, and can be much larger than 4K. (That's also the reason we don't use
         * parse_sector_size() here.) */

        *fssecsz = parsed;
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

        _cleanup_free_ char *source = NULL, *buffer = NULL, *resolved_source = NULL, *resolved_target = NULL, *options = NULL;
        Partition *partition = ASSERT_PTR(data);
        const char *p = rvalue, *target;
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

        r = extract_first_word(&p, &options, ":", EXTRACT_CUNESCAPE|EXTRACT_DONT_COALESCE_SEPARATORS);
        if (r < 0)
                return log_syntax(unit, LOG_ERR, filename, line, r, "Failed to extract options: %s", rvalue);

        if (!isempty(p))
                return log_syntax(unit, LOG_ERR, filename, line, SYNTHETIC_ERRNO(EINVAL), "Too many arguments: %s", rvalue);

        CopyFlags flags = COPY_REFLINK|COPY_HOLES|COPY_MERGE|COPY_REPLACE|COPY_SIGINT|COPY_HARDLINKS|COPY_ALL_XATTRS|COPY_GRACEFUL_WARN|COPY_TRUNCATE|COPY_RESTORE_DIRECTORY_TIMESTAMPS;
        for (const char *opts = options;;) {
                _cleanup_free_ char *word = NULL;
                const char *val;

                r = extract_first_word(&opts, &word, ",", EXTRACT_DONT_COALESCE_SEPARATORS | EXTRACT_UNESCAPE_SEPARATORS);
                if (r < 0)
                        return log_syntax(unit, LOG_ERR, filename, line, r, "Failed to parse CopyFile options: %s", options);
                if (r == 0)
                        break;

                if (isempty(word))
                        continue;

                if ((val = startswith(word, "fsverity="))) {
                        if (streq(val, "copy"))
                                flags |= COPY_PRESERVE_FS_VERITY;
                        else if (streq(val, "off"))
                                flags &= ~COPY_PRESERVE_FS_VERITY;
                        else
                                log_syntax(unit, LOG_WARNING, filename, line, 0, "fsverity= expects either 'off' or 'copy'.");
                } else
                        log_syntax(unit, LOG_WARNING, filename, line, 0, "Encountered unknown option '%s', ignoring.", word);
        }

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

        if (!GREEDY_REALLOC(partition->copy_files, partition->n_copy_files + 1))
                return log_oom();

        partition->copy_files[partition->n_copy_files++] = (CopyFiles) {
                .source = TAKE_PTR(resolved_source),
                .target = TAKE_PTR(resolved_target),
                .flags = flags,
        };

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

        char ***exclude_files = ASSERT_PTR(data);
        const char *p = ASSERT_PTR(rvalue);
        int r;

        if (isempty(rvalue)) {
                *exclude_files = strv_free(*exclude_files);
                return 0;
        }

        for (;;) {
                _cleanup_free_ char *word = NULL, *resolved = NULL;

                r = extract_first_word(&p, &word, NULL, EXTRACT_UNQUOTE);
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r, "Invalid syntax, ignoring: %s", p);
                        return 0;
                }
                if (r == 0)
                        return 0;

                r = specifier_printf(word, PATH_MAX-1, system_and_tmp_specifier_table, arg_root, NULL, &resolved);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Failed to expand specifiers in %s path, ignoring: %s", lvalue, word);
                        return 0;
                }

                r = path_simplify_and_warn(resolved, PATH_CHECK_ABSOLUTE|PATH_KEEP_TRAILING_SLASH, unit, filename, line, lvalue);
                if (r < 0)
                        return 0;

                if (strv_consume(exclude_files, TAKE_PTR(resolved)) < 0)
                        return log_oom();
        }

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

                if (strv_contains(*sv, d))
                        continue;

                r = strv_consume(sv, TAKE_PTR(d));
                if (r < 0)
                        return log_oom();
        }
}

static int config_parse_make_symlinks(
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
                _cleanup_free_ char *word = NULL, *path = NULL, *target = NULL, *d = NULL;

                r = extract_first_word(&p, &word, NULL, EXTRACT_UNQUOTE);
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r, "Invalid syntax, ignoring: %s", rvalue);
                        return 0;
                }
                if (r == 0)
                        return 0;

                const char *q = word;
                r = extract_many_words(&q, ":", EXTRACT_UNQUOTE|EXTRACT_DONT_COALESCE_SEPARATORS, &path, &target);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r, "Invalid syntax, ignoring: %s", q);
                        continue;
                }
                if (r != 2) {
                        log_syntax(unit, LOG_WARNING, filename, line, SYNTHETIC_ERRNO(EINVAL),
                                   "Missing source or target in %s, ignoring", rvalue);
                        continue;
                }

                r = specifier_printf(path, PATH_MAX-1, system_and_tmp_specifier_table, arg_root, /* userdata= */ NULL, &d);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Failed to expand specifiers in Subvolumes= parameter, ignoring: %s", path);
                        continue;
                }

                r = path_simplify_and_warn(d, PATH_CHECK_ABSOLUTE, unit, filename, line, lvalue);
                if (r < 0)
                        continue;

                r = strv_consume_pair(sv, TAKE_PTR(d), TAKE_PTR(target));
                if (r < 0)
                        return log_error_errno(r, "Failed to add symlink to list: %m");
        }
}

static int config_parse_subvolumes(
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

        OrderedHashmap **subvolumes = ASSERT_PTR(data);
        const char *p = ASSERT_PTR(rvalue);
        int r;

        for (;;) {
                _cleanup_free_ char *word = NULL, *path = NULL, *f = NULL, *d = NULL;
                Subvolume *s = NULL;

                r = extract_first_word(&p, &word, NULL, EXTRACT_UNQUOTE);
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r, "Invalid syntax, ignoring: %s", rvalue);
                        return 0;
                }
                if (r == 0)
                        return 0;

                const char *q = word;
                r = extract_many_words(&q, ":", EXTRACT_UNQUOTE|EXTRACT_DONT_COALESCE_SEPARATORS, &path, &f);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r, "Invalid syntax, ignoring: %s", q);
                        continue;
                }

                r = specifier_printf(path, PATH_MAX-1, system_and_tmp_specifier_table, arg_root, /* userdata= */ NULL, &d);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Failed to expand specifiers in Subvolumes= parameter, ignoring: %s", path);
                        continue;
                }

                r = path_simplify_and_warn(d, PATH_CHECK_ABSOLUTE, unit, filename, line, lvalue);
                if (r < 0)
                        continue;

                s = ordered_hashmap_get(*subvolumes, d);
                if (!s) {
                        s = new(Subvolume, 1);
                        if (!s)
                                return log_oom();

                        *s = (Subvolume) {
                                .path = TAKE_PTR(d),
                        };

                        r = ordered_hashmap_ensure_put(subvolumes, &subvolume_hash_ops, s->path, s);
                        if (r < 0) {
                                subvolume_free(s);
                                return r;
                        }
                }

                if (f) {
                        BtrfsSubvolFlags flags = subvolume_flags_from_string(f);
                        if (flags == -EBADRQC) {
                                log_syntax(unit, LOG_WARNING, filename, line, r, "Unknown subvolume flag in subvolume, ignoring: %s", f);
                                continue;
                        }
                        if (flags < 0) {
                                log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to parse subvolume flags, ignoring: %s", f);
                                continue;
                        }

                        s->flags = flags;
                }
        }
}

static int config_parse_default_subvolume(
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

        char **subvol = ASSERT_PTR(data);
        _cleanup_free_ char *p = NULL;
        int r;

        if (isempty(rvalue)) {
                *subvol = mfree(*subvol);
                return 0;
        }

        r = specifier_printf(rvalue, PATH_MAX-1, system_and_tmp_specifier_table, arg_root, NULL, &p);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to expand specifiers in DefaultSubvolume= parameter, ignoring: %s", rvalue);
                return 0;
        }

        r = path_simplify_and_warn(p, PATH_CHECK_ABSOLUTE, unit, filename, line, lvalue);
        if (r < 0)
                return 0;

        return free_and_replace(*subvol, p);
}

static DEFINE_CONFIG_PARSE_ENUM_WITH_DEFAULT(config_parse_encrypt, encrypt_mode, EncryptMode, ENCRYPT_OFF);

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

static int config_parse_mountpoint(
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

        _cleanup_free_ char *where = NULL, *options = NULL;
        Partition *p = ASSERT_PTR(data);
        int r;

        if (isempty(rvalue)) {
                partition_mountpoint_free_many(p->mountpoints, p->n_mountpoints);
                return 0;
        }

        const char *q = rvalue;
        r = extract_many_words(&q, ":", EXTRACT_CUNESCAPE|EXTRACT_DONT_COALESCE_SEPARATORS|EXTRACT_UNQUOTE,
                               &where, &options);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Invalid syntax in %s=, ignoring: %s", lvalue, rvalue);
                return 0;
        }
        if (r < 1) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Too few arguments in %s=, ignoring: %s", lvalue, rvalue);
                return 0;
        }
        if (!isempty(q)) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Too many arguments in %s=, ignoring: %s", lvalue, rvalue);
                return 0;
        }

        r = path_simplify_and_warn(where, PATH_CHECK_ABSOLUTE, unit, filename, line, lvalue);
        if (r < 0)
                return 0;

        if (!GREEDY_REALLOC(p->mountpoints, p->n_mountpoints + 1))
                return log_oom();

        p->mountpoints[p->n_mountpoints++] = (PartitionMountPoint) {
                .where = TAKE_PTR(where),
                .options = TAKE_PTR(options),
        };

        return 0;
}

static int config_parse_encrypted_volume(
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

        _cleanup_free_ char *volume = NULL, *keyfile = NULL, *options = NULL, *extra = NULL;
        bool fixate_volume_key = false;
        Partition *p = ASSERT_PTR(data);
        int r;

        if (isempty(rvalue)) {
                p->encrypted_volume = mfree(p->encrypted_volume);
                return 0;
        }

        const char *q = rvalue;
        r = extract_many_words(&q, ":", EXTRACT_CUNESCAPE|EXTRACT_DONT_COALESCE_SEPARATORS|EXTRACT_UNQUOTE,
                               &volume, &keyfile, &options, &extra);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Invalid syntax in %s=, ignoring: %s", lvalue, rvalue);
                return 0;
        }
        if (r < 1) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Too few arguments in %s=, ignoring: %s", lvalue, rvalue);
                return 0;
        }
        if (!isempty(q)) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Too many arguments in %s=, ignoring: %s", lvalue, rvalue);
                return 0;
        }

        if (!filename_is_valid(volume)) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Volume name %s is not valid, ignoring", volume);
                return 0;
        }

        partition_encrypted_volume_free(p->encrypted_volume);

        p->encrypted_volume = new(PartitionEncryptedVolume, 1);
        if (!p->encrypted_volume)
                return log_oom();

        for (const char *e = extra;;) {
                _cleanup_free_ char *word = NULL;

                r = extract_first_word(&e, &word, ",", EXTRACT_DONT_COALESCE_SEPARATORS | EXTRACT_UNESCAPE_SEPARATORS);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, 0,
                                   "Failed to parse extra options '%s', ignoring", word);
                        break;
                }
                if (r == 0)
                        break;

                if (streq(word, "fixate-volume-key"))
                        fixate_volume_key = true;
                else
                        log_syntax(unit, LOG_WARNING, filename, line, 0, "Unknown extra option '%s', ignoring", word);
        }

        *p->encrypted_volume = (PartitionEncryptedVolume) {
                .name = TAKE_PTR(volume),
                .keyfile = TAKE_PTR(keyfile),
                .options = TAKE_PTR(options),
                .fixate_volume_key = fixate_volume_key,
        };

        return 0;
}

static int config_parse_tpm2_pcrs(
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

        assert(rvalue);

        if (isempty(rvalue)) {
                /* Clear existing PCR values if empty */
                partition->tpm2_hash_pcr_values = mfree(partition->tpm2_hash_pcr_values);
                partition->tpm2_n_hash_pcr_values = 0;
                return 0;
        }

        return tpm2_parse_pcr_argument_append(rvalue, &partition->tpm2_hash_pcr_values,
                                              &partition->tpm2_n_hash_pcr_values);
}

static int parse_key_file(const char *filename, struct iovec *key) {
        _cleanup_(erase_and_freep) char *k = NULL;
        size_t n = 0;
        int r;

        r = read_full_file_full(
                        AT_FDCWD, filename,
                        /* offset= */ UINT64_MAX,
                        /* size= */ SIZE_MAX,
                        READ_FULL_FILE_SECURE|READ_FULL_FILE_WARN_WORLD_READABLE|READ_FULL_FILE_CONNECT_SOCKET,
                        /* bind_name= */ NULL,
                        &k, &n);
        if (r < 0)
                return log_error_errno(r, "Failed to read key file '%s': %m", filename);

        iovec_done_erase(key);
        *key = IOVEC_MAKE(TAKE_PTR(k), n);

        return 0;
}

static int config_parse_key_file(
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

        Partition *partition = ASSERT_PTR(userdata);

        assert(rvalue);

        if (isempty(rvalue)) {
                iovec_done_erase(&partition->key);
                return 0;
        }

        return parse_key_file(rvalue, &partition->key);
}

static DEFINE_CONFIG_PARSE_ENUM_WITH_DEFAULT(config_parse_integrity, integrity_mode, IntegrityMode, INTEGRITY_OFF);
static DEFINE_CONFIG_PARSE_ENUM_WITH_DEFAULT(config_parse_integrity_alg, integrity_alg, IntegrityAlg, INTEGRITY_ALG_HMAC_SHA256);

static DEFINE_CONFIG_PARSE_ENUM_WITH_DEFAULT(config_parse_verity, verity_mode, VerityMode, VERITY_OFF);
static DEFINE_CONFIG_PARSE_ENUM_WITH_DEFAULT(config_parse_minimize, minimize_mode, MinimizeMode, MINIMIZE_OFF);

static int partition_finalize_fstype(Partition *p, const char *path) {
        _cleanup_free_ char *e = NULL, *upper = NULL;

        assert(p);
        assert(path);

        if (!gpt_partition_type_has_filesystem(p->type))
                return 0;

        upper = strdup(partition_designator_to_string(p->type.designator));
        if (!upper)
                return log_oom();

        e = strjoin("SYSTEMD_REPART_OVERRIDE_FSTYPE_", string_replace_char(ascii_strupper(upper), '-', '_'));
        if (!e)
                return log_oom();

        const char *v = secure_getenv(e);
        if (!v || streq_ptr(p->format, v))
                return 0;

        log_syntax(NULL, LOG_NOTICE, path, 1, 0,
                   "Overriding defined file system type '%s' for '%s' partition with '%s'.",
                   p->format, partition_designator_to_string(p->type.designator), v);

        return free_and_strdup_warn(&p->format, v);
}

static bool partition_add_validatefs(const Partition *p) {
        assert(p);

        if (p->add_validatefs >= 0)
                return p->add_validatefs;

        return p->format && !STR_IN_SET(p->format, "swap", "vfat");
}

static bool partition_needs_populate(const Partition *p) {
        assert(p);
        assert(!p->supplement_for || !p->suppressing); /* Avoid infinite recursion */

        return p->n_copy_files > 0 ||
                !strv_isempty(p->make_directories) ||
                !strv_isempty(p->make_symlinks) ||
                partition_add_validatefs(p) ||
                (p->suppressing && partition_needs_populate(p->suppressing));
}

static MakeFileSystemFlags partition_mkfs_flags(const Partition *p) {
        MakeFileSystemFlags flags = 0;

        if (arg_discard && !p->discarded)
                flags |= MKFS_DISCARD;

        if (streq(p->format, "erofs") && !DEBUG_LOGGING && !isatty_safe(STDERR_FILENO))
                flags |= MKFS_QUIET;

        FOREACH_ARRAY(cf, p->copy_files, p->n_copy_files)
                if (cf->flags & COPY_PRESERVE_FS_VERITY) {
                        flags |= MKFS_FS_VERITY;
                        break;
                }

        return flags;
}

static int context_notify(
                Context *c,
                ProgressPhase phase,
                const char *object,
                unsigned percent) {

        int r;

        assert(c);
        assert(phase >= 0);
        assert(phase < _PROGRESS_PHASE_MAX);

        /* Send progress information, via sd_notify() and via varlink (if client asked for it by setting "more" flag) */

        _cleanup_free_ char *n = NULL;
        if (asprintf(&n,
                     "STATUS=Phase %1$s\n"
                     "X_SYSTEMD_PHASE=%1$s",
                     progress_phase_to_string(phase)) < 0)
                return log_oom_debug();

        if (percent != UINT_MAX)
                if (strextendf(&n, "\nX_SYSTEMD_PHASE_PROGRESS=%u", percent) < 0)
                        return log_oom_debug();

        r = sd_notify(/* unset_environment= */ false, n);
        if (r < 0)
                log_debug_errno(r, "Failed to send sd_notify() progress notification, ignoring: %m");

        if (c->link) {
                r = sd_varlink_notifybo(
                                c->link,
                                SD_JSON_BUILD_PAIR("phase", JSON_BUILD_STRING_UNDERSCORIFY(progress_phase_to_string(phase))),
                                JSON_BUILD_PAIR_STRING_NON_EMPTY("object", object),
                                JSON_BUILD_PAIR_UNSIGNED_NOT_EQUAL("progress", percent, UINT_MAX));
                if (r < 0)
                        log_debug_errno(r, "Failed to send varlink notify progress notification, ignoring: %m");
        }

        return 0;
}

static int partition_read_definition(
                Context *c,
                Partition *p,
                const char *path,
                const char *const *conf_file_dirs) {

        ConfigTableItem table[] = {
                { "Partition", "Type",                     config_parse_type,              0,                                  &p->type                    },
                { "Partition", "Label",                    config_parse_label,             0,                                  &p->new_label               },
                { "Partition", "VolumeLabel",              config_parse_label,             0,                                  &p->new_volume_label        },
                { "Partition", "UUID",                     config_parse_uuid,              0,                                  p                           },
                { "Partition", "Priority",                 config_parse_int32,             0,                                  &p->priority                },
                { "Partition", "Weight",                   config_parse_weight,            0,                                  &p->weight                  },
                { "Partition", "PaddingWeight",            config_parse_weight,            0,                                  &p->padding_weight          },
                { "Partition", "SizeMinBytes",             config_parse_size4096,         -1,                                  &p->size_min                },
                { "Partition", "SizeMaxBytes",             config_parse_size4096,          1,                                  &p->size_max                },
                { "Partition", "PaddingMinBytes",          config_parse_size4096,         -1,                                  &p->padding_min             },
                { "Partition", "PaddingMaxBytes",          config_parse_size4096,          1,                                  &p->padding_max             },
                { "Partition", "FactoryReset",             config_parse_bool,              0,                                  &p->factory_reset           },
                { "Partition", "CopyBlocks",               config_parse_copy_blocks,       0,                                  p                           },
                { "Partition", "Format",                   config_parse_fstype,            0,                                  &p->format                  },
                { "Partition", "CopyFiles",                config_parse_copy_files,        0,                                  p                           },
                { "Partition", "ExcludeFiles",             config_parse_exclude_files,     0,                                  &p->exclude_files_source    },
                { "Partition", "ExcludeFilesTarget",       config_parse_exclude_files,     0,                                  &p->exclude_files_target    },
                { "Partition", "MakeDirectories",          config_parse_make_dirs,         0,                                  &p->make_directories        },
                { "Partition", "MakeSymlinks",             config_parse_make_symlinks,     0,                                  &p->make_symlinks           },
                { "Partition", "Encrypt",                  config_parse_encrypt,           0,                                  &p->encrypt                 },
                { "Partition", "Verity",                   config_parse_verity,            0,                                  &p->verity                  },
                { "Partition", "VerityMatchKey",           config_parse_string,            0,                                  &p->verity_match_key        },
                { "Partition", "Flags",                    config_parse_gpt_flags,         0,                                  &p->gpt_flags               },
                { "Partition", "ReadOnly",                 config_parse_tristate,          0,                                  &p->read_only               },
                { "Partition", "NoAuto",                   config_parse_tristate,          0,                                  &p->no_auto                 },
                { "Partition", "GrowFileSystem",           config_parse_tristate,          0,                                  &p->growfs                  },
                { "Partition", "SplitName",                config_parse_string,            0,                                  &p->split_name_format       },
                { "Partition", "Minimize",                 config_parse_minimize,          0,                                  &p->minimize                },
                { "Partition", "Subvolumes",               config_parse_subvolumes,        0,                                  &p->subvolumes              },
                { "Partition", "DefaultSubvolume",         config_parse_default_subvolume, 0,                                  &p->default_subvolume       },
                { "Partition", "VerityDataBlockSizeBytes", config_parse_block_size,        0,                                  &p->verity_data_block_size  },
                { "Partition", "VerityHashBlockSizeBytes", config_parse_block_size,        0,                                  &p->verity_hash_block_size  },
                { "Partition", "MountPoint",               config_parse_mountpoint,        0,                                  p                           },
                { "Partition", "EncryptedVolume",          config_parse_encrypted_volume,  0,                                  p                           },
                { "Partition", "TPM2PCRs",                 config_parse_tpm2_pcrs,         0,                                  p                           },
                { "Partition", "KeyFile",                  config_parse_key_file,          0,                                  p                           },
                { "Partition", "Integrity",                config_parse_integrity,         0,                                  &p->integrity               },
                { "Partition", "IntegrityAlgorithm",       config_parse_integrity_alg,     0,                                  &p->integrity_alg           },
                { "Partition", "Compression",              config_parse_string,            CONFIG_PARSE_STRING_SAFE_AND_ASCII, &p->compression             },
                { "Partition", "CompressionLevel",         config_parse_string,            CONFIG_PARSE_STRING_SAFE_AND_ASCII, &p->compression_level       },
                { "Partition", "SupplementFor",            config_parse_string,            0,                                  &p->supplement_for_name     },
                { "Partition", "AddValidateFS",            config_parse_tristate,          0,                                  &p->add_validatefs          },
                { "Partition", "FileSystemSectorSize",     config_parse_fs_sector_size,    0,                                  &p->fs_sector_size          },
                {}
        };
        _cleanup_free_ char *filename = NULL;
        const char* dropin_dirname;
        int r;

        assert(c);
        assert(p);
        assert(path);

        r = path_extract_filename(path, &filename);
        if (r < 0)
                return log_error_errno(r, "Failed to extract filename from path '%s': %m", path);

        dropin_dirname = strjoina(filename, ".d");

        r = config_parse_many_full(
                        STRV_MAKE_CONST(path),
                        conf_file_dirs,
                        dropin_dirname,
                        c->definitions ? NULL : arg_root,
                        /* root_fd= */ -EBADF,
                        "Partition\0",
                        config_item_table_lookup, table,
                        CONFIG_PARSE_WARN,
                        p,
                        /* ret_stats_by_path= */ NULL,
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

        if ((p->copy_blocks_path || p->copy_blocks_auto) && (p->format || partition_needs_populate(p)))
                return log_syntax(NULL, LOG_ERR, path, 1, SYNTHETIC_ERRNO(EINVAL),
                                  "Format=/CopyFiles=/MakeDirectories=/MakeSymlinks= and CopyBlocks= cannot be combined, refusing.");

        if (partition_needs_populate(p) && streq_ptr(p->format, "swap"))
                return log_syntax(NULL, LOG_ERR, path, 1, SYNTHETIC_ERRNO(EINVAL),
                                  "Format=swap and CopyFiles=/MakeDirectories=/MakeSymlinks= cannot be combined, refusing.");

        if (!p->format) {
                const char *format = NULL;

                if (p->type.designator == PARTITION_SWAP)
                        format = "swap";
                else if (partition_needs_populate(p) || (p->encrypt != ENCRYPT_OFF && !(p->copy_blocks_path || p->copy_blocks_auto)))
                        /* Pick "vfat" as file system for esp and xbootldr partitions, otherwise default to "ext4". */
                        format = IN_SET(p->type.designator, PARTITION_ESP, PARTITION_XBOOTLDR) ? "vfat" : "ext4";

                if (format) {
                        p->format = strdup(format);
                        if (!p->format)
                                return log_oom();
                }
        }

        if (streq_ptr(p->format, "empty")) {
                p->format = mfree(p->format);

                if (p->no_auto < 0)
                        p->no_auto = true;

                if (!p->new_label) {
                        p->new_label = strdup("_empty");
                        if (!p->new_label)
                                return log_oom();
                }
        }

        if (p->minimize != MINIMIZE_OFF && !p->format && p->verity != VERITY_HASH)
                return log_syntax(NULL, LOG_ERR, path, 1, SYNTHETIC_ERRNO(EINVAL),
                                  "Minimize= can only be enabled if Format= or Verity=hash are set.");

        if (p->minimize == MINIMIZE_BEST && (p->format && !fstype_is_ro(p->format)) && p->verity != VERITY_HASH)
                return log_syntax(NULL, LOG_ERR, path, 1, SYNTHETIC_ERRNO(EINVAL),
                                  "Minimize=best can only be used with read-only filesystems or Verity=hash.");

        if (partition_needs_populate(p) && !mkfs_supports_root_option(p->format) && geteuid() != 0)
                return log_syntax(NULL, LOG_ERR, path, 1, SYNTHETIC_ERRNO(EPERM),
                                  "Need to be root to populate %s filesystems with CopyFiles=/MakeDirectories=/MakeSymlinks=.",
                                  p->format);

        if (p->format && fstype_is_ro(p->format) && !partition_needs_populate(p))
                return log_syntax(NULL, LOG_ERR, path, 1, SYNTHETIC_ERRNO(EINVAL),
                                  "Cannot format %s filesystem without source files, refusing.", p->format);

        if (p->verity != VERITY_OFF || p->encrypt != ENCRYPT_OFF) {
                r = dlopen_cryptsetup();
                if (r < 0)
                        return log_syntax(NULL, LOG_ERR, path, 1, r,
                                          "libcryptsetup not found, Verity=/Encrypt= are not supported: %m");
        }

        if (p->verity != VERITY_OFF && !p->verity_match_key)
                return log_syntax(NULL, LOG_ERR, path, 1, SYNTHETIC_ERRNO(EINVAL),
                                  "VerityMatchKey= must be set if Verity=%s.", verity_mode_to_string(p->verity));

        if (p->verity == VERITY_OFF && p->verity_match_key)
                return log_syntax(NULL, LOG_ERR, path, 1, SYNTHETIC_ERRNO(EINVAL),
                                  "VerityMatchKey= can only be set if Verity= is not \"%s\".",
                                  verity_mode_to_string(p->verity));

        if (IN_SET(p->verity, VERITY_HASH, VERITY_SIG) && (p->copy_blocks_path || p->copy_blocks_auto || p->format || partition_needs_populate(p)))
                return log_syntax(NULL, LOG_ERR, path, 1, SYNTHETIC_ERRNO(EINVAL),
                                  "CopyBlocks=/CopyFiles=/Format=/MakeDirectories=/MakeSymlinks= cannot be used with Verity=%s.",
                                  verity_mode_to_string(p->verity));

        if (p->verity != VERITY_OFF && p->encrypt != ENCRYPT_OFF)
                return log_syntax(NULL, LOG_ERR, path, 1, SYNTHETIC_ERRNO(EINVAL),
                                  "Encrypting verity hash/data partitions is not supported.");

        if (p->verity == VERITY_SIG && (p->size_min != UINT64_MAX || p->size_max != UINT64_MAX))
                return log_syntax(NULL, LOG_ERR, path, 1, SYNTHETIC_ERRNO(EINVAL),
                                  "SizeMinBytes=/SizeMaxBytes= cannot be used with Verity=%s.",
                                  verity_mode_to_string(p->verity));

        if (p->integrity == INTEGRITY_INLINE && p->encrypt == ENCRYPT_OFF)
                return log_syntax(NULL, LOG_ERR, path, 1, SYNTHETIC_ERRNO(EINVAL),
                                  "Integrity=inline requires Encrypt=.");

        if (p->default_subvolume && !ordered_hashmap_contains(p->subvolumes, p->default_subvolume))
                return log_syntax(NULL, LOG_ERR, path, 1, SYNTHETIC_ERRNO(EINVAL),
                                  "DefaultSubvolume= must be one of the paths in Subvolumes=.");

        if (p->supplement_for_name) {
                if (!filename_part_is_valid(p->supplement_for_name))
                        return log_syntax(NULL, LOG_ERR, path, 1, SYNTHETIC_ERRNO(EINVAL),
                                          "SupplementFor= is an invalid filename: %s",
                                          p->supplement_for_name);

                if (p->copy_blocks_path || p->copy_blocks_auto || p->encrypt != ENCRYPT_OFF ||
                    p->verity != VERITY_OFF)
                        return log_syntax(NULL, LOG_ERR, path, 1, SYNTHETIC_ERRNO(EINVAL),
                                          "SupplementFor= cannot be combined with CopyBlocks=/Encrypt=/Verity=");
        }

        /* Verity partitions are read only, let's imply the RO flag hence, unless explicitly configured otherwise. */
        if ((partition_designator_is_verity_hash(p->type.designator) ||
             partition_designator_is_verity_sig(p->type.designator) ||
             IN_SET(p->verity, VERITY_DATA, VERITY_SIG)) && p->read_only < 0)
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

        r = partition_finalize_fstype(p, path);
        if (r < 0)
                return r;

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
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Partition has no end.");

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
                        return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to read partition metadata.");

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

static int verify_regular_or_block(int fd) {
        struct stat st;

        assert(fd >= 0);

        if (fstat(fd, &st) < 0)
                return -errno;

        if (S_ISDIR(st.st_mode))
                return -EISDIR;

        if (S_ISLNK(st.st_mode))
                return -ELOOP;

        if (!S_ISREG(st.st_mode) && !S_ISBLK(st.st_mode))
                return -EBADFD;

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

        r = verify_regular_or_block(fd);
        if (r < 0)
                return log_error_errno(r, "%s is not a file nor a block device: %m", src);

        r = fdisk_new_context_at(fd, /* path= */ NULL, /* read_only= */ true, /* sector_size= */ UINT32_MAX, &c);
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
                        return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to read partition metadata.");

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

                np = partition_new(context);
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

                np->split_name_format = strdup("%t");
                if (!np->split_name_format)
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

static bool check_cross_def_ranges_valid(uint64_t a_min, uint64_t a_max, uint64_t b_min, uint64_t b_max) {
        if (a_min == UINT64_MAX && b_min == UINT64_MAX)
                return true;

        if (a_max == UINT64_MAX && b_max == UINT64_MAX)
                return true;

        return MAX(a_min != UINT64_MAX ? a_min : 0, b_min != UINT64_MAX ? b_min : 0) <= MIN(a_max, b_max);
}

static int supplement_find_target(const Context *context, const Partition *supplement, Partition **ret) {
        int r;

        assert(context);
        assert(supplement);
        assert(ret);

        LIST_FOREACH(partitions, p, context->partitions) {
                _cleanup_free_ char *filename = NULL;

                if (p == supplement)
                        continue;

                r = path_extract_filename(p->definition_path, &filename);
                if (r < 0)
                        return log_error_errno(r,
                                               "Failed to extract filename from path '%s': %m",
                                               p->definition_path);

                *ASSERT_PTR(endswith(filename, ".conf")) = 0; /* Remove the file extension */

                if (!streq(supplement->supplement_for_name, filename))
                        continue;

                if (p->supplement_for_name)
                        return log_syntax(NULL, LOG_ERR, supplement->definition_path, 1, SYNTHETIC_ERRNO(EINVAL),
                                          "SupplementFor= target is itself configured as a supplement.");

                if (p->suppressing)
                        return log_syntax(NULL, LOG_ERR, supplement->definition_path, 1, SYNTHETIC_ERRNO(EINVAL),
                                          "SupplementFor= target already has a supplement defined: %s",
                                          p->suppressing->definition_path);

                *ret = p;
                return 0;
        }

        return log_syntax(NULL, LOG_ERR, supplement->definition_path, 1, SYNTHETIC_ERRNO(EINVAL),
                          "Couldn't find target partition for SupplementFor=%s",
                          supplement->supplement_for_name);
}

static int context_read_definitions(Context *context) {
        _cleanup_strv_free_ char **files = NULL;
        Partition *last = LIST_FIND_TAIL(partitions, context->partitions);
        const char *const *dirs;
        int r;

        assert(context);

        (void) context_notify(context, PROGRESS_LOADING_DEFINITIONS, /* object= */ NULL, UINT_MAX);

        dirs = (const char* const*) (context->definitions ?: CONF_PATHS_STRV("repart.d"));

        r = conf_files_list_strv(
                        &files,
                        ".conf",
                        context->definitions ? NULL : arg_root,
                        CONF_FILES_REGULAR|CONF_FILES_FILTER_MASKED|CONF_FILES_WARN|CONF_FILES_DONT_PREFIX_ROOT,
                        dirs);
        if (r < 0)
                return log_error_errno(r, "Failed to enumerate *.conf files: %m");

        STRV_FOREACH(f, files) {
                _cleanup_(partition_freep) Partition *p = NULL;

                p = partition_new(context);
                if (!p)
                        return log_oom();

                p->definition_path = strdup(*f);
                if (!p->definition_path)
                        return log_oom();

                r = partition_read_definition(context, p, *f, dirs);
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
                                                          "Missing verity %s partition for verity %s partition with VerityMatchKey=%s.",
                                                          verity_mode_to_string(mode), verity_mode_to_string(p->verity), p->verity_match_key);
                        } else if (r == -ENOTUNIQ)
                                return log_syntax(NULL, LOG_ERR, p->definition_path, 1, SYNTHETIC_ERRNO(EINVAL),
                                                  "Multiple verity %s partitions found for verity %s partition with VerityMatchKey=%s.",
                                                  verity_mode_to_string(mode), verity_mode_to_string(p->verity), p->verity_match_key);
                        else if (r < 0)
                                return log_syntax(NULL, LOG_ERR, p->definition_path, 1, r,
                                                  "Failed to find verity %s partition for verity %s partition with VerityMatchKey=%s.",
                                                  verity_mode_to_string(mode), verity_mode_to_string(p->verity), p->verity_match_key);

                        if (q) {
                                if (q->priority != p->priority)
                                        return log_syntax(NULL, LOG_ERR, p->definition_path, 1, SYNTHETIC_ERRNO(EINVAL),
                                                          "Priority mismatch (%i != %i) for verity sibling partitions with VerityMatchKey=%s.",
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
                                          "Minimize= set for verity hash partition but data partition does not set CopyBlocks= or Minimize=.");
        }

        LIST_FOREACH(partitions, p, context->partitions) {
                Partition *tgt = NULL;

                if (!p->supplement_for_name)
                        continue;

                r = supplement_find_target(context, p, &tgt);
                if (r < 0)
                        return r;

                if (tgt->copy_blocks_path || tgt->copy_blocks_auto || tgt->encrypt != ENCRYPT_OFF ||
                    tgt->verity != VERITY_OFF)
                        return log_syntax(NULL, LOG_ERR, p->definition_path, 1, SYNTHETIC_ERRNO(EINVAL),
                                          "SupplementFor= target uses CopyBlocks=/Encrypt=/Verity=");

                if (!check_cross_def_ranges_valid(p->size_min, p->size_max, tgt->size_min, tgt->size_max))
                        return log_syntax(NULL, LOG_ERR, p->definition_path, 1, SYNTHETIC_ERRNO(EINVAL),
                                          "SizeMinBytes= larger than SizeMaxBytes= when merged with SupplementFor= target.");

                if (!check_cross_def_ranges_valid(p->padding_min, p->padding_max, tgt->padding_min, tgt->padding_max))
                        return log_syntax(NULL, LOG_ERR, p->definition_path, 1, SYNTHETIC_ERRNO(EINVAL),
                                          "PaddingMinBytes= larger than PaddingMaxBytes= when merged with SupplementFor= target.");

                p->supplement_for = tgt;
                tgt->suppressing = tgt->supplement_target_for = p;
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

static int context_load_fallback_metrics(Context *context) {
        assert(context);

        context->sector_size = arg_sector_size > 0 ? arg_sector_size : 512;
        context->grain_size = MAX(context->sector_size, 4096U);
        context->default_fs_sector_size = arg_sector_size > 0 ? arg_sector_size : DEFAULT_FILESYSTEM_SECTOR_SIZE;
        return 1; /* Starting from scratch */
}

static int context_load_partition_table(Context *context) {
        _cleanup_(fdisk_unref_contextp) struct fdisk_context *c = NULL;
        _cleanup_(fdisk_unref_tablep) struct fdisk_table *t = NULL;
        uint64_t left_boundary = UINT64_MAX, first_lba, last_lba, nsectors;
        _cleanup_free_ char *disk_uuid_string = NULL;
        bool from_scratch = false;
        sd_id128_t disk_uuid;
        size_t n_partitions;
        uint64_t grainsz, fs_secsz = DEFAULT_FILESYSTEM_SECTOR_SIZE;
        int r;

        assert(context);
        assert(context->node);
        assert(!context->fdisk_context);
        assert(!context->free_areas);
        assert(context->start == UINT64_MAX);
        assert(context->end == UINT64_MAX);
        assert(context->total == UINT64_MAX);

        context_notify(context, PROGRESS_LOADING_TABLE, /* object= */ NULL, UINT_MAX);

        c = fdisk_new_context();
        if (!c)
                return log_oom();

        if (arg_sector_size > 0) {
                fs_secsz = arg_sector_size;
                r = fdisk_save_user_sector_size(c, /* phy= */ 0, arg_sector_size);
        } else {
                uint32_t ssz;
                struct stat st;

                r = context_open_and_lock_backing_fd(
                                context->node,
                                context->dry_run ? LOCK_SH : LOCK_EX,
                                &context->backing_fd);
                if (r < 0)
                        return r;

                if (fstat(context->backing_fd, &st) < 0)
                        return log_error_errno(errno, "Failed to stat %s: %m", context->node);

                if (IN_SET(context->empty, EMPTY_REQUIRE, EMPTY_FORCE, EMPTY_CREATE) && S_ISREG(st.st_mode))
                        /* Don't probe sector size from partition table if we are supposed to start from an empty disk */
                        ssz = 512;
                else {
                        /* Auto-detect sector size if not specified. */
                        r = probe_sector_size_prefer_ioctl(context->backing_fd, &ssz);
                        if (r < 0)
                                return log_error_errno(r, "Failed to probe sector size of '%s': %m", context->node);

                        /* If we found the sector size and we're operating on a block device, use it as the file
                         * system sector size as well, as we know its the sector size of the actual block device and
                         * not just the offset at which we found the GPT header. */
                        if (r > 0 && S_ISBLK(st.st_mode)) {
                                log_debug("Probed sector size of %s is %" PRIu32 " bytes.", context->node, ssz);
                                fs_secsz = ssz;
                        }
                }

                r = fdisk_save_user_sector_size(c, /* phy= */ 0, ssz);
        }
        if (r < 0)
                return log_error_errno(r, "Failed to set sector size: %m");

        /* libfdisk doesn't have an API to operate on arbitrary fds, hence reopen the fd going via the
         * /proc/self/fd/ magic path if we have an existing fd. Open the original file otherwise. */
        r = fdisk_assign_device(
                        c,
                        context->backing_fd >= 0 ? FORMAT_PROC_FD_PATH(context->backing_fd) : context->node,
                        context->dry_run);
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
                        context->default_fs_sector_size = fs_secsz;
                        context->grain_size = MAX(context->sector_size, 4096U);
                        return /* from_scratch= */ true;
                }

                r = -EINVAL;
        }
        if (r < 0)
                return log_error_errno(r, "Failed to open device '%s': %m", context->node);

        if (context->backing_fd < 0) {
                /* If we have no fd referencing the device yet, make a copy of the fd now, so that we have one */
                r = context_open_and_lock_backing_fd(FORMAT_PROC_FD_PATH(fdisk_get_devfd(c)),
                                                     context->dry_run ? LOCK_SH : LOCK_EX,
                                                     &context->backing_fd);
                if (r < 0)
                        return r;
        }

        /* The offsets/sizes libfdisk returns to us will be in multiple of the sector size of the
         * device. This is typically 512, and sometimes 4096. Let's query libfdisk once for it, and then use
         * it for all our needs. Note that the values we use ourselves always are in bytes though, thus mean
         * the same thing universally. Also note that regardless what kind of sector size is in use we'll
         * place partitions at multiples of 4K. */
        unsigned long secsz = fdisk_get_sector_size(c);

        /* Insist on a power of two, and that it's a multiple of 512, i.e. the traditional sector size. */
        if (secsz < 512 || !ISPOWEROF2(secsz))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Sector size %lu is not a power of two larger than 512? Refusing.", secsz);

        /* Use at least 4K, and ensure it's a multiple of the sector size, regardless if that is smaller or
         * larger */
        grainsz = MAX(secsz, 4096U);

        log_debug("Sector size of device is %lu bytes. Using default filesystem sector size of %" PRIu64 " and grain size of %" PRIu64 ".", secsz, fs_secsz, grainsz);

        switch (context->empty) {

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
                        return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to read partition metadata.");

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

                        np = partition_new(context);
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

        LIST_FOREACH(partitions, p, context->partitions)
                if (PARTITION_SUPPRESSED(p) && PARTITION_EXISTS(p))
                        p->supplement_for->suppressing = NULL;

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
        context->default_fs_sector_size = fs_secsz;
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

                /* A supplement partition is only ever un-suppressed if the existing partition table prevented
                 * us from suppressing it. So when unloading the partition table, we must re-suppress. */
                if (p->supplement_for)
                        p->supplement_for->suppressing = p;
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
                        t = strjoin(FORMAT_BYTES(from), " ", glyph(GLYPH_ARROW_RIGHT), " ", FORMAT_BYTES(to));
        } else if (to != UINT64_MAX)
                t = strjoin(glyph(GLYPH_ARROW_RIGHT), " ", FORMAT_BYTES(to));
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

static int volume_label(const Partition *p, char **ret) {
        assert(p);
        assert(ret);

        if (p->new_volume_label)
                return strdup_to(ret, p->new_volume_label);

        const char *e = partition_label(p);
        if (!e)
                return -ENODATA;

        /* Let's prefix "luks-" for the label string used for LUKS superblocks. We do this so that the
         * /dev/disk/by-label/ symlink to the LUKS volume and the file system inside it do not clash */
        char *j = strjoin("luks-", e);
        if (!j)
                return -ENOMEM;

        *ret = j;
        return 0;
}

static int context_dump_partitions(Context *context) {
        _cleanup_(table_unrefp) Table *t = NULL;
        uint64_t sum_padding = 0, sum_size = 0;
        int r;
        const size_t roothash_col = 14, dropin_files_col = 15, split_path_col = 16;
        bool has_roothash = false, has_dropin_files = false, has_split_path = false;

        if (context->n_partitions == 0 && !sd_json_format_enabled(arg_json_format_flags)) {
                log_info("Empty partition table.");
                return 0;
        }

        t = table_new("type",         /* 0 */
                      "label",
                      "uuid",
                      "part",
                      "file",
                      "node",
                      "offset",
                      "old size",
                      "raw size",
                      "size",
                      "old padding",  /* 10 */
                      "raw padding",
                      "padding",
                      "activity",
                      "roothash",
                      "drop-in files",
                      "split path");
        if (!t)
                return log_oom();

        /* For compatibility, use the original longer name for JSON output. */
        table_set_json_field_name(t, 3, "partno");

        /* Starting in v257, these fields would be automatically formatted with underscores. This would have
         * been a breaking change, so to avoid that let's hard-code their original names. */
        table_set_json_field_name(t, 15, "drop-in_files");

        if (!DEBUG_LOGGING) {
                if (!sd_json_format_enabled(arg_json_format_flags))
                        (void) table_set_display(t, (size_t) 0, (size_t) 1, (size_t) 2, (size_t) 3, (size_t) 4,
                                                    (size_t) 8, (size_t) 9, (size_t) 12, roothash_col, dropin_files_col,
                                                    split_path_col);
                else
                        (void) table_set_display(t, (size_t) 0, (size_t) 1, (size_t) 2, (size_t) 3, (size_t) 4,
                                                    (size_t) 5, (size_t) 6, (size_t) 7, (size_t) 8, (size_t) 10,
                                                    (size_t) 11, (size_t) 13, roothash_col, dropin_files_col,
                                                    split_path_col);
        }

        (void) table_set_align_percent(t, table_get_cell(t, 0, 3), 100);
        (void) table_set_align_percent(t, table_get_cell(t, 0, 6), 100);
        (void) table_set_align_percent(t, table_get_cell(t, 0, 7), 100);
        (void) table_set_align_percent(t, table_get_cell(t, 0, 8), 100);
        (void) table_set_align_percent(t, table_get_cell(t, 0, 9), 100);
        (void) table_set_align_percent(t, table_get_cell(t, 0, 11), 100);
        (void) table_set_align_percent(t, table_get_cell(t, 0, 12), 100);

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

        if (!sd_json_format_enabled(arg_json_format_flags) && (sum_padding > 0 || sum_size > 0)) {
                const char *a, *b;

                a = strjoina(glyph(GLYPH_SIGMA), " = ", FORMAT_BYTES(sum_size));
                b = strjoina(glyph(GLYPH_SIGMA), " = ", FORMAT_BYTES(sum_padding));

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
                        fputs(glyph(GLYPH_DARK_SHADE), stdout);
                } else {
                        fputs(ansi_normal(), stdout);
                        fputs(glyph(GLYPH_LIGHT_SHADE), stdout);
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
                                        e = startswith(line[start_array[j-1]], glyph(GLYPH_TREE_RIGHT));
                                        if (e) {
                                                d = strjoin(glyph(GLYPH_TREE_BRANCH), e);
                                                if (!d)
                                                        return log_oom();
                                        }
                                }

                                if (!d) {
                                        d = strdup(glyph(GLYPH_TREE_VERTICAL));
                                        if (!d)
                                                return log_oom();
                                }

                        } else if (i == n_start_array - j) {
                                _cleanup_free_ char *hint = NULL;

                                (void) partition_hint(p, context->node, &hint);

                                if (streq_ptr(line[start_array[j-1]], glyph(GLYPH_TREE_VERTICAL)))
                                        d = strjoin(glyph(GLYPH_TREE_BRANCH), " ", strna(hint));
                                else
                                        d = strjoin(glyph(GLYPH_TREE_RIGHT), " ", strna(hint));

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

        if (arg_pretty == 0 && !sd_json_format_enabled(arg_json_format_flags))
                return 0;

        /* If we're outputting JSON, only dump after doing all operations so we can include the roothashes
         * in the output.  */
        if (!late && sd_json_format_enabled(arg_json_format_flags))
                return 0;

        /* If we're not outputting JSON, only dump again after doing all operations if there are any
         * roothashes that we need to communicate to the user. */
        if (late && !sd_json_format_enabled(arg_json_format_flags) && !context_has_roothash(context))
                return 0;

        r = context_dump_partitions(context);
        if (r < 0)
                return r;

        /* Only write the partition bar once, even if we're writing the partition table twice to communicate
         * roothashes. */
        if (!sd_json_format_enabled(arg_json_format_flags) && !late) {
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
#if HAVE_BLKID
        _cleanup_(blkid_free_probep) blkid_probe probe = NULL;
        int r;

        assert(context);
        assert(offset != UINT64_MAX);
        assert(size != UINT64_MAX);

        r = dlopen_libblkid();
        if (r < 0)
                return log_error_errno(r, "Failed to load libblkid: %m");

        probe = sym_blkid_new_probe();
        if (!probe)
                return log_oom();

        errno = 0;
        r = sym_blkid_probe_set_device(probe, fdisk_get_devfd(context->fdisk_context), offset, size);
        if (r < 0)
                return log_error_errno(errno ?: SYNTHETIC_ERRNO(EIO), "Failed to allocate device probe for wiping.");

        errno = 0;
        if (sym_blkid_probe_enable_superblocks(probe, true) < 0 ||
            sym_blkid_probe_set_superblocks_flags(probe, BLKID_SUBLKS_MAGIC|BLKID_SUBLKS_BADCSUM) < 0 ||
            sym_blkid_probe_enable_partitions(probe, true) < 0 ||
            sym_blkid_probe_set_partitions_flags(probe, BLKID_PARTS_MAGIC) < 0)
                return log_error_errno(errno ?: SYNTHETIC_ERRNO(EIO), "Failed to enable superblock and partition probing.");

        for (;;) {
                errno = 0;
                r = sym_blkid_do_probe(probe);
                if (r < 0)
                        return log_error_errno(errno_or_else(EIO), "Failed to probe for file systems.");
                if (r > 0)
                        break;

                errno = 0;
                if (sym_blkid_do_wipe(probe, false) < 0)
                        return log_error_errno(errno_or_else(EIO), "Failed to wipe file system signature.");
        }

        return 0;
#else
        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                               "Cannot wipe partition signatures, libblkid support is not compiled in.");
#endif
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
        p->discarded = true;
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

static bool partition_defer(Context *c, const Partition *p) {
        assert(c);
        assert(p);

        if (partition_type_defer(&p->type))
                return true;

        if (c->defer_partitions_empty && streq_ptr(p->new_label, "_empty"))
                return true;

        if (c->defer_partitions_factory_reset && p->factory_reset)
                return true;

        return false;
}

static int context_wipe_and_discard(Context *context) {
        int r;

        assert(context);

        if (context->empty == EMPTY_CREATE) /* If we just created the image, no need to wipe */
                return 0;

        /* Wipe and discard the contents of all partitions we are about to create. We skip the discarding if
         * we were supposed to start from scratch anyway, as in that case we just discard the whole block
         * device in one go early on. */

        LIST_FOREACH(partitions, p, context->partitions) {

                if (!p->allocated_to_area)
                        continue;

                if (partition_defer(context, p))
                        continue;

                (void) context_notify(context, PROGRESS_WIPING_PARTITION, p->definition_path, UINT_MAX);

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

static PartitionTarget* partition_target_free(PartitionTarget *t) {
        if (!t)
                return NULL;

        decrypted_partition_target_free(t->decrypted);
        loop_device_unref(t->loop);
        safe_close(t->fd);
        unlink_and_free(t->path);

        return mfree(t);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(PartitionTarget*, partition_target_free);

static int prepare_temporary_file(Context *context, PartitionTarget *t, uint64_t size) {
        _cleanup_(unlink_and_freep) char *temp = NULL;
        _cleanup_close_ int fd = -EBADF;
        const char *vt;
        unsigned attrs = 0;
        int r;

        assert(context);
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

        if (context->fdisk_context) {
                r = read_attr_fd(fdisk_get_devfd(context->fdisk_context), &attrs);
                if (r < 0 && !ERRNO_IS_NEG_NOT_SUPPORTED(r))
                        log_warning_errno(r, "Failed to read file attributes of %s, ignoring: %m", context->node);

                if (FLAGS_SET(attrs, FS_NOCOW_FL)) {
                        r = chattr_fd(fd, FS_NOCOW_FL, FS_NOCOW_FL);
                        if (r < 0 && !ERRNO_IS_IOCTL_NOT_SUPPORTED(r))
                                return log_error_errno(r, "Failed to disable copy-on-write on %s: %m", temp);
                }
        }

        if (ftruncate(fd, size) < 0)
                return log_error_errno(errno, "Failed to truncate temporary file to %s: %m",
                                       FORMAT_BYTES(size));

        t->fd = TAKE_FD(fd);
        t->path = TAKE_PTR(temp);

        return 0;
}

static bool loop_device_error_is_fatal(const Partition *p, int r) {
        assert(p);
        return arg_offline == 0 || (r != -ENOENT && !ERRNO_IS_PRIVILEGE(r));
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
                if (r < 0 && loop_device_error_is_fatal(p, r))
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

        r = prepare_temporary_file(context, t, size);
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

        log_info("Syncing future partition %"PRIu64" contents to disk.", p->partno);

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
                                               "Partition %" PRIu64 "'s contents (%s) don't fit in the partition (%s).",
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

/* libcryptsetup uses its own names for integrity algorithms, e.g. 'hmac(sha1)' but systemd
 * prefers more standardized 'hmac-sha1', do the conversion here. Default to hmac(sha256). */
static const char* dmcrypt_integrity_alg_name(Partition *p) {
        if (p->integrity != INTEGRITY_INLINE)
                return NULL;

        switch (p->integrity_alg) {
        case INTEGRITY_ALG_HMAC_SHA1:
                return "hmac(sha1)";
        case INTEGRITY_ALG_HMAC_SHA512:
                return "hmac(sha512)";
        case INTEGRITY_ALG_HMAC_SHA256:
        default:
                return "hmac(sha256)";
        }
}

/* Integrity puts specific limitations on the key size depending on the algorithm */
static size_t dmcrypt_proper_key_size(Partition *p) {
        if (p->integrity != INTEGRITY_INLINE)
                return VOLUME_KEY_SIZE;

        switch (p->integrity_alg) {
        case INTEGRITY_ALG_HMAC_SHA1:
                return 672/8;
        case INTEGRITY_ALG_HMAC_SHA512:
                return 1024/8;
        case INTEGRITY_ALG_HMAC_SHA256:
        default:
                return 768/8;
        }
}

static int partition_encrypt(Context *context, Partition *p, PartitionTarget *target, bool offline) {
#if HAVE_LIBCRYPTSETUP
#if HAVE_TPM2
        _cleanup_(erase_and_freep) char *base64_encoded = NULL;
#endif
        _cleanup_fclose_ FILE *h = NULL;
        _cleanup_free_ char *hp = NULL, *vol = NULL, *dm_name = NULL;
        const char *passphrase = NULL;
        const size_t volume_key_size = dmcrypt_proper_key_size(p);
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

        _cleanup_free_ char *vl = NULL;
        r = volume_label(p, &vl);
        if (r < 0)
                return log_error_errno(r, "Failed to generate volume label: %m");

        const char *node = partition_target_path(target);
        struct crypt_params_luks2 luks_params = {
                .label = vl,
                .sector_size = partition_fs_sector_size(context, p),
                .data_device = offline ? node : NULL,
                .integrity = dmcrypt_integrity_alg_name(p),
        };
        struct crypt_params_reencrypt reencrypt_params = {
                .mode = CRYPT_REENCRYPT_ENCRYPT,
                .direction = CRYPT_REENCRYPT_BACKWARD,
                .resilience = "datashift",
                .data_shift = LUKS2_METADATA_SIZE / 512,
                .luks2 = &luks_params,
                .flags = CRYPT_REENCRYPT_INITIALIZE_ONLY|CRYPT_REENCRYPT_MOVE_FIRST_SEGMENT,
        };

        if (offline) {
                /* libcryptsetup does not currently support reencryption of devices with integrity profiles.*/
                if (p->integrity == INTEGRITY_INLINE)
                        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "Integrity=inline cannot be enabled in offline mode.");

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

        _cleanup_(sym_crypt_freep) struct crypt_device *cd = NULL;
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
                        /* volume_key_size= */ volume_key_size,
                        &luks_params);
        if (r < 0)
                return log_error_errno(r, "Failed to LUKS2 format future partition: %m");

        if (p->encrypted_volume && p->encrypted_volume->fixate_volume_key) {
                _cleanup_free_ char *key_id = NULL, *hash_option = NULL;

                r = sym_crypt_get_volume_key_size(cd);
                if (r < 0)
                        return log_error_errno(r, "Failed to determine volume key size: %m");
                if (r == 0)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Volume key has zero size and 'fixate-volume-key' is used");

                _cleanup_(iovec_done) struct iovec vk = {
                        .iov_base = malloc(r),
                        .iov_len = r,
                };

                if (!vk.iov_base)
                        return log_oom();

                r = sym_crypt_volume_key_get(cd, CRYPT_ANY_SLOT, (char *) vk.iov_base, &vk.iov_len, NULL, 0);
                if (r < 0)
                        return log_error_errno(r, "Failed to get volume key: %m");

                r = cryptsetup_get_volume_key_id(
                                cd,
                                /* volume_name= */ p->encrypted_volume->name,
                                /* volume_key= */ vk.iov_base,
                                /* volume_key_size= */ vk.iov_len,
                                /* ret= */ &key_id);
                if (r < 0)
                        return log_error_errno(r, "Failed to get volume key hash: %m");

                hash_option = strjoin("fixate-volume-key=", key_id);
                if (!hash_option)
                        return log_oom();

                if (!strextend_with_separator(&p->encrypted_volume->options, ",", hash_option))
                        return log_oom();
        }

        if (IN_SET(p->encrypt, ENCRYPT_KEY_FILE, ENCRYPT_KEY_FILE_TPM2)) {
                /* Use partition-specific key if available, otherwise fall back to global key */
                struct iovec *iovec_key = arg_key.iov_base ? &arg_key : &p->key;

                r = sym_crypt_keyslot_add_by_volume_key(
                                cd,
                                CRYPT_ANY_SLOT,
                                NULL,
                                /* volume_key_size= */ volume_key_size,
                                strempty(iovec_key->iov_base),
                                iovec_key->iov_len);
                if (r < 0)
                        return log_error_errno(r, "Failed to add LUKS2 key: %m");

                passphrase = strempty(iovec_key->iov_base);
                passphrase_size = iovec_key->iov_len;
        }

        if (IN_SET(p->encrypt, ENCRYPT_TPM2, ENCRYPT_KEY_FILE_TPM2)) {
#if HAVE_TPM2
                _cleanup_(iovec_done) struct iovec pubkey = {}, srk = {};
                _cleanup_(iovec_done_erase) struct iovec secret = {};
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
                ssize_t base64_encoded_size;
                int keyslot;
                TPM2Flags flags = 0;
                Tpm2PCRValue *pcr_values = arg_tpm2_n_hash_pcr_values > 0 ? arg_tpm2_hash_pcr_values : p->tpm2_hash_pcr_values;
                size_t n_pcr_values = arg_tpm2_n_hash_pcr_values > 0 ? arg_tpm2_n_hash_pcr_values : p->tpm2_n_hash_pcr_values;

                if (n_pcr_values == 0 &&
                    arg_tpm2_public_key_pcr_mask == 0 &&
                    !arg_tpm2_pcrlock)
                        log_notice("Notice: encrypting future partition %" PRIu64 ", locking against TPM2 with an empty policy, i.e. without any state or access restrictions.\n"
                                   "Use --tpm2-public-key=, --tpm2-pcrlock=, or --tpm2-pcrs= to enable one or more restrictions.", p->partno);

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

                        if (!tpm2_pcr_values_has_all_values(pcr_values, n_pcr_values))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Must provide all PCR values when using TPM2 device key.");
                } else {
                        r = tpm2_context_new_or_warn(arg_tpm2_device, &tpm2_context);
                        if (r < 0)
                                return r;

                        if (!tpm2_pcr_values_has_all_values(pcr_values, n_pcr_values)) {
                                r = tpm2_pcr_read_missing_values(tpm2_context, pcr_values, n_pcr_values);
                                if (r < 0)
                                        return log_error_errno(r, "Could not read pcr values: %m");
                        }
                }

                uint16_t hash_pcr_bank = 0;
                uint32_t hash_pcr_mask = 0;
                if (n_pcr_values > 0) {
                        size_t hash_count;
                        r = tpm2_pcr_values_hash_count(pcr_values, n_pcr_values, &hash_count);
                        if (r < 0)
                                return log_error_errno(r, "Could not get hash count: %m");

                        if (hash_count > 1)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Multiple PCR banks selected.");

                        hash_pcr_bank = pcr_values[0].hash;
                        r = tpm2_pcr_values_to_mask(pcr_values, n_pcr_values, hash_pcr_bank, &hash_pcr_mask);
                        if (r < 0)
                                return log_error_errno(r, "Could not get hash mask: %m");
                }

                TPM2B_DIGEST policy_hash[2] = {
                        TPM2B_DIGEST_MAKE(NULL, TPM2_SHA256_DIGEST_SIZE),
                        TPM2B_DIGEST_MAKE(NULL, TPM2_SHA256_DIGEST_SIZE),
                };
                size_t n_policy_hash = 1;

                /* If both PCR public key unlock and pcrlock unlock is selected, then shard the encryption key. */
                r = tpm2_calculate_sealing_policy(
                                pcr_values,
                                n_pcr_values,
                                iovec_is_set(&pubkey) ? &public : NULL,
                                /* use_pin= */ false,
                                arg_tpm2_pcrlock && !iovec_is_set(&pubkey) ? &pcrlock_policy : NULL,
                                policy_hash + 0);
                if (r < 0)
                        return log_error_errno(r, "Could not calculate sealing policy digest for shard 0: %m");

                if (arg_tpm2_pcrlock && iovec_is_set(&pubkey)) {
                        r = tpm2_calculate_sealing_policy(
                                        pcr_values,
                                        n_pcr_values,
                                        /* public= */ NULL,      /* Turn this one off for the 2nd shard */
                                        /* use_pin= */ false,
                                        &pcrlock_policy,         /* But turn this one on */
                                        policy_hash + 1);
                        if (r < 0)
                                return log_error_errno(r, "Could not calculate sealing policy digest for shard 1: %m");

                        n_policy_hash++;
                }

                struct iovec *blobs = NULL;
                size_t n_blobs = 0;
                CLEANUP_ARRAY(blobs, n_blobs, iovec_array_free);

                if (arg_tpm2_device_key) {
                        if (n_policy_hash > 1)
                                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                                       "Combined signed PCR policies and pcrlock policies cannot be calculated offline, currently.");

                        blobs = new0(struct iovec, 1);
                        if (!blobs)
                                return log_oom();

                        n_blobs = 1;

                        r = tpm2_calculate_seal(
                                        arg_tpm2_seal_key_handle,
                                        &device_key_public,
                                        /* attributes= */ NULL,
                                        /* secret= */ NULL,
                                        policy_hash + 0,
                                        /* pin= */ NULL,
                                        &secret,
                                        blobs + 0,
                                        &srk);
                } else
                        r = tpm2_seal(tpm2_context,
                                      arg_tpm2_seal_key_handle,
                                      policy_hash,
                                      n_policy_hash,
                                      /* pin= */ NULL,
                                      &secret,
                                      &blobs,
                                      &n_blobs,
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
                                /* volume_key_size= */ volume_key_size,
                                base64_encoded,
                                base64_encoded_size);
                if (keyslot < 0)
                        return log_error_errno(keyslot, "Failed to add new TPM2 key: %m");

                struct iovec policy_hash_as_iovec[2] = {
                        IOVEC_MAKE(policy_hash[0].buffer, policy_hash[0].size),
                        IOVEC_MAKE(policy_hash[1].buffer, policy_hash[1].size),
                };

                r = tpm2_make_luks2_json(
                                keyslot,
                                hash_pcr_mask,
                                hash_pcr_bank,
                                &pubkey,
                                arg_tpm2_public_key_pcr_mask,
                                /* primary_alg= */ 0,
                                blobs,
                                n_blobs,
                                policy_hash_as_iovec,
                                n_policy_hash,
                                /* salt= */ NULL, /* no salt because tpm2_seal has no pin */
                                &srk,
                                &pcrlock_policy.nv_handle,
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

                r = sym_crypt_reencrypt_run(cd, NULL, NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to encrypt %s: %m", node);
        } else {
                _cleanup_free_ DecryptedPartitionTarget *t = NULL;
                _cleanup_close_ int dev_fd = -1;

                r = sym_crypt_activate_by_volume_key(
                                cd,
                                dm_name,
                                NULL,
                                /* volume_key_size= */ volume_key_size,
                                (arg_discard && p->integrity != INTEGRITY_INLINE ? CRYPT_ACTIVATE_ALLOW_DISCARDS : 0) | CRYPT_ACTIVATE_PRIVATE);
                if (r < 0)
                        return log_error_errno(r, "Failed to activate LUKS superblock: %m");

                /* crypt_wipe() the whole device to avoid integrity errors upon mkfs */
                if (p->integrity == INTEGRITY_INLINE) {
                        r = sym_crypt_wipe(
                                        cd,
                                        vol,
                                        CRYPT_WIPE_ZERO,
                                        /* offset= */ 0,
                                        /* length= */ 0,
                                        /* wipe_block_size= */ 1 * U64_MB,
                                        /* flags= */ 0,
                                        /* progress= */ NULL,
                                        /* usrptr= */ NULL);
                        if (r < 0)
                                return log_error_errno(r, "Failed to wipe LUKS device: %m");

                        log_info("%s integrity protection for future partition %" PRIu64 " initialized.",
                                 integrity_alg_to_string(p->integrity_alg), p->partno);
                }

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
                               "libcryptsetup is not supported, cannot encrypt.");
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

        /* Minimized partitions will use the copy blocks logic so skip those here. */
        if (p->copy_blocks_fd >= 0)
                return 0;

        assert_se(dp = p->siblings[VERITY_DATA]);
        assert(!dp->dropped);

        (void) partition_hint(p, node, &hint);

        r = dlopen_cryptsetup();
        if (r < 0)
                return log_error_errno(r, "libcryptsetup not found, cannot setup verity: %m");

        if (!node) {
                r = partition_target_prepare(context, p, p->new_size, /* need_path= */ true, &t);
                if (r < 0)
                        return r;

                node = partition_target_path(t);
        }

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
        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "libcryptsetup is not supported, cannot setup verity hashes.");
#endif
}

static int sign_verity_roothash(
                Context *context,
                const struct iovec *roothash,
                struct iovec *ret_signature) {

#if HAVE_OPENSSL
        _cleanup_(BIO_freep) BIO *rb = NULL;
        _cleanup_(PKCS7_freep) PKCS7 *p7 = NULL;
        _cleanup_free_ char *hex = NULL;
        _cleanup_free_ uint8_t *sig = NULL;
        int sigsz;

        assert(context);
        assert(context->certificate);
        assert(context->private_key);
        assert(roothash);
        assert(iovec_is_set(roothash));
        assert(ret_signature);

        hex = hexmem(roothash->iov_base, roothash->iov_len);
        if (!hex)
                return log_oom();

        rb = BIO_new_mem_buf(hex, -1);
        if (!rb)
                return log_oom();

        p7 = PKCS7_sign(context->certificate, context->private_key, NULL, rb, PKCS7_DETACHED|PKCS7_NOATTR|PKCS7_BINARY);
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
        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "OpenSSL is not supported, cannot setup verity signature.");
#endif
}

static const VeritySettings *lookup_verity_settings_by_uuid_pair(sd_id128_t data_uuid, sd_id128_t hash_uuid) {
        uint8_t root_hash_key[sizeof(sd_id128_t) * 2];

        if (sd_id128_is_null(data_uuid) || sd_id128_is_null(hash_uuid))
                return NULL;

        /* As per the https://uapi-group.org/specifications/specs/discoverable_partitions_specification/ the
         * UUIDs of the data and verity partitions are respectively the first and second halves of the
         * dm-verity roothash, so we can use them to match the signature to the right partition. */

        memcpy(root_hash_key, data_uuid.bytes, sizeof(sd_id128_t));
        memcpy(root_hash_key + sizeof(sd_id128_t), hash_uuid.bytes, sizeof(sd_id128_t));

        VeritySettings key = {
                .root_hash = IOVEC_MAKE(root_hash_key, sizeof(root_hash_key)),
        };

        return set_get(arg_verity_settings, &key);
}

static int partition_format_verity_sig(Context *context, Partition *p) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        _cleanup_free_ char *text = NULL, *hint = NULL;
        const VeritySettings *verity_settings;
        Partition *hp, *rp;
        uint8_t fp[X509_FINGERPRINT_SIZE];
        int whole_fd, r;
        bool has_fp = false;

        assert(p->verity == VERITY_SIG);

        if (p->dropped)
                return 0;

        if (PARTITION_EXISTS(p))
                return 0;

        assert_se(hp = p->siblings[VERITY_HASH]);
        assert(!hp->dropped);
        assert_se(rp = p->siblings[VERITY_DATA]);
        assert(!rp->dropped);

        verity_settings = lookup_verity_settings_by_uuid_pair(rp->current_uuid, hp->current_uuid);

        if (!verity_settings) {
#if HAVE_OPENSSL
                if (!context->private_key)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Verity signature partition signing requested but no private key provided (--private-key=).");

                if (!context->certificate)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Verity signature partition signing requested but no PEM certificate provided (--certificate=).");
#else
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Verity signature partition signing requested but OpenSSL support is disabled.");
#endif
        }

        (void) partition_hint(p, context->node, &hint);

        assert_se((whole_fd = fdisk_get_devfd(context->fdisk_context)) >= 0);

        _cleanup_(iovec_done) struct iovec sig_free = {};
        const struct iovec *roothash, *sig;
        if (verity_settings) {
                sig = &verity_settings->root_hash_sig;
                roothash = &verity_settings->root_hash;
        } else {
                r = sign_verity_roothash(context, &hp->roothash, &sig_free);
                if (r < 0)
                        return r;

                sig = &sig_free;
                roothash = &hp->roothash;
        }

#if HAVE_OPENSSL
        r = x509_fingerprint(context->certificate, fp);
        if (r < 0)
                return log_error_errno(r, "Unable to calculate X509 certificate fingerprint: %m");
        has_fp = true;
#endif

        r = sd_json_buildo(
                        &v,
                        SD_JSON_BUILD_PAIR("rootHash", SD_JSON_BUILD_HEX(roothash->iov_base, roothash->iov_len)),
                        SD_JSON_BUILD_PAIR_CONDITION(has_fp, "certificateFingerprint", SD_JSON_BUILD_HEX(fp, sizeof(fp))),
                        SD_JSON_BUILD_PAIR("signature", JSON_BUILD_IOVEC_BASE64(sig)));
        if (r < 0)
                return log_error_errno(r, "Failed to build verity signature JSON object: %m");

        r = sd_json_variant_format(v, 0, &text);
        if (r < 0)
                return log_error_errno(r, "Failed to format verity signature JSON object: %m");

        if (strlen(text)+1 > p->new_size)
                return log_error_errno(SYNTHETIC_ERRNO(E2BIG), "Verity signature too long for partition.");

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

static int progress_bytes(uint64_t n_bytes, uint64_t bps, void *userdata) {
        Partition *p = ASSERT_PTR(userdata);
        unsigned percent;

        p->copy_blocks_done += n_bytes;

        /* Catch division by zero. */
        if (p->copy_blocks_done >= p->copy_blocks_size)
                percent = 100;
        else
                percent = (unsigned) (100.0 * (double) p->copy_blocks_done / (double) p->copy_blocks_size);

        if (percent == p->last_percent)
                return 0;

        if (!ratelimit_below(&p->progress_ratelimit))
                return 0;

        if (bps != UINT64_MAX)
                (void) draw_progress_barf(
                                percent,
                                "%s %s %s %s/%s %s/s",
                                strna(p->copy_blocks_path),
                                glyph(GLYPH_ARROW_RIGHT),
                                strna(p->definition_path),
                                FORMAT_BYTES_WITH_POINT(p->copy_blocks_done),
                                FORMAT_BYTES_WITH_POINT(p->copy_blocks_size),
                                FORMAT_BYTES_WITH_POINT(bps));
        else
                (void) draw_progress_barf(
                                percent,
                                "%s %s %s %s/%s",
                                strna(p->copy_blocks_path),
                                glyph(GLYPH_ARROW_RIGHT),
                                strna(p->definition_path),
                                FORMAT_BYTES_WITH_POINT(p->copy_blocks_done),
                                FORMAT_BYTES_WITH_POINT(p->copy_blocks_size));

        p->last_percent = percent;

        (void) context_notify(p->context, PROGRESS_COPYING_PARTITION, p->definition_path, percent);

        return 0;
}

static int context_copy_blocks(Context *context) {
        int r;

        assert(context);

        /* Copy in file systems on the block level */

        LIST_FOREACH(partitions, p, context->partitions) {
                _cleanup_(partition_target_freep) PartitionTarget *t = NULL;

                if (p->dropped)
                        continue;

                if (PARTITION_EXISTS(p)) /* Never copy over existing partitions */
                        continue;

                if (partition_defer(context, p))
                        continue;

                /* For offline signing case */
                if (!set_isempty(arg_verity_settings) && partition_designator_is_verity_sig(p->type.designator))
                        return partition_format_verity_sig(context, p);

                if (p->copy_blocks_fd < 0)
                        continue;

                (void) context_notify(context, PROGRESS_COPYING_PARTITION, p->definition_path, UINT_MAX);

                assert(p->new_size != UINT64_MAX);

                size_t extra = p->encrypt != ENCRYPT_OFF ? LUKS2_METADATA_KEEP_FREE : 0;

                if (p->copy_blocks_size == UINT64_MAX)
                        p->copy_blocks_size = LESS_BY(p->new_size, extra);

                assert(p->new_size >= p->copy_blocks_size + extra);

                usec_t start_timestamp = now(CLOCK_MONOTONIC);

                r = partition_target_prepare(context, p, p->new_size,
                                             /* need_path= */ p->encrypt != ENCRYPT_OFF || p->siblings[VERITY_HASH],
                                             &t);
                if (r < 0)
                        return r;

                if (p->encrypt != ENCRYPT_OFF && t->loop) {
                        r = partition_encrypt(context, p, t, /* offline= */ false);
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

                r = copy_bytes_full(p->copy_blocks_fd, partition_target_fd(t), p->copy_blocks_size, COPY_REFLINK, /* ret_remains= */ NULL, /* ret_remains_size= */ NULL, progress_bytes, p);
                clear_progress_bar(/* prefix= */ NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to copy in data from '%s': %m", p->copy_blocks_path);

                log_info("Copying in of '%s' on block level completed.", p->copy_blocks_path);

                if (p->encrypt != ENCRYPT_OFF && !t->loop) {
                        r = partition_encrypt(context, p, t, /* offline= */ true);
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

                if (p->siblings[VERITY_HASH] && !partition_defer(context, p->siblings[VERITY_HASH])) {
                        r = partition_format_verity_hash(context, p->siblings[VERITY_HASH],
                                                         /* node= */ NULL, partition_target_path(t));
                        if (r < 0)
                                return r;
                }

                if (p->siblings[VERITY_SIG] && !partition_defer(context, p->siblings[VERITY_SIG])) {
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

static int shallow_join_strv(char ***ret, char **a, char **b) {
        _cleanup_free_ char **joined = NULL;
        char **iter;

        assert(ret);

        joined = new(char*, strv_length(a) + strv_length(b) + 1);
        if (!joined)
                return log_oom();

        iter = joined;

        STRV_FOREACH(i, a)
                *(iter++) = *i;

        STRV_FOREACH(i, b)
                if (!strv_contains(joined, *i))
                        *(iter++) = *i;

        *iter = NULL;

        *ret = TAKE_PTR(joined);
        return 0;
}

static int make_copy_files_denylist(
                Context *context,
                const Partition *p,
                const char *source,
                const char *target,
                Hashmap **ret) {

        _cleanup_hashmap_free_ Hashmap *denylist = NULL;
        _cleanup_free_ char **override_exclude_src = NULL, **override_exclude_tgt = NULL;
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

        if (p->suppressing) {
                r = shallow_join_strv(&override_exclude_src,
                                      p->exclude_files_source,
                                      p->suppressing->exclude_files_source);
                if (r < 0)
                        return r;
                r = shallow_join_strv(&override_exclude_tgt,
                                      p->exclude_files_target,
                                      p->suppressing->exclude_files_target);
                if (r < 0)
                        return r;
        }

        STRV_FOREACH(e, override_exclude_src ?: p->exclude_files_source) {
                if (path_startswith(source, *e))
                        return 1;

                r = add_exclude_path(*e, &denylist, endswith(*e, "/") ? DENY_CONTENTS : DENY_INODE);
                if (r < 0)
                        return r;
        }

        STRV_FOREACH(e, override_exclude_tgt ?: p->exclude_files_target) {
                _cleanup_free_ char *path = NULL;

                if (path_startswith(target, *e))
                        return 1;

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

static int add_subvolume_path(const char *path, BtrfsSubvolFlags flags, Hashmap **subvolumes) {
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

        r = hashmap_ensure_put(subvolumes, &inode_hash_ops, st, INT_TO_PTR(flags));
        if (r < 0)
                return log_oom();

        TAKE_PTR(st);

        return 0;
}

static int make_subvolumes_hashmap(const Partition *p, Hashmap **ret) {
        _cleanup_hashmap_free_ Hashmap *hashmap = NULL;
        Subvolume *subvolume;
        int r;

        assert(p);
        assert(ret);

        ORDERED_HASHMAP_FOREACH(subvolume, p->subvolumes) {
                _cleanup_free_ char *path = NULL;

                path = strdup(subvolume->path);
                if (!path)
                        return log_oom();

                r = hashmap_ensure_put(&hashmap, &path_hash_ops_free, path, INT_TO_PTR(subvolume->flags));
                if (r < 0)
                        return log_oom();

                TAKE_PTR(path);
        }

        if (p->suppressing) {
                Hashmap *suppressing;

                r = make_subvolumes_hashmap(p->suppressing, &suppressing);
                if (r < 0)
                        return r;

                r = hashmap_merge(hashmap, suppressing);
                if (r < 0)
                        return log_oom();
        }

        *ret = TAKE_PTR(hashmap);
        return 0;
}

static int make_subvolumes_by_source_inode_hashmap(
                const Partition *p,
                const char *source,
                const char *target,
                Hashmap **ret) {

        _cleanup_hashmap_free_ Hashmap *hashmap = NULL;
        Subvolume *subvolume;
        int r;

        assert(p);
        assert(target);
        assert(ret);

        ORDERED_HASHMAP_FOREACH(subvolume, p->subvolumes) {
                _cleanup_free_ char *path = NULL;

                const char *s = path_startswith(subvolume->path, target);
                if (!s)
                        continue;

                path = path_join(source, s);
                if (!path)
                        return log_oom();

                r = add_subvolume_path(path, subvolume->flags, &hashmap);
                if (r < 0)
                        return r;
        }

        if (p->suppressing) {
                Hashmap *suppressing;

                r = make_subvolumes_by_source_inode_hashmap(p->suppressing, source, target, &suppressing);
                if (r < 0)
                        return r;

                r = hashmap_merge(hashmap, suppressing);
                if (r < 0)
                        return log_oom();
        }

        *ret = TAKE_PTR(hashmap);
        return 0;
}

static int file_is_denylisted(const char *source, Hashmap *denylist) {
        _cleanup_close_ int pfd = -EBADF;
        struct stat st, rst;
        int r;

        r = chase_and_stat(source, arg_copy_source, CHASE_PREFIX_ROOT, /* ret_path= */ NULL, &st);
        if (r < 0)
                return log_error_errno(r, "Failed to stat source file '%s/%s': %m", strempty(arg_copy_source), source);

        if (PTR_TO_INT(hashmap_get(denylist, &st)) == DENY_INODE)
                return 1;

        if (stat(empty_to_root(arg_copy_source), &rst) < 0)
                return log_error_errno(errno, "Failed to stat '%s': %m", empty_to_root(arg_copy_source));

        pfd = chase_and_open_parent(source, arg_copy_source, CHASE_PREFIX_ROOT, /* ret_filename= */ NULL);
        if (pfd < 0)
                return log_error_errno(pfd, "Failed to chase '%s/%s': %m", strempty(arg_copy_source), source);

        for (;;) {
                if (fstat(pfd, &st) < 0)
                        return log_error_errno(errno, "Failed to stat parent: %m");

                if (PTR_TO_INT(hashmap_get(denylist, &st)) != DENY_DONT)
                        return 1;

                if (stat_inode_same(&st, &rst))
                        break;

                _cleanup_close_ int new_pfd = openat(pfd, "..", O_DIRECTORY|O_RDONLY);
                if (new_pfd < 0)
                        return log_error_errno(errno, "Failed to open parent directory: %m");

                close_and_replace(pfd, new_pfd);
        }

        return 0;
}

static int do_copy_files(Context *context, Partition *p, const char *root) {
        _cleanup_hashmap_free_ Hashmap *subvolumes = NULL;
        int r;

        assert(p);
        assert(root);

        r = make_subvolumes_hashmap(p, &subvolumes);
        if (r < 0)
                return r;

        _cleanup_free_ CopyFiles *copy_files = newdup(CopyFiles, p->copy_files, p->n_copy_files);
        if (!copy_files)
                return log_oom();

        size_t n_copy_files = p->n_copy_files;
        if (p->suppressing) {
                if (!GREEDY_REALLOC_APPEND(copy_files, n_copy_files,
                                           p->suppressing->copy_files, p->suppressing->n_copy_files))
                        return log_oom();
        }

        /* copy_tree_at() automatically copies the permissions of source directories to target directories if
         * it created them. However, the root directory is created by us, so we have to manually take care
         * that it is initialized. We use the first source directory targeting "/" as the metadata source for
         * the root directory. */
        FOREACH_ARRAY(line, copy_files, n_copy_files) {
                _cleanup_close_ int rfd = -EBADF, sfd = -EBADF;

                if (!path_equal(line->target, "/"))
                        continue;

                rfd = open(root, O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
                if (rfd < 0)
                        return -errno;

                sfd = chase_and_open(line->source, arg_copy_source, CHASE_PREFIX_ROOT, O_PATH|O_DIRECTORY|O_CLOEXEC|O_NOCTTY, NULL);
                if (sfd == -ENOTDIR)
                        continue;
                if (sfd < 0)
                        return log_error_errno(sfd, "Failed to open source file '%s%s': %m", strempty(arg_copy_source), line->source);

                (void) copy_xattr(sfd, NULL, rfd, NULL, COPY_ALL_XATTRS);
                (void) copy_access(sfd, rfd);
                (void) copy_times(sfd, rfd, 0);

                break;
        }

        FOREACH_ARRAY(line, copy_files, n_copy_files) {
                _cleanup_hashmap_free_ Hashmap *denylist = NULL;
                _cleanup_hashmap_free_ Hashmap *subvolumes_by_source_inode = NULL;
                _cleanup_close_ int sfd = -EBADF, pfd = -EBADF, tfd = -EBADF;
                usec_t ts = parse_source_date_epoch();

                r = make_copy_files_denylist(context, p, line->source, line->target, &denylist);
                if (r < 0)
                        return r;
                if (r > 0)
                        continue;

                r = make_subvolumes_by_source_inode_hashmap(p, line->source, line->target, &subvolumes_by_source_inode);
                if (r < 0)
                        return r;

                sfd = chase_and_open(line->source, arg_copy_source, CHASE_PREFIX_ROOT, O_CLOEXEC|O_NOCTTY, NULL);
                if (sfd == -ENOENT) {
                        log_notice_errno(sfd, "Failed to open source file '%s%s', skipping: %m", strempty(arg_copy_source), line->source);
                        continue;
                }
                if (sfd < 0)
                        return log_error_errno(sfd, "Failed to open source file '%s%s': %m", strempty(arg_copy_source), line->source);

                r = fd_verify_regular(sfd);
                if (r < 0) {
                        if (r != -EISDIR)
                                return log_error_errno(r, "Failed to check type of source file '%s': %m", line->source);

                        /* We are looking at a directory */
                        tfd = chase_and_open(line->target, root, CHASE_PREFIX_ROOT, O_RDONLY|O_DIRECTORY|O_CLOEXEC, NULL);
                        if (tfd < 0) {
                                _cleanup_free_ char *dn = NULL, *fn = NULL;

                                if (tfd != -ENOENT)
                                        return log_error_errno(tfd, "Failed to open target directory '%s': %m", line->target);

                                r = path_extract_filename(line->target, &fn);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to extract filename from '%s': %m", line->target);

                                r = path_extract_directory(line->target, &dn);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to extract directory from '%s': %m", line->target);

                                r = mkdir_p_root_full(root, dn, UID_INVALID, GID_INVALID, 0755, ts, subvolumes);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to create parent directory '%s': %m", dn);

                                pfd = chase_and_open(dn, root, CHASE_PREFIX_ROOT, O_RDONLY|O_DIRECTORY|O_CLOEXEC, NULL);
                                if (pfd < 0)
                                        return log_error_errno(pfd, "Failed to open parent directory of target: %m");

                                r = copy_tree_at(
                                                sfd, ".",
                                                pfd, fn,
                                                UID_INVALID, GID_INVALID,
                                                line->flags,
                                                denylist, subvolumes_by_source_inode);
                        } else
                                r = copy_tree_at(
                                                sfd, ".",
                                                tfd, ".",
                                                UID_INVALID, GID_INVALID,
                                                line->flags,
                                                denylist, subvolumes_by_source_inode);
                        if (r < 0)
                                return log_error_errno(r, "Failed to copy '%s%s' to '%s%s': %m",
                                                       strempty(arg_copy_source), line->source, strempty(root), line->target);
                } else {
                        _cleanup_free_ char *dn = NULL, *fn = NULL;

                        /* We are looking at a regular file */

                        r = file_is_denylisted(line->source, denylist);
                        if (r < 0)
                                return r;
                        if (r > 0) {
                                log_debug("%s is in the denylist, ignoring", line->source);
                                continue;
                        }

                        r = path_extract_filename(line->target, &fn);
                        if (r == -EADDRNOTAVAIL || r == O_DIRECTORY)
                                return log_error_errno(SYNTHETIC_ERRNO(EISDIR),
                                                       "Target path '%s' refers to a directory, but source path '%s' refers to regular file, can't copy.", line->target, line->source);
                        if (r < 0)
                                return log_error_errno(r, "Failed to extract filename from '%s': %m", line->target);

                        r = path_extract_directory(line->target, &dn);
                        if (r < 0)
                                return log_error_errno(r, "Failed to extract directory from '%s': %m", line->target);

                        r = mkdir_p_root_full(root, dn, UID_INVALID, GID_INVALID, 0755, ts, subvolumes);
                        if (r < 0)
                                return log_error_errno(r, "Failed to create parent directory: %m");

                        pfd = chase_and_open(dn, root, CHASE_PREFIX_ROOT, O_RDONLY|O_DIRECTORY|O_CLOEXEC, NULL);
                        if (pfd < 0)
                                return log_error_errno(pfd, "Failed to open parent directory of target: %m");

                        tfd = openat(pfd, fn, O_CREAT|O_EXCL|O_WRONLY|O_CLOEXEC, 0700);
                        if (tfd < 0)
                                return log_error_errno(errno, "Failed to create target file '%s': %m", line->target);

                        r = copy_bytes(sfd, tfd, UINT64_MAX, COPY_REFLINK|COPY_HOLES|COPY_SIGINT|COPY_TRUNCATE);
                        if (r < 0)
                                return log_error_errno(r, "Failed to copy '%s' to '%s%s': %m", line->source, strempty(arg_copy_source), line->target);

                        (void) copy_xattr(sfd, NULL, tfd, NULL, COPY_ALL_XATTRS);
                        (void) copy_access(sfd, tfd);
                        (void) copy_times(sfd, tfd, 0);

                        if (ts != USEC_INFINITY) {
                                struct timespec tspec;
                                timespec_store(&tspec, ts);

                                if (futimens(pfd, (const struct timespec[2]) { TIMESPEC_OMIT, tspec }) < 0)
                                        return -errno;
                        }
                }
        }

        return 0;
}

static int do_make_directories(Partition *p, const char *root) {
        _cleanup_hashmap_free_ Hashmap *subvolumes = NULL;
        _cleanup_free_ char **override_dirs = NULL;
        int r;

        assert(p);
        assert(root);

        r = make_subvolumes_hashmap(p, &subvolumes);
        if (r < 0)
                return r;

        if (p->suppressing) {
                r = shallow_join_strv(&override_dirs, p->make_directories, p->suppressing->make_directories);
                if (r < 0)
                        return r;
        }

        STRV_FOREACH(d, override_dirs ?: p->make_directories) {
                r = mkdir_p_root_full(root, *d, UID_INVALID, GID_INVALID, 0755, parse_source_date_epoch(), subvolumes);
                if (r < 0)
                        return log_error_errno(r, "Failed to create directory '%s' in file system: %m", *d);
        }

        return 0;
}

static int do_make_symlinks(Partition *p, const char *root) {
        int r;

        assert(p);
        assert(root);

        STRV_FOREACH_PAIR(path, target, p->make_symlinks) {
                _cleanup_close_ int parent_fd = -EBADF;
                _cleanup_free_ char *f = NULL;

                r = chase(*path, root, CHASE_PREFIX_ROOT|CHASE_PARENT|CHASE_EXTRACT_FILENAME, &f, &parent_fd);
                if (r < 0)
                        return log_error_errno(r, "Failed to resolve %s in %s", *path, root);

                if (symlinkat(*target, parent_fd, f) < 0)
                        return log_error_errno(errno, "Failed to create symlink at %s to %s: %m", *path, *target);
        }

        return 0;
}

static int make_subvolumes_read_only(Partition *p, const char *root) {
        _cleanup_free_ char *path = NULL;
        Subvolume *subvolume;
        int r;

        ORDERED_HASHMAP_FOREACH(subvolume, p->subvolumes) {
                if (!FLAGS_SET(subvolume->flags, BTRFS_SUBVOL_RO))
                        continue;

                path = path_join(root, subvolume->path);
                if (!path)
                        return log_oom();

                r = btrfs_subvol_set_read_only(path, true);
                if (r < 0)
                        return log_error_errno(r, "Failed to make subvolume '%s' read-only: %m", subvolume->path);
        }

        if (p->suppressing) {
                r = make_subvolumes_read_only(p->suppressing, root);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int set_default_subvolume(Partition *p, const char *root) {
        _cleanup_free_ char *path = NULL;
        int r;

        assert(p);
        assert(root);

        if (!p->default_subvolume)
                return 0;

        path = path_join(root, p->default_subvolume);
        if (!path)
                return log_oom();

        r = btrfs_subvol_make_default(path);
        if (r < 0)
                return log_error_errno(r, "Failed to make '%s' the default subvolume: %m", p->default_subvolume);

        return 0;
}

static int partition_acquire_sibling_labels(const Partition *p, char ***ret) {
        assert(p);
        assert(ret);

        _cleanup_strv_free_ char **l = NULL;
        if (p->new_label) {
                l = strv_new(p->new_label);
                if (!l)
                        return log_oom();
        }

        FOREACH_ELEMENT(sibling, p->siblings) {
                Partition *s = *sibling;

                if (!s || s == p || !s->new_label || strv_contains(l, s->new_label))
                        continue;

                if (strv_extend(&l, s->new_label) < 0)
                        return log_oom();
        }

        strv_sort(l); /* bring into a systematic order to make things reproducible */

        *ret = TAKE_PTR(l);
        return 0;
}

static int partition_acquire_sibling_uuids(const Partition *p, char ***ret) {
        assert(p);
        assert(ret);

        _cleanup_strv_free_ char **l = NULL;
        l = strv_new(SD_ID128_TO_UUID_STRING(p->type.uuid));
        if (!l)
                return log_oom();

        FOREACH_ELEMENT(sibling, p->siblings) {
                Partition *s = *sibling;

                if (!s || s == p)
                        continue;

                const char *u = SD_ID128_TO_UUID_STRING(s->type.uuid);
                if (strv_contains(l, u))
                        continue;

                if (strv_extend(&l, u) < 0)
                        return log_oom();
        }

        strv_sort(l); /* bring into a systematic order to make things reproducible */

        *ret = TAKE_PTR(l);
        return 0;
}


static int do_make_validatefs_xattrs(const Partition *p, const char *root) {
        int r;

        assert(p);
        assert(root);

        if (!partition_add_validatefs(p))
                return 0;

        _cleanup_close_ int fd = open(root, O_DIRECTORY|O_CLOEXEC);
        if (fd < 0)
                return log_error_errno(errno, "Failed to open root inode '%s': %m", root);

        _cleanup_strv_free_ char **l = NULL;
        r = partition_acquire_sibling_labels(p, &l);
        if (r < 0)
                return r;
        if (!strv_isempty(l)) {
                r = xsetxattr_strv(fd, /* path= */ NULL, AT_EMPTY_PATH, "user.validatefs.gpt_label", l);
                if (r < 0)
                        return log_error_errno(r, "Failed to set 'user.validatefs.gpt_label' extended attribute: %m");
        }
        l = strv_free(l);

        r = partition_acquire_sibling_uuids(p, &l);
        if (r < 0)
                return r;
        r = xsetxattr_strv(fd, /* path= */ NULL, AT_EMPTY_PATH, "user.validatefs.gpt_type_uuid", l);
        if (r < 0)
                return log_error_errno(r, "Failed to set 'user.validatefs.gpt_type_uuid' extended attribute: %m");
        l = strv_free(l);

        /* Prefer the data from MountPoint= if specified, otherwise use data we derive from the partition type */
        if (p->n_mountpoints > 0) {
                FOREACH_ARRAY(m, p->mountpoints, p->n_mountpoints)
                        if (strv_extend(&l, m->where) < 0)
                                return log_oom();
        } else {
                const char *m = gpt_partition_type_mountpoint_nulstr(p->type);
                if (m) {
                        l = strv_split_nulstr(m);
                        if (!l)
                                return log_oom();
                }
        }

        if (!strv_isempty(l)) {
                r = xsetxattr_strv(fd, /* path= */ NULL, AT_EMPTY_PATH, "user.validatefs.mount_point", l);
                if (r < 0)
                        return log_error_errno(r, "Failed to set 'user.validatefs.mount_point' extended attribute: %m");
        }

        return 0;
}

static int partition_populate_directory(Context *context, Partition *p, char **ret) {
        _cleanup_(rm_rf_physical_and_freep) char *root = NULL;
        const char *vt;
        int r;

        assert(ret);

        log_info("Preparing to populate %s filesystem.", p->format);

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

        r = do_make_symlinks(p, root);
        if (r < 0)
                return r;

        r = do_make_validatefs_xattrs(p, root);
        if (r < 0)
                return r;

        log_info("Ready to populate %s filesystem.", p->format);

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

        (void) dlopen_libmount();

        r = pidref_safe_fork(
                        "(sd-copy)",
                        FORK_DEATHSIG_SIGTERM|FORK_LOG|FORK_WAIT|FORK_NEW_MOUNTNS|FORK_MOUNTNS_SLAVE,
                        /* ret= */ NULL);
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

                if (do_make_symlinks(p, fs) < 0)
                        _exit(EXIT_FAILURE);

                if (do_make_validatefs_xattrs(p, fs) < 0)
                        _exit(EXIT_FAILURE);

                if (make_subvolumes_read_only(p, fs) < 0)
                        _exit(EXIT_FAILURE);

                if (set_default_subvolume(p, fs) < 0)
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

static int append_btrfs_subvols(char ***l, OrderedHashmap *subvolumes, const char *default_subvolume) {
        Subvolume *subvolume;
        int r;

        assert(l);

        ORDERED_HASHMAP_FOREACH(subvolume, subvolumes) {
                _cleanup_free_ char *s = NULL;

                if (streq_ptr(subvolume->path, default_subvolume) && !strextend(&s, "default"))
                        return log_oom();

                if (FLAGS_SET(subvolume->flags, BTRFS_SUBVOL_RO) && !strextend_with_separator(&s, "-", "ro"))
                        return log_oom();

                if (!strextend_with_separator(&s, ":", subvolume->path))
                        return log_oom();

                r = strv_extend_many(l, "--subvol", s);
                if (r < 0)
                        return log_oom();
        }

        return 0;
}

static int append_btrfs_inode_flags(char ***l, OrderedHashmap *subvolumes) {
        Subvolume *subvolume;
        int r;

        assert(l);

        ORDERED_HASHMAP_FOREACH(subvolume, subvolumes) {
                if (!FLAGS_SET(subvolume->flags, BTRFS_SUBVOL_NODATACOW))
                        continue;

                _cleanup_free_ char *s = strjoin("nodatacow:", subvolume->path);
                if (!s)
                        return log_oom();

                r = strv_extend_many(l, "--inode-flags", s);
                if (r < 0)
                        return log_oom();
        }

        return 0;
}

static int finalize_extra_mkfs_options(const Partition *p, const char *root, char ***ret) {
        _cleanup_strv_free_ char **sv = NULL;
        int r;

        assert(p);
        assert(ret);

        r = mkfs_options_from_env("REPART", p->format, &sv);
        if (r < 0)
                return log_error_errno(r,
                                       "Failed to determine mkfs command line options for '%s': %m",
                                       p->format);

        if (partition_needs_populate(p) && root && streq(p->format, "btrfs")) {
                r = append_btrfs_subvols(&sv, p->subvolumes, p->default_subvolume);
                if (r < 0)
                        return r;

                r = append_btrfs_inode_flags(&sv, p->subvolumes);
                if (r < 0)
                        return r;

                if (p->suppressing) {
                        r = append_btrfs_subvols(&sv, p->suppressing->subvolumes, NULL);
                        if (r < 0)
                                return r;

                        r = append_btrfs_inode_flags(&sv, p->suppressing->subvolumes);
                        if (r < 0)
                                return r;
                }
        }

        *ret = TAKE_PTR(sv);
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

                if (partition_defer(context, p))
                        continue;

                /* For offline signing case */
                if (!set_isempty(arg_verity_settings) && partition_designator_is_verity_sig(p->type.designator))
                        return partition_format_verity_sig(context, p);

                /* Minimized partitions will use the copy blocks logic so skip those here. */
                if (p->copy_blocks_fd >= 0)
                        continue;

                (void) context_notify(context, PROGRESS_FORMATTING_PARTITION, p->definition_path, UINT_MAX);

                assert(p->offset != UINT64_MAX);
                assert(p->new_size != UINT64_MAX);
                assert(p->new_size >= (p->encrypt != ENCRYPT_OFF ? LUKS2_METADATA_KEEP_FREE : 0));

                /* If we're doing encryption, keep free space at the end which is required
                 * for cryptsetup's offline encryption. */
                r = partition_target_prepare(context, p,
                                             p->new_size - (p->encrypt != ENCRYPT_OFF ? LUKS2_METADATA_KEEP_FREE : 0),
                                             /* need_path= */ true,
                                             &t);
                if (r < 0)
                        return r;

                if (p->encrypt != ENCRYPT_OFF && t->loop) {
                        r = partition_target_grow(t, p->new_size);
                        if (r < 0)
                                return r;

                        r = partition_encrypt(context, p, t, /* offline= */ false);
                        if (r < 0)
                                return log_error_errno(r, "Failed to encrypt device: %m");
                }

                log_info("Formatting future partition %" PRIu64 ".", p->partno);

                /* If we're not writing to a loop device or if we're populating a read-only filesystem, we
                 * have to populate using the filesystem's mkfs's --root= (or equivalent) option. To do that,
                 * we need to set up the final directory tree beforehand. */

                if (partition_needs_populate(p) &&
                    (!t->loop || fstype_is_ro(p->format) || (streq_ptr(p->format, "btrfs") && p->compression))) {
                        if (!mkfs_supports_root_option(p->format))
                                return log_error_errno(SYNTHETIC_ERRNO(ENODEV),
                                                        "Loop device access is required to populate %s filesystems.",
                                                        p->format);

                        r = partition_populate_directory(context, p, &root);
                        if (r < 0)
                                return r;
                }

                r = finalize_extra_mkfs_options(p, root, &extra_mkfs_options);
                if (r < 0)
                        return r;

                r = make_filesystem(
                                partition_target_path(t),
                                p->format,
                                strempty(p->new_label),
                                root,
                                p->fs_uuid,
                                partition_mkfs_flags(p),
                                partition_fs_sector_size(context, p),
                                p->compression,
                                p->compression_level,
                                extra_mkfs_options);
                if (r < 0)
                        return r;

                /* The mkfs binary we invoked might have removed our temporary file when we're not operating
                 * on a loop device, so open the file again to make sure our file descriptor points to actual
                 * new file. */

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

                        r = partition_encrypt(context, p, t, /* offline= */ true);
                        if (r < 0)
                                return log_error_errno(r, "Failed to encrypt device: %m");
                }

                /* Note that we always sync explicitly here, since mkfs.fat doesn't do that on its own, and
                 * if we don't sync before detaching a block device the in-flight sectors possibly won't hit
                 * the disk. */

                r = partition_target_sync(context, p, t);
                if (r < 0)
                        return r;

                if (p->siblings[VERITY_HASH] && !partition_defer(context, p->siblings[VERITY_HASH])) {
                        r = partition_format_verity_hash(context, p->siblings[VERITY_HASH],
                                                         /* node= */ NULL, partition_target_path(t));
                        if (r < 0)
                                return r;
                }

                if (p->siblings[VERITY_SIG] && !partition_defer(context, p->siblings[VERITY_SIG])) {
                        r = partition_format_verity_sig(context, p->siblings[VERITY_SIG]);
                        if (r < 0)
                                return r;
                }
        }

        return 0;
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

                (void) context_notify(context, PROGRESS_ACQUIRING_PARTITION_LABELS, p->definition_path, UINT_MAX);

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
        int r;

        BIT_FOREACH(i, flags) {
                r = strextendf_with_separator(&a, ",", "%i", i);
                if (r < 0)
                        return r;
        }

        return fdisk_partition_set_attrs(q, strempty(a));
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

                if (partition_defer(context, p))
                        continue;

                (void) context_notify(context, PROGRESS_ADJUSTING_PARTITION, p->definition_path, UINT_MAX);

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
                                               "%s and %s have the same resolved split name \"%s\", refusing.",
                                               p->definition_path, q->definition_path, p->split_path);
                }
        }

        return 0;
}

static int context_split(Context *context) {
        unsigned attrs = 0;
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

                if (partition_defer(context, p))
                        continue;

                if (fd < 0) {
                        assert_se((fd = fdisk_get_devfd(context->fdisk_context)) >= 0);

                        r = read_attr_fd(fd, &attrs);
                        if (r < 0 && !ERRNO_IS_NEG_NOT_SUPPORTED(r))
                                log_warning_errno(r, "Failed to read file attributes of %s, ignoring: %m", context->node);
                }

                fdt = xopenat_full(
                                AT_FDCWD,
                                p->split_path,
                                O_WRONLY|O_NOCTTY|O_CLOEXEC|O_NOFOLLOW|O_CREAT|O_EXCL,
                                attrs & FS_NOCOW_FL ? XO_NOCOW : 0,
                                0666);
                if (fdt < 0)
                        return log_error_errno(fdt, "Failed to open split partition file %s: %m", p->split_path);

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

        if (context->dry_run) {
                log_notice("Refusing to repartition, please re-run with --dry-run=no.");
                return 0;
        }

        log_info("Applying changes to %s.", context->node);

        if (context->from_scratch && context->empty != EMPTY_CREATE) {

                (void) context_notify(context, PROGRESS_WIPING_DISK, /* object= */ NULL, UINT_MAX);

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

        (void) context_notify(context, PROGRESS_WRITING_TABLE, /* object= */ NULL, UINT_MAX);

        r = fdisk_write_disklabel(context->fdisk_context);
        if (r < 0)
                return log_error_errno(r, "Failed to write partition table: %m");

        capable = blockdev_partscan_enabled_fd(fdisk_get_devfd(context->fdisk_context));
        if (capable == -ENOTBLK)
                log_debug("Not telling kernel to reread partition table, since we are not operating on a block device.");
        else if (capable < 0)
                return log_error_errno(capable, "Failed to check if block device supports partition scanning: %m");
        else if (capable > 0) {
                log_info("Informing kernel about changed partitions...");
                (void) context_notify(context, PROGRESS_REREADING_TABLE, /* object= */ NULL, UINT_MAX);

                r = reread_partition_table_fd(fdisk_get_devfd(context->fdisk_context), /* flags= */ 0);
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

        if (context->dry_run) {
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

#if HAVE_BLKID
        _cleanup_(blkid_free_probep) blkid_probe b = NULL;
        _cleanup_close_ int fd = -EBADF;
        _cleanup_free_ char *p = NULL;
        const char *pttype;
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

        r = dlopen_libblkid();
        if (r < 0)
                return log_error_errno(r, "Failed to find libblkid: %m");

        b = sym_blkid_new_probe();
        if (!b)
                return log_oom();

        errno = 0;
        r = sym_blkid_probe_set_device(b, fd, 0, 0);
        if (r != 0)
                return log_error_errno(errno_or_else(ENOMEM), "Failed to open block device '%s': %m", p);

        (void) sym_blkid_probe_enable_partitions(b, 1);
        (void) sym_blkid_probe_set_partitions_flags(b, BLKID_PARTS_ENTRY_DETAILS);

        errno = 0;
        r = sym_blkid_do_safeprobe(b);
        if (r == _BLKID_SAFEPROBE_ERROR)
                return log_error_errno(errno_or_else(EIO), "Unable to probe for partition table of '%s': %m", p);
        if (IN_SET(r, _BLKID_SAFEPROBE_AMBIGUOUS, _BLKID_SAFEPROBE_NOT_FOUND)) {
                log_debug("Didn't find partition table on block device '%s'.", p);
                return false;
        }

        assert(r == _BLKID_SAFEPROBE_FOUND);

        (void) sym_blkid_probe_lookup_value(b, "PTTYPE", &pttype, NULL);
        if (!streq_ptr(pttype, "gpt")) {
                log_debug("Didn't find a GPT partition table on '%s'.", p);
                return false;
        }

        errno = 0;
        pl = sym_blkid_probe_get_partitions(b);
        if (!pl)
                return log_error_errno(errno_or_else(EIO), "Unable read partition table of '%s': %m", p);

        pp = sym_blkid_partlist_devno_to_partition(pl, partition_devno);
        if (!pp) {
                log_debug("Partition %u:%u has no matching partition table entry on '%s'.",
                          major(partition_devno), minor(partition_devno), p);
                return false;
        }

        r = blkid_partition_get_type_id128(pp, &pt_parsed);
        if (r < 0) {
                log_debug_errno(r, "Failed to read partition type UUID of partition %u:%u: %m",
                                major(partition_devno), minor(partition_devno));
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
#else
        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                               "Cannot check partition type UUID and device location, libblkid support is not compiled in.");
#endif
}

static int resolve_copy_blocks_auto_candidate_harder(
                dev_t start_devno,
                GptPartitionType partition_type,
                dev_t restrict_devno,
                dev_t *ret_found_devno,
                sd_id128_t *ret_uuid) {

        _cleanup_(sd_device_unrefp) sd_device *d = NULL, *nd = NULL;
        int r;

        /* A wrapper around resolve_copy_blocks_auto_candidate(), but looks for verity/verity-sig associated
         * partitions, too. i.e. if the input is a data or verity partition, will try to find the
         * verity/verity-sig partition for it, based on udev metadata. */

        const char *property;
        if (partition_designator_is_verity_hash(partition_type.designator))
                property = "ID_DISSECT_PART_VERITY_DEVICE";
        else if (partition_designator_is_verity_sig(partition_type.designator))
                property = "ID_DISSECT_PART_VERITY_SIG_DEVICE";
        else
                goto not_found;

        r = sd_device_new_from_devnum(&d, 'b', start_devno);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate device object for " DEVNUM_FORMAT_STR ": %m", DEVNUM_FORMAT_VAL(start_devno));

        const char *node;
        r = sd_device_get_property_value(d, property, &node);
        if (r == -ENOENT) {
                log_debug_errno(r, "Property %s not set on " DEVNUM_FORMAT_STR ", skipping.", property, DEVNUM_FORMAT_VAL(start_devno));
                goto not_found;
        }
        if (r < 0)
                return log_error_errno(r, "Failed to read property %s from device " DEVNUM_FORMAT_STR ": %m", property, DEVNUM_FORMAT_VAL(start_devno));

        r = sd_device_new_from_devname(&nd, node);
        if (ERRNO_IS_NEG_DEVICE_ABSENT(r)) {
                log_debug_errno(r, "Device %s referenced in %s property not found, skipping: %m", node, property);
                goto not_found;
        }
        if (r < 0)
                return log_error_errno(r, "Failed to allocate device object for '%s': %m", node);

        r = device_in_subsystem(nd, "block");
        if (r < 0)
                return log_error_errno(r, "Failed to determine if '%s' is a block device: %m", node);
        if (r == 0) {
                log_debug("Device referenced by %s property of %s does not refer to block device, refusing.", property, node);
                goto not_found;
        }

        dev_t found_devno = 0;
        r = sd_device_get_devnum(nd, &found_devno);
        if (r < 0)
                return log_error_errno(r, "Failed to get device number for '%s': %m", node);

        r = resolve_copy_blocks_auto_candidate(found_devno, partition_type, restrict_devno, ret_uuid);
        if (r < 0)
                return r;
        if (r == 0)
                goto not_found;

        if (ret_found_devno)
                *ret_found_devno = found_devno;

        return 1;

not_found:
        if (ret_found_devno)
                *ret_found_devno = 0;
        if (ret_uuid)
                *ret_uuid = SD_ID128_NULL;

        return 0;
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

        r = path_is_mount_point(resolved);
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

        switch (type.designator) {

        case PARTITION_ROOT:
        case PARTITION_ROOT_VERITY:
        case PARTITION_ROOT_VERITY_SIG:
                try1 = "/";
                break;

        case PARTITION_USR:
        case PARTITION_USR_VERITY:
        case PARTITION_USR_VERITY_SIG:
                try1 = "/usr/";
                break;

        case PARTITION_ESP:
                try1 = "/efi/";
                try2 = "/boot/";
                break;

        case PARTITION_XBOOTLDR:
                try1 = "/boot/";
                break;

        default:
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                       "Partition type %s not supported from automatic source block device discovery.",
                                       strna(partition_designator_to_string(type.designator)));
        }

        r = find_backing_devno(try1, root, &devno);
        if (r == -ENOENT && try2)
                r = find_backing_devno(try2, root, &devno);
        if (r < 0)
                return log_error_errno(r, "Failed to resolve automatic CopyBlocks= path for partition type %s, sorry: %m",
                                       partition_designator_to_string(type.designator));

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
                                if (found != 0 && found != sl)
                                        return log_error_errno(SYNTHETIC_ERRNO(ENOTUNIQ),
                                                               "Multiple matching partitions found for partition type %s, refusing.",
                                                               partition_designator_to_string(type.designator));

                                found = sl;
                                found_uuid = u;
                        }

                        dev_t harder_devno = 0;
                        r = resolve_copy_blocks_auto_candidate_harder(sl, type, restrict_devno, &harder_devno, &u);
                        if (r < 0)
                                return r;
                        if (r > 0) {
                                /* We found a matching one! */
                                if (found != 0 && found != harder_devno)
                                        return log_error_errno(SYNTHETIC_ERRNO(ENOTUNIQ),
                                                               "Multiple matching partitions found, refusing.");

                                found = harder_devno;
                                found_uuid = u;
                        }
                }
        } else if (errno != ENOENT)
                return log_error_errno(errno, "Failed to open %s: %m", p);
        else {
                r = resolve_copy_blocks_auto_candidate(devno, type, restrict_devno, &found_uuid);
                if (r < 0)
                        return r;
                if (r > 0)
                        found = devno;
        }

        if (found == 0)
                return log_error_errno(SYNTHETIC_ERRNO(ENXIO),
                                       "Unable to automatically discover suitable partition to copy blocks from for partition type %s.",
                                       partition_designator_to_string(type.designator));

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

        if (!context->partitions)
                return 0;

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

                (void) context_notify(context, PROGRESS_OPENING_COPY_BLOCK_SOURCES, p->definition_path, UINT_MAX);

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
                } else if (S_ISCHR(st.st_mode))
                        size = UINT64_MAX;
                else
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Specified path to copy blocks from '%s' is not a regular file, block device or directory, refusing.", opened);

                if (size != UINT64_MAX) {
                        if (size <= 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "File to copy bytes from '%s' has zero size, refusing.", opened);
                        if (size % 512 != 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "File to copy bytes from '%s' has size that is not multiple of 512, refusing.", opened);
                }

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

static bool need_fstab_one(const Partition *p) {
        assert(p);

        if (p->dropped)
                return false;

        if (!p->format)
                return false;

        if (p->n_mountpoints == 0)
                return false;

        return true;
}

static bool need_fstab(const Context *context) {
        assert(context);

        LIST_FOREACH(partitions, p, context->partitions)
                if (need_fstab_one(p))
                        return true;

        return false;
}

static int make_by_uuid_symlink_path(const Partition *p, char **ret) {
        _cleanup_free_ char *what = NULL;

        assert(p);
        assert(ret);

        if (streq_ptr(p->format, "vfat")) {
                if (asprintf(&what, "UUID=%04X-%04X",
                             ((uint32_t) p->fs_uuid.bytes[0] << 8) |
                             ((uint32_t) p->fs_uuid.bytes[1] << 0),
                             ((uint32_t) p->fs_uuid.bytes[2] << 8) |
                             ((uint32_t) p->fs_uuid.bytes[3])) < 0) /* Take first 32 bytes of UUID */
                        return log_oom();
        } else {
                what = strjoin("UUID=", SD_ID128_TO_UUID_STRING(p->fs_uuid));
                if (!what)
                        return log_oom();
        }

        *ret = TAKE_PTR(what);
        return 0;
}

static int context_fstab(Context *context) {
        _cleanup_(unlink_and_freep) char *t = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_free_ char *path = NULL, *c = NULL;
        int r;

        assert(context);

        if (!arg_generate_fstab)
                return false;

        if (!need_fstab(context)) {
                log_notice("MountPoint= is not specified for any eligible partitions, not generating %s",
                           arg_generate_fstab);
                return 0;
        }

        path = path_join(arg_copy_source, arg_generate_fstab);
        if (!path)
                return log_oom();

        r = fopen_tmpfile_linkable(path, O_WRONLY|O_CLOEXEC, &t, &f);
        if (r < 0)
                return log_error_errno(r, "Failed to open temporary file for %s: %m", path);

        fputs(AUTOMATIC_FSTAB_HEADER_START "\n", f);

        LIST_FOREACH(partitions, p, context->partitions) {
                _cleanup_free_ char *what = NULL;

                if (!need_fstab_one(p))
                        continue;

                r = make_by_uuid_symlink_path(p, &what);
                if (r < 0)
                        return r;

                FOREACH_ARRAY(mountpoint, p->mountpoints, p->n_mountpoints) {
                        _cleanup_free_ char *options = NULL;

                        r = partition_pick_mount_options(
                                        p->type.designator,
                                        p->format,
                                        /* rw= */ true,
                                        /* discard= */ !IN_SET(p->type.designator, PARTITION_ESP, PARTITION_XBOOTLDR),
                                        &options,
                                        NULL);
                        if (r < 0)
                                return r;

                        if (!strextend_with_separator(&options, ",", mountpoint->options))
                                return log_oom();

                        fprintf(f, "%s %s %s %s 0 %i\n",
                                what,
                                mountpoint->where,
                                p->format,
                                options,
                                p->type.designator == PARTITION_ROOT ? 1 : 2);
                }
        }

        fputs(AUTOMATIC_FSTAB_HEADER_END "\n", f);

        switch (arg_append_fstab) {
        case APPEND_AUTO: {
                r = read_full_file(path, &c, NULL);
                if (r == -ENOENT) {
                        log_debug("File fstab not found in %s", path);
                        break;
                }
                if (r < 0)
                        return log_error_errno(r, "Failed to open %s: %m", path);

                const char *acs, *ace;
                acs = find_line(c, AUTOMATIC_FSTAB_HEADER_START);
                if (acs) {
                        fwrite(c, 1, acs - c, f);
                        ace = find_line_after(acs, AUTOMATIC_FSTAB_HEADER_END);
                        if (ace)
                                fputs(ace, f);
                } else
                        fputs(c, f);
                break;
        }
        case APPEND_NO:
        case APPEND_REPLACE:
                break;
        default:
                assert_not_reached();
        }

        r = fchmod_umask(fileno(f), 0666);
        if (r < 0)
                return log_error_errno(r, "Failed to adjust access mode of generated fstab file: %m");

        r = flink_tmpfile(f, t, path, IN_SET(arg_append_fstab, APPEND_AUTO, APPEND_REPLACE) ? LINK_TMPFILE_REPLACE : 0);
        if (r < 0)
                return log_error_errno(r, "Failed to link temporary file to %s: %m", path);

        t = mfree(t);

        log_info("%s written.", path);

        return 0;
}

static bool need_crypttab_one(const Partition *p) {
        assert(p);

        if (p->dropped)
                return false;

        if (p->encrypt == ENCRYPT_OFF)
                return false;

        if (!p->encrypted_volume)
                return false;

        return true;
}

static bool need_crypttab(Context *context) {
        assert(context);

        LIST_FOREACH(partitions, p, context->partitions)
                if (need_crypttab_one(p))
                        return true;

        return false;
}

static int context_crypttab(Context *context, bool late) {
        _cleanup_(unlink_and_freep) char *t = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_free_ char *path = NULL;
        int r;

        assert(context);

        if (!arg_generate_crypttab)
                return false;

        if (!need_crypttab(context)) {
                log_notice("EncryptedVolume= is not specified for any eligible partitions, not generating %s",
                           arg_generate_crypttab);
                return 0;
        }

        path = path_join(arg_copy_source, arg_generate_crypttab);
        if (!path)
                return log_oom();

        r = fopen_tmpfile_linkable(path, O_WRONLY|O_CLOEXEC, &t, &f);
        if (r < 0)
                return log_error_errno(r, "Failed to open temporary file for %s: %m", path);

        fprintf(f, "# Automatically generated by systemd-repart\n\n");

        LIST_FOREACH(partitions, p, context->partitions) {
                _cleanup_free_ char *volume = NULL;

                if (!need_crypttab_one(p))
                        continue;

                if (!p->encrypted_volume->name && asprintf(&volume, "luks-%s", SD_ID128_TO_UUID_STRING(p->luks_uuid)) < 0)
                        return log_oom();

                fprintf(f, "%s UUID=%s %s %s\n",
                        p->encrypted_volume->name ?: volume,
                        SD_ID128_TO_UUID_STRING(p->luks_uuid),
                        isempty(p->encrypted_volume->keyfile) ? "-" : p->encrypted_volume->keyfile,
                        strempty(p->encrypted_volume->options));
        }

        r = flink_tmpfile(f, t, path, late ? LINK_TMPFILE_REPLACE : 0);
        if (r < 0)
                return log_error_errno(r, "Failed to link temporary file to %s: %m", path);

        t = mfree(t);

        log_info("%s written.", path);

        return 0;
}

/* update block sizes for verity siblings, calculate hash partition size if requested */
static int context_update_verity_size(Context *context) {
        int r;

        assert(context);

        LIST_FOREACH(partitions, p, context->partitions) {
                Partition *dp;

                if (p->verity != VERITY_HASH)
                        continue;

                if (p->dropped)
                        continue;

                if (PARTITION_EXISTS(p)) /* Never format existing partitions */
                        continue;

                assert_se(dp = p->siblings[VERITY_DATA]);

                if (p->verity_data_block_size == UINT64_MAX)
                        p->verity_data_block_size = partition_fs_sector_size(context, p);

                if (p->verity_hash_block_size == UINT64_MAX)
                        p->verity_hash_block_size = partition_fs_sector_size(context, p);

                uint64_t sz;
                if (dp->size_max != UINT64_MAX) {
                        r = calculate_verity_hash_size(
                                        dp->size_max,
                                        p->verity_hash_block_size,
                                        p->verity_data_block_size,
                                        &sz);
                        if (r < 0)
                                return log_error_errno(r, "Failed to calculate size of dm-verity hash partition: %m");

                        if (sz > p->size_min || sz > p->size_max)
                                log_warning("The dm-verity hash partition %s may be too small for a data partition "
                                            "with SizeMaxBytes=%s. The hash partition would require %s for a data "
                                            "partition of specified max size. Consider increasing the size of the "
                                            "hash partition, or decreasing SizeMaxBytes= of the data partition.",
                                            p->definition_path, FORMAT_BYTES(dp->size_max), FORMAT_BYTES(sz));
                        else if (p->size_min == UINT64_MAX) {
                                log_debug("Derived size %s of verity hash partition %s from verity data partition %s.",
                                                FORMAT_BYTES(sz), p->definition_path, dp->definition_path);

                                p->size_min = sz;
                        }
                }
        }

        return 0;
}

static int context_minimize(Context *context) {
        const char *vt = NULL;
        unsigned attrs = 0;
        int r;

        assert(context);

        if (context->backing_fd >= 0) {
                r = read_attr_fd(context->backing_fd, &attrs);
                if (r < 0 && !ERRNO_IS_NEG_NOT_SUPPORTED(r))
                        log_warning_errno(r, "Failed to read file attributes of %s, ignoring: %m", context->node);
        }

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

                (void) context_notify(context, PROGRESS_MINIMIZING, p->definition_path, UINT_MAX);

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

                fd = xopenat_full(
                                AT_FDCWD,
                                temp,
                                O_CREAT|O_EXCL|O_CLOEXEC|O_RDWR|O_NOCTTY,
                                attrs & FS_NOCOW_FL ? XO_NOCOW : 0,
                                0600);
                if (fd < 0)
                        return log_error_errno(errno, "Failed to open temporary file %s: %m", temp);

                if (fstype_is_ro(p->format))
                        fs_uuid = p->fs_uuid;
                else {
                        /* This may seem huge but it will be created sparse so it doesn't take up any space
                         * on disk until written to. */
                        if (ftruncate(fd, 1024ULL * 1024ULL * 1024ULL * 1024ULL) < 0)
                                return log_error_errno(errno, "Failed to truncate temporary file to %s: %m",
                                                       FORMAT_BYTES(1024ULL * 1024ULL * 1024ULL * 1024ULL));

                        if (arg_offline <= 0) {
                                r = loop_device_make(fd, O_RDWR, 0, UINT64_MAX, context->sector_size, 0, LOCK_EX, &d);
                                if (r < 0 && loop_device_error_is_fatal(p, r))
                                        return log_error_errno(r, "Failed to make loopback device of %s: %m", temp);
                        }

                        /* We're going to populate this filesystem twice so use a random UUID the first time
                         * to avoid UUID conflicts. */
                        r = sd_id128_randomize(&fs_uuid);
                        if (r < 0)
                                return r;
                }

                if (!d || fstype_is_ro(p->format) || (streq_ptr(p->format, "btrfs") && p->compression)) {
                        if (!mkfs_supports_root_option(p->format))
                                return log_error_errno(SYNTHETIC_ERRNO(ENODEV),
                                                       "Loop device access is required to populate %s filesystems.",
                                                       p->format);

                        r = partition_populate_directory(context, p, &root);
                        if (r < 0)
                                return r;
                }

                r = finalize_extra_mkfs_options(p, root, &extra_mkfs_options);
                if (r < 0)
                        return r;

                r = make_filesystem(
                                d ? d->node : temp,
                                p->format,
                                strempty(p->new_label),
                                root,
                                fs_uuid,
                                partition_mkfs_flags(p),
                                partition_fs_sector_size(context, p),
                                p->compression,
                                p->compression_level,
                                extra_mkfs_options);
                if (r < 0)
                        return r;

                /* Read-only filesystems are minimal from the first try because they create and size the
                 * loopback file for us. */
                if (fstype_is_ro(p->format)) {
                        fd = safe_close(fd);

                        fd = open(temp, O_RDONLY|O_CLOEXEC|O_NONBLOCK);
                        if (fd < 0)
                                return log_error_errno(errno, "Failed to open temporary file %s: %m", temp);

                        if (fstat(fd, &st) < 0)
                                return log_error_errno(errno, "Failed to stat temporary file: %m");

                        if ((uint64_t) st.st_size > partition_max_size(context, p))
                                return log_error_errno(SYNTHETIC_ERRNO(E2BIG),
                                                       "Minimal partition size of %s filesystem of partition %s exceeds configured maximum size (%s > %s)",
                                                       p->format, strna(hint), FORMAT_BYTES(st.st_size), FORMAT_BYTES(partition_max_size(context, p)));

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
                fsz = MAX(partition_min_size(context, p), fsz);

                if (fsz > partition_max_size(context, p))
                        return log_error_errno(SYNTHETIC_ERRNO(E2BIG),
                                               "Minimal partition size of %s filesystem of partition %s exceeds configured maximum size (%s > %s)",
                                               p->format, strna(hint), FORMAT_BYTES(fsz), FORMAT_BYTES(partition_max_size(context, p)));

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
                        if (r < 0 && loop_device_error_is_fatal(p, r))
                                return log_error_errno(r, "Failed to make loopback device of %s: %m", temp);
                }

                r = make_filesystem(
                                d ? d->node : temp,
                                p->format,
                                strempty(p->new_label),
                                root,
                                p->fs_uuid,
                                partition_mkfs_flags(p),
                                partition_fs_sector_size(context, p),
                                p->compression,
                                p->compression_level,
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

                fd = xopenat_full(
                                AT_FDCWD,
                                temp,
                                O_RDONLY|O_CLOEXEC|O_CREAT|O_NONBLOCK,
                                attrs & FS_NOCOW_FL ? XO_NOCOW : 0,
                                0600);
                if (fd < 0)
                        return log_error_errno(errno, "Failed to open temporary file %s: %m", temp);

                r = partition_format_verity_hash(context, p, temp, dp->copy_blocks_path);
                if (r < 0)
                        return r;

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

static int context_load_keys(Context *context) {
#if HAVE_OPENSSL
        int r;

        assert(context);

        if (arg_certificate) {
                if (arg_certificate_source_type == OPENSSL_CERTIFICATE_SOURCE_FILE) {
                        r = parse_path_argument(arg_certificate, /* suppress_root= */ false, &arg_certificate);
                        if (r < 0)
                                return r;
                }

                r = openssl_load_x509_certificate(
                                arg_certificate_source_type,
                                arg_certificate_source,
                                arg_certificate,
                                &context->certificate);
                if (r < 0)
                        return log_error_errno(r, "Failed to load X.509 certificate from %s: %m", arg_certificate);
        }

        if (arg_private_key) {
                if (arg_private_key_source_type == OPENSSL_KEY_SOURCE_FILE) {
                        r = parse_path_argument(arg_private_key, /* suppress_root= */ false, &arg_private_key);
                        if (r < 0)
                                return r;
                }

                r = openssl_load_private_key(
                                arg_private_key_source_type,
                                arg_private_key_source,
                                arg_private_key,
                                &(AskPasswordRequest) {
                                        .tty_fd = -EBADF,
                                        .id = "repart-private-key-pin",
                                        .keyring = arg_private_key,
                                        .credential = "repart.private-key-pin",
                                        .until = USEC_INFINITY,
                                        .hup_fd = -EBADF,
                                },
                                &context->private_key,
                                &context->ui);
                if (r < 0)
                        return log_error_errno(r, "Failed to load private key from %s: %m", arg_private_key);
        }

#endif
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

static int parse_join_signature(const char *p, Set **verity_settings_map) {
        _cleanup_(verity_settings_freep) VeritySettings *verity_settings = NULL;
        _cleanup_free_ char *root_hash = NULL;
        const char *signature;
        _cleanup_(iovec_done) struct iovec content = {};
        int r;

        assert(p);
        assert(verity_settings_map);

        r = extract_first_word(&p, &root_hash, ":", 0);
        if (r < 0)
                return log_error_errno(r, "Failed to parse signature parameter '%s': %m", p);
        if (!p)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Expected hash:sig");
        if ((signature = startswith(p, "base64:"))) {
                r = unbase64mem(signature, &content.iov_base, &content.iov_len);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse root hash signature '%s': %m", signature);
        } else {
                r = read_full_file(p, (char**) &content.iov_base, &content.iov_len);
                if (r < 0)
                        return log_error_errno(r, "Failed to read root hash signature file '%s': %m", p);
        }
        if (!iovec_is_set(&content))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Empty verity signature specified.");
        if (content.iov_len > VERITY_SIG_SIZE)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Verity signatures larger than %llu are not allowed.",
                                       VERITY_SIG_SIZE);

        verity_settings = new(VeritySettings, 1);
        if (!verity_settings)
                return log_oom();

        *verity_settings = (VeritySettings) {
                .root_hash_sig = TAKE_STRUCT(content),
        };

        r = unhexmem(root_hash, &verity_settings->root_hash.iov_base, &verity_settings->root_hash.iov_len);
        if (r < 0)
                return log_error_errno(r, "Failed to parse root hash '%s': %m", root_hash);
        if (verity_settings->root_hash.iov_len < sizeof(sd_id128_t))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Root hash must be at least 128-bit long: %s",
                                       root_hash);

        r = set_ensure_put(verity_settings_map, &verity_settings_hash_ops, verity_settings);
        if (r < 0)
                return log_error_errno(r, "Failed to add entry to hashmap: %m");

        TAKE_PTR(verity_settings);

        return 0;
}

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("systemd-repart", "8", &link);
        if (r < 0)
                return log_oom();

        printf("%1$s [OPTIONS...] [DEVICE]\n"
               "\n%5$sGrow and add partitions to a partition table, and generate disk images (DDIs).%6$s\n\n"
               "  -h --help               Show this help\n"
               "     --version            Show package version\n"
               "     --no-pager           Do not pipe output into a pager\n"
               "     --no-legend          Do not show the headers and footers\n"
               "\n%3$sOperation:%4$s\n"
               "     --dry-run=BOOL       Whether to run dry-run operation\n"
               "     --empty=MODE         One of refuse, allow, require, force, create; controls\n"
               "                          how to handle empty disks lacking partition tables\n"
               "     --offline=BOOL       Whether to build the image offline\n"
               "     --discard=BOOL       Whether to discard backing blocks for new partitions\n"
               "     --sector-size=SIZE   Set the logical sector size for the image\n"
               "     --architecture=ARCH  Set the generic architecture for the image\n"
               "     --size=BYTES         Grow loopback file to specified size\n"
               "     --seed=UUID          128-bit seed UUID to derive all UUIDs from\n"
               "     --split=BOOL         Whether to generate split artifacts\n"
               "\n%3$sOutput:%4$s\n"
               "     --pretty=BOOL        Whether to show pretty summary before doing changes\n"
               "     --json=pretty|short|off\n"
               "                          Generate JSON output\n"
               "\n%3$sFactory Reset:%4$s\n"
               "     --factory-reset=BOOL Whether to remove data partitions before recreating\n"
               "                          them\n"
               "     --can-factory-reset  Test whether factory reset is defined\n"
               "\n%3$sConfiguration & Image Control:%4$s\n"
               "     --root=PATH          Operate relative to root path\n"
               "     --image=PATH         Operate relative to image file\n"
               "     --image-policy=POLICY\n"
               "                          Specify disk image dissection policy\n"
               "     --definitions=DIR    Find partition definitions in specified directory\n"
               "     --list-devices       List candidate block devices to operate on\n"
               "\n%3$sVerity:%4$s\n"
               "     --private-key=PATH|URI\n"
               "                          Private key to use when generating verity roothash\n"
               "                          signatures, or an engine or provider specific\n"
               "                          designation if --private-key-source= is used\n"
               "     --private-key-source=file|provider:PROVIDER|engine:ENGINE\n"
               "                          Specify how to use KEY for --private-key=. Allows\n"
               "                          an OpenSSL engine/provider to be used when generating\n"
               "                          verity roothash signatures\n"
               "     --certificate=PATH|URI\n"
               "                          PEM certificate to use when generating verity roothash\n"
               "                          signatures, or a provider specific designation if\n"
               "                           --certificate-source= is used\n"
               "     --certificate-source=file|provider:PROVIDER\n"
               "                          Specify how to interpret the certificate from\n"
               "                          --certificate=. Allows the certificate to be loaded\n"
               "                          from an OpenSSL provider\n"
               "     --join-signature=HASH:SIG\n"
               "                          Specify root hash and pkcs7 signature of root hash for\n"
               "                          verity as a tuple of hex encoded hash and a DER\n"
               "                          encoded PKCS7, either as a path to a file or as an\n"
               "                          ASCII base64 encoded string prefixed by 'base64:'\n"
               "\n%3$sEncryption:%4$s\n"
               "     --key-file=PATH      Key to use when encrypting partitions\n"
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
               "\n%3$sPartition Control:%4$s\n"
               "     --include-partitions=PARTITION1,PARTITION2,PARTITION3,…\n"
               "                          Ignore partitions not of the specified types\n"
               "     --exclude-partitions=PARTITION1,PARTITION2,PARTITION3,…\n"
               "                          Ignore partitions of the specified types\n"
               "     --defer-partitions=PARTITION1,PARTITION2,PARTITION3,…\n"
               "                          Take partitions of the specified types into account\n"
               "                          but don't populate them yet\n"
               "     --defer-partitions-empty=yes\n"
               "                          Defer all partitions marked for formatting as empty\n"
               "     --defer-partitions-factory-reset=yes\n"
               "                          Defer all partitions marked for factory reset\n"
               "\n%3$sCopying:%4$s\n"
               "  -s --copy-source=PATH   Specify the primary source tree to copy files from\n"
               "     --copy-from=IMAGE    Copy partitions from the given image(s)\n"
               "\n%3$sDDI Profile:%4$s\n"
               "  -S --make-ddi=sysext    Make a system extension DDI\n"
               "  -C --make-ddi=confext   Make a configuration extension DDI\n"
               "  -P --make-ddi=portable  Make a portable service DDI\n"
               "\n%3$sAuxiliary Resource Generation:%4$s\n"
               "     --append-fstab=MODE  One of no, auto, replace; controls how to join the\n"
               "                          content of a pre-existing fstab with the generated one\n"
               "     --generate-fstab=PATH\n"
               "                          Write fstab configuration to the given path\n"
               "     --generate-crypttab=PATH\n"
               "                          Write crypttab configuration to the given path\n"
               "\nSee the %2$s for details.\n",
               program_invocation_short_name,
               link,
               ansi_underline(),
               ansi_normal(),
               ansi_highlight(),
               ansi_normal());

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
                ARG_PRIVATE_KEY_SOURCE,
                ARG_CERTIFICATE,
                ARG_CERTIFICATE_SOURCE,
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
                ARG_DEFER_PARTITIONS_EMPTY,
                ARG_DEFER_PARTITIONS_FACTORY_RESET,
                ARG_SECTOR_SIZE,
                ARG_SKIP_PARTITIONS,
                ARG_ARCHITECTURE,
                ARG_OFFLINE,
                ARG_COPY_FROM,
                ARG_MAKE_DDI,
                ARG_APPEND_FSTAB,
                ARG_GENERATE_FSTAB,
                ARG_GENERATE_CRYPTTAB,
                ARG_LIST_DEVICES,
                ARG_JOIN_SIGNATURE,
        };

        static const struct option options[] = {
                { "help",                           no_argument,       NULL, 'h'                                },
                { "version",                        no_argument,       NULL, ARG_VERSION                        },
                { "no-pager",                       no_argument,       NULL, ARG_NO_PAGER                       },
                { "no-legend",                      no_argument,       NULL, ARG_NO_LEGEND                      },
                { "dry-run",                        required_argument, NULL, ARG_DRY_RUN                        },
                { "empty",                          required_argument, NULL, ARG_EMPTY                          },
                { "discard",                        required_argument, NULL, ARG_DISCARD                        },
                { "factory-reset",                  required_argument, NULL, ARG_FACTORY_RESET                  },
                { "can-factory-reset",              no_argument,       NULL, ARG_CAN_FACTORY_RESET              },
                { "root",                           required_argument, NULL, ARG_ROOT                           },
                { "image",                          required_argument, NULL, ARG_IMAGE                          },
                { "image-policy",                   required_argument, NULL, ARG_IMAGE_POLICY                   },
                { "seed",                           required_argument, NULL, ARG_SEED                           },
                { "pretty",                         required_argument, NULL, ARG_PRETTY                         },
                { "definitions",                    required_argument, NULL, ARG_DEFINITIONS                    },
                { "size",                           required_argument, NULL, ARG_SIZE                           },
                { "json",                           required_argument, NULL, ARG_JSON                           },
                { "key-file",                       required_argument, NULL, ARG_KEY_FILE                       },
                { "private-key",                    required_argument, NULL, ARG_PRIVATE_KEY                    },
                { "private-key-source",             required_argument, NULL, ARG_PRIVATE_KEY_SOURCE             },
                { "certificate",                    required_argument, NULL, ARG_CERTIFICATE                    },
                { "certificate-source",             required_argument, NULL, ARG_CERTIFICATE_SOURCE             },
                { "tpm2-device",                    required_argument, NULL, ARG_TPM2_DEVICE                    },
                { "tpm2-device-key",                required_argument, NULL, ARG_TPM2_DEVICE_KEY                },
                { "tpm2-seal-key-handle",           required_argument, NULL, ARG_TPM2_SEAL_KEY_HANDLE           },
                { "tpm2-pcrs",                      required_argument, NULL, ARG_TPM2_PCRS                      },
                { "tpm2-public-key",                required_argument, NULL, ARG_TPM2_PUBLIC_KEY                },
                { "tpm2-public-key-pcrs",           required_argument, NULL, ARG_TPM2_PUBLIC_KEY_PCRS           },
                { "tpm2-pcrlock",                   required_argument, NULL, ARG_TPM2_PCRLOCK                   },
                { "split",                          required_argument, NULL, ARG_SPLIT                          },
                { "include-partitions",             required_argument, NULL, ARG_INCLUDE_PARTITIONS             },
                { "exclude-partitions",             required_argument, NULL, ARG_EXCLUDE_PARTITIONS             },
                { "defer-partitions",               required_argument, NULL, ARG_DEFER_PARTITIONS               },
                { "defer-partitions-empty",         required_argument, NULL, ARG_DEFER_PARTITIONS_EMPTY         },
                { "defer-partitions-factory-reset", required_argument, NULL, ARG_DEFER_PARTITIONS_FACTORY_RESET },
                { "sector-size",                    required_argument, NULL, ARG_SECTOR_SIZE                    },
                { "architecture",                   required_argument, NULL, ARG_ARCHITECTURE                   },
                { "offline",                        required_argument, NULL, ARG_OFFLINE                        },
                { "copy-from",                      required_argument, NULL, ARG_COPY_FROM                      },
                { "copy-source",                    required_argument, NULL, 's'                                },
                { "make-ddi",                       required_argument, NULL, ARG_MAKE_DDI                       },
                { "append-fstab",                   required_argument, NULL, ARG_APPEND_FSTAB                   },
                { "generate-fstab",                 required_argument, NULL, ARG_GENERATE_FSTAB                 },
                { "generate-crypttab",              required_argument, NULL, ARG_GENERATE_CRYPTTAB              },
                { "list-devices",                   no_argument,       NULL, ARG_LIST_DEVICES                   },
                { "join-signature",                 required_argument, NULL, ARG_JOIN_SIGNATURE                 },
                {}
        };

        bool auto_public_key_pcr_mask = true, auto_pcrlock = true;
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

                        arg_relax_copy_block_security = false;

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
                                            parsed, glyph(GLYPH_ARROW_RIGHT), rounded);

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
                        r = parse_key_file(optarg, &arg_key);
                        if (r < 0)
                                return r;
                        break;
                }

                case ARG_PRIVATE_KEY: {
                        r = free_and_strdup_warn(&arg_private_key, optarg);
                        if (r < 0)
                                return r;
                        break;
                }

                case ARG_PRIVATE_KEY_SOURCE:
                        r = parse_openssl_key_source_argument(
                                        optarg,
                                        &arg_private_key_source,
                                        &arg_private_key_source_type);
                        if (r < 0)
                                return r;
                        break;

                case ARG_CERTIFICATE:
                        r = free_and_strdup_warn(&arg_certificate, optarg);
                        if (r < 0)
                                return r;
                        break;

                case ARG_CERTIFICATE_SOURCE:
                        r = parse_openssl_certificate_source_argument(
                                        optarg,
                                        &arg_certificate_source,
                                        &arg_certificate_source_type);
                        if (r < 0)
                                return r;
                        break;

                case ARG_TPM2_DEVICE: {
                        _cleanup_free_ char *device = NULL;

                        if (streq(optarg, "list"))
                                return tpm2_list_devices(/* legend= */ true, /* quiet= */ false);

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

                case ARG_DEFER_PARTITIONS_EMPTY:
                        r = parse_boolean_argument("--defer-partitions-empty=", optarg, &arg_defer_partitions_empty);
                        if (r < 0)
                                return r;

                        break;

                case ARG_DEFER_PARTITIONS_FACTORY_RESET:
                        r = parse_boolean_argument("--defer-partitions-factory-reset=", optarg, &arg_defer_partitions_factory_reset);
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
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid architecture '%s'.", optarg);

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

                case ARG_APPEND_FSTAB:
                        if (isempty(optarg)) {
                                arg_append_fstab = APPEND_AUTO;
                                break;
                        }

                        arg_append_fstab = append_mode_from_string(optarg);
                        if (arg_append_fstab < 0)
                                return log_error_errno(arg_append_fstab, "Failed to parse --append-fstab= parameter: %s", optarg);
                        break;

                case ARG_GENERATE_FSTAB:
                        r = parse_path_argument(optarg, /* suppress_root= */ false, &arg_generate_fstab);
                        if (r < 0)
                                return r;
                        break;

                case ARG_GENERATE_CRYPTTAB:
                        r = parse_path_argument(optarg, /* suppress_root= */ false, &arg_generate_crypttab);
                        if (r < 0)
                                return r;
                        break;

                case ARG_LIST_DEVICES:
                        r = blockdev_list(BLOCKDEV_LIST_REQUIRE_PARTITION_SCANNING|BLOCKDEV_LIST_SHOW_SYMLINKS|BLOCKDEV_LIST_IGNORE_ZRAM, /* ret_devices= */ NULL, /* ret_n_devices= */ NULL);
                        if (r < 0)
                                return r;

                        return 0;

                case ARG_JOIN_SIGNATURE:
                        r = parse_join_signature(optarg, &arg_verity_settings);
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

        if (!set_isempty(arg_verity_settings) && !arg_certificate)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Verity signature specified without --certificate=.");

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
                r = path_is_mount_point("/sysusr/usr");
                if (r <= 0) {
                        if (r < 0 && r != -ENOENT)
                                log_debug_errno(r, "Unable to determine whether /sysusr/usr is a mount point, assuming it is not: %m");

                        arg_root = strdup("/sysroot");
                } else
                        arg_root = strdup("/sysusr");
                if (!arg_root)
                        return log_oom();

                arg_relax_copy_block_security = true;
        }

        if (argc > optind) {
                if (empty_or_dash(argv[optind]))
                        arg_node_none = true;
                else {
                        arg_node = strdup(argv[optind]);
                        if (!arg_node)
                                return log_oom();
                        arg_node_none = false;
                }
        }

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

        if (arg_pretty < 0 && isatty_safe(STDOUT_FILENO))
                arg_pretty = true;

        if (arg_architecture >= 0) {
                FOREACH_ARRAY(p, arg_filter_partitions, arg_n_filter_partitions)
                        *p = gpt_partition_type_override_architecture(*p, arg_architecture);

                FOREACH_ARRAY(p, arg_defer_partitions, arg_n_defer_partitions)
                        *p = gpt_partition_type_override_architecture(*p, arg_architecture);
        }

        if (arg_append_fstab && !arg_generate_fstab)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "No --generate-fstab= specified for --append-fstab=%s.", append_mode_to_string(arg_append_fstab));

        r = sd_varlink_invocation(SD_VARLINK_ALLOW_ACCEPT);
        if (r < 0)
                return log_error_errno(r, "Failed to check if invoked in Varlink mode: %m");
        if (r > 0) {
                arg_varlink = true;
                arg_pager_flags |= PAGER_DISABLE;
        }

        return 1;
}

static int parse_proc_cmdline_factory_reset(void) {
        if (arg_factory_reset >= 0) /* Never override what is specified on the process command line */
                return 0;

        if (!in_initrd()) /* Never honour kernel command line factory reset request outside of the initrd */
                return 0;

        FactoryResetMode f = factory_reset_mode();
        if (f < 0)
                return log_error_errno(f, "Failed to determine factory reset status: %m");
        if (f != FACTORY_RESET_UNSPECIFIED) {
                arg_factory_reset = f == FACTORY_RESET_ON;

                if (arg_factory_reset)
                        log_notice("Honouring factory reset requested via kernel command line or EFI variable.");
        }

        return 0;
}

static int parse_efi_variable_factory_reset(void) {
        _cleanup_free_ char *value = NULL;
        int r;

        /* NB: This is legacy, people should move to the newer FactoryResetRequest variable! */

        // FIXME: Remove this in v260

        if (arg_factory_reset >= 0) /* Never override what is specified on the process command line */
                return 0;

        if (!in_initrd()) /* Never honour EFI variable factory reset request outside of the initrd */
                return 0;

        r = efi_get_variable_string(EFI_SYSTEMD_VARIABLE_STR("FactoryReset"), &value);
        if (r == -ENOENT || ERRNO_IS_NEG_NOT_SUPPORTED(r))
                return 0;
        if (r < 0)
                return log_error_errno(r, "Failed to read EFI variable FactoryReset: %m");

        log_warning("Warning, EFI variable FactoryReset is in use, please migrate to use FactoryResetRequest instead, support will be removed in v260!");

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

        // FIXME: Remove this in v260, see above

        r = efi_set_variable(EFI_SYSTEMD_VARIABLE_STR("FactoryReset"), NULL, 0);
        if (r == -ENOENT || ERRNO_IS_NEG_NOT_SUPPORTED(r))
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
        r = block_get_originating(devno, &devno, /* recursive= */ false);
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

        if (arg_node_none)
                return 0;

        if (arg_node) {
                if (context->empty == EMPTY_CREATE) {
                        _cleanup_close_ int fd = -EBADF;
                        _cleanup_free_ char *s = NULL;

                        s = strdup(arg_node);
                        if (!s)
                                return log_oom();

                        fd = xopenat_full(AT_FDCWD, arg_node, O_RDONLY|O_CREAT|O_EXCL|O_CLOEXEC|O_NOFOLLOW, XO_NOCOW, 0666);
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

        assert(IN_SET(context->empty, EMPTY_REFUSE, EMPTY_ALLOW));

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
                                        return log_error_errno(r, "Failed to determine backing device of %s%s: %m", strempty(arg_root), p);
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

static int determine_auto_size(
                Context *c,
                int level,
                bool ignore_allocated, /* If true, determines unallocated space needed */
                uint64_t *ret) {

        uint64_t sum;

        assert(c);

        sum = round_up_size(GPT_METADATA_SIZE, 4096);

        LIST_FOREACH(partitions, p, c->partitions) {
                uint64_t m;

                if (p->dropped || PARTITION_SUPPRESSED(p))
                        continue;

                m = partition_min_size_with_padding(c, p);
                if (m > UINT64_MAX - sum)
                        return log_error_errno(SYNTHETIC_ERRNO(EOVERFLOW), "Image would grow too large, refusing.");

                if (ignore_allocated && PARTITION_EXISTS(p))
                        m = LESS_BY(m, p->current_size + p->current_padding);

                sum += m;
        }

        if (c->total != UINT64_MAX)
                /* Image already allocated? Then show its size. */
                log_full(level,
                         "Automatically determined minimal disk image size as %s, current block device/image size is %s.",
                         FORMAT_BYTES(sum), FORMAT_BYTES(c->total));
        else
                /* If the image is being created right now, then it has no previous size, suppress any comment about it hence. */
                log_full(level,
                         "Automatically determined minimal disk image size as %s.",
                         FORMAT_BYTES(sum));

        if (ret)
                *ret = sum;
        return 0;
}

static int context_ponder(Context *context) {
        int r;

        assert(context);

        (void) context_notify(context, PROGRESS_PLACING, /* object= */ NULL, UINT_MAX);

        /* First try to fit new partitions in, dropping by priority until it fits */
        for (;;) {
                uint64_t largest_free_area;

                if (context_allocate_partitions(context, &largest_free_area))
                        break; /* Success! */

                if (context_unmerge_and_allocate_partitions(context))
                        break; /* We had to un-suppress a supplement or few, but still success! */

                if (context_drop_or_foreignize_one_priority(context))
                        continue; /* Still no luck. Let's drop a priority and try again. */

                /* No more priorities left to drop. This configuration just doesn't fit on this disk... */
                return log_error_errno(SYNTHETIC_ERRNO(ENOSPC),
                                       "Can't fit requested partitions into available free space (%s), refusing.",
                                       FORMAT_BYTES(largest_free_area));
        }

        LIST_FOREACH(partitions, p, context->partitions) {
                if (!p->supplement_for)
                        continue;

                if (PARTITION_SUPPRESSED(p)) {
                        assert(!p->allocated_to_area);
                        p->dropped = true;

                        log_debug("Partition %s can be merged into %s, suppressing supplement.",
                                  p->definition_path, p->supplement_for->definition_path);
                } else if (PARTITION_EXISTS(p))
                        log_info("Partition %s already exists on disk, using supplement verbatim.",
                                 p->definition_path);
                else
                        log_info("Couldn't allocate partitions with %s merged into %s, using supplement verbatim.",
                                 p->definition_path, p->supplement_for->definition_path);
        }

        /* Now assign free space according to the weight logic */
        r = context_grow_partitions(context);
        if (r < 0)
                return r;

        /* Now calculate where each new partition gets placed */
        context_place_partitions(context);

        return 0;
}

static int vl_method_list_candidate_devices(
                sd_varlink *link,
                sd_json_variant *parameters,
                sd_varlink_method_flags_t flags,
                void *userdata) {

        struct {
                bool ignore_root;
                bool ignore_empty;
        } p = {};

        static const sd_json_dispatch_field dispatch_table[] = {
                { "ignoreRoot",  SD_JSON_VARIANT_BOOLEAN, sd_json_dispatch_stdbool, voffsetof(p, ignore_root),  0 },
                { "ignoreEmpty", SD_JSON_VARIANT_BOOLEAN, sd_json_dispatch_stdbool, voffsetof(p, ignore_empty), 0 },
                {}
        };

        int r;

        assert(link);
        assert(FLAGS_SET(flags, SD_VARLINK_METHOD_MORE));

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        BlockDevice *l = NULL;
        size_t n = 0;
        CLEANUP_ARRAY(l, n, block_device_array_free);

        r = blockdev_list(
                        BLOCKDEV_LIST_SHOW_SYMLINKS|
                        BLOCKDEV_LIST_REQUIRE_PARTITION_SCANNING|
                        BLOCKDEV_LIST_IGNORE_ZRAM|
                        BLOCKDEV_LIST_METADATA|
                        (p.ignore_empty ? BLOCKDEV_LIST_IGNORE_EMPTY : 0)|
                        (p.ignore_root ? BLOCKDEV_LIST_IGNORE_ROOT : 0),
                        &l,
                        &n);
        if (r < 0)
                return r;

        r = varlink_set_sentinel(link, "io.systemd.Repart.NoCandidateDevices");
        if (r < 0)
                return r;

        FOREACH_ARRAY(d, l, n) {
                r = sd_varlink_replybo(link,
                                SD_JSON_BUILD_PAIR_STRING("node", d->node),
                                JSON_BUILD_PAIR_STRV_NON_EMPTY("symlinks", d->symlinks),
                                JSON_BUILD_PAIR_UNSIGNED_NOT_EQUAL("diskseq", d->diskseq, UINT64_MAX),
                                JSON_BUILD_PAIR_UNSIGNED_NOT_EQUAL("sizeBytes", d->size, UINT64_MAX),
                                JSON_BUILD_PAIR_STRING_NON_EMPTY("model", d->model),
                                JSON_BUILD_PAIR_STRING_NON_EMPTY("vendor", d->vendor),
                                JSON_BUILD_PAIR_STRING_NON_EMPTY("subsystem", d->subsystem));
                if (r < 0)
                        return r;
        }

        return 0;
}

static JSON_DISPATCH_ENUM_DEFINE(json_dispatch_empty_mode, EmptyMode, empty_mode_from_string);

typedef struct RunParameters {
        char *node;
        EmptyMode empty;
        bool dry_run;
        sd_id128_t seed;
        char **definitions;
        bool defer_partitions_empty;
        bool defer_partitions_factory_reset;
} RunParameters;

static void run_parameters_done(RunParameters *p) {
        assert(p);

        p->node = mfree(p->node);
        p->definitions = strv_free(p->definitions);
}

static int vl_method_run(
                sd_varlink *link,
                sd_json_variant *parameters,
                sd_varlink_method_flags_t flags,
                void *userdata) {

        static const sd_json_dispatch_field dispatch_table[] = {
                { "node",                        SD_JSON_VARIANT_STRING,  sd_json_dispatch_string,  offsetof(RunParameters, node),                           SD_JSON_NULLABLE                 },
                { "empty",                       SD_JSON_VARIANT_STRING,  json_dispatch_empty_mode, offsetof(RunParameters, empty),                          SD_JSON_MANDATORY                },
                { "seed",                        SD_JSON_VARIANT_STRING,  sd_json_dispatch_id128,   offsetof(RunParameters, seed),                           SD_JSON_NULLABLE                 },
                { "dryRun",                      SD_JSON_VARIANT_BOOLEAN, sd_json_dispatch_stdbool, offsetof(RunParameters, dry_run),                        SD_JSON_MANDATORY                },
                { "definitions",                 SD_JSON_VARIANT_ARRAY,   json_dispatch_strv_path,  offsetof(RunParameters, definitions),                    SD_JSON_MANDATORY|SD_JSON_STRICT },
                { "deferPartitionsEmpty",        SD_JSON_VARIANT_BOOLEAN, sd_json_dispatch_stdbool, offsetof(RunParameters, defer_partitions_empty),         SD_JSON_NULLABLE                 },
                { "deferPartitionsFactoryReset", SD_JSON_VARIANT_BOOLEAN, sd_json_dispatch_stdbool, offsetof(RunParameters, defer_partitions_factory_reset), SD_JSON_NULLABLE                 },
                {}
        };

        int r;

        assert(link);

        _cleanup_(run_parameters_done) RunParameters p = {
                .empty = _EMPTY_MODE_INVALID,
                .dry_run = true,
        };
        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        /* If no device node is specified, this is a dry run. Refuse if the caller claims otherwise. */
        if (!p.node && !p.dry_run)
                return sd_varlink_error_invalid_parameter_name(link, "dryRun");

        _cleanup_(context_freep) Context* context = NULL;
        context = context_new(
                        p.definitions,
                        p.empty,
                        p.dry_run,
                        p.seed);
        if (!context)
                return log_oom();

        context->defer_partitions_empty = p.defer_partitions_empty;
        context->defer_partitions_factory_reset = p.defer_partitions_factory_reset;

        if (FLAGS_SET(flags, SD_VARLINK_METHOD_MORE))
                context->link = sd_varlink_ref(link);

        r = context_read_seed(context, arg_root);
        if (r < 0)
                return r;

        r = context_read_definitions(context);
        if (r < 0)
                return r;

        if (p.node) {
                context->node = TAKE_PTR(p.node);

                r = context_load_partition_table(context);
                if (r == -EHWPOISON)
                        return sd_varlink_error(link, "io.systemd.Repart.ConflictingDiskLabelPresent", NULL);
        } else
                r = context_load_fallback_metrics(context);
        if (r < 0)
                return r;
        context->from_scratch = r > 0; /* Starting from scratch */

        r = context_open_copy_block_paths(context, (dev_t) -1);
        if (r < 0)
                return r;

        r = context_acquire_partition_uuids_and_labels(context);
        if (r < 0)
                return r;

        r = context_update_verity_size(context);
        if (r < 0)
                return r;

        r = context_minimize(context);
        if (r < 0)
                return r;

        /* If we have no node, just sum up how much space we need */
        if (!context->node) {
                /* Check if space issue is caused by the whole disk being too small */
                uint64_t size;
                r = determine_auto_size(context, LOG_DEBUG, /* ignore_allocated= */ false, &size);
                if (r < 0)
                        return r;

                return sd_varlink_replybo(
                                link,
                                SD_JSON_BUILD_PAIR_UNSIGNED("minimalSizeBytes", size));
        }

        r = context_ponder(context);
        if (r == -ENOSPC) {
                /* Check if space issue is caused by the whole disk being too small */
                uint64_t size = UINT64_MAX;
                (void) determine_auto_size(context, LOG_DEBUG, /* ignore_allocated= */ false, &size);
                if (size != UINT64_MAX && context->total != UINT64_MAX && size > context->total)
                        return sd_varlink_errorbo(
                                        link,
                                        "io.systemd.Repart.DiskTooSmall",
                                        SD_JSON_BUILD_PAIR_UNSIGNED("minimalSizeBytes", size),
                                        SD_JSON_BUILD_PAIR_UNSIGNED("currentSizeBytes", context->total));

                /* Or if the disk would fit, but theres's not enough unallocated space */
                uint64_t need_free = UINT64_MAX;
                (void) determine_auto_size(context, LOG_DEBUG, /* ignore_allocated= */ true, &need_free);
                return sd_varlink_errorbo(
                                link,
                                "io.systemd.Repart.InsufficientFreeSpace",
                                JSON_BUILD_PAIR_UNSIGNED_NOT_EQUAL("minimalSizeBytes", size, UINT64_MAX),
                                JSON_BUILD_PAIR_UNSIGNED_NOT_EQUAL("needFreeBytes", need_free, UINT64_MAX),
                                JSON_BUILD_PAIR_UNSIGNED_NOT_EQUAL("currentSizeBytes", context->total, UINT64_MAX));
        }
        if (r < 0)
                return r;

        if (p.dry_run) {
                uint64_t size;

                /* If we are doing a dry-run, report the minimal size. */
                r = determine_auto_size(context, LOG_DEBUG, /* ignore_allocated= */ false, &size);
                if (r < 0)
                        return r;

                return sd_varlink_replybo(
                                link,
                                SD_JSON_BUILD_PAIR_UNSIGNED("minimalSizeBytes", size),
                                JSON_BUILD_PAIR_UNSIGNED_NOT_EQUAL("currentSizeBytes", context->total, UINT64_MAX));
        }

        r = context_write_partition_table(context);
        if (r < 0)
                return r;

        context_disarm_auto_removal(context);

        return sd_varlink_reply(link, NULL);
}

static int vl_server(void) {
        _cleanup_(sd_varlink_server_unrefp) sd_varlink_server *varlink_server = NULL;
        int r;

        /* Invocation as Varlink service */

        r = varlink_server_new(
                        &varlink_server,
                        SD_VARLINK_SERVER_ROOT_ONLY,
                        /* userdata= */ NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate Varlink server: %m");

        r = sd_varlink_server_add_interface(varlink_server, &vl_interface_io_systemd_Repart);
        if (r < 0)
                return log_error_errno(r, "Failed to add Varlink interface: %m");

        r = sd_varlink_server_bind_method_many(
                        varlink_server,
                        "io.systemd.Repart.ListCandidateDevices", vl_method_list_candidate_devices,
                        "io.systemd.Repart.Run",                  vl_method_run);
        if (r < 0)
                return log_error_errno(r, "Failed to bind Varlink methods: %m");

        r = sd_varlink_server_loop_auto(varlink_server);
        if (r < 0)
                return log_error_errno(r, "Failed to run Varlink event loop: %m");

        return 0;
}

static int run(int argc, char *argv[]) {
        _cleanup_(loop_device_unrefp) LoopDevice *loop_device = NULL;
        _cleanup_(umount_and_freep) char *mounted_dir = NULL;
        _cleanup_(context_freep) Context* context = NULL;
        bool node_is_our_loop = false;
        int r;

        log_setup();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

#if HAVE_LIBCRYPTSETUP
        cryptsetup_enable_logging(NULL);
#endif

        if (arg_varlink)
                return vl_server();

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
                                arg_image_policy,
                                DISSECT_IMAGE_MOUNT_READ_ONLY |
                                (arg_node ? DISSECT_IMAGE_DEVICE_READ_ONLY : 0) | /* If a different node to make changes to is specified let's open the device in read-only mode) */
                                DISSECT_IMAGE_GPT_ONLY |
                                DISSECT_IMAGE_RELAX_VAR_CHECK |
                                DISSECT_IMAGE_USR_NO_ROOT |
                                DISSECT_IMAGE_REQUIRE_ROOT |
                                DISSECT_IMAGE_ALLOW_USERSPACE_VERITY,
                                &mounted_dir,
                                /* ret_dir_fd= */ NULL,
                                &loop_device);
                if (r < 0)
                        return r;

                arg_root = strdup(mounted_dir);
                if (!arg_root)
                        return log_oom();

                if (!arg_node && !arg_node_none) {
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

        context = context_new(
                        arg_definitions,
                        arg_empty,
                        arg_dry_run,
                        arg_seed);
        if (!context)
                return log_oom();

        r = context_load_keys(context);
        if (r < 0)
                return r;

        context->defer_partitions_empty = arg_defer_partitions_empty;
        context->defer_partitions_factory_reset = arg_defer_partitions_factory_reset;

        r = context_read_seed(context, arg_root);
        if (r < 0)
                return r;

        r = context_copy_from(context);
        if (r < 0)
                return r;

        if (arg_make_ddi) {
                _cleanup_free_ char *d = NULL, *dp = NULL;
                assert(!context->definitions);

                d = strjoin(arg_make_ddi, ".repart.d/");
                if (!d)
                        return log_oom();

                r = search_and_access(d, F_OK, NULL, CONF_PATHS_STRV("systemd/repart/definitions"), &dp);
                if (r < 0)
                        return log_error_errno(r, "DDI type '%s' is not defined: %m", arg_make_ddi);

                if (strv_consume(&context->definitions, TAKE_PTR(dp)) < 0)
                        return log_oom();
        } else
                strv_uniq(context->definitions);

        r = context_read_definitions(context);
        if (r < 0)
                return r;

        r = find_root(context);
        if (r == -ENODEV)
                return 76; /* Special return value which means "Root block device not found, so not doing
                            * anything". This isn't really an error when called at boot. */
        if (r < 0)
                return r;

        if (context->node) {
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
        } else
                r = context_load_fallback_metrics(context);
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

        /* Open all files to copy blocks from now, since we want to take their size into consideration */
        r = context_open_copy_block_paths(
                        context,
                        loop_device ? loop_device->devno :         /* if --image= is specified, only allow partitions on the loopback device */
                                      /* if --root= is specified, don't accept any block device, unless it
                                       * was set automatically because we are in the initrd  */
                                      arg_root && !arg_image && !arg_relax_copy_block_security ? 0 :
                                      (dev_t) -1);                 /* if neither is specified, make no restrictions */
        if (r < 0)
                return r;

        /* Make sure each partition has a unique UUID and unique label */
        r = context_acquire_partition_uuids_and_labels(context);
        if (r < 0)
                return r;

        r = context_fstab(context);
        if (r < 0)
                return r;

        r = context_crypttab(context, /* late= */ false);
        if (r < 0)
                return r;

        r = context_update_verity_size(context);
        if (r < 0)
                return r;

        r = context_minimize(context);
        if (r < 0)
                return r;

        if (arg_node_none) {
                (void) determine_auto_size(context, LOG_INFO, /* ignore_allocated= */ false, /* ret= */ NULL);
                return 0;
        }

        if (arg_size_auto) {
                r = determine_auto_size(context, LOG_INFO, /* ignore_allocated= */ false, &arg_size);
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

        r = context_ponder(context);
        if (r == -ENOSPC) {
                /* When we hit space issues, tell the user the minimal size. */
                (void) determine_auto_size(context, LOG_INFO, /* ignore_allocated= */ false, /* ret= */ NULL);
                return r;
        }
        if (r < 0)
                return r;

        (void) context_dump(context, /* late= */ false);

        r = context_write_partition_table(context);
        if (r < 0)
                return r;

        r = context_split(context);
        if (r < 0)
                return r;

        r = context_crypttab(context, /* late= */ true);
        if (r < 0)
                return r;

        (void) context_dump(context, /* late= */ true);

        context_disarm_auto_removal(context);

        return 0;
}

DEFINE_MAIN_FUNCTION_WITH_POSITIVE_FAILURE(run);
