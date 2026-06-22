/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "fsprg-openssl.h"
#include "hexdecoct.h"
#include "iovec-util.h"
#include "journal-authenticate.h"
#include "journal-def.h"
#include "journal-file.h"
#include "log.h"
#include "memory-util.h"
#include "string-util.h"
#include "time-util.h"

static void* fssheader_free(FSSHeader *p) {
        /* mmap() returns MAP_FAILED on error and sets the errno */
        if (!p || p == MAP_FAILED)
                return NULL;

        assert_se(munmap(p, PAGE_ALIGN(sizeof(FSSHeader))) >= 0);
        return NULL;
}

DEFINE_TRIVIAL_CLEANUP_FUNC(FSSHeader*, fssheader_free);

#if HAVE_OPENSSL
static uint64_t journal_file_tag_seqnum(JournalFile *f) {
        uint64_t r;

        assert(f);

        r = le64toh(f->header->n_tags) + 1;
        f->header->n_tags = htole64(r);

        return r;
}
#endif

int journal_file_append_tag(JournalFile *f) {
#if HAVE_OPENSSL
        Object *o;
        uint64_t p;
        int r;

        assert(f);

        if (!JOURNAL_HEADER_SEALED(f->header))
                return 0;

        if (!f->hmac_running) {
                r = journal_file_hmac_start(f);
                if (r < 0)
                        return r;
        }

        assert(f->hmac_ctx);

        r = journal_file_append_object(f, OBJECT_TAG, sizeof(struct TagObject), &o, &p);
        if (r < 0)
                return r;

        o->tag.seqnum = htole64(journal_file_tag_seqnum(f));

        uint64_t epoch;
        r = fsprg_get_epoch(&f->fsprg_state, &epoch);
        if (r < 0)
                return r;
        o->tag.epoch = htole64(epoch);

        log_debug("Writing tag %"PRIu64" for epoch %"PRIu64"",
                  le64toh(o->tag.seqnum), epoch);

        /* Add the tag object itself, so that we can protect its
         * header. This will exclude the actual hash value in it */
        r = journal_file_hmac_put_object(f, OBJECT_TAG, o, p);
        if (r < 0)
                return r;

        /* Get the HMAC tag and store it in the object */
        size_t len;
        if (sym_EVP_MAC_final(f->hmac_ctx, o->tag.tag, &len, TAG_LENGTH) <= 0 || len != TAG_LENGTH)
                r = -EIO;
        else
                r = 0;

        f->hmac_running = false;

        return r;
#else
        return -EOPNOTSUPP;
#endif
}

int journal_file_hmac_start(JournalFile *f) {
#if HAVE_OPENSSL
        int r;

        assert(f);

        if (!JOURNAL_HEADER_SEALED(f->header))
                return 0;

        if (f->hmac_running)
                return 0;

        uint8_t key[256 / 8]; /* Let's pass 256 bit from FSPRG to HMAC */
        CLEANUP_ERASE(key);
        r = fsprg_get_key(&f->fsprg_state, &IOVEC_MAKE(key, sizeof(key)));
        if (r < 0)
                return r;

        /* Prepare HMAC for next cycle */
        if (sym_EVP_MAC_init(f->hmac_ctx, key, sizeof(key), f->ossl_params) <= 0)
                return log_openssl_errors(LOG_DEBUG, "sym_EVP_MAC_init() failed");

        f->hmac_running = true;

        return 0;
#else
        return -EOPNOTSUPP;
#endif
}

static int journal_file_get_epoch(JournalFile *f, uint64_t realtime, uint64_t *epoch) {
        uint64_t t;

        assert(f);
        assert(epoch);
        assert(JOURNAL_HEADER_SEALED(f->header));

        if (f->fss_start_usec == 0 || f->fss_interval_usec == 0)
                return -EOPNOTSUPP;

        if (realtime < f->fss_start_usec)
                return -ESTALE;

        t = realtime - f->fss_start_usec;
        t = t / f->fss_interval_usec;

        *epoch = t;

        return 0;
}

static int journal_file_fsprg_need_evolve(JournalFile *f, uint64_t realtime) {
        uint64_t goal, epoch;
        int r;

        assert(f);

        if (!JOURNAL_HEADER_SEALED(f->header))
                return 0;

        r = journal_file_get_epoch(f, realtime, &goal);
        if (r < 0)
                return r;

        r = fsprg_get_epoch(&f->fsprg_state, &epoch);
        if (r < 0)
                return r;
        if (epoch > goal)
                return -ESTALE;

        return epoch != goal;
}

int journal_file_fsprg_evolve(JournalFile *f, uint64_t realtime) {
        uint64_t goal, epoch;
        int r;

        assert(f);

        if (!JOURNAL_HEADER_SEALED(f->header))
                return 0;

        r = journal_file_get_epoch(f, realtime, &goal);
        if (r < 0)
                return r;

        r = fsprg_get_epoch(&f->fsprg_state, &epoch);
        if (r < 0)
                return r;
        if (epoch < goal)
                log_debug("Evolving FSPRG key from epoch %"PRIu64" to %"PRIu64".", epoch, goal);

        for (;;) {
                if (epoch > goal)
                        return -ESTALE;
                if (epoch == goal)
                        return 0;

                r = fsprg_evolve(&f->fsprg_state);
                if (r < 0)
                        return r;

                r = fsprg_get_epoch(&f->fsprg_state, &epoch);
                if (r < 0)
                        return r;
                if (epoch < goal) {
                        r = journal_file_append_tag(f);
                        if (r < 0)
                                return r;
                }
        }
}

int journal_file_fsprg_seek(JournalFile *f, uint64_t goal) {
        int r;

        assert(f);

        if (!JOURNAL_HEADER_SEALED(f->header))
                return 0;

        assert(iovec_is_set(&f->fsprg_seed));

        if (iovec_is_set(&f->fsprg_state)) {
                /* Cheaper... */

                uint64_t epoch;
                r = fsprg_get_epoch(&f->fsprg_state, &epoch);
                if (r < 0)
                        return r;
                if (goal == epoch)
                        return 0;

                if (goal == epoch + 1)
                        return fsprg_evolve(&f->fsprg_state);
        } else {
                r = iovec_alloc(fsprg_state_size(FSPRG_RECOMMENDED_SECPAR), &f->fsprg_state);
                if (r < 0)
                        return r;
        }

        log_debug("Seeking FSPRG key to %"PRIu64".", goal);
        return fsprg_generate_state(FSPRG_RECOMMENDED_SECPAR, goal, &f->fsprg_seed, &f->fsprg_state);
}

int journal_file_maybe_append_tag(JournalFile *f, uint64_t realtime) {
        int r;

        assert(f);

        if (!JOURNAL_HEADER_SEALED(f->header))
                return 0;

        if (realtime <= 0)
                realtime = now(CLOCK_REALTIME);

        r = journal_file_fsprg_need_evolve(f, realtime);
        if (r <= 0)
                return 0;

        r = journal_file_append_tag(f);
        if (r < 0)
                return r;

        r = journal_file_fsprg_evolve(f, realtime);
        if (r < 0)
                return r;

        return 0;
}

int journal_file_hmac_put_object(JournalFile *f, ObjectType type, Object *o, uint64_t p) {
#if HAVE_OPENSSL
        int r;

        assert(f);

        if (!JOURNAL_HEADER_SEALED(f->header))
                return 0;

        r = journal_file_hmac_start(f);
        if (r < 0)
                return r;

        if (!o) {
                r = journal_file_move_to_object(f, type, p, &o);
                if (r < 0)
                        return r;
        } else if (type > OBJECT_UNUSED && o->object.type != type)
                return -EBADMSG;

        if (sym_EVP_MAC_update(f->hmac_ctx, (void*) o, offsetof(ObjectHeader, payload)) <= 0)
                return -EIO;

        switch (o->object.type) {

        case OBJECT_DATA:
                /* All but hash and payload are mutable */
                if (sym_EVP_MAC_update(f->hmac_ctx, (void*) &o->data.hash, sizeof(o->data.hash)) <= 0)
                        return -EIO;
                if (sym_EVP_MAC_update(f->hmac_ctx, journal_file_data_payload_field(f, o), le64toh(o->object.size) - journal_file_data_payload_offset(f)) <= 0)
                        return -EIO;
                break;

        case OBJECT_FIELD:
                /* Same here */
                if (sym_EVP_MAC_update(f->hmac_ctx, (void*) &o->field.hash, sizeof(o->field.hash)) <= 0)
                        return -EIO;
                if (sym_EVP_MAC_update(f->hmac_ctx, o->field.payload, le64toh(o->object.size) - offsetof(Object, field.payload)) <= 0)
                        return -EIO;
                break;

        case OBJECT_ENTRY:
                /* All */
                if (sym_EVP_MAC_update(f->hmac_ctx, (void*) &o->entry.seqnum, le64toh(o->object.size) - offsetof(Object, entry.seqnum)) <= 0)
                        return -EIO;
                break;

        case OBJECT_FIELD_HASH_TABLE:
        case OBJECT_DATA_HASH_TABLE:
        case OBJECT_ENTRY_ARRAY:
                /* Nothing: everything is mutable */
                break;

        case OBJECT_TAG:
                /* All but the tag itself */
                if (sym_EVP_MAC_update(f->hmac_ctx, (void*) &o->tag.seqnum, sizeof(o->tag.seqnum)) <= 0)
                        return -EIO;
                if (sym_EVP_MAC_update(f->hmac_ctx, (void*) &o->tag.epoch, sizeof(o->tag.epoch)) <= 0)
                        return -EIO;
                break;
        default:
                return -EINVAL;
        }

        return 0;
#else
        return -EOPNOTSUPP;
#endif
}

int journal_file_hmac_put_header(JournalFile *f) {
#if HAVE_OPENSSL
        int r;

        assert(f);

        if (!JOURNAL_HEADER_SEALED(f->header))
                return 0;

        r = journal_file_hmac_start(f);
        if (r < 0)
                return r;

        /* All but state+reserved, boot_id, arena_size,
         * tail_object_offset, n_objects, n_entries,
         * tail_entry_seqnum, head_entry_seqnum, entry_array_offset,
         * head_entry_realtime, tail_entry_realtime,
         * tail_entry_monotonic, n_data, n_fields, n_tags,
         * n_entry_arrays. */

        if (sym_EVP_MAC_update(f->hmac_ctx, f->header->signature, offsetof(Header, state) - offsetof(Header, signature)) <= 0)
                return -EIO;
        if (sym_EVP_MAC_update(f->hmac_ctx, (void*) &f->header->file_id, offsetof(Header, tail_entry_boot_id) - offsetof(Header, file_id)) <= 0)
                return -EIO;
        if (sym_EVP_MAC_update(f->hmac_ctx, (void*) &f->header->seqnum_id, offsetof(Header, arena_size) - offsetof(Header, seqnum_id)) <= 0)
                return -EIO;
        if (sym_EVP_MAC_update(f->hmac_ctx, (void*) &f->header->data_hash_table_offset, offsetof(Header, tail_object_offset) - offsetof(Header, data_hash_table_offset)) <= 0)
                return -EIO;

        return 0;
#else
        return -EOPNOTSUPP;
#endif
}

int journal_file_fss_load(JournalFile *f) {
        _cleanup_close_ int fd = -EBADF;
        _cleanup_free_ char *path = NULL;
        _cleanup_(fssheader_freep) FSSHeader *header = NULL;
        struct stat st;
        sd_id128_t machine;
        int r;

        assert(f);

        /* This function is used to determine whether sealing should be enabled in the journal header so we
         * can't check the header to check if sealing is enabled here. */

        r = sd_id128_get_machine(&machine);
        if (r < 0)
                return r;

        if (asprintf(&path, "/var/log/journal/" SD_ID128_FORMAT_STR "/fss",
                     SD_ID128_FORMAT_VAL(machine)) < 0)
                return -ENOMEM;

        fd = open(path, O_RDWR|O_CLOEXEC|O_NOCTTY, 0600);
        if (fd < 0) {
                if (errno != ENOENT)
                        log_error_errno(errno, "Failed to open %s: %m", path);

                return -errno;
        }

        if (fstat(fd, &st) < 0)
                return -errno;

        if (st.st_size < (off_t) sizeof(FSSHeader))
                return -ENODATA;

        header = mmap(NULL, PAGE_ALIGN(sizeof(FSSHeader)), PROT_READ, MAP_SHARED, fd, 0);
        if (header == MAP_FAILED)
                return -errno;

        if (memcmp(header->signature, FSS_HEADER_SIGNATURE, 8) != 0)
                return -EBADMSG;

        if (header->incompatible_flags != 0)
                return -EPROTONOSUPPORT;

        if (le64toh(header->header_size) < sizeof(FSSHeader))
                return -EBADMSG;

        uint16_t secpar = le16toh(header->fsprg_secpar);
        if (!fsprg_secpar_is_valid(secpar))
                return -EBADMSG;

        if (le64toh(header->fsprg_state_size) != fsprg_state_size(secpar))
                return -EBADMSG;

        f->fss_file_size = le64toh(header->header_size) + le64toh(header->fsprg_state_size);
        if ((uint64_t) st.st_size < f->fss_file_size)
                return -ENODATA;

        if (!sd_id128_equal(machine, header->machine_id))
                return -EHOSTDOWN;

        if (le64toh(header->start_usec) <= 0 || le64toh(header->interval_usec) <= 0)
                return -EBADMSG;

        size_t sz = PAGE_ALIGN(f->fss_file_size);
        assert(sz < SIZE_MAX);
        f->fss_file = mmap(NULL, sz, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
        if (f->fss_file == MAP_FAILED) {
                f->fss_file = NULL;
                return -errno;
        }

        f->fss_start_usec = le64toh(f->fss_file->start_usec);
        f->fss_interval_usec = le64toh(f->fss_file->interval_usec);

        f->fsprg_state = IOVEC_MAKE(
                        (uint8_t*) f->fss_file + le64toh(f->fss_file->header_size),
                        le64toh(f->fss_file->fsprg_state_size));

        return 0;
}

int journal_file_hmac_setup(JournalFile *f) {
#if HAVE_OPENSSL
        int r;

        if (!JOURNAL_HEADER_SEALED(f->header))
                return 0;

        r = dlopen_libcrypto(LOG_DEBUG);
        if (r < 0)
                return r;

        f->hmac = sym_EVP_MAC_fetch(NULL, "HMAC", NULL);
        if (!f->hmac)
                return log_openssl_errors(LOG_DEBUG, "EVP_MAC_fetch() failed");

        f->hmac_ctx = sym_EVP_MAC_CTX_new(f->hmac);
        if (!f->hmac_ctx)
                return log_openssl_errors(LOG_DEBUG, "EVP_MAC_CTX_new() failed");

        _cleanup_(OSSL_PARAM_BLD_freep) OSSL_PARAM_BLD *bld = sym_OSSL_PARAM_BLD_new();
        if (!bld)
                return log_openssl_errors(LOG_DEBUG, "OSSL_PARAM_BLD_new() failed");

        if (sym_OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_MAC_PARAM_DIGEST, "SHA256", 0) <= 0)
                return log_openssl_errors(LOG_DEBUG, "OSSL_PARAM_BLD_push_utf8_string() failed");

        f->ossl_params = sym_OSSL_PARAM_BLD_to_param(bld);
        if (!f->ossl_params)
                return log_openssl_errors(LOG_DEBUG, "OSSL_PARAM_BLD_to_param() failed");

        return 0;
#else
        return -EOPNOTSUPP;
#endif
}

int journal_file_append_first_tag(JournalFile *f) {
        uint64_t p;
        int r;

        if (!JOURNAL_HEADER_SEALED(f->header))
                return 0;

        log_debug("Calculating first tag...");

        r = journal_file_hmac_put_header(f);
        if (r < 0)
                return r;

        p = le64toh(f->header->field_hash_table_offset);
        if (p < offsetof(Object, hash_table.items))
                return -EINVAL;
        p -= offsetof(Object, hash_table.items);

        r = journal_file_hmac_put_object(f, OBJECT_FIELD_HASH_TABLE, NULL, p);
        if (r < 0)
                return r;

        p = le64toh(f->header->data_hash_table_offset);
        if (p < offsetof(Object, hash_table.items))
                return -EINVAL;
        p -= offsetof(Object, hash_table.items);

        r = journal_file_hmac_put_object(f, OBJECT_DATA_HASH_TABLE, NULL, p);
        if (r < 0)
                return r;

        r = journal_file_append_tag(f);
        if (r < 0)
                return r;

        return 0;
}

int journal_file_parse_verification_key(JournalFile *f, const char *key) {
        _cleanup_(erase_and_freep) uint8_t *seed = NULL;
        size_t seed_size;
        const char *k;
        unsigned long long start, interval;
        int r;

        assert(f);
        assert(key);

        seed_size = FSPRG_RECOMMENDED_SEEDLEN;
        seed = malloc(seed_size);
        if (!seed)
                return -ENOMEM;

        k = key;
        for (size_t c = 0; c < seed_size; c++) {
                int x, y;

                k = skip_leading_chars(k, "-");

                x = unhexchar(*k);
                if (x < 0)
                        return -EINVAL;
                k++;

                y = unhexchar(*k);
                if (y < 0)
                        return -EINVAL;
                k++;

                seed[c] = (uint8_t) (x * 16 + y);
        }

        if (*k != '/')
                return -EINVAL;
        k++;

        r = sscanf(k, "%llx-%llx", &start, &interval);
        if (r != 2)
                return -EINVAL;

        f->fsprg_seed = IOVEC_MAKE(TAKE_PTR(seed), seed_size);
        f->fss_start_usec = start * interval;
        f->fss_interval_usec = interval;

        return 0;
}

int journal_file_next_evolve_usec(JournalFile *f, usec_t *u) {
        uint64_t epoch;
        int r;

        assert(f);
        assert(u);

        if (!JOURNAL_HEADER_SEALED(f->header))
                return false;

        r = fsprg_get_epoch(&f->fsprg_state, &epoch);
        if (r < 0)
                return r;

        *u = (usec_t) (f->fss_start_usec + f->fss_interval_usec * epoch + f->fss_interval_usec);
        return true;
}
