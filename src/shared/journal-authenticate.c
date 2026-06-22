/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include "alloc-util.h"
#include "crypto-util.h"
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

#if HAVE_OPENSSL

struct JournalAuthContext {
        EVP_MAC *hmac;
        EVP_MAC_CTX *hmac_ctx;
        OSSL_PARAM *ossl_params;
        bool hmac_running;

        FSSHeader *fss_file;
        size_t fss_file_size;

        uint64_t fss_start_usec;
        uint64_t fss_interval_usec;

        struct iovec fsprg_state;
        struct iovec fsprg_seed;
};

static JournalAuthContext* journal_auth_free(JournalAuthContext *c) {
        if (!c)
                return NULL;

        if (c->fss_file) {
                size_t sz = PAGE_ALIGN(c->fss_file_size);
                assert(sz < SIZE_MAX);
                munmap(c->fss_file, sz);
        } else
                iovec_done_erase(&c->fsprg_state);

        iovec_done_erase(&c->fsprg_seed);

        if (c->ossl_params)
                sym_OSSL_PARAM_free(c->ossl_params);
        if (c->hmac_ctx)
                sym_EVP_MAC_CTX_free(c->hmac_ctx);
        if (c->hmac)
                sym_EVP_MAC_free(c->hmac);

        return mfree(c);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(JournalAuthContext*, journal_auth_free);

static void* fssheader_free(FSSHeader *p) {
        /* mmap() returns MAP_FAILED on error and sets the errno */
        if (!p || p == MAP_FAILED)
                return NULL;

        assert_se(munmap(p, PAGE_ALIGN(sizeof(FSSHeader))) >= 0);
        return NULL;
}

DEFINE_TRIVIAL_CLEANUP_FUNC(FSSHeader*, fssheader_free);

static int journal_auth_load(JournalAuthContext **ret) {
        int r;

        assert(ret);

        /* This function is used to determine whether sealing should be enabled in the journal header so we
         * can't check the header to check if sealing is enabled here. */

        sd_id128_t machine;
        r = sd_id128_get_machine(&machine);
        if (r < 0)
                return r;

        _cleanup_free_ char *path = NULL;
        if (asprintf(&path, "/var/log/journal/" SD_ID128_FORMAT_STR "/fss",
                     SD_ID128_FORMAT_VAL(machine)) < 0)
                return -ENOMEM;

        _cleanup_close_ int fd = open(path, O_RDWR|O_CLOEXEC|O_NOCTTY, 0600);
        if (fd < 0) {
                if (errno != ENOENT)
                        log_error_errno(errno, "Failed to open %s: %m", path);

                return -errno;
        }

        struct stat st;
        if (fstat(fd, &st) < 0)
                return -errno;

        if (st.st_size < (off_t) sizeof(FSSHeader))
                return -ENODATA;

        _cleanup_(fssheader_freep) FSSHeader *header =
                mmap(NULL, PAGE_ALIGN(sizeof(FSSHeader)), PROT_READ, MAP_SHARED, fd, 0);
        if (header == MAP_FAILED)
                return -errno;

        if (memcmp(header->signature, (uint8_t[]) FSS_HEADER_SIGNATURE, 8) != 0)
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

        size_t fss_file_size = le64toh(header->header_size) + le64toh(header->fsprg_state_size);
        if ((uint64_t) st.st_size < fss_file_size)
                return -ENODATA;

        if (!sd_id128_equal(machine, header->machine_id))
                return -EHOSTDOWN;

        if (le64toh(header->start_usec) <= 0 || le64toh(header->interval_usec) <= 0)
                return -EBADMSG;

        _cleanup_(journal_auth_freep) JournalAuthContext *c = new0(JournalAuthContext, 1);
        if (!c)
                return -ENOMEM;

        size_t sz = PAGE_ALIGN(fss_file_size);
        assert(sz < SIZE_MAX);
        FSSHeader *p = mmap(NULL, sz, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
        if (p == MAP_FAILED)
                return -errno;

        *c = (JournalAuthContext) {
                .fss_file_size = fss_file_size,
                .fss_file = p,

                .fss_start_usec = le64toh(p->start_usec),
                .fss_interval_usec = le64toh(p->interval_usec),

                .fsprg_state = IOVEC_MAKE(
                                (uint8_t*) p + le64toh(p->header_size),
                                le64toh(p->fsprg_state_size)),
        };

        *ret = TAKE_PTR(c);
        return 0;
}

static int journal_auth_load_key(JournalAuthContext **ret, const char *key) {
        int r;

        assert(ret);
        assert(key);

        size_t seed_size = FSPRG_RECOMMENDED_SEEDLEN;
        _cleanup_(erase_and_freep) uint8_t *seed = malloc(seed_size);
        if (!seed)
                return -ENOMEM;

        const char *k = key;
        for (size_t c = 0; c < seed_size; c++) {
                int x, y;

                k = skip_leading_chars(k, "-");

                x = unhexchar(*k);
                if (x < 0)
                        return -EKEYREJECTED;
                k++;

                y = unhexchar(*k);
                if (y < 0)
                        return -EKEYREJECTED;
                k++;

                seed[c] = (uint8_t) (x * 16 + y);
        }

        if (*k != '/')
                return -EKEYREJECTED;
        k++;

        unsigned long long start, interval;
        r = sscanf(k, "%llx-%llx", &start, &interval);
        if (r != 2)
                return -EKEYREJECTED;

        if (start <= 0 || interval <= 0)
                return -EKEYREJECTED;

        _cleanup_(journal_auth_freep) JournalAuthContext *c = new(JournalAuthContext, 1);
        if (!c)
                return -ENOMEM;

        *c = (JournalAuthContext) {
                .fss_start_usec = start * interval,
                .fss_interval_usec = interval,

                .fsprg_seed = IOVEC_MAKE(TAKE_PTR(seed), seed_size),
        };

        *ret = TAKE_PTR(c);
        return 0;
}

static int journal_auth_epoch_to_realtime_usec(const JournalAuthContext *c, uint64_t epoch, usec_t *ret_start, usec_t *ret_end) {
        assert(c);

        uint64_t start, end;
        if (!MUL_SAFE(&start, epoch, c->fss_interval_usec) ||
            !INC_SAFE(&start, c->fss_start_usec) ||
            !ADD_SAFE(&end, start, c->fss_interval_usec))
                return -ERANGE;

        if (ret_start)
                *ret_start = start;
        if (ret_end)
                *ret_end = end;

        return 0;
}

static int journal_auth_next_evolve_usec(const JournalAuthContext *c, usec_t *ret) {
        int r;

        assert(c);

        uint64_t epoch;
        r = fsprg_get_epoch(&c->fsprg_state, &epoch);
        if (r < 0)
                return r;

        return journal_auth_epoch_to_realtime_usec(c, epoch, /* ret_start= */ NULL, ret);
}

static int journal_auth_seek(JournalAuthContext *c, uint64_t goal) {
        int r;

        assert(c);
        assert(iovec_is_set(&c->fsprg_seed));

        if (iovec_is_set(&c->fsprg_state)) {
                uint64_t epoch;
                r = fsprg_get_epoch(&c->fsprg_state, &epoch);
                if (r < 0)
                        return r;
                if (goal == epoch)
                        return 0;

                if (goal == epoch + 1)
                        return fsprg_evolve(&c->fsprg_state);
        } else {
                r = iovec_alloc(fsprg_state_size(FSPRG_RECOMMENDED_SECPAR), &c->fsprg_state);
                if (r < 0)
                        return r;
        }

        log_debug("Seeking FSPRG key to %"PRIu64".", goal);
        return fsprg_generate_state(FSPRG_RECOMMENDED_SECPAR, goal, &c->fsprg_seed, &c->fsprg_state);
}

static int journal_auth_setup(JournalAuthContext *c) {
        int r;

        assert(c);

        if (c->hmac)
                return 0;

        r = dlopen_libcrypto(LOG_DEBUG);
        if (r < 0)
                return r;

        _cleanup_(EVP_MAC_freep) EVP_MAC *hmac = sym_EVP_MAC_fetch(NULL, "HMAC", NULL);
        if (!hmac)
                return log_openssl_errors(LOG_DEBUG, "EVP_MAC_fetch() failed");

        _cleanup_(EVP_MAC_CTX_freep) EVP_MAC_CTX *ctx = sym_EVP_MAC_CTX_new(hmac);
        if (!ctx)
                return log_openssl_errors(LOG_DEBUG, "EVP_MAC_CTX_new() failed");

        _cleanup_(OSSL_PARAM_BLD_freep) OSSL_PARAM_BLD *bld = sym_OSSL_PARAM_BLD_new();
        if (!bld)
                return log_openssl_errors(LOG_DEBUG, "OSSL_PARAM_BLD_new() failed");

        if (sym_OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_MAC_PARAM_DIGEST, "SHA256", 0) <= 0)
                return log_openssl_errors(LOG_DEBUG, "OSSL_PARAM_BLD_push_utf8_string() failed");

        _cleanup_(OSSL_PARAM_freep) OSSL_PARAM *params = sym_OSSL_PARAM_BLD_to_param(bld);
        if (!params)
                return log_openssl_errors(LOG_DEBUG, "OSSL_PARAM_BLD_to_param() failed");

        c->hmac = TAKE_PTR(hmac);
        c->hmac_ctx = TAKE_PTR(ctx);
        c->ossl_params = TAKE_PTR(params);
        return 0;
}

static int journal_auth_start(JournalAuthContext *c) {
        int r;

        assert(c);

        if (c->hmac_running)
                return 0;

        r = journal_auth_setup(c);
        if (r < 0)
                return r;

        uint8_t key[256 / 8]; /* Let's pass 256 bit from FSPRG to HMAC */
        CLEANUP_ERASE(key);
        r = fsprg_get_key(&c->fsprg_state, &IOVEC_MAKE(key, sizeof(key)));
        if (r < 0)
                return r;

        /* Prepare HMAC for next cycle */
        if (sym_EVP_MAC_init(c->hmac_ctx, key, sizeof(key), c->ossl_params) <= 0)
                return log_openssl_errors(LOG_DEBUG, "sym_EVP_MAC_init() failed");

        c->hmac_running = true;
        return 0;
}

static int journal_auth_end(JournalAuthContext *c, uint8_t ret[static TAG_LENGTH]) {
        assert(c);
        assert(ret);

        if (!c->hmac_running)
                return -EINVAL;

        c->hmac_running = false;

        uint8_t tag[TAG_LENGTH];
        CLEANUP_ERASE(tag);

        size_t len;
        if (sym_EVP_MAC_final(c->hmac_ctx, tag, &len, TAG_LENGTH) <= 0 || len != TAG_LENGTH)
                return -EIO;

        memcpy(ret, tag, TAG_LENGTH);
        return 0;
}

static int journal_auth_put_header(JournalAuthContext *c, JournalFile *f) {
        int r;

        assert(c);
        assert(f);

        r = journal_auth_start(c);
        if (r < 0)
                return r;

        /* All but state+reserved, boot_id, arena_size,
         * tail_object_offset, n_objects, n_entries,
         * tail_entry_seqnum, head_entry_seqnum, entry_array_offset,
         * head_entry_realtime, tail_entry_realtime,
         * tail_entry_monotonic, n_data, n_fields, n_tags,
         * n_entry_arrays. */

        if (sym_EVP_MAC_update(c->hmac_ctx, f->header->signature, offsetof(Header, state) - offsetof(Header, signature)) <= 0)
                return -EIO;
        if (sym_EVP_MAC_update(c->hmac_ctx, (void*) &f->header->file_id, offsetof(Header, tail_entry_boot_id) - offsetof(Header, file_id)) <= 0)
                return -EIO;
        if (sym_EVP_MAC_update(c->hmac_ctx, (void*) &f->header->seqnum_id, offsetof(Header, arena_size) - offsetof(Header, seqnum_id)) <= 0)
                return -EIO;
        if (sym_EVP_MAC_update(c->hmac_ctx, (void*) &f->header->data_hash_table_offset, offsetof(Header, tail_object_offset) - offsetof(Header, data_hash_table_offset)) <= 0)
                return -EIO;

        return 0;
}

static int journal_auth_put_object(JournalAuthContext *c, JournalFile *f, ObjectType type, Object *o, uint64_t p) {
        int r;

        assert(c);
        assert(f);

        r = journal_auth_start(c);
        if (r < 0)
                return r;

        if (!o) {
                r = journal_file_move_to_object(f, type, p, &o);
                if (r < 0)
                        return r;
        } else if (type > OBJECT_UNUSED && o->object.type != type)
                return -EBADMSG;

        if (sym_EVP_MAC_update(c->hmac_ctx, (void*) o, offsetof(ObjectHeader, payload)) <= 0)
                return -EIO;

        switch (o->object.type) {

        case OBJECT_DATA:
                /* All but hash and payload are mutable */
                if (sym_EVP_MAC_update(c->hmac_ctx, (void*) &o->data.hash, sizeof(o->data.hash)) <= 0)
                        return -EIO;
                if (sym_EVP_MAC_update(c->hmac_ctx, journal_file_data_payload_field(f, o), le64toh(o->object.size) - journal_file_data_payload_offset(f)) <= 0)
                        return -EIO;
                break;

        case OBJECT_FIELD:
                /* Same here */
                if (sym_EVP_MAC_update(c->hmac_ctx, (void*) &o->field.hash, sizeof(o->field.hash)) <= 0)
                        return -EIO;
                if (sym_EVP_MAC_update(c->hmac_ctx, o->field.payload, le64toh(o->object.size) - offsetof(Object, field.payload)) <= 0)
                        return -EIO;
                break;

        case OBJECT_ENTRY:
                /* All */
                if (sym_EVP_MAC_update(c->hmac_ctx, (void*) &o->entry.seqnum, le64toh(o->object.size) - offsetof(Object, entry.seqnum)) <= 0)
                        return -EIO;
                break;

        case OBJECT_FIELD_HASH_TABLE:
        case OBJECT_DATA_HASH_TABLE:
        case OBJECT_ENTRY_ARRAY:
                /* Nothing: everything is mutable */
                break;

        case OBJECT_TAG:
                /* All but the tag itself */
                if (sym_EVP_MAC_update(c->hmac_ctx, (void*) &o->tag.seqnum, sizeof(o->tag.seqnum)) <= 0)
                        return -EIO;
                if (sym_EVP_MAC_update(c->hmac_ctx, (void*) &o->tag.epoch, sizeof(o->tag.epoch)) <= 0)
                        return -EIO;
                break;
        default:
                return -EINVAL;
        }

        return 0;
}

static int journal_auth_append_tag(JournalAuthContext *c, JournalFile *f) {
        int r;

        assert(c);
        assert(f);

        r = journal_auth_start(c);
        if (r < 0)
                return r;

        Object *o;
        uint64_t p;
        r = journal_file_append_object(f, OBJECT_TAG, sizeof(struct TagObject), &o, &p);
        if (r < 0)
                return r;

        uint64_t seqnum = le64toh(f->header->n_tags) + 1;
        f->header->n_tags = htole64(seqnum);

        o->tag.seqnum = htole64(seqnum);

        uint64_t epoch;
        r = fsprg_get_epoch(&c->fsprg_state, &epoch);
        if (r < 0)
                return r;
        o->tag.epoch = htole64(epoch);

        log_debug("Writing tag %"PRIu64" for epoch %"PRIu64"",
                  le64toh(o->tag.seqnum), epoch);

        /* Add the tag object itself, so that we can protect its
         * header. This will exclude the actual hash value in it */
        r = journal_auth_put_object(c, f, OBJECT_TAG, o, p);
        if (r < 0)
                return r;

        /* Get the HMAC tag and store it in the object */
        return journal_auth_end(c, o->tag.tag);
}

static int journal_auth_append_tag_first(JournalAuthContext *c, JournalFile *f) {
        uint64_t p;
        int r;

        assert(c);
        assert(f);

        log_debug("Calculating first tag...");

        r = journal_auth_put_header(c, f);
        if (r < 0)
                return r;

        p = le64toh(f->header->field_hash_table_offset);
        if (p < offsetof(Object, hash_table.items))
                return -EINVAL;
        p -= offsetof(Object, hash_table.items);

        r = journal_auth_put_object(c, f, OBJECT_FIELD_HASH_TABLE, NULL, p);
        if (r < 0)
                return r;

        p = le64toh(f->header->data_hash_table_offset);
        if (p < offsetof(Object, hash_table.items))
                return -EINVAL;
        p -= offsetof(Object, hash_table.items);

        r = journal_auth_put_object(c, f, OBJECT_DATA_HASH_TABLE, NULL, p);
        if (r < 0)
                return r;

        return journal_auth_append_tag(c, f);
}

static int journal_auth_append_tag_maybe(JournalAuthContext *c, JournalFile *f, usec_t realtime) {
        int r;

        assert(c);
        assert(f);

        if (realtime <= 0)
                realtime = now(CLOCK_REALTIME);

        uint64_t goal = usec_sub_unsigned(realtime, c->fss_start_usec) / c->fss_interval_usec;

        for (;;) {
                uint64_t epoch;
                r = fsprg_get_epoch(&c->fsprg_state, &epoch);
                if (r < 0)
                        return r;
                if (epoch >= goal)
                        return 0;

                r = journal_auth_append_tag(c, f);
                if (r < 0)
                        return r;

                r = fsprg_evolve(&c->fsprg_state);
                if (r < 0)
                        return r;
        }
}

static const JournalAuthOps journal_auth_ops = {
        .free = journal_auth_free,
        .load = journal_auth_load,
        .load_key = journal_auth_load_key,
        .epoch_to_realtime_usec = journal_auth_epoch_to_realtime_usec,
        .next_evolve_usec = journal_auth_next_evolve_usec,
        .seek = journal_auth_seek,
        .start = journal_auth_start,
        .end = journal_auth_end,
        .put_header = journal_auth_put_header,
        .put_object = journal_auth_put_object,
        .append_tag = journal_auth_append_tag,
        .append_tag_first = journal_auth_append_tag_first,
        .append_tag_maybe = journal_auth_append_tag_maybe,
};

void journal_auth_init(void) {
        journal_auth_set_ops(&journal_auth_ops);
}

#else

void journal_auth_init(void) {
}

#endif /* HAVE_OPENSSL */
