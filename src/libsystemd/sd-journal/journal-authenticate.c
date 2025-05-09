/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "fsprg.h"
#include "gcrypt-util.h"
#include "hexdecoct.h"
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

#if HAVE_GCRYPT
static uint64_t journal_file_tag_seqnum(JournalFile *f) {
        uint64_t r;

        assert(f);

        r = le64toh(f->header->n_tags) + 1;
        f->header->n_tags = htole64(r);

        return r;
}
#endif

int journal_file_append_tag(JournalFile *f) {
#if HAVE_GCRYPT
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

        assert(f->hmac);

        r = journal_file_append_object(f, OBJECT_TAG, sizeof(struct TagObject), &o, &p);
        if (r < 0)
                return r;

        o->tag.seqnum = htole64(journal_file_tag_seqnum(f));
        o->tag.epoch = htole64(FSPRG_GetEpoch(f->fsprg_state));

        log_debug("Writing tag %"PRIu64" for epoch %"PRIu64"",
                  le64toh(o->tag.seqnum),
                  FSPRG_GetEpoch(f->fsprg_state));

        /* Add the tag object itself, so that we can protect its
         * header. This will exclude the actual hash value in it */
        r = journal_file_hmac_put_object(f, OBJECT_TAG, o, p);
        if (r < 0)
                return r;

        /* Get the HMAC tag and store it in the object */
        memcpy(o->tag.tag, sym_gcry_md_read(f->hmac, 0), TAG_LENGTH);
        f->hmac_running = false;

        return 0;
#else
        return -EOPNOTSUPP;
#endif
}

int journal_file_hmac_start(JournalFile *f) {
#if HAVE_GCRYPT
        uint8_t key[256 / 8]; /* Let's pass 256 bit from FSPRG to HMAC */
        gcry_error_t err;
        int r;

        assert(f);

        if (!JOURNAL_HEADER_SEALED(f->header))
                return 0;

        if (f->hmac_running)
                return 0;

        /* Prepare HMAC for next cycle */
        sym_gcry_md_reset(f->hmac);

        r = FSPRG_GetKey(f->fsprg_state, key, sizeof(key), 0);
        if (r < 0)
                return r;

        err = sym_gcry_md_setkey(f->hmac, key, sizeof(key));
        if (gcry_err_code(err) != GPG_ERR_NO_ERROR)
                return log_debug_errno(SYNTHETIC_ERRNO(EIO),
                                       "sym_gcry_md_setkey() failed with error code: %s",
                                       sym_gcry_strerror(err));

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

        epoch = FSPRG_GetEpoch(f->fsprg_state);
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

        epoch = FSPRG_GetEpoch(f->fsprg_state);
        if (epoch < goal)
                log_debug("Evolving FSPRG key from epoch %"PRIu64" to %"PRIu64".", epoch, goal);

        for (;;) {
                if (epoch > goal)
                        return -ESTALE;
                if (epoch == goal)
                        return 0;

                r = FSPRG_Evolve(f->fsprg_state);
                if (r < 0)
                        return r;

                epoch = FSPRG_GetEpoch(f->fsprg_state);
                if (epoch < goal) {
                        r = journal_file_append_tag(f);
                        if (r < 0)
                                return r;
                }
        }
}

int journal_file_fsprg_seek(JournalFile *f, uint64_t goal) {
        void *msk;
        uint64_t epoch;
        int r;

        assert(f);

        if (!JOURNAL_HEADER_SEALED(f->header))
                return 0;

        assert(f->fsprg_seed);

        if (f->fsprg_state) {
                /* Cheaper... */

                epoch = FSPRG_GetEpoch(f->fsprg_state);
                if (goal == epoch)
                        return 0;

                if (goal == epoch + 1)
                        return FSPRG_Evolve(f->fsprg_state);
        } else {
                f->fsprg_state_size = FSPRG_stateinbytes(FSPRG_RECOMMENDED_SECPAR);
                f->fsprg_state = malloc(f->fsprg_state_size);
                if (!f->fsprg_state)
                        return -ENOMEM;
        }

        log_debug("Seeking FSPRG key to %"PRIu64".", goal);

        msk = alloca_safe(FSPRG_mskinbytes(FSPRG_RECOMMENDED_SECPAR));

        r = FSPRG_GenMK(msk, NULL, f->fsprg_seed, f->fsprg_seed_size, FSPRG_RECOMMENDED_SECPAR);
        if (r < 0)
                return r;

        return FSPRG_Seek(f->fsprg_state, goal, msk, f->fsprg_seed, f->fsprg_seed_size);
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
#if HAVE_GCRYPT
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

        sym_gcry_md_write(f->hmac, o, offsetof(ObjectHeader, payload));

        switch (o->object.type) {

        case OBJECT_DATA:
                /* All but hash and payload are mutable */
                sym_gcry_md_write(f->hmac, &o->data.hash, sizeof(o->data.hash));
                sym_gcry_md_write(f->hmac, journal_file_data_payload_field(f, o), le64toh(o->object.size) - journal_file_data_payload_offset(f));
                break;

        case OBJECT_FIELD:
                /* Same here */
                sym_gcry_md_write(f->hmac, &o->field.hash, sizeof(o->field.hash));
                sym_gcry_md_write(f->hmac, o->field.payload, le64toh(o->object.size) - offsetof(Object, field.payload));
                break;

        case OBJECT_ENTRY:
                /* All */
                sym_gcry_md_write(f->hmac, &o->entry.seqnum, le64toh(o->object.size) - offsetof(Object, entry.seqnum));
                break;

        case OBJECT_FIELD_HASH_TABLE:
        case OBJECT_DATA_HASH_TABLE:
        case OBJECT_ENTRY_ARRAY:
                /* Nothing: everything is mutable */
                break;

        case OBJECT_TAG:
                /* All but the tag itself */
                sym_gcry_md_write(f->hmac, &o->tag.seqnum, sizeof(o->tag.seqnum));
                sym_gcry_md_write(f->hmac, &o->tag.epoch, sizeof(o->tag.epoch));
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
#if HAVE_GCRYPT
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

        sym_gcry_md_write(f->hmac, f->header->signature, offsetof(Header, state) - offsetof(Header, signature));
        sym_gcry_md_write(f->hmac, &f->header->file_id, offsetof(Header, tail_entry_boot_id) - offsetof(Header, file_id));
        sym_gcry_md_write(f->hmac, &f->header->seqnum_id, offsetof(Header, arena_size) - offsetof(Header, seqnum_id));
        sym_gcry_md_write(f->hmac, &f->header->data_hash_table_offset, offsetof(Header, tail_object_offset) - offsetof(Header, data_hash_table_offset));

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

        if (le64toh(header->fsprg_state_size) != FSPRG_stateinbytes(le16toh(header->fsprg_secpar)))
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

        f->fsprg_state = (uint8_t*) f->fss_file + le64toh(f->fss_file->header_size);
        f->fsprg_state_size = le64toh(f->fss_file->fsprg_state_size);

        return 0;
}

int journal_file_hmac_setup(JournalFile *f) {
#if HAVE_GCRYPT
        gcry_error_t e;
        int r;

        if (!JOURNAL_HEADER_SEALED(f->header))
                return 0;

        r = initialize_libgcrypt(true);
        if (r < 0)
                return r;

        e = sym_gcry_md_open(&f->hmac, GCRY_MD_SHA256, GCRY_MD_FLAG_HMAC);
        if (e != 0)
                return -EOPNOTSUPP;

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
        _cleanup_free_ uint8_t *seed = NULL;
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

        f->fsprg_seed = TAKE_PTR(seed);
        f->fsprg_seed_size = seed_size;

        f->fss_start_usec = start * interval;
        f->fss_interval_usec = interval;

        return 0;
}

bool journal_file_next_evolve_usec(JournalFile *f, usec_t *u) {
        uint64_t epoch;

        assert(f);
        assert(u);

        if (!JOURNAL_HEADER_SEALED(f->header))
                return false;

        epoch = FSPRG_GetEpoch(f->fsprg_state);

        *u = (usec_t) (f->fss_start_usec + f->fss_interval_usec * epoch + f->fss_interval_usec);

        return true;
}
