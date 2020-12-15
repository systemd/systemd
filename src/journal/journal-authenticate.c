/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <sys/mman.h>

#include "fd-util.h"
#include "fsprg.h"
#include "openssl-util.h"
#include "hexdecoct.h"
#include "journal-authenticate.h"
#include "journal-def.h"
#include "journal-file.h"
#include "memory-util.h"
#include "time-util.h"

static uint64_t journal_file_tag_seqnum(JournalFile *f) {
        uint64_t r;

        assert(f);

        r = le64toh(f->header->n_tags) + 1;
        f->header->n_tags = htole64(r);

        return r;
}

int journal_file_append_tag(JournalFile *f) {
        Object *o;
        uint64_t p;
        uint8_t md[DIGEST_MAX];
        int r;

        assert(f);

        if (!f->seal)
                return 0;

        if (!f->hmac_running)
                return 0;

        assert(f->hctx);

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
        if (HMAC_Final(f->hctx, md, NULL) <= 0)
                return -EIO;
        memcpy(o->tag.tag, md, TAG_LENGTH);
        f->hmac_running = false;

        return 0;
}

int journal_file_hmac_start(JournalFile *f) {
        uint8_t key[256 / 8]; /* Let's pass 256 bit from FSPRG to HMAC */
        assert(f);

        if (!f->seal)
                return 0;

        if (f->hmac_running)
                return 0;

        /* Prepare HMAC for next cycle */
        if (HMAC_CTX_reset(f->hctx) <= 0)
                return -EIO;
        if (HMAC_Init_ex(f->hctx, key, sizeof(key), RND_HASH, NULL) <= 0)
                return -EIO;

        FSPRG_GetKey(f->fsprg_state, key, sizeof(key), 0);

        f->hmac_running = true;

        return 0;
}

static int journal_file_get_epoch(JournalFile *f, uint64_t realtime, uint64_t *epoch) {
        uint64_t t;

        assert(f);
        assert(epoch);
        assert(f->seal);

        if (f->fss_start_usec == 0 ||
            f->fss_interval_usec == 0)
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

        if (!f->seal)
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

        if (!f->seal)
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
        }
}

int journal_file_fsprg_seek(JournalFile *f, uint64_t goal) {
        void *msk;
        uint64_t epoch;

        assert(f);

        if (!f->seal)
                return 0;

        assert(f->fsprg_seed);

        if (f->fsprg_state) {
                /* Cheaper... */

                epoch = FSPRG_GetEpoch(f->fsprg_state);
                if (goal == epoch)
                        return 0;

                if (goal == epoch+1) {
                        return FSPRG_Evolve(f->fsprg_state);
                }
        } else {
                f->fsprg_state_size = FSPRG_stateinbytes(FSPRG_RECOMMENDED_SECPAR);
                f->fsprg_state = malloc(f->fsprg_state_size);

                if (!f->fsprg_state)
                        return -ENOMEM;
        }

        log_debug("Seeking FSPRG key to %"PRIu64".", goal);

        msk = alloca(FSPRG_mskinbytes(FSPRG_RECOMMENDED_SECPAR));
        FSPRG_GenMK(msk, NULL, f->fsprg_seed, f->fsprg_seed_size, FSPRG_RECOMMENDED_SECPAR);
        return FSPRG_Seek(f->fsprg_state, goal, msk, f->fsprg_seed, f->fsprg_seed_size);
}

int journal_file_maybe_append_tag(JournalFile *f, uint64_t realtime) {
        int r;

        assert(f);

        if (!f->seal)
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
        int r;

        assert(f);

        if (!f->seal)
                return 0;

        r = journal_file_hmac_start(f);
        if (r < 0)
                return r;

        if (!o) {
                r = journal_file_move_to_object(f, type, p, &o);
                if (r < 0)
                        return r;
        } else {
                if (type > OBJECT_UNUSED && o->object.type != type)
                        return -EBADMSG;
        }

        if (HMAC_Update(f->hctx, (uint8_t*) o, offsetof(ObjectHeader, payload)) <= 0)
                return -EIO;

        switch (o->object.type) {

        case OBJECT_DATA:
                /* All but hash and payload are mutable */
                if (HMAC_Update(f->hctx, (uint8_t*) &o->data.hash, sizeof(o->data.hash)) <= 0)
                        return -EIO;
                if (HMAC_Update(f->hctx, o->data.payload,
                                le64toh(o->object.size) - offsetof(DataObject, payload)))
                        return -EIO;
                break;

        case OBJECT_FIELD:
                /* Same here */
                if (HMAC_Update(f->hctx, (uint8_t*) &o->field.hash, sizeof(o->field.hash)) <= 0)
                        return -EIO;
                if (HMAC_Update(f->hctx, o->field.payload, le64toh(o->object.size) - offsetof(FieldObject, payload)) <= 0)
                        return -EIO;
                break;

        case OBJECT_ENTRY:
                /* All */
                if (HMAC_Update(f->hctx, (uint8_t*) &o->entry.seqnum, le64toh(o->object.size) - offsetof(EntryObject, seqnum)) <= 0)
                        return -EIO;
                break;

        case OBJECT_FIELD_HASH_TABLE:
        case OBJECT_DATA_HASH_TABLE:
        case OBJECT_ENTRY_ARRAY:
                /* Nothing: everything is mutable */
                break;

        case OBJECT_TAG:
                /* All but the tag itself */
                if (HMAC_Update(f->hctx, (uint8_t*) &o->tag.seqnum, sizeof(o->tag.seqnum)) <= 0)
                        return -EIO;
                if (HMAC_Update(f->hctx, (uint8_t*) &o->tag.epoch, sizeof(o->tag.epoch)) <= 0)
                        return -EIO;
                break;
        default:
                return -EINVAL;
        }

        return 0;
}

int journal_file_hmac_put_header(JournalFile *f) {
        int r;

        assert(f);

        if (!f->seal)
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

        if (HMAC_Update(f->hctx, f->header->signature,
                        offsetof(Header, state) - offsetof(Header, signature)) <= 0)
                return -EIO;
        if (HMAC_Update(f->hctx, (uint8_t*) &f->header->file_id,
                        offsetof(Header, boot_id) - offsetof(Header, file_id)) <= 0)
                return -EIO;
        if (HMAC_Update(f->hctx, (uint8_t*) &f->header->seqnum_id,
                        offsetof(Header, arena_size) - offsetof(Header, seqnum_id)) <= 0)
                return -EIO;
        if (HMAC_Update(f->hctx, (uint8_t*) &f->header->data_hash_table_offset,
                        offsetof(Header, tail_object_offset) - offsetof(Header, data_hash_table_offset)) <= 0)
                return -EIO;

        return 0;
}

int journal_file_fss_load(JournalFile *f) {
        int r, fd = -1;
        char *p = NULL;
        struct stat st;
        FSSHeader *m = NULL;
        sd_id128_t machine;

        assert(f);

        if (!f->seal)
                return 0;

        r = sd_id128_get_machine(&machine);
        if (r < 0)
                return r;

        if (asprintf(&p, "/var/log/journal/" SD_ID128_FORMAT_STR "/fss",
                     SD_ID128_FORMAT_VAL(machine)) < 0)
                return -ENOMEM;

        fd = open(p, O_RDWR|O_CLOEXEC|O_NOCTTY, 0600);
        if (fd < 0) {
                if (errno != ENOENT)
                        log_error_errno(errno, "Failed to open %s: %m", p);

                r = -errno;
                goto finish;
        }

        if (fstat(fd, &st) < 0) {
                r = -errno;
                goto finish;
        }

        if (st.st_size < (off_t) sizeof(FSSHeader)) {
                r = -ENODATA;
                goto finish;
        }

        m = mmap(NULL, PAGE_ALIGN(sizeof(FSSHeader)), PROT_READ, MAP_SHARED, fd, 0);
        if (m == MAP_FAILED) {
                m = NULL;
                r = -errno;
                goto finish;
        }

        if (memcmp(m->signature, FSS_HEADER_SIGNATURE, 8) != 0) {
                r = -EBADMSG;
                goto finish;
        }

        if (m->incompatible_flags != 0) {
                r = -EPROTONOSUPPORT;
                goto finish;
        }

        if (le64toh(m->header_size) < sizeof(FSSHeader)) {
                r = -EBADMSG;
                goto finish;
        }

        if (le64toh(m->fsprg_state_size) != FSPRG_stateinbytes(le16toh(m->fsprg_secpar))) {
                r = -EBADMSG;
                goto finish;
        }

        f->fss_file_size = le64toh(m->header_size) + le64toh(m->fsprg_state_size);
        if ((uint64_t) st.st_size < f->fss_file_size) {
                r = -ENODATA;
                goto finish;
        }

        if (!sd_id128_equal(machine, m->machine_id)) {
                r = -EHOSTDOWN;
                goto finish;
        }

        if (le64toh(m->start_usec) <= 0 ||
            le64toh(m->interval_usec) <= 0) {
                r = -EBADMSG;
                goto finish;
        }

        f->fss_file = mmap(NULL, PAGE_ALIGN(f->fss_file_size), PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
        if (f->fss_file == MAP_FAILED) {
                f->fss_file = NULL;
                r = -errno;
                goto finish;
        }

        f->fss_start_usec = le64toh(f->fss_file->start_usec);
        f->fss_interval_usec = le64toh(f->fss_file->interval_usec);

        f->fsprg_state = (uint8_t*) f->fss_file + le64toh(f->fss_file->header_size);
        f->fsprg_state_size = le64toh(f->fss_file->fsprg_state_size);

        r = 0;

finish:
        if (m)
                munmap(m, PAGE_ALIGN(sizeof(FSSHeader)));

        safe_close(fd);
        free(p);

        return r;
}

int journal_file_hmac_setup(JournalFile *f) {
        if (!f->seal)
                return 0;

        f->hctx = HMAC_CTX_new();
        if(!f->hctx)
                return -ENOMEM;

        return 0;
}

int journal_file_append_first_tag(JournalFile *f) {
        int r;
        uint64_t p;

        if (!f->seal)
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
        uint8_t *seed;
        size_t seed_size, c;
        const char *k;
        int r;
        unsigned long long start, interval;

        seed_size = FSPRG_RECOMMENDED_SEEDLEN;
        seed = malloc(seed_size);
        if (!seed)
                return -ENOMEM;

        k = key;
        for (c = 0; c < seed_size; c++) {
                int x, y;

                while (*k == '-')
                        k++;

                x = unhexchar(*k);
                if (x < 0) {
                        free(seed);
                        return -EINVAL;
                }
                k++;
                y = unhexchar(*k);
                if (y < 0) {
                        free(seed);
                        return -EINVAL;
                }
                k++;

                seed[c] = (uint8_t) (x * 16 + y);
        }

        if (*k != '/') {
                free(seed);
                return -EINVAL;
        }
        k++;

        r = sscanf(k, "%llx-%llx", &start, &interval);
        if (r != 2) {
                free(seed);
                return -EINVAL;
        }

        f->fsprg_seed = seed;
        f->fsprg_seed_size = seed_size;

        f->fss_start_usec = start * interval;
        f->fss_interval_usec = interval;

        return 0;
}

bool journal_file_next_evolve_usec(JournalFile *f, usec_t *u) {
        uint64_t epoch;

        assert(f);
        assert(u);

        if (!f->seal)
                return false;

        epoch = FSPRG_GetEpoch(f->fsprg_state);

        *u = (usec_t) (f->fss_start_usec + f->fss_interval_usec * epoch + f->fss_interval_usec);

        return true;
}
