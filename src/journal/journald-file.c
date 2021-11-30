/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "chattr-util.h"
#include "fd-util.h"
#include "format-util.h"
#include "journal-authenticate.h"
#include "journald-file.h"
#include "path-util.h"
#include "random-util.h"
#include "set.h"
#include "sync-util.h"

JournaldFile* journald_file_close(JournaldFile *f) {
        if (!f)
                return NULL;

        journal_file_close(f->file);

        return mfree(f);
}

int journald_file_open(
                int fd,
                const char *fname,
                int flags,
                mode_t mode,
                bool compress,
                uint64_t compress_threshold_bytes,
                bool seal,
                JournalMetrics *metrics,
                MMapCache *mmap_cache,
                Set *deferred_closes,
                JournaldFile *template,
                JournaldFile **ret) {
        _cleanup_free_ JournaldFile *f = NULL;
        int r;

        set_clear_with_destructor(deferred_closes, journald_file_close);

        f = new0(JournaldFile, 1);
        if (!f)
                return -ENOMEM;

        r = journal_file_open(fd, fname, flags, mode, compress, compress_threshold_bytes, seal, metrics,
                              mmap_cache, template ? template->file : NULL, &f->file);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(f);

        return 0;
}


JournaldFile* journald_file_initiate_close(JournaldFile *f, Set *deferred_closes) {
        int r;

        assert(f);

        if (deferred_closes) {
                r = set_put(deferred_closes, f);
                if (r < 0)
                        log_debug_errno(r, "Failed to add file to deferred close set, closing immediately.");
                else {
                        (void) journal_file_set_offline(f->file, false);
                        return NULL;
                }
        }

        return journald_file_close(f);
}

int journald_file_rotate(
                JournaldFile **f,
                bool compress,
                uint64_t compress_threshold_bytes,
                bool seal,
                Set *deferred_closes) {

        JournaldFile *new_file = NULL;
        int r;

        assert(f);
        assert(*f);

        r = journal_file_archive((*f)->file);
        if (r < 0)
                return r;

        r = journald_file_open(
                        -1,
                        (*f)->file->path,
                        (*f)->file->flags,
                        (*f)->file->mode,
                        compress,
                        compress_threshold_bytes,
                        seal,
                        NULL,            /* metrics */
                        (*f)->file->mmap,
                        deferred_closes,
                        *f,              /* template */
                        &new_file);

        journald_file_initiate_close(*f, deferred_closes);
        *f = new_file;

        return r;
}

int journald_file_open_reliably(
                const char *fname,
                int flags,
                mode_t mode,
                bool compress,
                uint64_t compress_threshold_bytes,
                bool seal,
                JournalMetrics *metrics,
                MMapCache *mmap_cache,
                Set *deferred_closes,
                JournaldFile *template,
                JournaldFile **ret) {

        int r;

        r = journald_file_open(-1, fname, flags, mode, compress, compress_threshold_bytes, seal, metrics,
                               mmap_cache, deferred_closes, template, ret);
        if (!IN_SET(r,
                    -EBADMSG,           /* Corrupted */
                    -ENODATA,           /* Truncated */
                    -EHOSTDOWN,         /* Other machine */
                    -EPROTONOSUPPORT,   /* Incompatible feature */
                    -EBUSY,             /* Unclean shutdown */
                    -ESHUTDOWN,         /* Already archived */
                    -EIO,               /* IO error, including SIGBUS on mmap */
                    -EIDRM,             /* File has been deleted */
                    -ETXTBSY))          /* File is from the future */
                return r;

        if ((flags & O_ACCMODE) == O_RDONLY)
                return r;

        if (!(flags & O_CREAT))
                return r;

        if (!endswith(fname, ".journal"))
                return r;

        /* The file is corrupted. Rotate it away and try it again (but only once) */
        log_warning_errno(r, "File %s corrupted or uncleanly shut down, renaming and replacing.", fname);

        r = journal_file_dispose(AT_FDCWD, fname);
        if (r < 0)
                return r;

        return journald_file_open(-1, fname, flags, mode, compress, compress_threshold_bytes, seal, metrics,
                                  mmap_cache, deferred_closes, template, ret);
}
