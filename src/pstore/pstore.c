/* SPDX-License-Identifier: LGPL-2.1+ */

/*
 * Generally speaking, the pstore contains a small number of files
 * that in turn contain a small amount of data.
 */
#include <errno.h>
#include <stdio.h>
#include <stdio_ext.h>
#include <sys/prctl.h>
#include <sys/xattr.h>
#include <unistd.h>

#include "sd-daemon.h"
#include "sd-journal.h"
#include "sd-login.h"
#include "sd-messages.h"

#include "acl-util.h"
#include "alloc-util.h"
#include "capability-util.h"
#include "cgroup-util.h"
#include "compress.h"
#include "conf-parser.h"
#include "copy.h"
#include "dirent-util.h"
#include "escape.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "io-util.h"
#include "journal-importer.h"
#include "log.h"
#include "macro.h"
#include "main-func.h"
#include "missing.h"
#include "mkdir.h"
#include "parse-util.h"
#include "process-util.h"
#include "signal-util.h"
#include "socket-util.h"
#include "special.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "tmpfile-util.h"
#include "user-util.h"
#include "util.h"

#define ARRAY_SIZE(ARRAY) (sizeof(ARRAY)/sizeof(ARRAY[0]))

#define PATHSZ 1024
#define ARG_SOURCEDIR_DEFAULT "/sys/fs/pstore"
#define ARG_ARCHIVEDIR_DEFAULT "/var/lib/systemd/pstore"

/*
 * Command line argument handling
 */
typedef enum PstoreStorage {
        PSTORE_STORAGE_NONE,
        PSTORE_STORAGE_ARCHIVE,
        PSTORE_STORAGE_JOURNAL,
        _PSTORE_STORAGE_MAX,
        _PSTORE_STORAGE_INVALID = -1
} PstoreStorage;

static const char* const pstore_storage_table[_PSTORE_STORAGE_MAX] = {
        [PSTORE_STORAGE_NONE] = "none",
        [PSTORE_STORAGE_ARCHIVE] = "archive",
        [PSTORE_STORAGE_JOURNAL] = "journal",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP(pstore_storage, PstoreStorage);
static DEFINE_CONFIG_PARSE_ENUM(config_parse_pstore_storage, pstore_storage, PstoreStorage, "Failed to parse storage setting");

static PstoreStorage arg_storage = PSTORE_STORAGE_ARCHIVE;

static bool arg_allowunlink = true;
static char *arg_sourcedir = NULL;
static char *arg_archivedir = NULL;
STATIC_DESTRUCTOR_REGISTER(arg_sourcedir, freep);
STATIC_DESTRUCTOR_REGISTER(arg_archivedir, freep);

static int parse_config(void) {
    int rc;
    static const ConfigTableItem items[] = {
            { "Pstore", "AllowUnlink",      config_parse_bool,              0, &arg_allowunlink },
            { "Pstore", "Storage",          config_parse_pstore_storage,    0, &arg_storage     },
            { "Pstore", "SourceDir",        config_parse_path,              0, &arg_sourcedir   },
            { "Pstore", "ArchiveDir",       config_parse_path,              0, &arg_archivedir  },
            {}
    };

    rc = config_parse_many_nulstr(PKGSYSCONFDIR "/pstore.conf",
                                    CONF_PATHS_NULSTR("systemd/pstore.conf.d"),
                                    "Pstore\0",
                                    config_item_table_lookup, items,
                                    CONFIG_PARSE_WARN, NULL);
    if (NULL == arg_sourcedir)
    {
        arg_sourcedir = (char *)malloc(sizeof(ARG_SOURCEDIR_DEFAULT)+1);
        if (NULL != arg_sourcedir)
            strcpy(arg_sourcedir, ARG_SOURCEDIR_DEFAULT);
    }
    if (NULL == arg_archivedir)
    {
        arg_archivedir = (char *)malloc(sizeof(ARG_ARCHIVEDIR_DEFAULT)+1);
        if (NULL != arg_archivedir)
            strcpy(arg_archivedir, ARG_ARCHIVEDIR_DEFAULT);
    }
    return rc;
}

/*
 * File list handling
 */
typedef struct dirent_cs
{
    struct dirent de;
    struct stat statbuf;
    int is_binary;
    char *contents;
    struct dirent_cs *next;
    struct dirent_cs *prev;
} dirent_ct;

#define END_OF_DIRENT_LIST(LIST, DC) ((DC)->next == (LIST))
#define START_OF_DIRENT_LIST(LIST, DC) ((DC) == (LIST))

#define FOR_EACH_DIRENT_IN_LIST(LIST, VAR) \
    for (VAR = LIST; VAR; VAR = (VAR->next == LIST) ? NULL : VAR->next)

void dump_dirent_in_list (dirent_ct *list);
void prepend_dirent_to_list (dirent_ct **list, dirent_ct *dc);
void append_dirent_to_list (dirent_ct **list, dirent_ct *dc);
void remove_dirent_from_list (dirent_ct **list, dirent_ct *dc);
void sort_files (dirent_ct **list, int ascending);
void free_files (dirent_ct **list);
int move_file (dirent_ct *dc, const char *subdir);


void
dump_dirent_in_list (dirent_ct *list)
{
    dirent_ct *dc;
    FOR_EACH_DIRENT_IN_LIST(list, dc)
    {
        printf(" %08x %8lu %s\n", dc->statbuf.st_mode, dc->statbuf.st_size, dc->de.d_name);
    }
}

void
prepend_dirent_to_list (dirent_ct **list, dirent_ct *dc)
{
    if (NULL == *list)
    {
        *list = dc;
        dc->next = dc->prev = dc;
    }
    else
    {
        dirent_ct *first = *list;
        dirent_ct *last = (*list)->prev;
        dc->next = first;
        dc->prev = last;
        first->prev = dc;
        last->next = dc;
        *list = dc;
    }
}

void
append_dirent_to_list (dirent_ct **list, dirent_ct *dc)
{
    if (NULL == *list)
    {
        *list = dc;
        dc->next = dc->prev = dc;
    }
    else
    {
        dirent_ct *first = *list;
        dirent_ct *last = (*list)->prev;
        dc->next = first;
        dc->prev = last;
        first->prev = dc;
        last->next = dc;
    }
}

void
remove_dirent_from_list (dirent_ct **list, dirent_ct *dc)
{
    dirent_ct *prev = dc->prev;
    dirent_ct *next = dc->next;
    prev->next = next;
    next->prev = prev;
    *list = (*list == dc) ? ((dc->next == dc) ? NULL : next) : *list;
}

void
sort_files (dirent_ct **list, int ascending)
{
    // Simple brute force linear sort
    int sorted = 0;
    dirent_ct *dc;
    do
    {
        sorted = 1;
        FOR_EACH_DIRENT_IN_LIST(*list, dc)
        {
            if (ascending)
            {
                if (!END_OF_DIRENT_LIST(*list, dc) &&
                    /* lexigraphical sort, ascending */
                    (strcmp(dc->de.d_name, dc->next->de.d_name) > 0))
                {
                    remove_dirent_from_list(list, dc);
                    append_dirent_to_list(list, dc);
                    sorted = 0;
                    break; // re-start sort
                }
            }
            else
            {
                if (!START_OF_DIRENT_LIST(*list, dc) &&
                    /* lexigraphical sort, descending */
                    (strcmp(dc->de.d_name, dc->prev->de.d_name) > 0))
                {
                    remove_dirent_from_list(list, dc);
                    prepend_dirent_to_list(list, dc);
                    sorted = 0;
                    break; // re-start sort
                }
            }
        }
    } while (!sorted);
}

void
free_files (dirent_ct **list)
{
    dirent_ct *dc;
    FOR_EACH_DIRENT_IN_LIST(*list, dc)
    {
        if (NULL != dc->contents)
        {
            free(dc->contents);
        }
        remove_dirent_from_list(list, dc);
        free(dc);
        break; // re-start loop
    }
}

int
move_file (dirent_ct *dc, const char *subdir)
{
    char ifdpath[PATHSZ];
    int remove_file = 0;
    int rc = 0;

    snprintf(ifdpath, sizeof(ifdpath), "%s/%s", arg_sourcedir, dc->de.d_name);

    if (PSTORE_STORAGE_ARCHIVE == arg_storage)
    {
        /* This code copies the file from the pstore to other storage.
       The rename() syscall is not utilized as it results in the
       Invalid cross-device link error.
       In addition, an optional subdirectory can be specified in
       forming the final destination path.
        */
        char ofdpath[PATHSZ];

        if (NULL != subdir)
        {
            snprintf(ofdpath, sizeof(ofdpath), "%s/%s/%s", arg_archivedir, subdir, dc->de.d_name);
        }
        else
        {
            snprintf(ofdpath, sizeof(ofdpath), "%s/%s", arg_archivedir, dc->de.d_name);
        }

        /* Make sure destination exists */
        rc = mkdir_parents(ofdpath, S_IRWXU|S_IRGRP|S_IXGRP|S_IROTH|S_IXOTH /*0755*/);
        if (0 == rc)
        {
            int ofd;

            ofd = open(ofdpath, O_CREAT|O_TRUNC|O_WRONLY, S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH/*0644*/);
            if (ofd < 0)
            {
                log_error("open(%s): %s\n", ofdpath, strerror(errno));
                rc = errno;
            }
            else
            {
                if (NULL != dc->contents)
                {
                    ssize_t wrc;
                    wrc = write(ofd, dc->contents, dc->statbuf.st_size);
                    // Detect write problem
                    if (wrc != dc->statbuf.st_size)
                    {
                        log_error("write(%s): %s\n", ofdpath, strerror(errno));
                        rc = errno;
                    }
                    else
                        remove_file = 1;
                }
            }
            close(ofd);
// FIX??? update ofd stat.time to same info as dc.stat.time?
        }
        else
        {
            log_error("mkdir_parents(): %s\n", strerror(errno));
            rc = errno;
        }
    }
    else
    if (PSTORE_STORAGE_JOURNAL == arg_storage)
    {
        //sd_journal_send("MESSAGE=%s", dc->de.d_name, NULL);
        if (dc->is_binary)
        {
            //WITH_BINARY= but how to know end of binary blob if contained in 0 terminated string?
        }
        else
        {
            rc = sd_journal_send("MESSAGE=File %s:\n%s", dc->de.d_name, dc->contents, NULL);
        }
        // NOTE: If journald not running, rc always 0
        remove_file = (0 == rc);
    }

    /* If file copied properly, remove it from pstore */
    if ((0 == rc) && remove_file && arg_allowunlink)
    {
        unlink(ifdpath);
    }

    return rc;
}

static void
write_dmesg (const char *dmesg, ssize_t size, const char *id)
{
    if ((NULL != dmesg) && (size > 0))
    {
        char ofdpath[PATHSZ];
        ssize_t wrc;
        int ofd;

        log_info("Record ID %s\n", id);

        if (NULL != id)
        {
            snprintf(ofdpath, sizeof(ofdpath), "%s/%s/dmesg.txt", arg_archivedir, id);
        }
        else
        {
            snprintf(ofdpath, sizeof(ofdpath), "%s/dmesg.txt", arg_archivedir);
        }

        ofd = open(ofdpath, O_CREAT|O_TRUNC|O_WRONLY, S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH/*0644*/);
        if (ofd < 0)
        {
            log_error("open(%s): %s\n", ofdpath, strerror(errno));
        }
        else
        {
            wrc = write(ofd, dmesg, size);
            if (wrc != size)
            {
                log_error("write(%s): %s\n", ofdpath, strerror(errno));
            }
        }
        close(ofd);
    }
}

/*
 * Pstore content rule handling
 */
typedef struct rules_s
{
    void (*handler)(struct rules_s *rule, dirent_ct *dc);
    const char *handlerName;
    const char *pattern;
} rules_t;
void dmesg_handler (struct rules_s *rule, dirent_ct *dc);
void move_handler (struct rules_s *rule, dirent_ct *dc);
rules_t rules[] =
{
    // from Linux/fs/pstore/inode.c
    // the %s is record->psi->name (eg efi, erst)
    // the %llu is record->id
    { dmesg_handler, "dmesg", "dmesg-*", },     // PSTORE_TYPE_DMESG: "dmesg-%s-%llu%s",
    { move_handler, "console", "console-*", },  // PSTORE_TYPE_CONSOLE: "console-%s-%llu",
    { move_handler, "pmsg", "pmsg-*", },        // PSTORE_TYPE_PMSG: "pmsg-%s-%llu",
    { move_handler, "ftrace", "ftrace-*", },    // PSTORE_TYPE_FTRACE: "ftrace-%s-%llu",
    { move_handler, "mce", "mce-*", },          // PSTORE_TYPE_MCE: "mce-%s-%llu",
    { move_handler, "ppcrtas", "rtas-*", },     // PSTORE_TYPE_PPC_RTAS: "rtas-%s-%llu",
    { move_handler, "ppcof", "powerpc-ofw-*", },// PSTORE_TYPE_PPC_OF: "powerpc-ofw-%s-%llu",
    { move_handler, "ppccommon", "powerpc-common-*", }, // PSTORE_TYPE_PPC_COMMON: "powerpc-common-%s-%llu",
    { move_handler, "ppcopal", "powerpc-opal-*", },     // PSTORE_TYPE_PPC_OPAL: "powerpc-opal-%s-%llu",
    { move_handler, "unknown", "unknown-*", },      // PSTORE_TYPE_UNKNOWN: "unknown-%s-%llu",
};

void
dmesg_handler (struct rules_s *rule, dirent_ct *dc)
{
    /* dmesg-* files recorded on this list */
    static dirent_ct *dmesgfiles = NULL;

    if (NULL != dc)
    {
        /* Collect the file for later processing */
        dc->is_binary = 0;
        append_dirent_to_list(&dmesgfiles, dc);
    }
    else
    {
        /* End of files, move files, reconstruct dmesg.txt */
        char *dmesg = NULL, *dmesg2;
        ssize_t dmesgsize = 0;
        char id1[PATHSZ], id2[PATHSZ], *id;
        char *currentid;
        char *p;

        if (NULL == dmesgfiles) return;

        id1[0] = id2[0] = '\0';
        id = id1;

        /* Sort in reverse order so as to be able to reconstruct dmesg */
        sort_files(&dmesgfiles, 0);

        /* Handle each file */
        FOR_EACH_DIRENT_IN_LIST(dmesgfiles, dc)
        {
            int move_file_and_continue = 0;

            if (endswith(dc->de.d_name, ".enc.z"))
                move_file_and_continue = 1;
            p = strrchr(dc->de.d_name, '-');
            if (NULL == p)
                move_file_and_continue = 1;

            if (move_file_and_continue)
            {
                // A dmesg file on which we do not do additional processing
                move_file(dc, NULL);
                continue;
            }

            /* See if this file is one of a related group of files
               in order to reconstruct dmesg */

            /* When dmesg is written into pstore, it is done so
            in small chunks, whatever the exchange buffer size is
            with the underlying pstore backend (ie. EFI may be ~2KiB),
            which means an example pstore with approximately 64KB of
            storage may have up to roughly 32 dmesg files that could be
            related, depending upon the size of the original dmesg.
            Here we look at the dmesg filename and try to discern if
            files are part of a related group, meaning the same original
            dmesg.
            The two known pstore backends are EFI and ERST. These backends
            store data in the Common Platform Error Record, CPER, format.
            The dmesg- filename contains the CPER record id, a 64bit number
            (in decimal notation). In Linux, the record id is encoded with
            two digits for the dmesg part (chunk) number and 3 digits for
            the count number. So allowing an additional digit to compensate
            for advancing time, this code ignores the last six digits of the
            filename in determining the record id.
            For the EFI backend, the record id encodes an id
            in the upper 32 bits, and a timestamp in the lower 32-bits.
            So ignoring the least significant 6 digits has proven to
            generally identify related dmesg entries.
            */
#define PSTORE_FILENAME_IGNORE 6

            /* extract common portion of record id */
            currentid = NULL;
            if (strlen(p) > PSTORE_FILENAME_IGNORE)
            {
                currentid = (id == id1) ? id2 : id1;
                strcpy(currentid, p+1);
                currentid[strlen(currentid) - PSTORE_FILENAME_IGNORE] = '\0';
            }

            /* Now move file from pstore to archive storage */
            move_file(dc, currentid);

            /* If the current record id is NOT the same as the
                previous record id, then start a new dmesg.txt file
            */
            if (0 != strcmp(currentid, id))
            {
                /* Encountered a new dmesg group, close out old one, open new one */
                if (NULL != dmesg)
                {
                    write_dmesg(dmesg, dmesgsize, id);
                    free(dmesg);
                    dmesg = NULL;
                    dmesgsize = 0;
                }

                /* Swap record id pointers */
                id[0] = '\0'; // invalidate previous record id
                id = (id == id1) ? id2 : id1; // make current id
            }

            /* Reconstruction of dmesg is done as a useful courtesy, do not log errors */
            dmesg2 = (char *)realloc(dmesg, dmesgsize + strlen(dc->de.d_name) + sizeof(":\n"));
            if (NULL != dmesg2)
            {
                dmesg = dmesg2;
                dmesgsize += sprintf(&dmesg[dmesgsize], "%s:\n", dc->de.d_name);
                dmesg2 = realloc(dmesg, dmesgsize + dc->statbuf.st_size);
                if (NULL != dmesg2)
                {
                    dmesg = dmesg2;
                    memcpy(&dmesg[dmesgsize], dc->contents, dc->statbuf.st_size);
                    dmesgsize += dc->statbuf.st_size;
                }
            }
        }
        if (NULL != dmesg)
        {
            write_dmesg(dmesg, dmesgsize, id);
            free(dmesg);
        }

        free_files(&dmesgfiles);
    }
}

void
move_handler (struct rules_s *rule, dirent_ct *dc)
{
    /* Simply move file out of pstore into archive storage */
    static dirent_ct *movefiles = NULL;

    if (NULL != dc)
    {
        append_dirent_to_list(&movefiles, dc);
    }
    else
    {
        // end of files
        FOR_EACH_DIRENT_IN_LIST(movefiles, dc)
        {
            move_file(dc, NULL);
        }
        free_files(&movefiles);
    }
}

static int
list_files (dirent_ct **list, const char *sourcepath)
{
    DIR *dirp;
    int rc = 0;

    errno = 0;
    dirp = opendir(sourcepath);
    if (NULL == dirp)
    {
        log_error("opendir(%s): %s\n", sourcepath, strerror(errno));
        rc = errno;
    }
    else
    {
        struct dirent *de;
        dirent_ct *dc;
        do
        {
            errno = 0;
            de = readdir(dirp);
            if ((NULL != de) && (NULL == startswith(de->d_name, ".")))
            {
                char pathname[PATHSZ];
                struct stat statbuf;

                snprintf(pathname, sizeof(pathname), "%s/%s", sourcepath, de->d_name);
                if (0 == lstat(pathname, &statbuf))
                {
                    if (NULL != (dc = (dirent_ct *)malloc(sizeof(dirent_ct))))
                    {
                        dc->de = *de;
                        dc->statbuf = statbuf;
                        dc->is_binary = 1;
                        append_dirent_to_list(list, dc);

                        /* Now read contents of pstore file */
                        dc->contents = (char *)malloc(dc->statbuf.st_size);
                        if (NULL != dc->contents)
                        {
                            int ifd;
                            ssize_t rrc;

                            ifd = open(pathname, O_RDONLY);
                            if (ifd < 0)
                            {
                                log_error("open(%s): %s\n", pathname, strerror(errno));
                            }
                            else
                            {
                                rrc = read(ifd, dc->contents, dc->statbuf.st_size);
                                if (rrc != dc->statbuf.st_size)
                                {
                                    log_error("read(%s, %ld) only returned %ld bytes\n", pathname, dc->statbuf.st_size, rrc);
// FIX??? do we keep partial bytes or throw all away?
                                }
                            }
                        }
                        else
                        {
                            log_error("malloc(%s, %ld): failed\n", pathname, dc->statbuf.st_size);
                        }
                    }
                    else
                    {
                        log_error("malloc() failed: out of memory!\n");
                    }
                }
                else
                {
                    log_error("lstat(%s): %s\n", pathname, strerror(errno));
                    rc = errno;
                    break;
                }
            }
            else
            {
                if (errno)
                {
                    log_error("readdir(): %s\n", strerror(errno));
                    rc = errno;
                    break;
                }
                /* else end of dir */
            }
        } while (NULL != de);
    }
    return rc;
}

static int
run (int argc, char *argv[])
{
    unsigned i;
    int process_pstore = 0;
    int rc = 0;
    dirent_ct *fileList = NULL;

    log_open();

    /* Ignore all parse errors */
    (void) parse_config();

    log_debug("Selected storage '%s'.", pstore_storage_to_string(arg_storage));
    log_debug("Selected SourceDir '%s'.", arg_sourcedir);
    log_debug("Selected ArchiveDir '%s'.", arg_archivedir);
    log_debug("Selected AllowUnlink '%d'.", arg_allowunlink);

    if (PSTORE_STORAGE_NONE == arg_storage)
    {
        // Do nothing, intentionally, leaving pstore untouched
        process_pstore = 0;
    }
    else
    {
        process_pstore = 1;
        /* Obtain list of files in pstore */
        rc = list_files(&fileList, arg_sourcedir);
    }

    /* Process pstore contents, if no errors in reading pstore */
    if ((0 == rc) && process_pstore)
    {
        for (i = 0; i < ARRAY_SIZE(rules); ++i)
        {
            struct rules_s *rule = &rules[i];
            int last_file = 0;
            while (!last_file)
            {
                dirent_ct *dc;
                int handle = 0;
                FOR_EACH_DIRENT_IN_LIST(fileList, dc)
                {
                    char pattern[PATHSZ];
                    int plen = strlen(rule->pattern);
                    int starts = (rule->pattern[plen-1] == '*');
                    int ends = (rule->pattern[0] == '*');

                    handle = 0;
                    last_file = END_OF_DIRENT_LIST(fileList, dc);

                    if (starts)
                    {
                        strncpy(pattern, &rule->pattern[0], plen-1);
                        pattern[plen-1] = '\0';
                        handle |= (NULL != startswith(dc->de.d_name, pattern));
                    }
                    if (ends)
                    {
                        strncpy(pattern, &rule->pattern[1], plen-1);
                        pattern[plen-1] = '\0';
                        handle |= (NULL != endswith(dc->de.d_name, pattern));
                    }
                    if (handle)
                    {
                        /* handler will now own dc */
                        remove_dirent_from_list(&fileList, dc);
                        rule->handler(rule, dc);
                        break; // re-start loop, since just modified the list
                    }
                    // else we leave unknown file alone...
                }
                if (!handle) last_file = 1;
            }
            /* Signal end of files for rule */
            rule->handler(rule, NULL);
        }
        free_files(&fileList);
    }

    return rc;
}

DEFINE_MAIN_FUNCTION(run);
