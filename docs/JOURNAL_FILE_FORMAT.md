---
title: Journal File Format
category: Interfaces
layout: default
SPDX-License-Identifier: LGPL-2.1-or-later
---

# Journal File Format

_Note that this document describes the binary on-disk format of journals only.
For interfacing with web technologies there's the [Journal JSON Format](JOURNAL_EXPORT_FORMATS#journal-json-format).
For transfer of journal data across the network there's the
[Journal Export Format](JOURNAL_EXPORT_FORMATS#journal-export-format)._

The systemd journal stores log data in a binary format with several features:

* Fully indexed by all fields
* Can store binary data, up to 2^64-1 in size
* Seekable
* Primarily append-based, hence robust to corruption
* Support for in-line compression
* Support for in-line Forward Secure Sealing

This document explains the basic structure of the file format on disk.
We are making this available primarily to allow review and provide documentation.
Note that the actual implementation in the
[systemd codebase](https://github.com/systemd/systemd/blob/main/src/libsystemd/sd-journal/)
is the only ultimately authoritative description of the format,
so if this document and the code disagree, the code is right.
That said we'll of course try hard to keep this document up-to-date and accurate.

Instead of implementing your own reader or writer for journal files we ask you to use the
[Journal's native CAPI](https://www.freedesktop.org/software/systemd/man/sd-journal.html)
to access these files.
It provides you with full access to the files, and will not withhold any data.
If you find a limitation, please ping us and we might add some additional interfaces for you.

If you need access to the raw journal data in serialized stream form without C API our recommendation is to make use of the
[Journal Export Format](JOURNAL_EXPORT_FORMATS#journal-export-format),
which you can get via `journalctl -o export` or via `systemd-journal-gatewayd`.
The export format is much simpler to parse, but complete and accurate.
Due to its stream-based nature it is not indexed.

_Or, to put this in other words: this low-level document is probably not what you want to use as base of your project.
You want our [C API](https://www.freedesktop.org/software/systemd/man/sd-journal.html) instead!
And if you really don't want the C API, then you want the
[Journal Export Format or Journal JSON Format](/JOURNAL_EXPORT_FORMATS) instead!
This document is primarily for your entertainment and education.
Thank you!_

This document assumes you have a basic understanding of the journal concepts, the properties of a journal entry and so on.
If not, please go and read up, then come back!
This is a good opportunity to read about the
[basic properties of journal entries](https://www.freedesktop.org/software/systemd/man/systemd.journal-fields.html),
in particular realize that they may include binary non-text data (though usually don't),
and the same field might have multiple values assigned within the same entry.

This document describes the current format of systemd 246.
The documented format is compatible with the format used in the first versions of the journal,
but received various compatible and incompatible additions since.

If you are wondering why the journal file format has been created in the first place instead of adopting an existing database implementation,
please have a look [at this thread](https://lists.freedesktop.org/archives/systemd-devel/2012-October/007054.html).


## Basics

* All offsets, sizes, time values, hashes (and most other numeric values) are 32-bit/64-bit unsigned integers in LE format.
* Offsets are always relative to the beginning of the file.
* The 64-bit hash function siphash24 is used for newer journal files.
  For older files [Jenkins lookup3](https://en.wikipedia.org/wiki/Jenkins_hash_function) is used,
  more specifically `jenkins_hashlittle2()` with the first 32-bit integer it returns as higher 32-bit part of the 64-bit value,
  and the second one uses as lower 32-bit part.
* All structures are aligned to 64-bit boundaries and padded to multiples of 64-bit
* The format is designed to be read and written via memory mapping using multiple mapped windows.
* All time values are stored in usec since the respective epoch.
* Wall clock time values are relative to the Unix time epoch, i.e. January 1st, 1970. (`CLOCK_REALTIME`)
* Monotonic time values are always stored jointly with the kernel boot ID value (i.e. `/proc/sys/kernel/random/boot_id`) they belong to.
  They tend to be relative to the start of the boot, but aren't for containers. (`CLOCK_MONOTONIC`)
* Randomized, unique 128-bit IDs are used in various locations. These are generally UUID v4 compatible, but this is not a requirement.

## General Rules

If any kind of corruption is noticed by a writer it should immediately rotate
the file and start a new one. No further writes should be attempted to the
original file, but it should be left around so that as little data as possible
is lost.

If any kind of corruption is noticed by a reader it should try hard to handle
this gracefully, such as skipping over the corrupted data, but allowing access
to as much data around it as possible.

A reader should verify all offsets and other data as it reads it. This includes
checking for alignment and range of offsets in the file, especially before
trying to read it via a memory map.

A reader must interleave rotated and corrupted files as good as possible and
present them as single stream to the user.

All fields marked as "reserved" must be initialized with 0 when writing and be
ignored on reading. They are currently not used but might be used later on.


## Structure

The file format's data structures are declared in
[journal-def.h](https://github.com/systemd/systemd/blob/main/src/libsystemd/sd-journal/journal-def.h).

The file format begins with a header structure. After the header structure
object structures follow. Objects are appended to the end as time
progresses. Most data stored in these objects is not altered anymore after
having been written once, with the exception of records necessary for
indexing. When new data is appended to a file the writer first writes all new
objects to the end of the file, and then links them up at front after that's
done. Currently, seven different object types are known:

```c
enum {
        OBJECT_UNUSED,
        OBJECT_DATA,
        OBJECT_FIELD,
        OBJECT_ENTRY,
        OBJECT_DATA_HASH_TABLE,
        OBJECT_FIELD_HASH_TABLE,
        OBJECT_ENTRY_ARRAY,
        OBJECT_TAG,
        _OBJECT_TYPE_MAX
};
```

* A **DATA** object, which encapsulates the contents of one field of an entry, i.e. a string such as `_SYSTEMD_UNIT=avahi-daemon.service`, or `MESSAGE=Foobar made a booboo.` but possibly including large or binary data, and always prefixed by the field name and "=".
* A **FIELD** object, which encapsulates a field name, i.e. a string such as `_SYSTEMD_UNIT` or `MESSAGE`, without any `=` or even value.
* An **ENTRY** object, which binds several **DATA** objects together into a log entry.
* A **DATA_HASH_TABLE** object, which encapsulates a hash table for finding existing **DATA** objects.
* A **FIELD_HASH_TABLE** object, which encapsulates a hash table for finding existing **FIELD** objects.
* An **ENTRY_ARRAY** object, which encapsulates a sorted array of offsets to entries, used for seeking by binary search.
* A **TAG** object, consisting of an FSS sealing tag for all data from the beginning of the file or the last tag written (whichever is later).

## Header

The Header struct defines, well, you guessed it, the file header:

```c
_packed_ struct Header {
        uint8_t signature[8]; /* "LPKSHHRH" */
        le32_t compatible_flags;
        le32_t incompatible_flags;
        uint8_t state;
        uint8_t reserved[7];
        sd_id128_t file_id;
        sd_id128_t machine_id;
        sd_id128_t tail_entry_boot_id;
        sd_id128_t seqnum_id;
        le64_t header_size;
        le64_t arena_size;
        le64_t data_hash_table_offset;
        le64_t data_hash_table_size;
        le64_t field_hash_table_offset;
        le64_t field_hash_table_size;
        le64_t tail_object_offset;
        le64_t n_objects;
        le64_t n_entries;
        le64_t tail_entry_seqnum;
        le64_t head_entry_seqnum;
        le64_t entry_array_offset;
        le64_t head_entry_realtime;
        le64_t tail_entry_realtime;
        le64_t tail_entry_monotonic;
        /* Added in 187 */
        le64_t n_data;
        le64_t n_fields;
        /* Added in 189 */
        le64_t n_tags;
        le64_t n_entry_arrays;
        /* Added in 246 */
        le64_t data_hash_chain_depth;
        le64_t field_hash_chain_depth;
        /* Added in 252 */
        le32_t tail_entry_array_offset;
        le32_t tail_entry_array_n_entries;
        /* Added in 254 */
        le64_t tail_entry_offset;
};
```

The first 8 bytes of Journal files must contain the ASCII characters `LPKSHHRH`.

If a writer finds that the **machine_id** of a file to write to does not match
the machine it is running on it should immediately rotate the file and start a
new one.

When journal file is first created the **file_id** is randomly and uniquely
initialized.

When a writer creates a file it shall initialize the **tail_entry_boot_id** to
the current boot ID of the system. When appending an entry it shall update the
field to the boot ID of that entry, so that it is guaranteed that the
**tail_entry_monotonic** field refers to a timestamp of the monotonic clock
associated with the boot with the ID indicated by the **tail_entry_boot_id**
field. (Compatibility note: in older versions of the journal, the field was
also supposed to be updated whenever the file was opened for any form of
writing, including when opened to mark it as archived. This behaviour has been
deemed problematic since without an associated boot ID the
**tail_entry_monotonic** field is useless. To indicate whether the boot ID is
updated only on append the JOURNAL_COMPATIBLE_TAIL_ENTRY_BOOT_ID is set. If it
is not set, the **tail_entry_monotonic** field is not usable).

The currently used part of the file is the **header_size** plus the
**arena_size** field of the header. If a writer needs to write to a file where
the actual file size on disk is smaller than the reported value it shall
immediately rotate the file and start a new one. If a writer is asked to write
to a file with a header that is shorter than its own definition of the struct
Header, it shall immediately rotate the file and start a new one.

The **n_objects** field contains a counter for objects currently available in
this file. As objects are appended to the end of the file this counter is
increased.

The first object in the file starts immediately after the header. The last
object in the file is at the offset **tail_object_offset**, which may be 0 if
no object is in the file yet.

The **n_entries**, **n_data**, **n_fields**, **n_tags**, **n_entry_arrays** are
counters of the objects of the specific types.

**tail_entry_seqnum** and **head_entry_seqnum** contain the sequential number
(see below) of the last or first entry in the file, respectively, or 0 if no
entry has been written yet.

**tail_entry_realtime** and **head_entry_realtime** contain the wallclock
timestamp of the last or first entry in the file, respectively, or 0 if no
entry has been written yet.

**tail_entry_monotonic** is the monotonic timestamp of the last entry in the
file, referring to monotonic time of the boot identified by
**tail_entry_boot_id**, but only if the
JOURNAL_COMPATIBLE_TAIL_ENTRY_BOOT_ID feature flag is set, see above. If it
is not set, this field might refer to a different boot then the one in the
**tail_entry_boot_id** field, for example when the file was ultimately
archived.

**data_hash_chain_depth** is a counter of the deepest chain in the data hash
table, minus one. This is updated whenever a chain is found that is longer than
the previous deepest chain found. Note that the counter is updated during hash
table lookups, as the chains are traversed. This counter is used to determine
when it is a good time to rotate the journal file, because hash collisions
became too frequent.

Similar, **field_hash_chain_depth** is a counter of the deepest chain in the
field hash table, minus one.

**tail_entry_array_offset** and **tail_entry_array_n_entries** allow immediate
access to the last entry array in the global entry array chain.

**tail_entry_offset** allow immediate access to the last entry in the journal
file.

## Extensibility

The format is supposed to be extensible in order to enable future additions of
features. Readers should simply skip objects of unknown types as they read
them. If a compatible feature extension is made a new bit is registered in the
header's **compatible_flags** field. If a feature extension is used that makes
the format incompatible a new bit is registered in the header's
**incompatible_flags** field. Readers should check these two bit fields, if
they find a flag they don't understand in compatible_flags they should continue
to read the file, but if they find one in **incompatible_flags** they should
fail, asking for an update of the software. Writers should refuse writing if
there's an unknown bit flag in either of these fields.

The file header may be extended as new features are added. The size of the file
header is stored in the header. All header fields up to **n_data** are known to
unconditionally exist in all revisions of the file format, all fields starting
with **n_data** needs to be explicitly checked for via a size check, since they
were additions after the initial release.

Currently only five extensions flagged in the flags fields are known:

```c
enum {
        HEADER_INCOMPATIBLE_COMPRESSED_XZ   = 1 << 0,
        HEADER_INCOMPATIBLE_COMPRESSED_LZ4  = 1 << 1,
        HEADER_INCOMPATIBLE_KEYED_HASH      = 1 << 2,
        HEADER_INCOMPATIBLE_COMPRESSED_ZSTD = 1 << 3,
        HEADER_INCOMPATIBLE_COMPACT         = 1 << 4,
};

enum {
        HEADER_COMPATIBLE_SEALED             = 1 << 0,
        HEADER_COMPATIBLE_TAIL_ENTRY_BOOT_ID = 1 << 1,
};
```

HEADER_INCOMPATIBLE_COMPRESSED_XZ indicates that the file includes DATA objects
that are compressed using XZ. Similarly, HEADER_INCOMPATIBLE_COMPRESSED_LZ4
indicates that the file includes DATA objects that are compressed with the LZ4
algorithm. And HEADER_INCOMPATIBLE_COMPRESSED_ZSTD indicates that there are
objects compressed with ZSTD.

HEADER_INCOMPATIBLE_KEYED_HASH indicates that instead of the unkeyed Jenkins
hash function the keyed siphash24 hash function is used for the two hash
tables, see below.

HEADER_INCOMPATIBLE_COMPACT indicates that the journal file uses the new binary
format that uses less space on disk compared to the original format.

HEADER_COMPATIBLE_SEALED indicates that the file includes TAG objects required
for Forward Secure Sealing.

HEADER_COMPATIBLE_TAIL_ENTRY_BOOT_ID indicates whether the
**tail_entry_boot_id** field is strictly updated on initial creation of the
file and whenever an entry is updated (in which case the flag is set), or also
when the file is archived (in which case it is unset). New files should always
set this flag (and thus not update the **tail_entry_boot_id** except when
creating the file and when appending an entry to it.

## Dirty Detection

```c
enum {
        STATE_OFFLINE = 0,
        STATE_ONLINE = 1,
        STATE_ARCHIVED = 2,
        _STATE_MAX
};
```

If a file is opened for writing the **state** field should be set to
STATE_ONLINE. If a file is closed after writing the **state** field should be
set to STATE_OFFLINE. After a file has been rotated it should be set to
STATE_ARCHIVED. If a writer is asked to write to a file that is not in
STATE_OFFLINE it should immediately rotate the file and start a new one,
without changing the file.

After and before the state field is changed, `fdatasync()` should be executed on
the file to ensure the dirty state hits disk.


## Sequence Numbers

All entries carry sequence numbers that are monotonically counted up for each
entry (starting at 1) and are unique among all files which carry the same
**seqnum_id** field. This field is randomly generated when the journal daemon
creates its first file. All files generated by the same journal daemon instance
should hence carry the same seqnum_id. This should guarantee a monotonic stream
of sequential numbers for easy interleaving even if entries are distributed
among several files, such as the system journal and many per-user journals.


## Concurrency

The file format is designed to be usable in a simultaneous
single-writer/multiple-reader scenario. The synchronization model is very weak
in order to facilitate storage on the most basic of file systems (well, the
most basic ones that provide us with `mmap()` that is), and allow good
performance. No file locking is used. The only time where disk synchronization
via `fdatasync()` should be enforced is after and before changing the **state**
field in the file header (see below). It is recommended to execute a memory
barrier after appending and initializing new objects at the end of the file,
and before linking them up in the earlier objects.

This weak synchronization model means that it is crucial that readers verify
the structural integrity of the file as they read it and handle invalid
structure gracefully. (Checking what you read is a pretty good idea out of
security considerations anyway.) This specifically includes checking offset
values, and that they point to valid objects, with valid sizes and of the type
and hash value expected. All code must be written with the fact in mind that a
file with inconsistent structure might just be inconsistent temporarily, and
might become consistent later on. Payload OTOH requires less scrutiny, as it
should only be linked up (and hence visible to readers) after it was
successfully written to memory (though not necessarily to disk). On non-local
file systems it is a good idea to verify the payload hashes when reading, in
order to avoid annoyances with `mmap()` inconsistencies.

Clients intending to show a live view of the journal should use `inotify()` for
this to watch for files changes. Since file writes done via `mmap()` do not
result in `inotify()` writers shall truncate the file to its current size after
writing one or more entries, which results in inotify events being
generated. Note that this is not used as a transaction scheme (it doesn't
protect anything), but merely for triggering wakeups.

Note that inotify will not work on network file systems if reader and writer
reside on different hosts. Readers which detect they are run on journal files
on a non-local file system should hence not rely on inotify for live views but
fall back to simple time based polling of the files (maybe recheck every 2s).


## Objects

All objects carry a common header:

```c
enum {
        OBJECT_COMPRESSED_XZ   = 1 << 0,
        OBJECT_COMPRESSED_LZ4  = 1 << 1,
        OBJECT_COMPRESSED_ZSTD = 1 << 2,
};

_packed_ struct ObjectHeader {
        uint8_t type;
        uint8_t flags;
        uint8_t reserved[6];
        le64_t size;
        uint8_t payload[];
};
```

The **type** field is one of the object types listed above. The **flags** field
currently knows three flags: OBJECT_COMPRESSED_XZ, OBJECT_COMPRESSED_LZ4 and
OBJECT_COMPRESSED_ZSTD. It is only valid for DATA objects and indicates that
the data payload is compressed with XZ/LZ4/ZSTD. If one of the
OBJECT_COMPRESSED_* flags is set for an object then the matching
HEADER_INCOMPATIBLE_COMPRESSED_XZ/HEADER_INCOMPATIBLE_COMPRESSED_LZ4/HEADER_INCOMPATIBLE_COMPRESSED_ZSTD
flag must be set for the file as well. At most one of these three bits may be
set. The **size** field encodes the size of the object including all its
headers and payload.


## Data Objects

```c
_packed_ struct DataObject {
        ObjectHeader object;
        le64_t hash;
        le64_t next_hash_offset;
        le64_t next_field_offset;
        le64_t entry_offset; /* the first array entry we store inline */
        le64_t entry_array_offset;
        le64_t n_entries;
        union {                                                         \
                struct {                                                \
                        uint8_t payload[] ;                             \
                } regular;                                              \
                struct {                                                \
                        le32_t tail_entry_array_offset;                 \
                        le32_t tail_entry_array_n_entries;              \
                        uint8_t payload[];                              \
                } compact;                                              \
        };                                                              \
};
```

Data objects carry actual field data in the **payload[]** array, including a
field name, a `=` and the field data. Example:
`_SYSTEMD_UNIT=foobar.service`. The **hash** field is a hash value of the
payload. If the `HEADER_INCOMPATIBLE_KEYED_HASH` flag is set in the file header
this is the siphash24 hash value of the payload, keyed by the file ID as stored
in the **file_id** field of the file header. If the flag is not set it is the
non-keyed Jenkins hash of the payload instead. The keyed hash is preferred as
it makes the format more robust against attackers that want to trigger hash
collisions in the hash table.

**next_hash_offset** is used to link up DATA objects in the DATA_HASH_TABLE if
a hash collision happens (in a singly linked list, with an offset of 0
indicating the end). **next_field_offset** is used to link up data objects with
the same field name from the FIELD object of the field used.

**entry_offset** is an offset to the first ENTRY object referring to this DATA
object. **entry_array_offset** is an offset to an ENTRY_ARRAY object with
offsets to other entries referencing this DATA object. Storing the offset to
the first ENTRY object in-line is an optimization given that many DATA objects
will be referenced from a single entry only (for example, `MESSAGE=` frequently
includes a practically unique string). **n_entries** is a counter of the total
number of ENTRY objects that reference this object, i.e. the sum of all
ENTRY_ARRAYS chained up from this object, plus 1.

The **payload[]** field contains the field name and date unencoded, unless
OBJECT_COMPRESSED_XZ/OBJECT_COMPRESSED_LZ4/OBJECT_COMPRESSED_ZSTD is set in the
`ObjectHeader`, in which case the payload is compressed with the indicated
compression algorithm.

If the `HEADER_INCOMPATIBLE_COMPACT` flag is set, Two extra fields are stored to
allow immediate access to the tail entry array in the DATA object's entry array
chain.

## Field Objects

```c
_packed_ struct FieldObject {
        ObjectHeader object;
        le64_t hash;
        le64_t next_hash_offset;
        le64_t head_data_offset;
        uint8_t payload[];
};
```

Field objects are used to enumerate all possible values a certain field name
can take in the entire journal file.

The **payload[]** array contains the actual field name, without '=' or any
field value. Example: `_SYSTEMD_UNIT`. The **hash** field is a hash value of
the payload. As for the DATA objects, this too is either the `.file_id` keyed
siphash24 hash of the payload, or the non-keyed Jenkins hash.

**next_hash_offset** is used to link up FIELD objects in the FIELD_HASH_TABLE
if a hash collision happens (in singly linked list, offset 0 indicating the
end). **head_data_offset** points to the first DATA object that shares this
field name. It is the head of a singly linked list using DATA's
**next_field_offset** offset.


## Entry Objects

```
_packed_ struct EntryObject {
        ObjectHeader object;
        le64_t seqnum;
        le64_t realtime;
        le64_t monotonic;
        sd_id128_t boot_id;
        le64_t xor_hash;
        union {                                 \
                struct {                        \
                        le64_t object_offset;   \
                        le64_t hash;            \
                } regular[];                    \
                struct {                        \
                        le32_t object_offset;   \
                } compact[];                    \
        } items;                                \
};
```

An ENTRY object binds several DATA objects together into one log entry, and
includes other metadata such as various timestamps.

The **seqnum** field contains the sequence number of the entry, **realtime**
the realtime timestamp, and **monotonic** the monotonic timestamp for the boot
identified by **boot_id**.

The **xor_hash** field contains a binary XOR of the hashes of the payload of
all DATA objects referenced by this ENTRY. This value is usable to check the
contents of the entry, being independent of the order of the DATA objects in
the array. Note that even for files that have the
`HEADER_INCOMPATIBLE_KEYED_HASH` flag set (and thus siphash24 the otherwise
used hash function) the hash function used for this field, as singular
exception, is the Jenkins lookup3 hash function. The XOR hash value is used to
quickly compare the contents of two entries, and to define a well-defined order
between two entries that otherwise have the same sequence numbers and
timestamps.

The **items[]** array contains references to all DATA objects of this entry,
plus their respective hashes (which are calculated the same way as in the DATA
objects, i.e. keyed by the file ID).

If the `HEADER_INCOMPATIBLE_COMPACT` flag is set, DATA object offsets are stored
as 32-bit integers instead of 64-bit and the unused hash field per data object is
not stored anymore.

In the file ENTRY objects are written ordered monotonically by sequence
number. For continuous parts of the file written during the same boot
(i.e. with the same boot_id) the monotonic timestamp is monotonic too. Modulo
wallclock time jumps (due to incorrect clocks being corrected) the realtime
timestamps are monotonic too.


## Hash Table Objects

```c
_packed_ struct HashItem {
        le64_t head_hash_offset;
        le64_t tail_hash_offset;
};

_packed_ struct HashTableObject {
        ObjectHeader object;
        HashItem items[];
};
```

The structure of both DATA_HASH_TABLE and FIELD_HASH_TABLE objects are
identical. They implement a simple hash table, with each cell containing
offsets to the head and tail of the singly linked list of the DATA and FIELD
objects, respectively. DATA's and FIELD's next_hash_offset field are used to
chain up the objects. Empty cells have both offsets set to 0.

Each file contains exactly one DATA_HASH_TABLE and one FIELD_HASH_TABLE
objects. Their payload is directly referred to by the file header in the
**data_hash_table_offset**, **data_hash_table_size**,
**field_hash_table_offset**, **field_hash_table_size** fields. These offsets do
_not_ point to the object headers but directly to the payloads. When a new
journal file is created the two hash table objects need to be created right
away as first two objects in the stream.

If the hash table fill level is increasing over a certain fill level (Learning
from Java's Hashtable for example: > 75%), the writer should rotate the file
and create a new one.

The DATA_HASH_TABLE should be sized taking into account to the maximum size the
file is expected to grow, as configured by the administrator or disk space
considerations. The FIELD_HASH_TABLE should be sized to a fixed size; the
number of fields should be pretty static as it depends only on developers'
creativity rather than runtime parameters.


## Entry Array Objects


```c
_packed_ struct EntryArrayObject {
        ObjectHeader object;
        le64_t next_entry_array_offset;
        union {
                le64_t regular[];
                le32_t compact[];
        } items;
};
```

Entry Arrays are used to store a sorted array of offsets to entries. Entry
arrays are strictly sorted by offsets on disk, and hence by their timestamps
and sequence numbers (with some restrictions, see above).

If the `HEADER_INCOMPATIBLE_COMPACT` flag is set, offsets are stored as 32-bit
integers instead of 64-bit.

Entry Arrays are chained up. If one entry array is full another one is
allocated and the **next_entry_array_offset** field of the old one pointed to
it. An Entry Array with **next_entry_array_offset** set to 0 is the last in the
list. To optimize allocation and seeking, as entry arrays are appended to a
chain of entry arrays they should increase in size (double).

Due to being monotonically ordered entry arrays may be searched with a binary
search (bisection).

One chain of entry arrays links up all entries written to the journal. The
first entry array is referenced in the **entry_array_offset** field of the
header.

Each DATA object also references an entry array chain listing all entries
referencing a specific DATA object. Since many DATA objects are only referenced
by a single ENTRY the first offset of the list is stored inside the DATA object
itself, an ENTRY_ARRAY object is only needed if it is referenced by more than
one ENTRY.


## Tag Object

```c
#define TAG_LENGTH (256/8)

_packed_ struct TagObject {
        ObjectHeader object;
        le64_t seqnum;
        le64_t epoch;
        uint8_t tag[TAG_LENGTH]; /* SHA-256 HMAC */
};
```

Tag objects are used to seal off the journal for alteration. In regular
intervals a tag object is appended to the file. The tag object consists of a
SHA-256 HMAC tag that is calculated from the objects stored in the file since
the last tag was written, or from the beginning if no tag was written yet. The
key for the HMAC is calculated via the externally maintained FSPRG logic for
the epoch that is written into **epoch**. The sequence number **seqnum** is
increased with each tag. When calculating the HMAC of objects header fields
that are volatile are excluded (skipped). More specifically all fields that
might validly be altered to maintain a consistent file structure (such as
offsets to objects added later for the purpose of linked lists and suchlike)
after an object has been written are not protected by the tag. This means a
verifier has to independently check these fields for consistency of
structure. For the fields excluded from the HMAC please consult the source code
directly. A verifier should read the file from the beginning to the end, always
calculating the HMAC for the objects it reads. Each time a tag object is
encountered the HMAC should be verified and restarted. The tag object sequence
numbers need to increase strictly monotonically. Tag objects themselves are
partially protected by the HMAC (i.e. seqnum and epoch is included, the tag
itself not).


## Algorithms

### Reading

Given an offset to an entry all data fields are easily found by following the
offsets in the data item array of the entry.

Listing entries without filter is done by traversing the list of entry arrays
starting with the headers' **entry_array_offset** field.

Seeking to an entry by timestamp or sequence number (without any matches) is
done via binary search in the entry arrays starting with the header's
**entry_array_offset** field. Since these arrays double in size as more are
added the time cost of seeking is O(log(n)*log(n)) if n is the number of
entries in the file.

When seeking or listing with one field match applied the DATA object of the
match is first identified, and then its data entry array chain traversed. The
time cost is the same as for seeks/listings with no match.

If multiple matches are applied, multiple chains of entry arrays should be
traversed in parallel. Since they all are strictly monotonically ordered by
offset of the entries, advancing in one can be directly applied to the others,
until an entry matching all matches is found. In the worst case seeking like
this is O(n) where n is the number of matching entries of the "loosest" match,
but in the common case should be much more efficient at least for the
well-known fields, where the set of possible field values tend to be closely
related. Checking whether an entry matches a number of matches is efficient
since the item array of the entry contains hashes of all data fields
referenced, and the number of data fields of an entry is generally small (<
30).

When interleaving multiple journal files seeking tends to be a frequently used
operation, but in this case can be effectively suppressed by caching results
from previous entries.

When listing all possible values a certain field can take it is sufficient to
look up the FIELD object and follow the chain of links to all DATA it includes.

### Writing

When an entry is appended to the journal, for each of its data fields the data
hash table should be checked. If the data field does not yet exist in the file,
it should be appended and added to the data hash table. When a data field's data
object is added, the field hash table should be checked for the field name of
the data field, and a field object be added if necessary. After all data fields
(and recursively all field names) of the new entry are appended and linked up
in the hashtables, the entry object should be appended and linked up too.

At regular intervals a tag object should be written if sealing is enabled (see
above). Before the file is closed a tag should be written too, to seal it off.

Before writing an object, time and disk space limits should be checked and
rotation triggered if necessary.


## Optimizing Disk IO

_A few general ideas to keep in mind:_

The hash tables for looking up fields and data should be quickly in the memory
cache and not hurt performance. All entries and entry arrays are ordered
strictly by time on disk, and hence should expose an OK access pattern on
rotating media, when read sequentially (which should be the most common case,
given the nature of log data).

The disk access patterns of the binary search for entries needed for seeking
are problematic on rotating disks. This should not be a major issue though,
since seeking should not be a frequent operation.

When reading, collecting data fields for presenting entries to the user is
problematic on rotating disks. In order to optimize these patterns the item
array of entry objects should be sorted by disk offset before
writing. Effectively, frequently used data objects should be in the memory
cache quickly. Non-frequently used data objects are likely to be located
between the previous and current entry when reading and hence should expose an
OK access pattern. Problematic are data objects that are neither frequently nor
infrequently referenced, which will cost seek time.

And that's all there is to it.

Thanks for your interest!
