/*
 * malloc.h
 *
 * Internals for the memory allocator
 */

#include <stdint.h>
#include <stddef.h>

/*
 * This is the minimum chunk size we will ask the kernel for; this should
 * be a multiple of the page size on all architectures.
 */
#define MALLOC_CHUNK_SIZE	65536
#define MALLOC_CHUNK_MASK       (MALLOC_CHUNK_SIZE-1)

/*
 * This structure should be a power of two.  This becomes the
 * alignment unit.
 */
struct free_arena_header;

struct arena_header {
  size_t type;
  size_t size;			/* Also gives the location of the next entry */
  struct free_arena_header *next, *prev;
};

#ifdef DEBUG_MALLOC
#define ARENA_TYPE_USED 0x64e69c70
#define ARENA_TYPE_FREE 0x012d610a
#define ARENA_TYPE_HEAD 0x971676b5
#define ARENA_TYPE_DEAD 0xeeeeeeee
#else
#define ARENA_TYPE_USED 0
#define ARENA_TYPE_FREE 1
#define ARENA_TYPE_HEAD 2
#endif

#define ARENA_SIZE_MASK (~(sizeof(struct arena_header)-1))

/*
 * This structure should be no more than twice the size of the
 * previous structure.
 */
struct free_arena_header {
  struct arena_header a;
  struct free_arena_header *next_free, *prev_free;
};

extern struct free_arena_header __malloc_head;
