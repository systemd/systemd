/*
 * malloc.c
 *
 * Very simple linked-list based malloc()/free().
 */

#include <stdlib.h>
#include <sys/mman.h>
#include "malloc.h"

struct free_arena_header __malloc_head =
{
  {
    ARENA_TYPE_HEAD,
    0,
    &__malloc_head,
    &__malloc_head,
  },
  &__malloc_head,
  &__malloc_head
};

static void *__malloc_from_block(struct free_arena_header *fp, size_t size)
{
  size_t fsize;
  struct free_arena_header *nfp, *na;

  fsize = fp->a.size;
  
  /* We need the 2* to account for the larger requirements of a free block */
  if ( fsize >= size+2*sizeof(struct arena_header) ) {
    /* Bigger block than required -- split block */
    nfp = (struct free_arena_header *)((char *)fp + size);
    na = fp->a.next;

    nfp->a.type = ARENA_TYPE_FREE;
    nfp->a.size = fsize-size;
    fp->a.type  = ARENA_TYPE_USED;
    fp->a.size  = size;

    /* Insert into all-block chain */
    nfp->a.prev = fp;
    nfp->a.next = na;
    na->a.prev = nfp;
    fp->a.next = nfp;
    
    /* Replace current block on free chain */
    nfp->next_free = fp->next_free;
    nfp->prev_free = fp->prev_free;
    fp->next_free->prev_free = nfp;
    fp->prev_free->next_free = nfp;
  } else {
    /* Allocate the whole block */
    fp->a.type = ARENA_TYPE_USED;

    /* Remove from free chain */
    fp->next_free->prev_free = fp->prev_free;
    fp->prev_free->next_free = fp->next_free;
  }
  
  return (void *)(&fp->a + 1);
}

static struct free_arena_header *
__free_block(struct free_arena_header *ah)
{
  struct free_arena_header *pah, *nah;

  pah = ah->a.prev;
  nah = ah->a.next;
  if ( pah->a.type == ARENA_TYPE_FREE &&
       (char *)pah+pah->a.size == (char *)ah ) {
    /* Coalesce into the previous block */
    pah->a.size += ah->a.size;
    pah->a.next = nah;
    nah->a.prev = pah;

#ifdef DEBUG_MALLOC
    ah->a.type = ARENA_TYPE_DEAD;
#endif

    ah = pah;
    pah = ah->a.prev;
  } else {
    /* Need to add this block to the free chain */
    ah->a.type = ARENA_TYPE_FREE;

    ah->next_free = __malloc_head.next_free;
    ah->prev_free = &__malloc_head;
    __malloc_head.next_free = ah;
    ah->next_free->prev_free = ah;
  }

  /* In either of the previous cases, we might be able to merge
     with the subsequent block... */
  if ( nah->a.type == ARENA_TYPE_FREE &&
       (char *)ah+ah->a.size == (char *)nah ) {
    ah->a.size += nah->a.size;

    /* Remove the old block from the chains */
    nah->next_free->prev_free = nah->prev_free;
    nah->prev_free->next_free = nah->next_free;
    ah->a.next = nah->a.next;
    nah->a.next->a.prev = ah;

#ifdef DEBUG_MALLOC
    nah->a.type = ARENA_TYPE_DEAD;
#endif
  }

  /* Return the block that contains the called block */
  return ah;
}

void *malloc(size_t size)
{
  struct free_arena_header *fp;
  struct free_arena_header *pah;
  size_t fsize;

  if ( size == 0 )
    return NULL;

  /* Add the obligatory arena header, and round up */
  size = (size+2*sizeof(struct arena_header)-1) & ARENA_SIZE_MASK;

  for ( fp = __malloc_head.next_free ; fp->a.type != ARENA_TYPE_HEAD ;
	fp = fp->next_free ) {
    if ( fp->a.size >= size ) {
      /* Found fit -- allocate out of this block */
      return __malloc_from_block(fp, size);
    }
  }

  /* Nothing found... need to request a block from the kernel */
  fsize = (size+MALLOC_CHUNK_MASK) & ~MALLOC_CHUNK_MASK;

#ifdef MALLOC_USING_SBRK
  fp = (struct free_arena_header *) sbrk(fsize);
#else
  fp = (struct free_arena_header *)
    mmap(NULL, fsize, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, 0, 0);
#endif

  if ( fp == (struct free_arena_header *)MAP_FAILED ) {
    return NULL;		/* Failed to get a block */
  }

  /* Insert the block into the management chains.  We need to set
     up the size and the main block list pointer, the rest of
     the work is logically identical to free(). */
  fp->a.type = ARENA_TYPE_FREE;
  fp->a.size = fsize;

  /* We need to insert this into the main block list in the proper
     place -- this list is required to be sorted.  Since we most likely
     get memory assignments in ascending order, search backwards for
     the proper place. */
  for ( pah = __malloc_head.a.prev ; pah->a.type != ARENA_TYPE_HEAD ;
	pah = pah->a.prev ) {
    if ( pah < fp )
      break;
  }

  /* Now pah points to the node that should be the predecessor of
     the new node */
  fp->a.next = pah->a.next;
  fp->a.prev = pah;
  pah->a.next  = fp;
  fp->a.next->a.prev = fp;


  /* Insert into the free chain and coalesce with adjacent blocks */
  fp = __free_block(fp);

  /* Now we can allocate from this block */
  return __malloc_from_block(fp, size);
}

void free(void *ptr)
{
  struct free_arena_header *ah;

  if ( !ptr )
    return;

  ah = (struct free_arena_header *)
    ((struct arena_header *)ptr - 1);

#ifdef DEBUG_MALLOC
  assert( ah->a.type == ARENA_TYPE_USED );
#endif

  __free_block(ah);

  /* Here we could insert code to return memory to the system. */
}
