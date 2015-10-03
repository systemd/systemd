/*
   SipHash reference C implementation

   Written in 2012 by
   Jean-Philippe Aumasson <jeanphilippe.aumasson@gmail.com>
   Daniel J. Bernstein <djb@cr.yp.to>

   To the extent possible under law, the author(s) have dedicated all copyright
   and related and neighboring rights to this software to the public domain
   worldwide. This software is distributed without any warranty.

   You should have received a copy of the CC0 Public Domain Dedication along with
   this software. If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.

   (Minimal changes made by Lennart Poettering, to make clean for inclusion in systemd)
*/
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "siphash24.h"

typedef uint64_t u64;
typedef uint32_t u32;
typedef uint8_t u8;

#define ROTL(x,b) (u64)( ((x) << (b)) | ( (x) >> (64 - (b))) )

#define U32TO8_LE(p, v)         \
    (p)[0] = (u8)((v)      ); (p)[1] = (u8)((v) >>  8); \
    (p)[2] = (u8)((v) >> 16); (p)[3] = (u8)((v) >> 24);

#define U64TO8_LE(p, v)         \
  U32TO8_LE((p),     (u32)((v)      ));   \
  U32TO8_LE((p) + 4, (u32)((v) >> 32));

#define U8TO64_LE(p) \
  (((u64)((p)[0])      ) | \
   ((u64)((p)[1]) <<  8) | \
   ((u64)((p)[2]) << 16) | \
   ((u64)((p)[3]) << 24) | \
   ((u64)((p)[4]) << 32) | \
   ((u64)((p)[5]) << 40) | \
   ((u64)((p)[6]) << 48) | \
   ((u64)((p)[7]) << 56))

#define SIPROUND(state)         \
  do {              \
    (state)->v0 += (state)->v1; (state)->v1=ROTL((state)->v1,13); (state)->v1 ^= (state)->v0; (state)->v0=ROTL((state)->v0,32); \
    (state)->v2 += (state)->v3; (state)->v3=ROTL((state)->v3,16); (state)->v3 ^= (state)->v2;     \
    (state)->v0 += (state)->v3; (state)->v3=ROTL((state)->v3,21); (state)->v3 ^= (state)->v0;     \
    (state)->v2 += (state)->v1; (state)->v1=ROTL((state)->v1,17); (state)->v1 ^= (state)->v2; (state)->v2=ROTL((state)->v2,32); \
  } while(0)

struct siphash {
  u64 v0;
  u64 v1;
  u64 v2;
  u64 v3;
  u64 padding;
  size_t inlen;
};

static void siphash_init(struct siphash *state, const uint8_t k[16]) {
  u64 k0, k1;

  k0 = U8TO64_LE( k );
  k1 = U8TO64_LE( k + 8 );

  /* "somepseudorandomlygeneratedbytes" */
  state->v0 = 0x736f6d6570736575ULL ^ k0;
  state->v1 = 0x646f72616e646f6dULL ^ k1;
  state->v2 = 0x6c7967656e657261ULL ^ k0;
  state->v3 = 0x7465646279746573ULL ^ k1;
  state->padding = 0;
  state->inlen = 0;
}

static void siphash24_compress(const void *_in, size_t inlen, struct siphash *state) {
  u64 m;
  const u8 *in = _in;
  const u8 *end = in + inlen;
  int left = state->inlen & 7;

  /* update total length */
  state->inlen += inlen;

  /* if padding exists, fill it out */
  if (left > 0) {
    for ( ; in < end && left < 8; in ++, left ++ )
      state->padding |= ( ( u64 )*in ) << (left * 8);

    if (in == end && left < 8)
      /* we did not have enough input to fill out the padding completely */
      return;

#ifdef DEBUG
    printf( "(%3d) v0 %08x %08x\n", ( int )state->inlen, ( u32 )( state->v0 >> 32 ), ( u32 )state->v0 );
    printf( "(%3d) v1 %08x %08x\n", ( int )state->inlen, ( u32 )( state->v1 >> 32 ), ( u32 )state->v1 );
    printf( "(%3d) v2 %08x %08x\n", ( int )state->inlen, ( u32 )( state->v2 >> 32 ), ( u32 )state->v2 );
    printf( "(%3d) v3 %08x %08x\n", ( int )state->inlen, ( u32 )( state->v3 >> 32 ), ( u32 )state->v3 );
    printf( "(%3d) compress padding %08x %08x\n", ( int )state->inlen, ( u32 )( state->padding >> 32 ), ( u32 )state->padding );
#endif
    state->v3 ^= state->padding;
    SIPROUND(state);
    SIPROUND(state);
    state->v0 ^= state->padding;

    state->padding = 0;
  }

  end -= ( state->inlen % sizeof (u64) );

  for ( ; in < end; in += 8 )
  {
    m = U8TO64_LE( in );
#ifdef DEBUG
    printf( "(%3d) v0 %08x %08x\n", ( int )state->inlen, ( u32 )( state->v0 >> 32 ), ( u32 )state->v0 );
    printf( "(%3d) v1 %08x %08x\n", ( int )state->inlen, ( u32 )( state->v1 >> 32 ), ( u32 )state->v1 );
    printf( "(%3d) v2 %08x %08x\n", ( int )state->inlen, ( u32 )( state->v2 >> 32 ), ( u32 )state->v2 );
    printf( "(%3d) v3 %08x %08x\n", ( int )state->inlen, ( u32 )( state->v3 >> 32 ), ( u32 )state->v3 );
    printf( "(%3d) compress %08x %08x\n", ( int )state->inlen, ( u32 )( m >> 32 ), ( u32 )m );
#endif
    state->v3 ^= m;
    SIPROUND(state);
    SIPROUND(state);
    state->v0 ^= m;
  }

  left = state->inlen & 7;

  switch( left )
  {
  case 7: state->padding |= ( ( u64 )in[ 6] )  << 48;

  case 6: state->padding |= ( ( u64 )in[ 5] )  << 40;

  case 5: state->padding |= ( ( u64 )in[ 4] )  << 32;

  case 4: state->padding |= ( ( u64 )in[ 3] )  << 24;

  case 3: state->padding |= ( ( u64 )in[ 2] )  << 16;

  case 2: state->padding |= ( ( u64 )in[ 1] )  <<  8;

  case 1: state->padding |= ( ( u64 )in[ 0] ); break;

  case 0: break;
  }
}

static u64 siphash24_finalize(struct siphash *state) {
  u64 b;

  b = state->padding | (( ( u64 )state->inlen ) << 56);
#ifdef DEBUG
  printf( "(%3d) v0 %08x %08x\n", ( int )state->inlen, ( u32 )( state->v0 >> 32 ), ( u32 )state->v0 );
  printf( "(%3d) v1 %08x %08x\n", ( int )state->inlen, ( u32 )( state->v1 >> 32 ), ( u32 )state->v1 );
  printf( "(%3d) v2 %08x %08x\n", ( int )state->inlen, ( u32 )( state->v2 >> 32 ), ( u32 )state->v2 );
  printf( "(%3d) v3 %08x %08x\n", ( int )state->inlen, ( u32 )( state->v3 >> 32 ), ( u32 )state->v3 );
  printf( "(%3d) padding   %08x %08x\n", ( int )state->inlen, ( u32 )( state->padding >> 32 ), ( u32 )state->padding );
#endif
  state->v3 ^= b;
  SIPROUND(state);
  SIPROUND(state);
  state->v0 ^= b;

#ifdef DEBUG
  printf( "(%3d) v0 %08x %08x\n", ( int )state->inlen, ( u32 )( state->v0 >> 32 ), ( u32 )state->v0 );
  printf( "(%3d) v1 %08x %08x\n", ( int )state->inlen, ( u32 )( state->v1 >> 32 ), ( u32 )state->v1 );
  printf( "(%3d) v2 %08x %08x\n", ( int )state->inlen, ( u32 )( state->v2 >> 32 ), ( u32 )state->v2 );
  printf( "(%3d) v3 %08x %08x\n", ( int )state->inlen, ( u32 )( state->v3 >> 32 ), ( u32 )state->v3 );
#endif
  state->v2 ^= 0xff;
  SIPROUND(state);
  SIPROUND(state);
  SIPROUND(state);
  SIPROUND(state);

  return state->v0 ^ state->v1 ^ state->v2  ^ state->v3;
}

/* SipHash-2-4 */
void siphash24(uint8_t out[8], const void *_in, size_t inlen, const uint8_t k[16])
{
  struct siphash state;
  u64 b;

  siphash_init(&state, k);

  siphash24_compress(_in, inlen, &state);

  b = siphash24_finalize(&state);

  U64TO8_LE( out, b );
}
