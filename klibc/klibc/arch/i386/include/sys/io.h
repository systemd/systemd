#ident "$Id: io.h,v 1.2 2004/01/25 07:49:39 hpa Exp $"
/* ----------------------------------------------------------------------- *
 *   
 *   Copyright 2004 H. Peter Anvin - All Rights Reserved
 *
 *   Permission is hereby granted, free of charge, to any person
 *   obtaining a copy of this software and associated documentation
 *   files (the "Software"), to deal in the Software without
 *   restriction, including without limitation the rights to use,
 *   copy, modify, merge, publish, distribute, sublicense, and/or
 *   sell copies of the Software, and to permit persons to whom
 *   the Software is furnished to do so, subject to the following
 *   conditions:
 *   
 *   The above copyright notice and this permission notice shall
 *   be included in all copies or substantial portions of the Software.
 *   
 *   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 *   EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 *   OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 *   NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 *   HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 *   WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 *   FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 *   OTHER DEALINGS IN THE SOFTWARE.
 *
 * ----------------------------------------------------------------------- */

/*
 * sys/io.h for the i386 architecture
 *
 * Basic I/O macros
 */

#ifndef _SYS_IO_H
#define _SYS_IO_H 1

/* I/O-related system calls */

int iopl(int);
int ioperm(unsigned long, unsigned long, int);

/* Basic I/O macros */

static __inline__ void
outb(unsigned char __v, unsigned short __p)
{
  asm volatile("outb %0,%1" : : "a" (__v), "dN" (__p));
}

static __inline__ void
outw(unsigned short __v, unsigned short __p)
{
  asm volatile("outw %0,%1" : : "a" (__v), "dN" (__p));
}

static __inline__ void
outl(unsigned int __v, unsigned short __p)
{
  asm volatile("outl %0,%1" : : "a" (__v), "dN" (__p));
}

static __inline__ unsigned char
inb(unsigned short __p)
{
  unsigned char __v;
  asm volatile("inb %1,%0" : "=a" (__v) : "dN" (__p));
  return __v;
}

static __inline__ unsigned short
inw(unsigned short __p)
{
  unsigned short __v;
  asm volatile("inw %1,%0" : "=a" (__v) : "dN" (__p));
  return __v;
}

static __inline__ unsigned int
inl(unsigned short __p)
{
  unsigned int __v;
  asm volatile("inl %1,%0" : "=a" (__v) : "dN" (__p));
  return __v;
}

/* String I/O macros */

static __inline__ void
outsb (unsigned short __p, const void *__d, unsigned long __n)
{
  asm volatile("cld; rep; outsb" : "+S" (__d), "+c" (__n) : "d" (__p));
}

static __inline__ void
outsw (unsigned short __p, const void *__d, unsigned long __n)
{
  asm volatile("cld; rep; outsw" : "+S" (__d), "+c" (__n) : "d" (__p));
}

static __inline__ void
outsl (unsigned short __p, const void *__d, unsigned long __n)
{
  asm volatile("cld; rep; outsl" : "+S" (__d), "+c" (__n) : "d" (__p));
}


static __inline__ void
insb (unsigned short __p, void *__d, unsigned long __n)
{
  asm volatile("cld; rep; insb" : "+D" (__d), "+c" (__n) : "d" (__p));
}

static __inline__ void
insw (unsigned short __p, void *__d, unsigned long __n)
{
  asm volatile("cld; rep; insw" : "+D" (__d), "+c" (__n) : "d" (__p));
}

static __inline__ void
insl (unsigned short __p, void *__d, unsigned long __n)
{
  asm volatile("cld; rep; insl" : "+D" (__d), "+c" (__n) : "d" (__p));
}

#endif /* _SYS_IO_H */
