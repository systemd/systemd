/*
 * setresuid.c
 */

#include <unistd.h>
#include <sys/syscall.h>

#ifdef __NR_setresuid

_syscall3(int,setresuid,uid_t,a0,uid_t,a1,uid_t,a2);

#elif defined(__NR_setresuid32)

static inline _syscall3(int,setresuid32,uid_t,a0,uid_t,a1,uid_t,a2);

int setresuid(uid_t a0, uid_t a1, uid_t a2)
{
  if ( sizeof(uid_t) == sizeof(uint32_t) ) {
    return setresuid32(a0,a1,a2);
  } else {
    uint32_t x0 = (a0 == (uid_t)-1) ? (uint32_t)-1 : a0;
    uint32_t x1 = (a1 == (uid_t)-1) ? (uint32_t)-1 : a1;
    uint32_t x2 = (a2 == (uid_t)-1) ? (uint32_t)-1 : a2;
    
    return setresuid32(x0,x1,x2);
  }
}

#endif

