#include <sys/types.h>
#include <utmpx.h>

/* sysdep: +utmpx */

#define UW_TMP_UFILE _UTMPX_FILE
#define UW_TMP_WFILE _WTMPX_FILE

#ifndef ut_time
#define ut_time ut_tv.tv_sec
#endif

typedef struct futmpx uw_tmp;
