/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "format-util.h"
#include "socket-util.h"
#include "stdio-util.h"
#include "string-util.h"
#include "utmp-wtmp.h"
#include "tests.h"

#ifndef UT_LINESIZE
#  define UT_LINESIZE      32
#endif
#ifndef UT_NAMESIZE
#  define UT_NAMESIZE      32
#endif
#ifndef UT_HOSTSIZE
#  define UT_HOSTSIZE     256
#endif

TEST(dump_run_utmp) {
        _unused_ _cleanup_(utxent_cleanup) bool utmpx = false;

        utmpx = utxent_start();

        for (struct utmpx *u; (u = getutxent()); ) {
                char _type_buf[DECIMAL_STR_MAX(short)];
                const char *type =
                        u->ut_type == EMPTY         ? "EMPTY" :
                        u->ut_type == RUN_LVL       ? "RUN_LVL" :
                        u->ut_type == BOOT_TIME     ? "BOOT_TIME" :
                        u->ut_type == NEW_TIME      ? "NEW_TIME" :
                        u->ut_type == OLD_TIME      ? "OLD_TIME" :
                        u->ut_type == INIT_PROCESS  ? "INIT_PROCESS" :
                        u->ut_type == LOGIN_PROCESS ? "LOGIN_PROCESS" :
                        u->ut_type == USER_PROCESS  ? "USER_PROCESS" :
                        u->ut_type == DEAD_PROCESS  ? "DEAD_PROCESS" :
                        u->ut_type == ACCOUNTING    ? "ACCOUNTING" :
                        _type_buf;
                if (type == _type_buf)
                        xsprintf(_type_buf, "%hd", u->ut_type);

                union in_addr_union addr = {};
                memcpy(&addr, u->ut_addr_v6, MIN(sizeof(addr), sizeof(u->ut_addr_v6)));
                bool is_ipv4 = memeqzero((const uint8_t*) &addr + 4, sizeof(addr) - 4);

                log_info("%14s %10"PID_PRI" line=%-7.*s id=%-4.4s name=%-8.*s session=%lu host=%.*s addr=%s",
                         type,
                         u->ut_pid,
                         UT_LINESIZE, u->ut_line,
                         u->ut_id,
                         UT_NAMESIZE, u->ut_user,
                         (long unsigned) u->ut_session,
                         UT_HOSTSIZE, u->ut_host,
                         IN_ADDR_TO_STRING(is_ipv4 ? AF_INET : AF_INET6, &addr));
        }
}

DEFINE_TEST_MAIN(LOG_DEBUG);
