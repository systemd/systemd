/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "ether-addr-util.h"
#include "tests.h"

#define INFINIBAD_ADDR_1 ((const struct hw_addr_data){ .length = 20, .infiniband = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20} })

static void test_HW_ADDR_TO_STRING(void) {
        log_info("/* %s */", __func__);

        const char *s = HW_ADDR_TO_STR(&(const struct hw_addr_data){6});
        log_info("null: %s", s);

        log_info("null×2: %s, %s",
                 HW_ADDR_TO_STR(&(const struct hw_addr_data){6}),
                 HW_ADDR_TO_STR(&(const struct hw_addr_data){6}));
        log_info("null×3: %s, %s, %s",
                 HW_ADDR_TO_STR(&(const struct hw_addr_data){6}),
                 s,
                 HW_ADDR_TO_STR(&(const struct hw_addr_data){6}));

        log_info("infiniband: %s", HW_ADDR_TO_STR(&INFINIBAD_ADDR_1));

        /* Let's nest function calls in a stupid way. */
        _cleanup_free_ char *t = NULL;
        log_info("infiniband×3: %s\n%14s%s\n%14s%s",
                 HW_ADDR_TO_STR(&(const struct hw_addr_data){20}), "",
                 t = strdup(HW_ADDR_TO_STR(&INFINIBAD_ADDR_1)), "",
                 HW_ADDR_TO_STR(&(const struct hw_addr_data){20}));

        const char *p;
        /* Let's use a separate selection statement */
        if ((p = HW_ADDR_TO_STR(&(const struct hw_addr_data){6})))
                log_info("joint: %s, %s", s, p);
}

int main(int argc, char *argv[]) {
        test_setup_logging(LOG_INFO);

        test_HW_ADDR_TO_STRING();
        return 0;
}
