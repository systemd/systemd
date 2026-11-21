/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "pkcs11-util.h"
#include "tests.h"

TEST(pkcs11_slot_is_enumerable) {
        /* A hardware reader with a token in it. */
        ASSERT_TRUE(pkcs11_slot_is_enumerable(&(CK_SLOT_INFO) {
                .flags = CKF_HW_SLOT|CKF_TOKEN_PRESENT,
        }));
        ASSERT_TRUE(pkcs11_slot_is_enumerable(&(CK_SLOT_INFO) {
                .flags = CKF_HW_SLOT|CKF_TOKEN_PRESENT|CKF_REMOVABLE_DEVICE,
        }));

        /* A software token, such as the p11-kit trust store. */
        ASSERT_FALSE(pkcs11_slot_is_enumerable(&(CK_SLOT_INFO) {
                .flags = CKF_TOKEN_PRESENT,
        }));

        /* A hardware reader without a token. */
        ASSERT_FALSE(pkcs11_slot_is_enumerable(&(CK_SLOT_INFO) {
                .flags = CKF_HW_SLOT|CKF_REMOVABLE_DEVICE,
        }));
        ASSERT_FALSE(pkcs11_slot_is_enumerable(&(CK_SLOT_INFO) {}));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
