/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "hexdecoct.h"
#include "iovec-util.h"
#include "pkcs7-util.h"
#include "tests.h"

TEST(pkcs7_extract_signers) {

        const char tsig[] =
                "MIIEgwYJKoZIhvcNAQcCoIIEdDCCBHACAQExDzANBglghkgBZQMEAgEFADALBgkqhkiG9w0BBwGgggLp"
                "MIIC5TCCAc2gAwIBAgIURlvlj5ak0ZhvNS8hENNKwVv60x0wDQYJKoZIhvcNAQELBQAwGzEZMBcGA1UE"
                "AwwQbWtvc2kgb2YgbGVubmFydDAeFw0yNTAyMDMxMTAwMjNaFw0yNzAyMDMxMTAwMjNaMBsxGTAXBgNV"
                "BAMMEG1rb3NpIG9mIGxlbm5hcnQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCldQdmHVgU"
                "m4saaSqEpF1EVRf9pcIxpVShROBGAbxpxs4BQ7vV7zCg5bXwEVaqaENlIyzqPAj+YQifQS3Dj6LQfH3i"
                "War+ciKAv4PYcESG+pcdBb2kJOS8cVD6abZlO9rInvdhXK6PhYF7VohMwMPj/yJYdO50skwA5OQsCHO6"
                "amowh0tVzNzpbaJZg6wWIyTf3+ZzZdnOl5EvBCaUqeUhbaxRV9SrAw51rzAOnndUhW1we/vVKEGAPk3c"
                "SCb0LLPBG20XX2C00UXgnCWBkU5rkq6BnWSuInhFKCa48avstIet1ZFBA5T5J83ncU9UOVFksEYBXFoc"
                "lzcmcbx/2/oFAgMBAAGjITAfMB0GA1UdDgQWBBQewILFCixwq2rejOvJqmZSug2BBDANBgkqhkiG9w0B"
                "AQsFAAOCAQEAIvaeNPaJUoIUN5lQC/kcCiKeys96WNRGL2wbTp5PqdnRw14sbWY5iC2z13ih3dmTI9NF"
                "TBa7C/ji+5BaAfiJF17LOV00Y8eP5V94fHz4isb0sv5RzLsE4h8X7QFk4JBdV5GiCDzPXjxQAx9kM2so"
                "9RGtL8EhHpNygYDgyZ18YeiwcUPkCXT+xG2rM6s/Xlsji0s/18ycI4G8AC8dj5HycyS9BiZHgKrkgqTb"
                "VPo4zHYzhZdh0Qrd0J4YpoaotzQ35bkH9PtIkF6C7mE1Z7uMSGFkGQASgJ0BDTpM8QPAf2HIR2xxEtJR"
                "ZXkwxxdC+W9AJAzqJldmCHYGSrSR54J0rDGCAV4wggFaAgEBMDMwGzEZMBcGA1UEAwwQbWtvc2kgb2Yg"
                "bGVubmFydAIURlvlj5ak0ZhvNS8hENNKwVv60x0wDQYJYIZIAWUDBAIBBQAwDQYJKoZIhvcNAQEBBQAE"
                "ggEAXccqvpiEWsz/xvuLhINVZKIOznVdqjkERbZSqCBK94BYESSd+cijaB4XbYaFUZ45Bb3uUDQ56Ojq"
                "WoY1elEfqPyCb4vc887QoHmxI0BtdIaHhIDfCGBxhX8fwMknxqjgFa9YvONmDtv4QG4syTw+U3SEqBaa"
                "Avftqaa4v4eLk4uZ0nMIgMkx4qOlaxknpP404/nyZPANkOIwDxviNtRBCN9zSiPSqo1zre1vqzaM57Ww"
                "8zJASsPEzNR7OsPoLaIZv2OHXpowsRB78TuXGkQnm74T6xdG6DNs24jTYJuCPfGuYLHbrytdhXpFBS6m"
                "Orz9715jK2NU5VvGhNVXX4chcw==";

        _cleanup_free_ void *sig = NULL;
        size_t siglen;
        ASSERT_OK(unbase64mem(tsig, &sig, &siglen));

        size_t n_signers = 0;
        Signer *signers = NULL;
        CLEANUP_ARRAY(signers, n_signers, signer_free_many);

        ASSERT_OK_EQ(pkcs7_extract_signers(&IOVEC_MAKE(sig, siglen), &signers, &n_signers), 1);
        ASSERT_EQ(n_signers, 1U);
        ASSERT_EQ(signers[0].issuer.iov_len, 29U);
        ASSERT_EQ(signers[0].serial.iov_len, 22U);

        _cleanup_free_ char *issuer = NULL;
        ASSERT_OK(base64mem(signers[0].issuer.iov_base, signers[0].issuer.iov_len, &issuer));

        _cleanup_free_ char *serial = NULL;
        ASSERT_OK(base64mem(signers[0].serial.iov_base, signers[0].serial.iov_len, &serial));

        ASSERT_STREQ(issuer, "MBsxGTAXBgNVBAMMEG1rb3NpIG9mIGxlbm5hcnQ=");
        ASSERT_STREQ(serial, "AhRGW+WPlqTRmG81LyEQ00rBW/rTHQ==");
}

DEFINE_TEST_MAIN(LOG_INFO);
