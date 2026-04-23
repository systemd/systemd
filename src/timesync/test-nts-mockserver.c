/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Copyright © 2026 Trifecta Tech Foundation */

/* This is a mock NTS server that is only used for integration tests.
 * Any error in the protocol quickly results in an assert, and it can
 * only communicate with a single client (hence why the NTS cookies
 * do not matter)
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <unistd.h>

#include "nts.h"
#include "nts_crypto.h"
#include "nts_extfields.h"
#include "memory-util.h"
#include "timesyncd-ntp-message.h"

/* always pick this AEAD */
static const NTS_AEADAlgorithmType algo = NTS_AEAD_AES_SIV_CMAC_384;

/* always pick this NTP port */
static const uint16_t Port = 12345;

typedef uint8_t AEADKey[64];

static uint32_t get_current_ntp_sec(void) {
        struct timespec time;
        clock_gettime(CLOCK_REALTIME, &time);

        return time.tv_sec + OFFSET_1900_1970; /* wrap around is intended */
}

static struct ntp_ts ntp_time(uint32_t secs) {
        return (struct ntp_ts){ .sec = htobe32(secs), .frac = 0 };
}

/* we want to fail but not actually cause a core dump since this will run in
 * integration tests; in some scenarios failure of this server is precisely the point
 */
#define soft_assert(condition)                                                          \
        if (!(condition)) {                                                             \
                fprintf(stderr, "server failed: %s (line %d)\n", #condition, __LINE__); \
                exit(1);                                                                \
        }

static void serve_ntp_request(int sock, AEADKey c2s, AEADKey s2c, int sabotage) {
        struct sockaddr_in client = {};
        struct ntp_msg packet;
        uint8_t buf[1280];

        socklen_t addrlen = sizeof(client);
        int len = recvfrom(sock, buf, sizeof(buf), MSG_WAITALL, (struct sockaddr*)&client, &addrlen);

        soft_assert(len >= 48);

        const NTS_AEADParam *cipher = NTS_get_param(algo);
        soft_assert(cipher);

        memcpy(&packet, buf, sizeof(packet));

        uint8_t unique_id[32];
        if (len > 48) {
                /* We only parse the extension fields to check the authenticity tag; parse_extension_fields
                 * is meant for use in clients, not servers so it'll ignore Cookie Placeholders.
                 * Also note that the order of the s2c and c2s keys has to be reversed. */
                NTS_Query const query = {
                        { (void*)"42", 2 },
                        s2c, c2s,
                        *cipher,
                        0,
                };
                NTS_Receipt rcpt;
                soft_assert(NTS_parse_extension_fields(buf, len, &query, &rcpt) > 0);
                /* getting "new cookies" from a client is an error */
                soft_assert(rcpt.new_cookie->data == NULL);

                memcpy(unique_id, rcpt.identifier, 32);
        }

        /* simulate a SNTP reponse - you are always 42 seconds behind */
        uint64_t reply_time = get_current_ntp_sec() + 42;

        packet.field = 044;
        packet.stratum = 15;
        packet.reference_time = (struct ntp_ts){ 0, 0 };
        packet.origin_time    = packet.trans_time;
        packet.recv_time      = ntp_time(reply_time);
        packet.trans_time     = ntp_time(reply_time);

        if (len > 48 && sabotage <= 1) {
                int padding = 0;
                uint16_t payload[] = {
                        /* Always send two cookies to see what happens */
                        htobe16(0x0204 /*Cookie*/), htobe16(8), htobe16(1), htobe16(1),
                        htobe16(0x0204 /*Cookie*/), htobe16(8), htobe16(1), htobe16(2),
                };
                static_assert(sizeof(payload)%4 == 0, "payload must dword-padded");

                uint16_t id_field[] = {
                        htobe16(0x0104 /*UniqId*/), htobe16(36),
                           2, 4, 6, 8,10,12,14,16,18,20,22,24,26,28,30,32,
                };
                memcpy(id_field+2, unique_id, sizeof(unique_id));
                uint16_t auth_enc_field[] = {
                        htobe16(0x0404 /*AE Fld*/), htobe16(8+cipher->nonce_size+cipher->block_size+sizeof(payload)+padding),
                          htobe16(cipher->nonce_size),
                          htobe16(cipher->block_size+sizeof(payload)),
                };

                zero(buf);
                uint8_t *p = buf;
                p = mempcpy(p, &packet, sizeof(packet));
                p = mempcpy(p, id_field, sizeof(id_field));
                p = mempcpy(p, auth_enc_field, sizeof(auth_enc_field));

                AssociatedData info[] = {
                        { buf,  sizeof(packet) + sizeof(id_field) },
                        { p,    cipher->nonce_size },
                        {},
                };

                int ciphertext = NTS_encrypt(
                        p + cipher->nonce_size, sizeof(buf) - (p - buf - cipher->nonce_size),
                        (uint8_t*)payload, sizeof(payload),
                        info,
                        cipher, s2c
                );

                soft_assert(ciphertext > 0);
                p += cipher->nonce_size + ciphertext + padding;
                if (sabotage) {
                        /* flip a random bit */
                        uint8_t index;
                        getrandom(&index, 1, 0);
                        buf[index % 48] ^= 1;
                }

                sendto(sock, buf, p - buf, MSG_CONFIRM, (struct sockaddr*)&client, addrlen);
        } else {
                sendto(sock, &packet, sizeof(packet), MSG_CONFIRM, (struct sockaddr*)&client, addrlen);
        }

        close(sock);
}

static int alpn_select(
                SSL *ssl,
                const unsigned char **out,
                unsigned char *outlen,
                const unsigned char *in,
                unsigned int inlen,
                void *arg) {

        (void) ssl;
        (void) arg;
        soft_assert(SSL_select_next_proto((unsigned char**)out, outlen, (unsigned char*)"\x07ntske/1", 8, in, inlen) == OPENSSL_NPN_NEGOTIATED);
        return SSL_TLSEXT_ERR_OK;
}

static void wait_for_nts_ke(AEADKey c2s, AEADKey s2c, int sabotage) {
        /* configure TLS */
        SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
        soft_assert(ctx);

        soft_assert(SSL_CTX_use_certificate_chain_file(ctx, "server.crt") > 0);
        soft_assert(SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) > 0);

        SSL_CTX_set_alpn_select_cb(ctx, alpn_select, NULL);

        SSL *tls = SSL_new(ctx);
        soft_assert(tls);

        /* await the TCP connect */
        BIO *acceptor = BIO_new_accept("4460");
        soft_assert(acceptor);
        soft_assert(BIO_do_accept(acceptor) > 0);
        soft_assert(BIO_do_accept(acceptor) > 0);
        BIO *bio = BIO_pop(acceptor);
        close(BIO_get_fd(acceptor, NULL));

        soft_assert(bio);

        if (sabotage > 5) {
                /* refuse to shake hands */
                sleep(20);
        }
        if (sabotage > 4) {
                /* drop the horn */
                exit(0);
        }

        SSL_set_bio(tls, bio, bio);

        soft_assert(SSL_accept(tls) > 0);

        /* read the NTS packet */
        NTS_Agreement NTS;
        int readbytes;
        uint8_t buf[1280];
        readbytes = SSL_read(tls, buf, sizeof(buf));
        soft_assert(readbytes > 0);

        if (sabotage > 3) {
                /* silent treatment */
                exit(0);
        }

        if (NTS_decode_response(buf, readbytes, &NTS) < 0) {
                printf("NTS error: %s (read %d bytes)\n", NTS_error_string(NTS.error), readbytes);
                abort();
        }

        /* store the key */
        soft_assert(NTS_TLS_extract_keys((void*)tls, algo, c2s, s2c, sizeof(AEADKey)) == 0);

        /* custom hostname is intentionally padded to 10 bytes, so "127.0.0.01" is not a typo */
        const char ntphost[] = "127.0.0.01";
        static_assert(strlen(ntphost) == 10, "sanity check failed");

        /* send a static reply */
        uint16_t reply[] = {
                htobe16(6/*NTPv4Server*/),       htobe16(10), 0,0,0,0,0, /* filled in below */
                htobe16(1/*NextProto*/),         htobe16(2), htobe16(0),
                htobe16(4/*AEADAlgorithm*/), htobe16(2), htobe16(algo),
                htobe16(7/*NTPv4Port*/),         htobe16(2), htobe16(12345),
                /* only send 2 cookies just to see what happens */
                htobe16(5/*NTPv4Cookie*/),       htobe16(4), htobe16(0), htobe16(1),
                htobe16(5/*NTPv4Cookie*/),       htobe16(4), htobe16(0), htobe16(2),
                htobe16(0/*EndOfMessage*/ | 0x8000),  htobe16(0),
        };
        memcpy(reply+2, ntphost, sizeof(ntphost));
        if (sabotage > 2) {
                /* tamper with the length of the ntp server field, make sure it's not "10" */
                unsigned char *p = (unsigned char*) reply;
                getrandom(p+3, 1, 0);
                p[3] = (p[3] % 32 + 1) ^ 10;
        }

        SSL_write(tls, reply, sizeof(reply));
        SSL_free(tls);
        SSL_CTX_free(ctx);
}

/* the number of arguments decide at which
 * points in the NTS process a hiccup is simulated
 */
int main(int argc, char **argv) {
        AEADKey c2s, s2c;
        int sabo = argc>1 ? atoi(argv[1]) : 0;

        /* bind the NTP socket ahead of time to prevent a race */
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        soft_assert(sock > 0);

        struct sockaddr_in server = {};
        server.sin_family = AF_INET;
        server.sin_port = htobe16(Port);
        inet_aton("127.0.0.1", &server.sin_addr);

        soft_assert(bind(sock, (struct sockaddr*)&server, sizeof(server)) == 0);

        puts("KE started");
        wait_for_nts_ke(c2s, s2c, sabo);
        puts("KE done");

        puts("NTP listening");
        serve_ntp_request(sock, c2s, s2c, sabo);
        puts("NTP replied");

        return 0;
}
