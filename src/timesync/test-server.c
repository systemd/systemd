/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* This is a mock NTS server that is only used for integration tests.
 * Any error in the protocol quickly results in an assert, and it can
 * only communicate with a single client (hence why the NTS cookies
 * do not matter)
 */

#include <arpa/inet.h>
#include <assert.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "nts.h"
#include "nts_crypto.h"
#include "nts_extfields.h"
#include "memory-util.h"

struct ntp_packet {
        uint8_t li_vn_mode;
        uint8_t stratum;
        uint8_t poll;
        uint8_t precision;
        uint32_t root_delay;
        uint32_t root_dispersion;
        char reference_id[4];
        uint64_t timestamp[4];
};

/* always pick this AEAD */
static const NTS_AEADAlgorithmType algo = NTS_AEAD_AES_SIV_CMAC_384;

/* always pick this NTP port */
static const uint16_t Port = 12345;

typedef uint8_t AEADKey[64];

static uint64_t get_current_ntp_time(void) {
        struct timespec time;
        clock_gettime(CLOCK_REALTIME, &time);

        uint64_t secs = time.tv_sec + 2208988800; /* wrap around is intended */
        uint64_t frac = time.tv_nsec * ((1ULL<<32) / 1E9L);
        return secs << 32 | frac;
}

static void serve_ntp_request(AEADKey c2s, AEADKey s2c) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    assert(sock > 0);

    struct sockaddr_in server = {}, client = {};
    server.sin_family = AF_INET;
    server.sin_port = htobe16(Port);
    inet_aton("127.0.0.1", &server.sin_addr);

    assert(bind(sock, (struct sockaddr*)&server, sizeof(server)) == 0);

    struct ntp_packet packet;
    uint8_t buf[1280];

    socklen_t addrlen = sizeof(client);
    int len = recvfrom(sock, buf, sizeof(buf), MSG_WAITALL, (struct sockaddr*)&client, &addrlen);

    assert(len >= 48);

    const struct NTS_AEADParam *cipher = NTS_get_param(algo);
    assert(cipher);

    memcpy(&packet, buf, sizeof(packet));

    uint8_t unique_id[32];
    if (len > 48) {
        /* We only parse the extension fields to check the authenticity tag; parse_extension_fields
         * is meant for use in clients, not servers so it'll ignore Cookie Placeholders.
         * Also note that the order of the s2c and c2s keys has to be reversed. */
        struct NTS_Query const query = {
            { (void*)"42", 2 },
            s2c, c2s,
            *cipher,
            0,
        };
        struct NTS_Receipt rcpt;
        assert(NTS_parse_extension_fields(buf, len, &query, &rcpt) > 0);
        /* getting "new cookies" from a client is an error */
        assert(rcpt.new_cookie->data == NULL);

        memcpy(unique_id, rcpt.identifier, 32);
    }

    /* simulate a SNTP reponse - you are always 42 seconds behind */
    uint64_t reply_time = get_current_ntp_time() + (42ULL<<32);

    packet.li_vn_mode = 044;
    packet.stratum = 15;
    packet.timestamp[0] = 0;
    packet.timestamp[1] = packet.timestamp[3];
    packet.timestamp[2] = htobe64(reply_time);
    packet.timestamp[3] = htobe64(reply_time);

    if (len > 48) {
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

        assert(ciphertext > 0);
        p += cipher->nonce_size + ciphertext + padding;

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
    assert(SSL_select_next_proto((unsigned char**)out, outlen, (unsigned char*)"\x07ntske/1", 8, in, inlen) == OPENSSL_NPN_NEGOTIATED);
    return SSL_TLSEXT_ERR_OK;
}

static void wait_for_nts_ke(AEADKey c2s, AEADKey s2c) {
    /* configure TLS */

    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    assert(ctx);

    assert(SSL_CTX_use_certificate_chain_file(ctx, "server.crt") > 0);
    assert(SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) > 0);

    SSL_CTX_set_alpn_select_cb(ctx, alpn_select, NULL);

    SSL *tls = SSL_new(ctx);
    assert(tls);

    /* await the TCP connect */
    BIO *acceptor = BIO_new_accept("4460");
    assert(acceptor);
    assert(BIO_do_accept(acceptor) > 0);
    assert(BIO_do_accept(acceptor) > 0);
    BIO *bio = BIO_pop(acceptor);
    close(BIO_get_fd(acceptor, NULL));

    assert(bio);

    SSL_set_bio(tls, bio, bio);

    assert(SSL_accept(tls) > 0);

    /* read the NTS packet */
    struct NTS_Agreement NTS;
    int readbytes;
    uint8_t buf[1280];
    readbytes = SSL_read(tls, buf, sizeof(buf));
    assert(readbytes > 0);

    if (NTS_decode_response(buf, readbytes, &NTS) < 0) {
        printf("NTS error: %s (read %d bytes)\n", NTS_error_string(NTS.error), readbytes);
        abort();
    }

    /* store the key */
    assert(NTS_TLS_extract_keys((void*)tls, algo, c2s, s2c, sizeof(AEADKey)) == 0);

    /* send a static reply */
    const char ntphost[] = "127.0.0.01";
    static_assert(strlen(ntphost) == 10, "sanity check failed");

    uint16_t reply[] = {
        htobe16(6/*NTPv4Server*/),   htobe16(10), 0,0,0,0,0, /* filled in below */
        htobe16(1/*NextProto*/),     htobe16(2), htobe16(0),
        htobe16(4/*AEADAlgorithm*/), htobe16(2), htobe16(algo),
        htobe16(7/*NTPv4Port*/),     htobe16(2), htobe16(12345),
        /* only send 2 cookies just to see what happens */
        htobe16(5/*NTPv4Cookie*/),   htobe16(4), htobe16(0), htobe16(1),
        htobe16(5/*NTPv4Cookie*/),   htobe16(4), htobe16(0), htobe16(2),
        htobe16(0/*EndOfMessage*/ | 0x8000),  htobe16(0),
    };
    memcpy(reply+2, ntphost, sizeof(ntphost));

    SSL_write(tls, reply, sizeof(reply));
    SSL_free(tls);
    SSL_CTX_free(ctx);
}

int main(void) {
    AEADKey c2s, s2c;

    printf("KE: ");
    wait_for_nts_ke(c2s, s2c);
    puts("OK");

    printf("NTP: ");
    serve_ntp_request(c2s, s2c);
    puts("OK");

    return 0;
}
