/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "hexdecoct.h"
#include "log.h"
#include "resolved-dns-packet.h"
#include "tests.h"

TEST(dns_packet_new) {
        size_t i;
         _cleanup_(dns_packet_unrefp) DnsPacket *p2 = NULL;

        for (i = 0; i <= DNS_PACKET_SIZE_MAX; i++) {
                _cleanup_(dns_packet_unrefp) DnsPacket *p = NULL;

                assert_se(dns_packet_new(&p, DNS_PROTOCOL_DNS, i, DNS_PACKET_SIZE_MAX) == 0);

                log_debug("dns_packet_new: %zu → %zu", i, p->allocated);
                assert_se(p->allocated >= MIN(DNS_PACKET_SIZE_MAX, i));

                if (i > DNS_PACKET_SIZE_START + 10 && i < DNS_PACKET_SIZE_MAX - 10)
                        i = MIN(i * 2, DNS_PACKET_SIZE_MAX - 10);
        }

        assert_se(dns_packet_new(&p2, DNS_PROTOCOL_DNS, DNS_PACKET_SIZE_MAX + 1, DNS_PACKET_SIZE_MAX) == -EFBIG);
}

TEST(naptr) {
        _cleanup_(dns_packet_unrefp) DnsPacket *p = NULL;

        static const char twilio_reply[] =
                "Sq+BgAABAAkAAAABBnR3aWxpbwNjb20AACMAAcAMACMAAQAABwgAMgAUAAoBUwdTSVArRDJUAARf"
                "c2lwBF90Y3AEcHN0bgdpZTEtdG54BnR3aWxpbwNjb20AwAwAIwABAAAHCAAyAAoACgFTB1NJUCtE"
                "MlUABF9zaXAEX3VkcARwc3RuB3VzMi10bngGdHdpbGlvA2NvbQDADAAjAAEAAAcIADQAFAAKAVMI"
                "U0lQUytEMlQABV9zaXBzBF90Y3AEcHN0bgd1czEtdG54BnR3aWxpbwNjb20AwAwAIwABAAAHCAAy"
                "AAoACgFTB1NJUCtEMlUABF9zaXAEX3VkcARwc3RuB2llMS10bngGdHdpbGlvA2NvbQDADAAjAAEA"
                "AAcIADIAFAAKAVMHU0lQK0QyVAAEX3NpcARfdGNwBHBzdG4HdXMyLXRueAZ0d2lsaW8DY29tAMAM"
                "ACMAAQAABwgANAAUAAoBUwhTSVBTK0QyVAAFX3NpcHMEX3RjcARwc3RuB3VzMi10bngGdHdpbGlv"
                "A2NvbQDADAAjAAEAAAcIADQAFAAKAVMIU0lQUytEMlQABV9zaXBzBF90Y3AEcHN0bgdpZTEtdG54"
                "BnR3aWxpbwNjb20AwAwAIwABAAAHCAAyAAoACgFTB1NJUCtEMlUABF9zaXAEX3VkcARwc3RuB3Vz"
                "MS10bngGdHdpbGlvA2NvbQDADAAjAAEAAAcIADIAFAAKAVMHU0lQK0QyVAAEX3NpcARfdGNwBHBz"
                "dG4HdXMxLXRueAZ0d2lsaW8DY29tAAAAKQIAAAAAAAAA";

        static const char twilio_reply_string[] =
                "20 10 \"S\" \"SIP+D2T\" \"\" _sip._tcp.pstn.ie1-tnx.twilio.com.\n"
                "10 10 \"S\" \"SIP+D2U\" \"\" _sip._udp.pstn.us2-tnx.twilio.com.\n"
                "20 10 \"S\" \"SIPS+D2T\" \"\" _sips._tcp.pstn.us1-tnx.twilio.com.\n"
                "10 10 \"S\" \"SIP+D2U\" \"\" _sip._udp.pstn.ie1-tnx.twilio.com.\n"
                "20 10 \"S\" \"SIP+D2T\" \"\" _sip._tcp.pstn.us2-tnx.twilio.com.\n"
                "20 10 \"S\" \"SIPS+D2T\" \"\" _sips._tcp.pstn.us2-tnx.twilio.com.\n"
                "20 10 \"S\" \"SIPS+D2T\" \"\" _sips._tcp.pstn.ie1-tnx.twilio.com.\n"
                "10 10 \"S\" \"SIP+D2U\" \"\" _sip._udp.pstn.us1-tnx.twilio.com.\n"
                "20 10 \"S\" \"SIP+D2T\" \"\" _sip._tcp.pstn.us1-tnx.twilio.com.\n";

        static const char twilio_reply_json[] =
                "[\n"
                "        {\n"
                "               \"key\" : {\n"
                "                       \"class\" : 1,\n"
                "                       \"type\" : 35,\n"
                "                       \"name\" : \"twilio.com\"\n"
                "               },\n"
                "               \"order\" : 20,\n"
                "               \"preference\" : 10,\n"
                "               \"naptrFlags\" : \"S\",\n"
                "               \"services\" : \"SIP+D2T\",\n"
                "               \"regexp\" : \"\",\n"
                "               \"replacement\" : \"_sip._tcp.pstn.ie1-tnx.twilio.com\"\n"
                "       },\n"
                "       {\n"
                "               \"key\" : {\n"
                "                       \"class\" : 1,\n"
                "                       \"type\" : 35,\n"
                "                       \"name\" : \"twilio.com\"\n"
                "               },\n"
                "               \"order\" : 10,\n"
                "               \"preference\" : 10,\n"
                "               \"naptrFlags\" : \"S\",\n"
                "               \"services\" : \"SIP+D2U\",\n"
                "               \"regexp\" : \"\",\n"
                "               \"replacement\" : \"_sip._udp.pstn.us2-tnx.twilio.com\"\n"
                "       },\n"
                "       {\n"
                "               \"key\" : {\n"
                "                       \"class\" : 1,\n"
                "                       \"type\" : 35,\n"
                "                       \"name\" : \"twilio.com\"\n"
                "               },\n"
                "               \"order\" : 20,\n"
                "               \"preference\" : 10,\n"
                "               \"naptrFlags\" : \"S\",\n"
                "               \"services\" : \"SIPS+D2T\",\n"
                "               \"regexp\" : \"\",\n"
                "               \"replacement\" : \"_sips._tcp.pstn.us1-tnx.twilio.com\"\n"
                "       },\n"
                "       {\n"
                "               \"key\" : {\n"
                "                       \"class\" : 1,\n"
                "                       \"type\" : 35,\n"
                "                       \"name\" : \"twilio.com\"\n"
                "               },\n"
                "               \"order\" : 10,\n"
                "               \"preference\" : 10,\n"
                "               \"naptrFlags\" : \"S\",\n"
                "               \"services\" : \"SIP+D2U\",\n"
                "               \"regexp\" : \"\",\n"
                "               \"replacement\" : \"_sip._udp.pstn.ie1-tnx.twilio.com\"\n"
                "       },\n"
                "       {\n"
                "               \"key\" : {\n"
                "                       \"class\" : 1,\n"
                "                       \"type\" : 35,\n"
                "                       \"name\" : \"twilio.com\"\n"
                "               },\n"
                "               \"order\" : 20,\n"
                "               \"preference\" : 10,\n"
                "               \"naptrFlags\" : \"S\",\n"
                "               \"services\" : \"SIP+D2T\",\n"
                "               \"regexp\" : \"\",\n"
                "               \"replacement\" : \"_sip._tcp.pstn.us2-tnx.twilio.com\"\n"
                "       },\n"
                "       {\n"
                "               \"key\" : {\n"
                "                       \"class\" : 1,\n"
                "                       \"type\" : 35,\n"
                "                       \"name\" : \"twilio.com\"\n"
                "               },\n"
                "               \"order\" : 20,\n"
                "               \"preference\" : 10,\n"
                "               \"naptrFlags\" : \"S\",\n"
                "               \"services\" : \"SIPS+D2T\",\n"
                "               \"regexp\" : \"\",\n"
                "               \"replacement\" : \"_sips._tcp.pstn.us2-tnx.twilio.com\"\n"
                "       },\n"
                "       {\n"
                "               \"key\" : {\n"
                "                       \"class\" : 1,\n"
                "                       \"type\" : 35,\n"
                "                       \"name\" : \"twilio.com\"\n"
                "               },\n"
                "               \"order\" : 20,\n"
                "               \"preference\" : 10,\n"
                "               \"naptrFlags\" : \"S\",\n"
                "               \"services\" : \"SIPS+D2T\",\n"
                "               \"regexp\" : \"\",\n"
                "               \"replacement\" : \"_sips._tcp.pstn.ie1-tnx.twilio.com\"\n"
                "       },\n"
                "       {\n"
                "               \"key\" : {\n"
                "                       \"class\" : 1,\n"
                "                       \"type\" : 35,\n"
                "                       \"name\" : \"twilio.com\"\n"
                "               },\n"
                "               \"order\" : 10,\n"
                "               \"preference\" : 10,\n"
                "               \"naptrFlags\" : \"S\",\n"
                "               \"services\" : \"SIP+D2U\",\n"
                "               \"regexp\" : \"\",\n"
                "               \"replacement\" : \"_sip._udp.pstn.us1-tnx.twilio.com\"\n"
                "       },\n"
                "       {\n"
                "               \"key\" : {\n"
                "                       \"class\" : 1,\n"
                "                       \"type\" : 35,\n"
                "                       \"name\" : \"twilio.com\"\n"
                "               },\n"
                "               \"order\" : 20,\n"
                "               \"preference\" : 10,\n"
                "               \"naptrFlags\" : \"S\",\n"
                "               \"services\" : \"SIP+D2T\",\n"
                "               \"regexp\" : \"\",\n"
                "               \"replacement\" : \"_sip._tcp.pstn.us1-tnx.twilio.com\"\n"
                "       }\n"
                "]\n";

        _cleanup_free_ void *buf = NULL;
        size_t sz = 0;

        assert_se(unbase64mem(twilio_reply, &buf, &sz) >= 0);

        assert_se(dns_packet_new(&p, DNS_PROTOCOL_DNS, sz, DNS_PACKET_SIZE_MAX) == 0);
        assert_se(p->allocated >= sz);

        memcpy(DNS_PACKET_DATA(p), buf, sz);
        p->size = sz;

        assert_se(dns_packet_extract(p) >= 0);

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *a = NULL;
        _cleanup_free_ char *joined = NULL;
        DnsResourceRecord *rr;
        DNS_ANSWER_FOREACH(rr, p->answer) {
                const char *s;

                s = ASSERT_PTR(dns_resource_record_to_string(rr));
                printf("%s\n", s);

                assert_se(strextend(&joined, s, "\n"));

                _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
                assert_se(dns_resource_record_to_json(rr, &v) >= 0);

                assert_se(sd_json_variant_append_array(&a, v) >= 0);
        }

        assert(streq(joined, twilio_reply_string));

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *parsed = NULL;
        assert_se(sd_json_parse(twilio_reply_json, /* flags= */ 0, &parsed, /* ret_line= */ NULL, /* ret_column= */ NULL) >= 0);

        assert_se(sd_json_variant_equal(parsed, a));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
