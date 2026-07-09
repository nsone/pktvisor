#include <catch2/catch_test_macros.hpp>

#include "DnsLayer.h"
#include "dns.h"
#include <cstring>

using namespace visor::lib::dns;

// ---------------------------------------------------------------------------
// Helpers for building minimal raw DNS query packets in wire format.
//
// Layout (no transport headers):
//   12 bytes  dnshdr  (fixed header)
//   QNAME     wire-encoded name
//   2 bytes   QTYPE
//   2 bytes   QCLASS
// ---------------------------------------------------------------------------

// Build a 12-byte DNS header with QDCOUNT=1, all other counts 0.
static void write_dns_header(uint8_t *buf, uint16_t qdcount = 1)
{
    memset(buf, 0, 12);
    buf[0] = 0x00; buf[1] = 0x01; // transaction ID = 1
    // flags: standard query
    buf[4] = (uint8_t)(qdcount >> 8);
    buf[5] = (uint8_t)(qdcount & 0xFF);
}

// Append wire-encoded "www.example.com\0" after the header.
// Returns total packet length.
static size_t append_plain_qname(uint8_t *buf, size_t offset, const char *label, uint8_t labellen)
{
    buf[offset++] = labellen;
    memcpy(buf + offset, label, labellen);
    offset += labellen;
    buf[offset++] = 0x00; // root label
    // QTYPE A, QCLASS IN
    buf[offset++] = 0x00; buf[offset++] = 0x01;
    buf[offset++] = 0x00; buf[offset++] = 0x01;
    return offset;
}

static std::pair<std::string, std::string> convert(const AggDomainResult &result)
{
    return {std::string(result.first), std::string(result.second)};
}

TEST_CASE("DNS Utilities", "[dns]")
{
    std::pair<std::string, std::string> result;
    std::string domain;

    SECTION("aggregateDomain")
    {
        domain = "biz.foo.bar.com";
        result = convert(aggregateDomain(domain));
        CHECK(result.first == ".bar.com");
        CHECK(result.second == ".foo.bar.com");

        domain = "a.com";
        result = convert(aggregateDomain(domain));
        CHECK(result.first == "a.com");
        CHECK(result.second == "");

        domain = "abcdefg.com.";
        result = convert(aggregateDomain(domain));
        CHECK(result.first == "abcdefg.com.");
        CHECK(result.second == "");

        domain = "foo.bar.com";
        result = convert(aggregateDomain(domain));
        CHECK(result.first == ".bar.com");
        CHECK(result.second == "foo.bar.com");

        domain = ".";
        result = convert(aggregateDomain(domain));
        CHECK(result.first == ".");
        CHECK(result.second == "");

        domain = "..";
        result = convert(aggregateDomain(domain));
        CHECK(result.first == "..");
        CHECK(result.second == "");

        domain = "a";
        result = convert(aggregateDomain(domain));
        CHECK(result.first == "a");
        CHECK(result.second == "");

        domain = "a.";
        result = convert(aggregateDomain(domain));
        CHECK(result.first == "a.");
        CHECK(result.second == "");

        domain = "foo.bar.com.";
        result = convert(aggregateDomain(domain));
        CHECK(result.first == ".bar.com.");
        CHECK(result.second == "foo.bar.com.");

        domain = ".foo.bar.com";
        result = convert(aggregateDomain(domain));
        CHECK(result.first == ".bar.com");
        CHECK(result.second == ".foo.bar.com");

        domain = "a.b.c";
        result = convert(aggregateDomain(domain));
        CHECK(result.first == ".b.c");
        CHECK(result.second == "a.b.c");

        domain = ".b.c";
        result = convert(aggregateDomain(domain));
        CHECK(result.first == ".b.c");
        CHECK(result.second == "");
    }

    SECTION("aggregateDomain with static suffix")
    {
        std::string static_suffix;

        domain = "biz.foo.bar.com";
        static_suffix = ".bar.com";
        result = convert(aggregateDomain(domain, static_suffix.size()));
        CHECK(result.first == ".foo.bar.com");
        CHECK(result.second == "biz.foo.bar.com");

        domain = "biz.foo.bar.com";
        static_suffix = "bar.com";
        result = convert(aggregateDomain(domain, static_suffix.size()));
        CHECK(result.first == ".foo.bar.com");
        CHECK(result.second == "biz.foo.bar.com");

        domain = "biz.foo.bar.com";
        static_suffix = "foo.bar.com";
        result = convert(aggregateDomain(domain, static_suffix.size()));
        CHECK(result.first == "biz.foo.bar.com");
        CHECK(result.second == "");

        domain = "foo.bar.com.";
        static_suffix = "biz.foo.bar.com";
        result = convert(aggregateDomain(domain, static_suffix.size()));
        CHECK(result.first == ".bar.com.");
        CHECK(result.second == "foo.bar.com.");

        domain = "www.google.co.uk";
        static_suffix = ".co.uk";
        result = convert(aggregateDomain(domain, static_suffix.size()));
        CHECK(result.first == ".google.co.uk");
        CHECK(result.second == "www.google.co.uk");

        domain = "www.google.co.uk";
        static_suffix = "google.co.uk";
        result = convert(aggregateDomain(domain, static_suffix.size()));
        CHECK(result.first == "www.google.co.uk");
        CHECK(result.second == "");
    }
}

// ---------------------------------------------------------------------------
// RFC 9267 §2 — forward compression pointer must be rejected
// RFC 9267 §3 — label length > 63 must be rejected
// ---------------------------------------------------------------------------

TEST_CASE("RFC 9267 §2 — compression pointer validation", "[dns][rfc9267]")
{
    SECTION("valid backward compression pointer is accepted")
    {
        // Packet layout (all offsets from byte 0):
        //  0x00–0x0b  12-byte DNS header
        //  0x0c        label len = 4
        //  0x0d–0x10  "test"
        //  0x11        label len = 3
        //  0x12–0x14  "com"
        //  0x15        0x00  (root)
        //  0x16–0x17   QTYPE / QCLASS  (first question ends here)
        //  0x18        compression pointer 0xC0 0x0C  → offset 0x0C  (backward: valid)
        //  0x1a–0x1b   QTYPE / QCLASS  (second question)
        uint8_t pkt[30];
        memset(pkt, 0, sizeof(pkt));
        write_dns_header(pkt, 2); // QDCOUNT = 2
        // First QNAME: test.com
        pkt[12] = 4; memcpy(pkt + 13, "test", 4);
        pkt[17] = 3; memcpy(pkt + 18, "com", 3);
        pkt[21] = 0x00;
        pkt[22] = 0x00; pkt[23] = 0x01; // QTYPE
        pkt[24] = 0x00; pkt[25] = 0x01; // QCLASS
        // Second QNAME: compression pointer back to offset 12
        pkt[26] = 0xC0; pkt[27] = 0x0C;
        pkt[28] = 0x00; pkt[29] = 0x01; // QTYPE
        // no QCLASS bytes — but parseResources needs name + type for queries

        DnsLayer layer(pkt, sizeof(pkt), nullptr, nullptr);
        CHECK(layer.parseResources(false, false, true) == true);
        auto *q = layer.getFirstQuery();
        REQUIRE(q != nullptr);
        CHECK(q->getName() == "test.com");
    }

    SECTION("forward compression pointer is rejected (RFC 9267 §2)")
    {
        // Compression pointer at offset 12 pointing forward to offset 14
        // (14 > 12, so it is a forward pointer — must be rejected).
        uint8_t pkt[24];
        memset(pkt, 0, sizeof(pkt));
        write_dns_header(pkt);
        // QNAME starts at offset 12: 0xC0 0x0E → points to offset 14 (forward)
        pkt[12] = 0xC0; pkt[13] = 0x0E;
        pkt[14] = 3; memcpy(pkt + 15, "com", 3);
        pkt[18] = 0x00;
        pkt[19] = 0x00; pkt[20] = 0x01; // QTYPE
        pkt[21] = 0x00; pkt[22] = 0x01; // QCLASS

        DnsLayer layer(pkt, sizeof(pkt), nullptr, nullptr);
        CHECK(layer.parseResources(false, false, true) == false);
    }

    SECTION("self-referential pointer loop is rejected (RFC 9267 §2)")
    {
        // Pointer at offset 12 that points back to itself (offset 12).
        // offsetInLayer (12) == curOffsetInLayer (12) → rejected.
        uint8_t pkt[20];
        memset(pkt, 0, sizeof(pkt));
        write_dns_header(pkt);
        pkt[12] = 0xC0; pkt[13] = 0x0C; // points to offset 12
        pkt[14] = 0x00; pkt[15] = 0x01; // QTYPE
        pkt[16] = 0x00; pkt[17] = 0x01; // QCLASS

        DnsLayer layer(pkt, sizeof(pkt), nullptr, nullptr);
        CHECK(layer.parseResources(false, false, true) == false);
    }
}

TEST_CASE("RFC 9267 §3 — label length validation", "[dns][rfc9267]")
{
    SECTION("label length <= 63 is accepted")
    {
        // Single label of exactly 3 characters: "abc"
        uint8_t pkt[22];
        memset(pkt, 0, sizeof(pkt));
        write_dns_header(pkt);
        size_t len = append_plain_qname(pkt, 12, "abc", 3);
        DnsLayer layer(pkt, len, nullptr, nullptr);
        CHECK(layer.parseResources(false, false, true) == true);
        auto *q = layer.getFirstQuery();
        REQUIRE(q != nullptr);
        CHECK(q->getName() == "abc");
    }

    SECTION("label length > 63 is rejected (RFC 9267 §3 / RFC 1035 §2.3.4)")
    {
        // Label length byte set to 64 — exceeds the RFC 1035 maximum of 63.
        uint8_t label[64];
        memset(label, 'a', 64);
        uint8_t pkt[12 + 1 + 64 + 1 + 4]; // header + len + 64 bytes + NUL + QTYPE/QCLASS
        memset(pkt, 0, sizeof(pkt));
        write_dns_header(pkt);
        pkt[12] = 64;
        memcpy(pkt + 13, label, 64);
        pkt[77] = 0x00;
        pkt[78] = 0x00; pkt[79] = 0x01;
        pkt[80] = 0x00; pkt[81] = 0x01;

        DnsLayer layer(pkt, sizeof(pkt), nullptr, nullptr);
        CHECK(layer.parseResources(false, false, true) == false);
    }
}
