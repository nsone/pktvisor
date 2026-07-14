#include <catch2/catch_test_macros.hpp>

#include "DnsLayer.h"
#include "DnsAdditionalRecord.h"
#include "dns.h"
#include <cstring>
#include <memory>
#include <vector>

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
        //  0x00–0x0b  12-byte DNS header (QDCOUNT=2)
        //  0x0c        label len = 4
        //  0x0d–0x10  "test"
        //  0x11        label len = 3
        //  0x12–0x14  "com"
        //  0x15        0x00  (root)
        //  0x16–0x17   QTYPE / QCLASS  (first question)
        //  0x18–0x19   compression pointer 0xC0 0x0C  → offset 0x0C  (backward: valid)
        //  0x1a–0x1b   QTYPE
        //  0x1c–0x1d   QCLASS  (second question)
        // Heap-allocated so Layer::~Layer() can safely delete[] it.
        constexpr size_t pktLen = 32;
        auto pkt = std::make_unique<uint8_t[]>(pktLen);
        memset(pkt.get(), 0, pktLen);
        write_dns_header(pkt.get(), 2); // QDCOUNT = 2
        // First QNAME: test.com
        pkt[12] = 4; memcpy(pkt.get() + 13, "test", 4);
        pkt[17] = 3; memcpy(pkt.get() + 18, "com", 3);
        pkt[21] = 0x00;
        pkt[22] = 0x00; pkt[23] = 0x01; // QTYPE
        pkt[24] = 0x00; pkt[25] = 0x01; // QCLASS
        // Second QNAME: compression pointer back to offset 12
        pkt[26] = 0xC0; pkt[27] = 0x0C;
        pkt[28] = 0x00; pkt[29] = 0x01; // QTYPE
        pkt[30] = 0x00; pkt[31] = 0x01; // QCLASS

        DnsLayer layer(pkt.release(), pktLen, nullptr, nullptr);
        CHECK(layer.parseResources(false, false, true) == true);
        auto *q = layer.getFirstQuery();
        REQUIRE(q != nullptr);
        CHECK(q->getName() == "test.com");
    }

    SECTION("forward compression pointer is rejected (RFC 9267 §2)")
    {
        // Compression pointer at offset 12 pointing forward to offset 14
        // (14 > 12, so it is a forward pointer — must be rejected).
        constexpr size_t pktLen = 24;
        auto pkt = std::make_unique<uint8_t[]>(pktLen);
        memset(pkt.get(), 0, pktLen);
        write_dns_header(pkt.get());
        // QNAME starts at offset 12: 0xC0 0x0E → points to offset 14 (forward)
        pkt[12] = 0xC0; pkt[13] = 0x0E;
        pkt[14] = 3; memcpy(pkt.get() + 15, "com", 3);
        pkt[18] = 0x00;
        pkt[19] = 0x00; pkt[20] = 0x01; // QTYPE
        pkt[21] = 0x00; pkt[22] = 0x01; // QCLASS

        DnsLayer layer(pkt.release(), pktLen, nullptr, nullptr);
        CHECK(layer.parseResources(false, false, true) == false);
    }

    SECTION("self-referential pointer loop is rejected (RFC 9267 §2)")
    {
        // Pointer at offset 12 that points back to itself (offset 12).
        // offsetInLayer (12) == curOffsetInLayer (12) → rejected.
        constexpr size_t pktLen = 20;
        auto pkt = std::make_unique<uint8_t[]>(pktLen);
        memset(pkt.get(), 0, pktLen);
        write_dns_header(pkt.get());
        pkt[12] = 0xC0; pkt[13] = 0x0C; // points to offset 12
        pkt[14] = 0x00; pkt[15] = 0x01; // QTYPE
        pkt[16] = 0x00; pkt[17] = 0x01; // QCLASS

        DnsLayer layer(pkt.release(), pktLen, nullptr, nullptr);
        CHECK(layer.parseResources(false, false, true) == false);
    }
}

TEST_CASE("RFC 9267 §3 — label length validation", "[dns][rfc9267]")
{
    SECTION("label length <= 63 is accepted")
    {
        // Single label of exactly 3 characters: "abc"
        constexpr size_t pktLen = 22;
        auto pkt = std::make_unique<uint8_t[]>(pktLen);
        memset(pkt.get(), 0, pktLen);
        write_dns_header(pkt.get());
        size_t len = append_plain_qname(pkt.get(), 12, "abc", 3);
        DnsLayer layer(pkt.release(), len, nullptr, nullptr);
        CHECK(layer.parseResources(false, false, true) == true);
        auto *q = layer.getFirstQuery();
        REQUIRE(q != nullptr);
        CHECK(q->getName() == "abc");
    }

    SECTION("label length > 63 is rejected (RFC 9267 §3 / RFC 1035 §2.3.4)")
    {
        // Label length byte set to 64 — exceeds the RFC 1035 maximum of 63.
        constexpr size_t pktLen = 12 + 1 + 64 + 1 + 4; // header + len + 64 bytes + NUL + QTYPE/QCLASS
        auto pkt = std::make_unique<uint8_t[]>(pktLen);
        memset(pkt.get(), 0, pktLen);
        write_dns_header(pkt.get());
        pkt[12] = 64;
        memset(pkt.get() + 13, 'a', 64);
        pkt[77] = 0x00;
        pkt[78] = 0x00; pkt[79] = 0x01;
        pkt[80] = 0x00; pkt[81] = 0x01;

        DnsLayer layer(pkt.release(), pktLen, nullptr, nullptr);
        CHECK(layer.parseResources(false, false, true) == false);
    }
}

// ---------------------------------------------------------------------------
// parse_additional_records_ecs — stack-overflow regression (CVE-class fix)
//
// A crafted OPT/ECS record whose address payload exceeds 4 bytes for IPv4
// used to overflow the 4-byte stack buffer via the unguarded loop.
// The fix clamps the loop bound with std::min(size, offset + IPV4_BYTE_SIZE).
// ---------------------------------------------------------------------------

// Build a minimal OPT record wire payload with an ECS (EDNS Client Subnet)
// option whose address bytes may be oversized.
//
// OPT RDATA layout (rfc6891 / rfc7871):
//   [0..1]  option-code  (CSUBNET = 8)
//   [2..3]  option-length (total bytes following, i.e. 4 + addr_bytes)
//   [4..5]  family (1 = IPv4)
//   [6]     source-netmask
//   [7]     scope-netmask
//   [8..]   address bytes (variable)
static std::vector<uint8_t> make_ecs_rdata(uint8_t addr_byte_count, uint8_t src_prefix = 24)
{
    // option-length covers family(2) + src_mask(1) + scope_mask(1) + addr_bytes
    uint16_t opt_len = static_cast<uint16_t>(4 + addr_byte_count);
    std::vector<uint8_t> rdata;
    // The parser reads: be16toh((array[1]<<8)|array[0]), so fields must be
    // stored with array[0]=hi-byte, array[1]=lo-byte (i.e. big-endian / network order).
    // option_code = 8 (CSUBNET): hi=0x00, lo=0x08
    rdata.push_back(0x00); rdata.push_back(0x08);
    // option_length: big-endian
    rdata.push_back(static_cast<uint8_t>(opt_len >> 8));
    rdata.push_back(static_cast<uint8_t>(opt_len & 0xFF));
    // family = 1 (IPv4): hi=0x00, lo=0x01
    rdata.push_back(0x00); rdata.push_back(0x01);
    // source_netmask, scope_netmask
    rdata.push_back(src_prefix); rdata.push_back(0x00);
    // address bytes (filled with 0xAB for distinctiveness)
    for (uint8_t i = 0; i < addr_byte_count; i++) {
        rdata.push_back(0xAB);
    }
    return rdata;
}

TEST_CASE("parse_additional_records_ecs — IPv4 overflow regression", "[dns][ecs]")
{
    // We exercise parse_additional_records_ecs directly by constructing a
    // DnsResource that reports a specific data length through a raw buffer.
    // The simplest approach is to build the whole DNS wire packet so that
    // parseResources() populates m_FirstAdditional, then call the function.

    // DNS wire layout:
    //   12 bytes  header  (QR=1 response, QDCOUNT=1, ARCOUNT=1)
    //   QNAME "." (single 0x00 byte) + QTYPE + QCLASS
    //   OPT RR in the additional section

    // OPT RR format (no name = 0x00, TYPE=41, CLASS=payload-size, TTL=ext-rcode+flags, RDLENGTH, RDATA)
    auto build_dns_with_ecs = [](const std::vector<uint8_t> &ecs_rdata) -> std::pair<std::unique_ptr<uint8_t[]>, size_t> {
        // Minimise QNAME: single root label 0x00, QTYPE A (1), QCLASS IN (1)
        // Header: ID=1, QR=1 (response), QDCOUNT=1, ARCOUNT=1
        std::vector<uint8_t> pkt;
        pkt.resize(12, 0);
        pkt[0] = 0x00; pkt[1] = 0x01; // ID
        pkt[2] = 0x80; pkt[3] = 0x00; // QR=1
        pkt[4] = 0x00; pkt[5] = 0x01; // QDCOUNT=1
        // ARCOUNT=1 at bytes 10-11
        pkt[10] = 0x00; pkt[11] = 0x01;

        // QNAME: root (0x00), QTYPE=1, QCLASS=1
        pkt.push_back(0x00);
        pkt.push_back(0x00); pkt.push_back(0x01); // QTYPE A
        pkt.push_back(0x00); pkt.push_back(0x01); // QCLASS IN

        // OPT RR: NAME=0x00, TYPE=41 (OPT), CLASS=512 (UDP payload), TTL=0, RDLENGTH, RDATA
        pkt.push_back(0x00); // NAME = root
        pkt.push_back(0x00); pkt.push_back(0x29); // TYPE = 41 (OPT)
        pkt.push_back(0x02); pkt.push_back(0x00); // CLASS = 512 (UDP payload size)
        pkt.push_back(0x00); pkt.push_back(0x00); pkt.push_back(0x00); pkt.push_back(0x00); // TTL = 0
        uint16_t rdlen = static_cast<uint16_t>(ecs_rdata.size());
        pkt.push_back(static_cast<uint8_t>(rdlen >> 8));
        pkt.push_back(static_cast<uint8_t>(rdlen & 0xFF));
        pkt.insert(pkt.end(), ecs_rdata.begin(), ecs_rdata.end());

        size_t sz = pkt.size();
        auto buf = std::make_unique<uint8_t[]>(sz);
        memcpy(buf.get(), pkt.data(), sz);
        return {std::move(buf), sz};
    };

    SECTION("normal IPv4 ECS (4 addr bytes) — parses without crash")
    {
        auto rdata = make_ecs_rdata(4);
        auto [buf, sz] = build_dns_with_ecs(rdata);
        DnsLayer layer(buf.release(), sz, nullptr, nullptr);
        REQUIRE(layer.parseResources(false, false, true));
        auto *add = layer.getFirstAdditionalRecord();
        REQUIRE(add != nullptr);
        auto ecs = parse_additional_records_ecs(add);
        REQUIRE(ecs != nullptr);
        CHECK(ecs->family == 1);
        CHECK(ecs->source_netmask == 24);
        // 0xAB.0xAB.0xAB.0xAB
        CHECK(ecs->client_subnet == "171.171.171.171");
    }

    SECTION("oversized IPv4 addr payload (8 bytes) — no stack overflow, returns result")
    {
        // Before the fix this would corrupt the stack and trigger __stack_chk_fail.
        auto rdata = make_ecs_rdata(8);
        auto [buf, sz] = build_dns_with_ecs(rdata);
        DnsLayer layer(buf.release(), sz, nullptr, nullptr);
        REQUIRE(layer.parseResources(false, false, true));
        auto *add = layer.getFirstAdditionalRecord();
        REQUIRE(add != nullptr);
        // Must not crash; result may or may not parse cleanly depending on data,
        // but the stack must remain intact (canary survives).
        auto ecs = parse_additional_records_ecs(add);
        // The fix clamps to 4 bytes so inet_ntop still gets a valid buffer.
        REQUIRE(ecs != nullptr);
        CHECK(ecs->family == 1);
    }

    SECTION("zero addr bytes — returns a result with empty client_subnet")
    {
        auto rdata = make_ecs_rdata(0, 0);
        auto [buf, sz] = build_dns_with_ecs(rdata);
        DnsLayer layer(buf.release(), sz, nullptr, nullptr);
        REQUIRE(layer.parseResources(false, false, true));
        auto *add = layer.getFirstAdditionalRecord();
        REQUIRE(add != nullptr);
        auto ecs = parse_additional_records_ecs(add);
        REQUIRE(ecs != nullptr);
        // No address bytes → inet_ntop runs on zeroed buffer → "0.0.0.0"
        CHECK(ecs->client_subnet == "0.0.0.0");
    }

    SECTION("IPv6 ECS (16 addr bytes) — full address decoded correctly")
    {
        // Build ECS rdata with family=2 (IPv6) and 16 address bytes.
        // Before the fix the loop bound was std::min(size, 16) which, with
        // offset=8, only ever copied bytes array[8..15] → ipv6[0..7], leaving
        // the upper 8 bytes zeroed and producing a truncated address.
        uint8_t addr_byte_count = 16;
        uint16_t opt_len = static_cast<uint16_t>(4 + addr_byte_count);
        std::vector<uint8_t> rdata;
        // big-endian (network order) to match parser: be16toh((array[1]<<8)|array[0])
        rdata.push_back(0x00); rdata.push_back(0x08); // option_code = CSUBNET (8)
        rdata.push_back(static_cast<uint8_t>(opt_len >> 8));
        rdata.push_back(static_cast<uint8_t>(opt_len & 0xFF));
        rdata.push_back(0x00); rdata.push_back(0x02); // family = 2 (IPv6)
        rdata.push_back(64);   rdata.push_back(0x00); // source/scope netmask
        // 16 address bytes encoding 2001:db8::1
        uint8_t v6[16] = {0x20,0x01,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,0x01};
        for (auto b : v6) rdata.push_back(b);

        auto [buf, sz] = build_dns_with_ecs(rdata);
        DnsLayer layer(buf.release(), sz, nullptr, nullptr);
        REQUIRE(layer.parseResources(false, false, true));
        auto *add = layer.getFirstAdditionalRecord();
        REQUIRE(add != nullptr);
        auto ecs = parse_additional_records_ecs(add);
        REQUIRE(ecs != nullptr);
        CHECK(ecs->family == 2);
        CHECK(ecs->source_netmask == 64);
        // inet_ntop canonical form for 2001:db8::1
        CHECK(ecs->client_subnet == "2001:db8::1");
    }
}
