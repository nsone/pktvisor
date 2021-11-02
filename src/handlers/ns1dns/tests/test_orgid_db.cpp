#include "orgid_db.h"

#include <catch2/catch.hpp>
#include "tests/temp_dir.h"

#include <lmdb++.h>

using binary = std::basic_string<uint8_t>;

static binary operator""_bin(const char *data, size_t size)
{
    return binary(reinterpret_cast<const binary::value_type *>(data), size);
}

TEST_CASE("Organization ID lookup", "[orgid][lmdb]")
{
    SECTION("Empty implementation")
    {
        ns1::pktvisor::EmptyOrgIDDatabase db;
        auto id = db.lookup_by_name("\007example\003com\000"_bin);
        CHECK(!id);
    }

    SECTION("LMDB implementation")
    {
        temporary_dir dir("test_orgid_db.XXXXXXX");

        // generate fixture
        {
            auto id = [](uint8_t v) {
                return binary{0, 0, 0, 0, 0, 0, 0, v};
            };

            const struct {
                binary key;
                binary value;
            } data[] = {
                // meta
                {"\000meta"_bin, "{}"_bin},
                // data
                {"\001arpa\000ip6\0002\0000\0000\0001\0000\000d\000b\0008\0001\000"_bin, id(7)},
                {"\001arpa\000ip6\0002\0000\0000\0001\0000\000d\000b\0008\0002\000"_bin, id(8)},
                {"\001com\000"_bin, id(1)},
                {"\001com\0example\0"_bin, id(2)},
                {"\001com\0example\0foo\0"_bin, id(3)},
                {"\001com\0example\0www\0"_bin, id(4)},
                {"\001test\0"_bin, id(5)},
                {"\001tld\0"_bin, id(6)},
                // unrelated values
                {"\002garbage"_bin, "trash"_bin},
            };

            auto db = lmdb::env::create();
            db.set_mapsize(1024 * 1024); // 1 MB
            db.open(dir.path().c_str());

            auto txn = lmdb::txn::begin(db, nullptr, 0);
            auto dbi = lmdb::dbi::open(txn);

            for (auto &kv : data) {
                lmdb::val key{kv.key.data(), kv.key.size()};
                lmdb::val val{kv.value.data(), kv.value.size()};
                dbi.put(txn, key, val);
            }

            txn.commit();
            db.close();
        }

        const struct {
            const char *name;
            binary in;
            uint64_t expect;
        } tests[] = {
            // most common use cases
            {"example.com", "\007example\003com\000"_bin, 2},
            {"sub.example.com", "\003sub\007example\003com\000"_bin, 2},
            {"wwa.example.com", "\003wwa\007example\003com\000"_bin, 2},
            {"www.example.com", "\003www\007example\003com\000"_bin, 4},
            {"wwz.example.com", "\003wwz\007example\003com\000"_bin, 2},
            {"wwww.example.com", "\004wwww\007example\003com\000"_bin, 2},
            {"a.ww.example.com", "\001a\002ww\007example\003com\000"_bin, 2},
            {"www.test", "\003www\004test\000"_bin, 5},
            // root and TLD
            {"test", "\004test\000"_bin, 5},
            {"root", "\000"_bin, 0},
            // non-existence
            {"tes", "\003tes\000"_bin, 0},
            {"testa", "\005testa\000"_bin, 0},
            {"www.a", "\003www\001a\000"_bin, 0},
            {"www.z", "\003www\001z\000"_bin, 0},
            // reverse zones
            {
                "2001:db8:1000::cafe",
                "\x01\x65\x01\x66\x01\x61\x01\x63\x01\x30\x01\x30\x01\x30\x01\x30" \
                "\x01\x30\x01\x30\x01\x30\x01\x30\x01\x30\x01\x30\x01\x30\x01\x30" \
                "\x01\x30\x01\x30\x01\x30\x01\x30\x01\x30\x01\x30\x01\x30\x01\x31" \
                "\x01\x38\x01\x62\x01\x64\x01\x30\x01\x31\x01\x30\x01\x30\x01\x32" \
                "\x03\x69\x70\x36\x04\x61\x72\x70\x61\x00"_bin,
                7,
            },
            {
                "2001:db8:2000::cafe",
                "\x01\x65\x01\x66\x01\x61\x01\x63\x01\x30\x01\x30\x01\x30\x01\x30" \
                "\x01\x30\x01\x30\x01\x30\x01\x30\x01\x30\x01\x30\x01\x30\x01\x30" \
                "\x01\x30\x01\x30\x01\x30\x01\x30\x01\x30\x01\x30\x01\x30\x01\x32" \
                "\x01\x38\x01\x62\x01\x64\x01\x30\x01\x31\x01\x30\x01\x30\x01\x32" \
                "\x03\x69\x70\x36\x04\x61\x72\x70\x61\x00"_bin,
                8,
            },
            {
                "2001:db8:3000::cafe",
                "\x01\x65\x01\x66\x01\x61\x01\x63\x01\x30\x01\x30\x01\x30\x01\x30" \
                "\x01\x30\x01\x30\x01\x30\x01\x30\x01\x30\x01\x30\x01\x30\x01\x30" \
                "\x01\x30\x01\x30\x01\x30\x01\x30\x01\x30\x01\x30\x01\x30\x01\x33" \
                "\x01\x38\x01\x62\x01\x64\x01\x30\x01\x31\x01\x30\x01\x30\x01\x32" \
                "\x03\x69\x70\x36\x04\x61\x72\x70\x61\x00"_bin,
                0,
            },
            // zero bytes treatment
            {"w\\000w.example.com", "\003w\0w\007example\003com\000"_bin, 2},
            // input normalization
            {"FOO.EXAMPLE.COM", "\003FOO\007EXAMPLE\003COM\000"_bin, 3},
        };

        ns1::pktvisor::LMDBOrgIDDatabase cache(dir.path().c_str());

        for (auto &t : tests) {
            INFO("name " << t.name);
            auto got = cache.lookup_by_name(t.in).value_or(0);
            CHECK(got == t.expect);
        }
    }
}
