#include "orgid_db.h"

#include <catch2/catch.hpp>

using namespace ns1::pktvisor;

TEST_CASE("lookup format", "[orgid]")
{
    SECTION("normalize_lookup_name")
    {
        struct {
            std::string name;
            binary input;
            binary expect;
        } tests[] = {
            {
                "DNS1.P01.NSone.NET.",
                {4, 'D', 'N', 'S', '1', 3, 'P', '0', '1', 5, 'N', 'S', 'o', 'n', 'e', 3, 'N', 'E', 'T', 0},
                {4, 'd', 'n', 's', '1', 3, 'p', '0', '1', 5, 'n', 's', 'o', 'n', 'e', 3, 'n', 'e', 't', 0},
            },
            {
                "zero.by\\000te.test.",
                {4, 'z', 'e', 'r', 'o', 5, 'b', 'y', '\0', 't', 'e', 4, 't', 'e', 's', 't', 0},
                {4, 't', 'e', 's', 't', 0},
            },
            {
                "com.",
                {3, 'c', 'o', 'm', 0},
                {3, 'c', 'o', 'm', 0},
            },
            {
                ".",
                {0},
                {0},
            },
        };

        for (const auto &tc : tests) {
            INFO("case " << tc.name);
            auto got = internal::normalize_lookup_name(tc.input);
            CHECK(got == tc.expect);
        }
    }

    SECTION("normalize_lookup_name errors")
    {
        struct {
            std::string name;
            binary input;
        } tests[] = {
            {
                "empty buffer",
                {},
            },
            {
                "compression pointer",
                {3, 'w', 'w', 'w', 0xc0, 0x0a},
            },
            {
                "buffer overflow",
                {5, 't', 'e', 's', 't'},
            },
            {
                "missing terminating label",
                {3, 'f', 'o', 'o'},
            },
            {
                "extra trailing byte",
                {1, 'a', 0, 0},
            },
        };

        for (const auto &tc : tests) {
            INFO("case " << tc.name);
            CHECK_THROWS_AS(internal::normalize_lookup_name(tc.input), std::invalid_argument);
        }
    }

    SECTION("encode_lookup_format")
    {
        struct {
            std::string name;
            binary input;
            binary expect;
        } tests[] = {
            {
                "www.example.test.",
                {3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 4, 't', 'e', 's', 't', 0},
                {'t', 'e', 's', 't', 0, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0, 'w', 'w', 'w', 0},
            },
            {
                "root",
                {0},
                {},
            },
            {
                "net.",
                {3, 'n', 'e', 't', 0},
                {'n', 'e', 't', 0},
            },
            {
                "case.test.",
                {4, 'C', 'A', 'S', 'E', 4, 'T', 'E', 'S', 'T', 0},
                {'t', 'e', 's', 't', 0, 'c', 'a', 's', 'e', 0},
            },

        };

        for (const auto &tc : tests) {
            INFO("case " << tc.name);
            auto got = internal::encode_lookup_format(tc.input);
            CHECK(got == tc.expect);
        }
    }
}
