#include "orgid_db.h"

#include <cassert>
#include <stdexcept>
#include <vector>

#include <lmdb++.h>

using namespace ns1::pktvisor;

// Single-byte prefix for data keys in LMDB.
const uint8_t DATA_PREFIX = 1;

LMDBOrgIDDatabase::LMDBOrgIDDatabase(const char *path)
    : _env{nullptr}
    , _dbi{0}
{
    _env = lmdb::env::create();
    _env.open(path, MDB_RDONLY|MDB_NORDAHEAD, 0755);

    auto txn = lmdb::txn::begin(_env, nullptr, MDB_RDONLY);
    _dbi = lmdb::dbi::open(txn);
    txn.commit();
}

static std::optional<uint64_t> decode_id(const lmdb::val &data)
{
    if (data.size() != sizeof(uint64_t)) {
        return std::nullopt;
    }

    uint64_t id = 0;
    std::memmove(&id, data.data(), sizeof(uint64_t));
    return be64toh(id);
}

/**
 * Create buffer for the full search key.
 *
 * For given domain name, the buffer will be <data-prefix><name-in-lookup-format>.
 */
static std::vector<uint8_t> create_search_buffer(domain_name_view name)
{
    binary lookup = internal::encode_lookup_format(name);

    std::vector<uint8_t> buffer(lookup.size() + 1, 0);
    buffer[0] = DATA_PREFIX;
    memmove(&buffer[1], lookup.data(), lookup.size());

    return buffer;
}


/**
 * Check if the key is the data key.
 */
static bool is_data_key(const lmdb::val &key)
{
    return key.size() > 0 && key.data()[0] == DATA_PREFIX;
}

/**
 * Check if two LMDB values are equal.
 */
static bool is_equal_value(const lmdb::val &a, const lmdb::val &b)
{
    return a.size() == b.size() && memcmp(a.data(), b.data(), a.size()) == 0;
}

/**
 * Determine common suffix of two data keys.
 */
static size_t key_common_suffix(const lmdb::val &a, const lmdb::val &b)
{
    size_t result = 0;

    assert(is_data_key(a));
    assert(is_data_key(b));

    // The keys are stored in the lookup format:
    // www.example.com will be stored as 0x01 com 0x00 example 0x00 www 0x00
    //
    // We will scan the names starting at offset 1 skipping the data key prefix
    // and we will mark position of the last matching zero label which is the
    // DNS label boundary.
    for (size_t i = 1; i < a.size() && i < b.size(); i++) {
        // interrupt if label starts to differ
        if (a.data<uint8_t>()[i] != b.data<uint8_t>()[i]) {
            break;
        }

        // mark the position if found the end of the label
        if (a.data<uint8_t>()[i] == '\0') {
            result = i + 1;
        }
    }

    return result;
}


std::optional<uint64_t> LMDBOrgIDDatabase::lookup_by_name(domain_name_view name)
{
    const std::vector<uint8_t> buffer = create_search_buffer(name);

    lmdb::txn txn = lmdb::txn::begin(_env, nullptr, MDB_RDONLY);
    lmdb::cursor cursor = lmdb::cursor::open(txn, _dbi);

    lmdb::val search{buffer.data(), buffer.size()};
    for (;;) {
        lmdb::val key{search.data(), search.size()};
        lmdb::val value{nullptr, 0};

        // get the equal or the first greater-than key
        bool found = cursor.get(key, value, MDB_SET_RANGE);

        // exact match means we found the zone
        if (found && is_equal_value(search, key)) {
            return decode_id(value);
        }

        // move the cursor back to get the first lesser-than key
        if (found) {
            found = cursor.get(key, value, MDB_PREV);
        } else {
            found = cursor.get(key, value, MDB_LAST);
        }

        // zone doesn't exist if there is no candidate key
        if (!found || !is_data_key(key)) {
            return std::nullopt;
        }

        // determine the longest matching suffix
        size_t search_len = key_common_suffix(search, key);

        // zone doesn't exist if there is no overlap
        if (search_len == 0) {
            return std::nullopt;
        }

        // we got a zone match if the whole key is a suffix
        if (search_len == key.size()) {
            return decode_id(value);
        }

        // retry the search just with the matching suffix
        assert(search_len < search.size());
        search.assign(buffer.data(), search_len);
    }
}

/**
 * Take domain name in DNS wire format, remove all leading labels that contain
 * a zero byte, and turn all upper-case ASCII characters into lower-case ones.
 *
 * @param name DNS name in wire format.
 * @return Canonical DNS name in wire format.
 */
binary internal::normalize_lookup_name(const binary_view &name)
{
    binary result(name);
    auto skip = result.begin();

    auto it = result.begin();
    while (it < result.end() && *it != 0) {
        uint8_t len = *it;
        if (len & 0xc0) {
            throw std::invalid_argument("expected name without compression");
        }
        it++;

        auto next = it + static_cast<size_t>(len);
        if (next >= result.cend()) {
            throw std::invalid_argument("label exceeds buffer");
        }

        while (it < next) {
            // The format doesn't support zero bytes in domain name. In case we
            // encounter it, skip all previous labels and use just the suffix.
            if (*it == '\0') {
                skip = next;
                it = next;
                break;
            }

            // Normalize to lowercase ASCII
            if (*it >= 'A' && *it <= 'Z') {
                *it |= 0x20;
            }

            it++;
        }
    }

    if (it + 1 != result.end()) {
        throw std::invalid_argument("wrong name termination");
    }

    result.erase(result.begin(), skip);

    return result;
}

/**
 * Convert DNS name in wire format to the LMDB lookup format.
 * @param wire DNS name in wire format.
 * @return DNS name in LMDB lookup format.
 */
binary internal::encode_lookup_format(const binary_view &wire)
{
    const binary name = normalize_lookup_name(wire);

    binary result;
    result.reserve(name.length());

    for (auto it = name.cbegin(); it < name.cend() && *it > 0; /* explicit */) {
        uint8_t len = *it;
        assert(len < 64);

        auto label = it + 1;
        auto next = label + static_cast<size_t>(len);
        assert(next < name.cend());

        result.insert(result.begin(), 1, '\0');
        result.insert(result.begin(), label, next);

        it = next;
    }

    return result;
}
