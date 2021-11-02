#pragma once

#include "types.h"

#include <cstdint>
#include <optional>
#include <string_view>

#include <lmdb++.h>

namespace ns1::pktvisor {

using domain_name_view = binary_view;

/**
 * OrgIDDatabase provides lookup of organization ID by domain name.
 */
class OrgIDDatabase
{
public:
    OrgIDDatabase() = default;
    virtual ~OrgIDDatabase() = default;

    /**
     * Find organization by DNS name.
     *
     * @param name DNS name in wire format.
     * @return Organization ID or nullopt if not found.
     */
    virtual std::optional<uint64_t> lookup_by_name(domain_name_view name) = 0;
};

/**
 * EmptyOrgIDDatabase is a placeholder database that has no organization ID information.
 */
class EmptyOrgIDDatabase : public OrgIDDatabase
{
public:
    std::optional<uint64_t> lookup_by_name(domain_name_view) override
    {
        return std::nullopt;
    }
};

/**
 * LMDBOrgIDDatabase is organization ID database backed up by LMDB.
 */
class LMDBOrgIDDatabase : public OrgIDDatabase
{
    lmdb::env _env;
    lmdb::dbi _dbi;

public:
    LMDBOrgIDDatabase(const char *path);
    ~LMDBOrgIDDatabase() = default;

    // non-copyable
    LMDBOrgIDDatabase(const LMDBOrgIDDatabase &) = delete;
    LMDBOrgIDDatabase &operator=(const LMDBOrgIDDatabase &) = delete;

    // movable
    LMDBOrgIDDatabase(LMDBOrgIDDatabase &&) = default;
    LMDBOrgIDDatabase &operator=(LMDBOrgIDDatabase &&) = default;

    std::optional<uint64_t> lookup_by_name(domain_name_view name) override;
};

namespace internal {

binary normalize_lookup_name(const binary_view &name);
binary encode_lookup_format(const binary_view &name);

}; // namespace internal

}; // namespace ns1::pktvisor
