#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#
# Usage:
#   # Pull the latest list and regenerate the header:
#   curl -o tests/public_suffix_list.dat https://publicsuffix.org/list/public_suffix_list.dat
#   python3 generate_psl.py
#
# The script reads tests/public_suffix_list.dat (ICANN section only),
# builds the ICANN_DOMAINS map, and overwrites PublicSuffixList.h.
#
# Wildcard entries (*.foo.bar) and exception entries (!foo.bar) are skipped
# because match_public_suffix() performs only exact sub-suffix matching.

import os
import sys
from collections import defaultdict

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DAT_FILE = os.path.join(SCRIPT_DIR, "tests", "public_suffix_list.dat")
OUT_FILE = os.path.join(SCRIPT_DIR, "PublicSuffixList.h")

HEADER = """\
// This Source Code Form is subject to the terms of the Mozilla Public
// Licensesv, v. 2.0. If a copy of the MPL was not distributed with this
// filesv, You can obtain one at https://mozilla.org/MPL/2.0/.

// Please pull this list fromsv, and only from https://publicsuffix.org/list/public_suffix_list.datsv,
// rather than any other VCS sites. Pulling from any other URL is not guaranteed to be supported.

// Instructions on pulling and using this list can be found at https://publicsuffix.org/list/.

#pragma once

#include "robin_hood.h"
#include <string_view>
#include <vector>

namespace visor::lib::dns {

using namespace std::literals;

// ===BEGIN ICANN DOMAINS===
static const robin_hood::unordered_node_map<std::string_view, std::vector<std::string_view>> ICANN_DOMAINS = {
"""

FOOTER = """\
};
// dont add newGTLDs
// ===END ICANN DOMAINS===

static inline bool ends_with(std::string_view str, std::string_view suffix)
{
    return str.size() >= suffix.size() && 0 == str.compare(str.size() - suffix.size(), suffix.size(), suffix);
}

static inline size_t match_public_suffix(std::string_view str)
{
    auto pos = str.find_last_of('.');
    if (pos == std::string::npos || (pos + 1) == str.size()) {
        return 0;
    }

    auto it = ICANN_DOMAINS.find(str.substr(pos + 1));
    if (it == ICANN_DOMAINS.end()) {
        return 0;
    }

    for (const auto &psuffix_sub : it->second) {
        if (ends_with(str, psuffix_sub)) {
            return psuffix_sub.size() + 1;
        }
    }

    return it->first.size() + 1;
}

}
"""


def parse_icann_domains(dat_path):
    """Return an ordered dict: TLD -> [sub-suffixes], only from the ICANN section."""
    domains = defaultdict(list)
    seen = set()
    order = []
    in_icann = False

    with open(dat_path, encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if line == "// ===BEGIN ICANN DOMAINS===":
                in_icann = True
                continue
            if line == "// ===END ICANN DOMAINS===" or line == "// newGTLDs":
                break
            if not in_icann or not line or line.startswith("//") or line.startswith("!") or line.startswith("*"):
                continue
            # e.g. "ac" -> TLD entry (no dot)  |  "com.ac" -> sub-suffix entry
            if "." not in line:
                tld = line
            else:
                tld = line.rsplit(".", 1)[-1]
                domains[tld].append(line)
            if tld not in seen:
                seen.add(tld)
                order.append(tld)

    return order, domains


def main():
    if not os.path.exists(DAT_FILE):
        print(f"ERROR: {DAT_FILE} not found. Run:\n  curl -o tests/public_suffix_list.dat https://publicsuffix.org/list/public_suffix_list.dat", file=sys.stderr)
        sys.exit(1)

    order, domains = parse_icann_domains(DAT_FILE)

    lines = [HEADER]
    for tld in order:
        subs = domains[tld]
        sub_str = ", ".join(f'"{s}"sv' for s in subs)
        lines.append(f'    {{"{tld}"sv, {{{sub_str}}}}},\n')
    lines.append(FOOTER)

    with open(OUT_FILE, "w", encoding="utf-8") as f:
        f.writelines(lines)

    print(f"Written {OUT_FILE}  ({len(order)} TLD entries)")


if __name__ == "__main__":
    main()
