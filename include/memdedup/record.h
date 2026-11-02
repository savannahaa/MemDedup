#pragma once
#include "types.h"
#include <array>
#include <string>

namespace memdedup {
// Strings must already be canonicalized and encoded as valid UTF-8.
// The complete compact JSON array is padded to 64 bytes; overlength is rejected.
Item encodeTriple(const std::array<std::string, 3> &triple);
std::string decodeTripleRecord(const Item &record);
} // namespace memdedup
