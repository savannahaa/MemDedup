#pragma once

#include "bucket.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace memdedup {

struct PairwiseMaskSetup {
    std::vector<FieldElement> pairMaskSeeds;
};

PairwiseMaskSetup establishDirectPairMaskSeeds(std::size_t providerIdx, std::size_t providerCount,
                                               const std::string &host, std::uint16_t basePort,
                                               std::uint64_t seed);

} // namespace memdedup
