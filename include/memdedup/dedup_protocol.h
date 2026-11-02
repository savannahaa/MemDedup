#pragma once

#include "bucket.h"
#include "types.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <unordered_set>
#include <vector>

namespace memdedup {

struct ProtocolParams {
    bool packedOperations = false;
    std::array<std::uint8_t, 32> encryptionKey{};
    bool hasEncryptionKey = false;
    std::size_t providerCount = 3;
    std::size_t hashCount = 3;
    std::size_t primaryBuckets = 0;
    std::size_t auxiliaryBuckets = 0;
    double auxiliaryLoadFactor = 2.0;
    std::uint64_t seed = 0x4d5053555f444544ULL; // "MPSU_DED"
    std::size_t itemBits = 512;
    std::vector<FieldElement> pairMaskSeeds;

    // Private per-provider seed for the randomization coefficient r_{i,j} in Alg. 1 line 6.
    // Providers must generate a fresh random 32-byte value locally; the cloud never receives it
    // and never populates this field. Only encodePrimary/encodeAuxiliary consume this key.
    std::array<std::uint8_t, 32> providerSecretSeed{};
    bool providerHasSecretSeed = false;
};

struct DecodeReport {
    std::unordered_set<Item> items;
    std::vector<std::size_t> unresolvedBuckets;
    std::size_t peeledCount = 0;
};

class DedupProtocol {
  public:
    explicit DedupProtocol(ProtocolParams params);

    std::vector<Bucket> encodePrimary(std::size_t providerIdx, const std::vector<Item> &items,
                                      const std::vector<Bucket> *precomputedMasks = nullptr) const;

    std::vector<Bucket>
    encodeAuxiliary(std::size_t providerIdx, const std::vector<Item> &items,
                    const std::vector<unsigned char> &unresolvedPrimary,
                    std::size_t auxiliaryBuckets,
                    const std::vector<Bucket> *precomputedMasks = nullptr) const;

    std::vector<Bucket> precomputePrimaryMasks(std::size_t providerIdx) const;
    std::vector<Bucket> precomputeAuxiliaryMasks(std::size_t providerIdx,
                                                 std::size_t auxiliaryBuckets) const;

    DecodeReport decode(std::vector<Bucket> table, std::size_t bucketCount,
                        FieldElement hashSeed) const;

    bool isAuxiliaryCandidate(const Item &item,
                              const std::vector<unsigned char> &unresolvedPrimary) const;
    std::size_t effectiveAuxiliaryBuckets(std::size_t sizingItems) const;
    FieldElement primaryHashSeed() const { return mPrimaryHashSeed; }
    FieldElement auxiliaryHashSeed() const { return mAuxiliaryHashSeed; }

  public:
    // Reversible 512-bit record cipher used before packing the operation bit.
    FieldElement encrypt(const Item &item) const;
    Item decrypt(FieldElement cipher) const;

  private:
    FieldElement tag(FieldElement cipher) const;
    FieldElement coefficient(std::size_t providerIdx, const Item &item) const;
    FieldElement pairMaskValue(FieldElement pairSeed, std::uint32_t component, std::size_t bucket,
                               FieldElement tableSalt) const;
    Bucket maskForProvider(std::size_t providerIdx, std::size_t bucket,
                           FieldElement tableSalt) const;
    std::vector<std::size_t> bucketLocations(const Item &item, std::size_t bucketCount,
                                             FieldElement hashSeed) const;
    ProtocolParams mParams;
    FieldElement mPrimaryHashSeed;
    FieldElement mAuxiliaryHashSeed;
    FieldElement mPrimaryMaskSalt;
    FieldElement mAuxiliaryMaskSalt;
    std::array<std::uint8_t, 32> mEncryptionKey{};
    std::array<std::uint8_t, 32> mPrimaryHashKey{};
    std::array<std::uint8_t, 32> mAuxiliaryHashKey{};
    std::array<std::uint8_t, 32> mTagKey{};
    std::array<std::uint8_t, 32> mCoeffKey{};
    bool mCoeffKeyReady = false;
    FieldElement mTagSeed;
};

} // namespace memdedup
