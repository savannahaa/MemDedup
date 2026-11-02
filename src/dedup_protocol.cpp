#include "dedup_protocol.h"

#include "hash_util.h"

#include <algorithm>
#include <array>
#include <cmath>
#include <optional>
#include <queue>
#include <stdexcept>
#include <unordered_map>

namespace memdedup {

namespace {

struct Singleton {
    FieldElement cnt = 0;
    FieldElement cipher = 0;
};

struct CachedCipher {
    Item item;
    FieldElement tag = 0;
    std::vector<std::size_t> buckets;
};

std::size_t ceilToSize(double value) {
    if (value <= 0) {
        return 0;
    }
    return static_cast<std::size_t>(std::ceil(value));
}

void addMaskTable(std::vector<Bucket> &table, const std::vector<Bucket> &masks) {
    if (table.size() != masks.size()) {
        throw std::invalid_argument("precomputed mask table has unexpected size");
    }
    for (std::size_t bucket = 0; bucket < table.size(); ++bucket) {
        table[bucket].add(masks[bucket]);
    }
}

struct PairMaskKeys {
    bool add = true;
    std::array<Blake3Key, 3> components{};
};

template <typename Callback>
void forEachBucketLocation(const Blake3Key &hashKey, Item item, std::size_t bucketCount,
                           std::size_t hashCount, Callback callback) {
    if (bucketCount < hashCount) {
        throw std::invalid_argument("bucket count must be at least hashCount");
    }

    if (hashCount <= 16) {
        std::array<std::size_t, 16> locations{};
        std::size_t locationCount = 0;
        std::uint32_t attempt = 0;
        while (locationCount < hashCount) {
            const auto bucket = hashIndex(hashKey, item, attempt, bucketCount);
            if (std::find(locations.begin(), locations.begin() + locationCount, bucket) ==
                locations.begin() + locationCount) {
                locations[locationCount++] = bucket;
                callback(bucket);
            }
            ++attempt;
        }
        return;
    }

    std::vector<std::size_t> locations;
    locations.reserve(hashCount);
    std::uint32_t attempt = 0;
    while (locations.size() < hashCount) {
        const auto bucket = hashIndex(hashKey, item, attempt, bucketCount);
        if (std::find(locations.begin(), locations.end(), bucket) == locations.end()) {
            locations.push_back(bucket);
            callback(bucket);
        }
        ++attempt;
    }
}

std::vector<PairMaskKeys> makePairMaskKeys(std::size_t providerIdx, std::size_t providerCount,
                                           const std::vector<FieldElement> &pairSeeds,
                                           FieldElement tableSalt) {
    if (pairSeeds.size() != providerCount) {
        throw std::invalid_argument(
            "pairwise mask seeds must be established before mask generation");
    }

    std::vector<PairMaskKeys> keys;
    keys.reserve(providerCount > 0 ? providerCount - 1 : 0);
    for (std::size_t other = 0; other < providerCount; ++other) {
        if (other == providerIdx) {
            continue;
        }

        const auto baseSeed = mix(pairSeeds[other], tableSalt);
        PairMaskKeys entry;
        entry.add = providerIdx < other;
        for (std::uint32_t component = 0; component < entry.components.size(); ++component) {
            entry.components[component] = makeBlake3Key(mix(baseSeed, component), kFieldU64Purpose);
        }
        keys.push_back(entry);
    }
    return keys;
}

std::vector<Bucket> precomputeMaskTable(std::size_t providerIdx, std::size_t providerCount,
                                        const std::vector<FieldElement> &pairSeeds,
                                        std::size_t bucketCount, FieldElement tableSalt) {
    const auto pairKeys = makePairMaskKeys(providerIdx, providerCount, pairSeeds, tableSalt);
    std::vector<Bucket> masks(bucketCount);
    for (std::size_t bucket = 0; bucket < masks.size(); ++bucket) {
        Bucket mask;
        for (const auto &pairKey : pairKeys) {
            const Bucket pair{
                hashToField(pairKey.components[0], static_cast<FieldElement>(bucket)),
                hashToField(pairKey.components[1], static_cast<FieldElement>(bucket)),
                hashToField(pairKey.components[2], static_cast<FieldElement>(bucket)),
            };
            if (pairKey.add) {
                mask.add(pair);
            } else {
                mask.sub(pair);
            }
        }
        masks[bucket] = mask;
    }
    return masks;
}

bool isSupportedElementBits(std::size_t bits) { return bits == 512; }

FieldElement halfMask(std::size_t halfBits) { return (FieldElement(1) << halfBits) - 1; }

constexpr int kFeistelRounds = 4;

class DeterministicCipher {
  public:
    DeterministicCipher(const std::array<std::uint8_t, 32> &key, std::size_t elementBits)
        : mKey(key), mHalfBits(elementBits / 2), mHalfMask(halfMask(mHalfBits)) {
        if (!isSupportedElementBits(elementBits) || (elementBits % 2) != 0) {
            throw std::invalid_argument("element bit length must be 512");
        }
    }

    FieldElement encrypt(FieldElement plaintext) const {
        if (plaintext >= Field::recordDomainLimit()) {
            throw std::invalid_argument("plaintext is outside Z_q");
        }

        auto cipher = encryptInternal(plaintext);
        while (cipher >= Field::recordDomainLimit()) {
            cipher = encryptInternal(cipher);
        }
        return cipher;
    }

    FieldElement decrypt(FieldElement cipher) const {
        if (cipher >= Field::recordDomainLimit()) {
            throw std::invalid_argument("ciphertext is outside Z_q");
        }

        auto plaintext = decryptInternal(cipher);
        while (plaintext >= Field::recordDomainLimit()) {
            plaintext = decryptInternal(plaintext);
        }
        return plaintext;
    }

  private:
    FieldElement roundFunction(FieldElement right, std::uint32_t round) const {
        blake3_hasher hash;
        blake3_hasher_init_keyed(&hash, mKey.data());
        blake3UpdateU64(hash, right);
        blake3UpdateU64(hash, round);
        return finalizeBlake3U64(hash) & mHalfMask;
    }

    FieldElement encryptInternal(FieldElement value) const {
        FieldElement left = value >> mHalfBits;
        FieldElement right = value & mHalfMask;
        for (std::uint32_t round = 0; round < kFeistelRounds; ++round) {
            const auto nextLeft = right;
            const auto nextRight = (left ^ roundFunction(right, round)) & mHalfMask;
            left = nextLeft;
            right = nextRight;
        }
        return ((left & mHalfMask) << mHalfBits) | right;
    }

    FieldElement decryptInternal(FieldElement value) const {
        FieldElement left = value >> mHalfBits;
        FieldElement right = value & mHalfMask;
        for (std::uint32_t round = kFeistelRounds; round > 0; --round) {
            const auto prevRight = left;
            const auto prevLeft = (right ^ roundFunction(left, round - 1)) & mHalfMask;
            left = prevLeft;
            right = prevRight;
        }
        return ((left & mHalfMask) << mHalfBits) | right;
    }

    const std::array<std::uint8_t, 32> &mKey;
    std::size_t mHalfBits = 32;
    FieldElement mHalfMask = 0xffffffffULL;
};

FieldElement itemToPlaintext(Item item, std::size_t itemBits) {
    if (!isSupportedElementBits(itemBits)) {
        throw std::invalid_argument("item bit length must be 512");
    }
    if (item >= Field::recordDomainLimit()) {
        throw std::invalid_argument("record is outside the JSON-compatible update cipher domain");
    }
    return item;
}

Item plaintextToItem(FieldElement value, std::size_t itemBits) {
    if (!isSupportedElementBits(itemBits)) {
        throw std::invalid_argument("item bit length must be 512");
    }
    if (value >= Field::modulus()) {
        throw std::invalid_argument(
            "decoded record is outside the JSON-compatible update cipher domain");
    }
    return value;
}

} // namespace

DedupProtocol::DedupProtocol(ProtocolParams params) : mParams(params) {
    if (mParams.providerCount == 0) {
        throw std::invalid_argument("providerCount must be positive");
    }
    if (mParams.hashCount == 0) {
        throw std::invalid_argument("hashCount must be positive");
    }
    if (!isSupportedElementBits(mParams.itemBits)) {
        throw std::invalid_argument("itemBits must be 512");
    }
    Field::configureElementBits(mParams.itemBits);

    mPrimaryHashSeed = stringSeed("primary-hash", mParams.seed);
    mAuxiliaryHashSeed = stringSeed("auxiliary-hash", mParams.seed);
    mPrimaryMaskSalt = stringSeed("primary-mask", mParams.seed);
    mAuxiliaryMaskSalt = stringSeed("auxiliary-mask", mParams.seed);
    if (!mParams.hasEncryptionKey)
        throw std::invalid_argument("record encryption key must be supplied");
    mEncryptionKey = mParams.encryptionKey;
    mTagSeed = stringSeed("tag", mParams.seed);
    mPrimaryHashKey = makeBlake3Key(mPrimaryHashSeed, kIbltU64Purpose);
    mAuxiliaryHashKey = makeBlake3Key(mAuxiliaryHashSeed, kIbltU64Purpose);
    mTagKey = makeBlake3Key(mTagSeed, kFieldU64Purpose);

    // Alg. 1 line 6 requires r_{i,j} = PRF(seed_i, x_{ij}) with a *private* per-provider seed.
    // Only fold the secret into mCoeffKey when a provider supplied one. The cloud constructs
    // DedupProtocol without providerSecretSeed and never calls coefficient(); it will only
    // decode buckets, so leaving mCoeffKey uninitialized is safe here.
    if (mParams.providerHasSecretSeed) {
        blake3_hasher hasher;
        blake3_hasher_init_derive_key(&hasher, "PrivDedup coefficient PRF seed_i v1");
        blake3_hasher_update(&hasher, mParams.providerSecretSeed.data(),
                             mParams.providerSecretSeed.size());
        blake3UpdateU64(hasher, mParams.seed);
        blake3_hasher_finalize(&hasher, mCoeffKey.data(), mCoeffKey.size());
        mCoeffKeyReady = true;
    }
}

std::vector<Bucket>
DedupProtocol::encodePrimary(std::size_t providerIdx, const std::vector<Item> &items,
                             const std::vector<Bucket> *precomputedMasks) const {
    if (mParams.primaryBuckets == 0) {
        throw std::invalid_argument("primaryBuckets must be set before encoding");
    }

    std::vector<Bucket> table(mParams.primaryBuckets);
    const DeterministicCipher cipher(mEncryptionKey, mParams.itemBits);
    for (const auto &item : items) {
        const auto cipherValue =
            (mParams.packedOperations ? item
                                      : cipher.encrypt(itemToPlaintext(item, mParams.itemBits)));
        const auto itemTag = tag(cipherValue);
        const auto coeff = coefficient(providerIdx, item);
        const Bucket contribution{
            coeff,
            Field::mul(coeff, cipherValue),
            Field::mul(coeff, itemTag),
        };

        forEachBucketLocation(mPrimaryHashKey, item, mParams.primaryBuckets, mParams.hashCount,
                              [&](std::size_t bucket) { table[bucket].add(contribution); });
    }

    if (precomputedMasks != nullptr) {
        addMaskTable(table, *precomputedMasks);
    } else {
        for (std::size_t bucket = 0; bucket < table.size(); ++bucket) {
            table[bucket].add(maskForProvider(providerIdx, bucket, mPrimaryMaskSalt));
        }
    }
    return table;
}

std::vector<Bucket>
DedupProtocol::encodeAuxiliary(std::size_t providerIdx, const std::vector<Item> &items,
                               const std::vector<unsigned char> &unresolvedPrimary,
                               std::size_t auxiliaryBuckets,
                               const std::vector<Bucket> *precomputedMasks) const {
    if (auxiliaryBuckets == 0) {
        throw std::invalid_argument("auxiliaryBuckets must be positive");
    }

    std::vector<Bucket> table(auxiliaryBuckets);
    const DeterministicCipher cipher(mEncryptionKey, mParams.itemBits);
    for (const auto &item : items) {
        if (!isAuxiliaryCandidate(item, unresolvedPrimary)) {
            continue;
        }

        const auto cipherValue =
            (mParams.packedOperations ? item
                                      : cipher.encrypt(itemToPlaintext(item, mParams.itemBits)));
        const auto itemTag = tag(cipherValue);
        const auto coeff = coefficient(providerIdx, item);
        const Bucket contribution{
            coeff,
            Field::mul(coeff, cipherValue),
            Field::mul(coeff, itemTag),
        };

        forEachBucketLocation(mAuxiliaryHashKey, item, auxiliaryBuckets, mParams.hashCount,
                              [&](std::size_t bucket) { table[bucket].add(contribution); });
    }

    if (precomputedMasks != nullptr) {
        addMaskTable(table, *precomputedMasks);
    } else {
        for (std::size_t bucket = 0; bucket < table.size(); ++bucket) {
            table[bucket].add(maskForProvider(providerIdx, bucket, mAuxiliaryMaskSalt));
        }
    }
    return table;
}

std::vector<Bucket> DedupProtocol::precomputePrimaryMasks(std::size_t providerIdx) const {
    if (mParams.primaryBuckets == 0) {
        throw std::invalid_argument("primaryBuckets must be set before mask precomputation");
    }
    if (providerIdx >= mParams.providerCount) {
        throw std::invalid_argument("providerIdx must be in [0, providerCount)");
    }

    return precomputeMaskTable(providerIdx, mParams.providerCount, mParams.pairMaskSeeds,
                               mParams.primaryBuckets, mPrimaryMaskSalt);
}

std::vector<Bucket> DedupProtocol::precomputeAuxiliaryMasks(std::size_t providerIdx,
                                                            std::size_t auxiliaryBuckets) const {
    if (auxiliaryBuckets == 0) {
        throw std::invalid_argument("auxiliaryBuckets must be positive");
    }
    if (providerIdx >= mParams.providerCount) {
        throw std::invalid_argument("providerIdx must be in [0, providerCount)");
    }

    return precomputeMaskTable(providerIdx, mParams.providerCount, mParams.pairMaskSeeds,
                               auxiliaryBuckets, mAuxiliaryMaskSalt);
}

DecodeReport DedupProtocol::decode(std::vector<Bucket> table, std::size_t bucketCount,
                                   FieldElement hashSeed) const {
    if (table.size() != bucketCount) {
        throw std::invalid_argument("decode table size does not match bucketCount");
    }

    DecodeReport report;
    std::queue<std::size_t> queue;
    std::unordered_map<FieldElement, CachedCipher> cache;
    const DeterministicCipher itemCipher(mEncryptionKey, mParams.itemBits);

    auto singletonFromBucket = [&](const Bucket &bucket) -> std::optional<Singleton> {
        if (bucket.isZero() || bucket.cnt == 0) {
            return std::nullopt;
        }

        const auto cipherValue = Field::div(bucket.sumCipher, bucket.cnt);
        if (bucket.sumTag != Field::mul(bucket.cnt, tag(cipherValue))) {
            return std::nullopt;
        }
        return Singleton{bucket.cnt, cipherValue};
    };

    auto resolveCipher = [&](FieldElement cipherValue) -> const CachedCipher & {
        auto cached = cache.find(cipherValue);
        if (cached != cache.end()) {
            return cached->second;
        }

        CachedCipher entry;
        entry.item = (mParams.packedOperations
                          ? cipherValue
                          : plaintextToItem(itemCipher.decrypt(cipherValue), mParams.itemBits));
        entry.tag = tag(cipherValue);
        entry.buckets = bucketLocations(entry.item, bucketCount, hashSeed);
        auto inserted = cache.emplace(cipherValue, std::move(entry));
        return inserted.first->second;
    };

    auto tryEnqueue = [&](std::size_t bucketIdx) {
        auto singleton = singletonFromBucket(table[bucketIdx]);
        if (!singleton.has_value()) {
            return;
        }

        const auto &resolved = resolveCipher(singleton->cipher);
        if (std::find(resolved.buckets.begin(), resolved.buckets.end(), bucketIdx) ==
            resolved.buckets.end()) {
            return;
        }
        queue.push(bucketIdx);
    };

    for (std::size_t bucket = 0; bucket < bucketCount; ++bucket) {
        tryEnqueue(bucket);
    }

    while (!queue.empty()) {
        const auto bucketIdx = queue.front();
        queue.pop();

        auto singleton = singletonFromBucket(table[bucketIdx]);
        if (!singleton.has_value()) {
            continue;
        }

        const auto &resolved = resolveCipher(singleton->cipher);
        if (std::find(resolved.buckets.begin(), resolved.buckets.end(), bucketIdx) ==
            resolved.buckets.end()) {
            continue;
        }

        report.items.insert(resolved.item);
        ++report.peeledCount;

        const Bucket contribution{
            singleton->cnt,
            Field::mul(singleton->cnt, singleton->cipher),
            Field::mul(singleton->cnt, resolved.tag),
        };

        for (auto location : resolved.buckets) {
            table[location].sub(contribution);
            tryEnqueue(location);
        }
    }

    for (std::size_t bucket = 0; bucket < table.size(); ++bucket) {
        if (!table[bucket].isZero()) {
            report.unresolvedBuckets.push_back(bucket);
        }
    }
    return report;
}

FieldElement DedupProtocol::encrypt(const Item &item) const {
    const DeterministicCipher cipher(mEncryptionKey, mParams.itemBits);
    return (mParams.packedOperations ? item
                                     : cipher.encrypt(itemToPlaintext(item, mParams.itemBits)));
}

Item DedupProtocol::decrypt(FieldElement cipherValue) const {
    const DeterministicCipher cipher(mEncryptionKey, mParams.itemBits);
    return plaintextToItem(cipher.decrypt(cipherValue), mParams.itemBits);
}

FieldElement DedupProtocol::tag(FieldElement cipher) const { return hashToField(mTagKey, cipher); }

FieldElement DedupProtocol::coefficient(std::size_t providerIdx, const Item &item) const {
    if (!mCoeffKeyReady) {
        throw std::runtime_error("coefficient() called without a provider secret seed; "
                                 "ProtocolParams::providerSecretSeed must be set on providers");
    }
    const auto value = hashToField(mCoeffKey, item, providerIdx);
    return value == 0 ? 1 : value;
}

FieldElement DedupProtocol::pairMaskValue(FieldElement pairSeed, std::uint32_t component,
                                          std::size_t bucket, FieldElement tableSalt) const {
    auto seed = mix(pairSeed, tableSalt);
    seed = mix(seed, component);
    return hashToField(seed, static_cast<FieldElement>(bucket));
}

Bucket DedupProtocol::maskForProvider(std::size_t providerIdx, std::size_t bucket,
                                      FieldElement tableSalt) const {
    if (mParams.pairMaskSeeds.size() != mParams.providerCount) {
        throw std::invalid_argument(
            "pairwise mask seeds must be established before mask generation");
    }

    Bucket mask;
    for (std::size_t other = 0; other < mParams.providerCount; ++other) {
        if (other == providerIdx) {
            continue;
        }

        const auto pairSeed = mParams.pairMaskSeeds[other];
        Bucket pair{
            pairMaskValue(pairSeed, 0, bucket, tableSalt),
            pairMaskValue(pairSeed, 1, bucket, tableSalt),
            pairMaskValue(pairSeed, 2, bucket, tableSalt),
        };

        if (providerIdx < other) {
            mask.add(pair);
        } else {
            mask.sub(pair);
        }
    }
    return mask;
}

std::vector<std::size_t> DedupProtocol::bucketLocations(const Item &item, std::size_t bucketCount,
                                                        FieldElement hashSeed) const {
    if (bucketCount < mParams.hashCount) {
        throw std::invalid_argument("bucket count must be at least hashCount");
    }

    std::vector<std::size_t> locations;
    locations.reserve(mParams.hashCount);
    std::uint32_t attempt = 0;
    while (locations.size() < mParams.hashCount) {
        const auto bucket = hashSeed == mPrimaryHashSeed
                                ? hashIndex(mPrimaryHashKey, item, attempt, bucketCount)
                                : (hashSeed == mAuxiliaryHashSeed
                                       ? hashIndex(mAuxiliaryHashKey, item, attempt, bucketCount)
                                       : hashIndex(hashSeed, item, attempt, bucketCount));
        if (std::find(locations.begin(), locations.end(), bucket) == locations.end()) {
            locations.push_back(bucket);
        }
        ++attempt;
    }
    return locations;
}

bool DedupProtocol::isAuxiliaryCandidate(
    const Item &item, const std::vector<unsigned char> &unresolvedPrimary) const {
    bool selected = true;
    forEachBucketLocation(mPrimaryHashKey, item, unresolvedPrimary.size(), mParams.hashCount,
                          [&](std::size_t bucket) {
                              if (unresolvedPrimary[bucket] == 0) {
                                  selected = false;
                              }
                          });
    return selected;
}

std::size_t DedupProtocol::effectiveAuxiliaryBuckets(std::size_t sizingItems) const {
    if (mParams.auxiliaryBuckets != 0) {
        return mParams.auxiliaryBuckets;
    }

    return std::max<std::size_t>(
        mParams.hashCount + 1,
        ceilToSize(mParams.auxiliaryLoadFactor * static_cast<double>(sizingItems)));
}

} // namespace memdedup
