#pragma once

#include "field.h"

extern "C" {
#include "blake3.h"
}

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace memdedup {

using Blake3Key = std::array<std::uint8_t, BLAKE3_KEY_LEN>;

constexpr std::uint64_t kFieldU64Purpose = 0x6469656c642d7536ULL;
constexpr std::uint64_t kFieldStringPurpose = 0x6469656c642d7374ULL;
constexpr std::uint64_t kIbltU64Purpose = 0x69626c742d753634ULL;
constexpr std::uint64_t kMixPurpose = 0x6d69782d73656564ULL;

inline FieldElement load64LE(const unsigned char *data) {
    FieldElement value = 0;
    for (std::size_t i = 0; i < 64; ++i) {
        value |= FieldElement(data[i]) << (8 * i);
    }
    return value;
}

inline void store64LE(FieldElement value, unsigned char *data) {
    for (std::size_t i = 0; i < 64; ++i) {
        data[i] = static_cast<unsigned char>((value >> (8 * i)) & 0xffU);
    }
}

inline void blake3UpdateU64(blake3_hasher &hash, FieldElement value) {
    unsigned char data[64];
    store64LE(value, data);
    blake3_hasher_update(&hash, data, sizeof(data));
}

inline void deriveBlake3Key(FieldElement seed, FieldElement purpose,
                            std::uint8_t key[BLAKE3_KEY_LEN]) {
    blake3_hasher hash;
    blake3_hasher_init_derive_key(&hash, "PrivDedup BLAKE3 PRF key derivation v1");
    blake3UpdateU64(hash, seed);
    blake3UpdateU64(hash, purpose);
    blake3_hasher_finalize(&hash, key, BLAKE3_KEY_LEN);
}

inline Blake3Key makeBlake3Key(FieldElement seed, FieldElement purpose) {
    Blake3Key key{};
    deriveBlake3Key(seed, purpose, key.data());
    return key;
}

inline FieldElement finalizeBlake3U64(blake3_hasher &hash) {
    unsigned char out[64];
    blake3_hasher_finalize(&hash, out, sizeof(out));
    return load64LE(out) % Field::modulus();
}

inline FieldElement blake3PrfU64s(const Blake3Key &key, FieldElement a, FieldElement b = 0,
                                  FieldElement c = 0) {
    blake3_hasher hash;
    blake3_hasher_init_keyed(&hash, key.data());
    blake3UpdateU64(hash, a);
    blake3UpdateU64(hash, b);
    blake3UpdateU64(hash, c);
    return finalizeBlake3U64(hash);
}

inline FieldElement blake3PrfU64s(FieldElement seed, FieldElement purpose, FieldElement a,
                                  FieldElement b = 0, FieldElement c = 0) {
    return blake3PrfU64s(makeBlake3Key(seed, purpose), a, b, c);
}

inline FieldElement blake3PrfBytes(const Blake3Key &key, std::string_view value,
                                   FieldElement domain = 0) {
    blake3_hasher hash;
    blake3_hasher_init_keyed(&hash, key.data());
    blake3UpdateU64(hash, domain);
    blake3_hasher_update(&hash, value.data(), value.size());
    return finalizeBlake3U64(hash);
}

inline FieldElement blake3PrfBytes(FieldElement seed, FieldElement purpose, std::string_view value,
                                   FieldElement domain = 0) {
    return blake3PrfBytes(makeBlake3Key(seed, purpose), value, domain);
}

inline FieldElement mix(FieldElement seed, FieldElement value) {
    return blake3PrfU64s(seed, kMixPurpose, value);
}

inline FieldElement hashToField(FieldElement seed, FieldElement a, FieldElement b = 0,
                                FieldElement c = 0) {
    return blake3PrfU64s(seed, kFieldU64Purpose, a, b, c) % Field::modulus();
}

inline FieldElement hashToField(FieldElement seed, std::string_view value,
                                FieldElement domain = 0) {
    return blake3PrfBytes(seed, kFieldStringPurpose, value, domain) % Field::modulus();
}

inline FieldElement hashToField(const Blake3Key &key, FieldElement a, FieldElement b = 0,
                                FieldElement c = 0) {
    return blake3PrfU64s(key, a, b, c) % Field::modulus();
}

inline FieldElement nonZeroHashToField(FieldElement seed, FieldElement a, FieldElement b = 0,
                                       FieldElement c = 0) {
    auto value = hashToField(seed, a, b, c);
    return value == 0 ? 1 : value;
}

inline std::size_t hashIndex(FieldElement seed, FieldElement item, std::uint32_t hashId,
                             std::size_t bucketCount) {
    std::uint8_t key[BLAKE3_KEY_LEN];
    deriveBlake3Key(seed, kIbltU64Purpose, key);
    blake3_hasher hash;
    blake3_hasher_init_keyed(&hash, key);
    blake3UpdateU64(hash, hashId);
    blake3UpdateU64(hash, static_cast<FieldElement>(bucketCount));
    blake3UpdateU64(hash, item);
    return static_cast<std::size_t>(finalizeBlake3U64(hash) % bucketCount);
}

inline std::size_t hashIndex(const Blake3Key &key, FieldElement item, std::uint32_t hashId,
                             std::size_t bucketCount) {
    blake3_hasher hash;
    blake3_hasher_init_keyed(&hash, key.data());
    blake3UpdateU64(hash, hashId);
    blake3UpdateU64(hash, static_cast<FieldElement>(bucketCount));
    blake3UpdateU64(hash, item);
    return static_cast<std::size_t>(finalizeBlake3U64(hash) % bucketCount);
}

inline FieldElement stringSeed(const std::string &text, FieldElement seed) {
    return blake3PrfBytes(seed, 0x7374722d73656564ULL, text);
}

} // namespace memdedup
