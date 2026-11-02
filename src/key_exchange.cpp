#include "key_exchange.h"

#include "hash_util.h"
#include "network.h"

#include <algorithm>
#include <array>
#include <limits>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include <openssl/evp.h>

namespace memdedup {
namespace {

constexpr std::size_t kX25519KeyBytes = 32;

using X25519Key = std::array<unsigned char, kX25519KeyBytes>;

struct X25519KeyPair {
    X25519Key privateKey{};
    X25519Key publicKey{};
};

struct EvpPkeyDeleter {
    void operator()(EVP_PKEY *key) const { EVP_PKEY_free(key); }
};

struct EvpPkeyCtxDeleter {
    void operator()(EVP_PKEY_CTX *ctx) const { EVP_PKEY_CTX_free(ctx); }
};

using EvpPkeyPtr = std::unique_ptr<EVP_PKEY, EvpPkeyDeleter>;
using EvpPkeyCtxPtr = std::unique_ptr<EVP_PKEY_CTX, EvpPkeyCtxDeleter>;

void requireOpenSsl(int ok, const char *action) {
    if (ok <= 0) {
        throw std::runtime_error(std::string("OpenSSL X25519 failure: ") + action);
    }
}

X25519KeyPair makeX25519KeyPair() {
    EvpPkeyCtxPtr ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr));
    if (!ctx) {
        throw std::runtime_error("OpenSSL X25519 failure: create keygen context");
    }

    EVP_PKEY *rawKey = nullptr;
    requireOpenSsl(EVP_PKEY_keygen_init(ctx.get()), "keygen init");
    requireOpenSsl(EVP_PKEY_keygen(ctx.get(), &rawKey), "keygen");
    EvpPkeyPtr key(rawKey);

    X25519KeyPair pair;
    std::size_t privateLen = pair.privateKey.size();
    std::size_t publicLen = pair.publicKey.size();
    requireOpenSsl(EVP_PKEY_get_raw_private_key(key.get(), pair.privateKey.data(), &privateLen),
                   "export private key");
    requireOpenSsl(EVP_PKEY_get_raw_public_key(key.get(), pair.publicKey.data(), &publicLen),
                   "export public key");
    if (privateLen != pair.privateKey.size() || publicLen != pair.publicKey.size()) {
        throw std::runtime_error("OpenSSL X25519 returned an unexpected key length");
    }
    return pair;
}

X25519Key parseX25519PublicKey(const std::vector<unsigned char> &bytes) {
    if (bytes.size() != kX25519KeyBytes) {
        throw std::runtime_error("peer X25519 public key has unexpected length");
    }
    X25519Key key{};
    std::copy(bytes.begin(), bytes.end(), key.begin());
    return key;
}

std::vector<unsigned char> keyToBytes(const X25519Key &key) {
    return std::vector<unsigned char>(key.begin(), key.end());
}

X25519Key deriveX25519SharedSecret(const X25519Key &privateKey, const X25519Key &peerPublicKey) {
    EvpPkeyPtr local(EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, privateKey.data(),
                                                  privateKey.size()));
    EvpPkeyPtr peer(EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, peerPublicKey.data(),
                                                peerPublicKey.size()));
    if (!local || !peer) {
        throw std::runtime_error("OpenSSL X25519 failure: import key");
    }

    EvpPkeyCtxPtr ctx(EVP_PKEY_CTX_new(local.get(), nullptr));
    if (!ctx) {
        throw std::runtime_error("OpenSSL X25519 failure: create derive context");
    }

    X25519Key shared{};
    std::size_t sharedLen = shared.size();
    requireOpenSsl(EVP_PKEY_derive_init(ctx.get()), "derive init");
    requireOpenSsl(EVP_PKEY_derive_set_peer(ctx.get(), peer.get()), "set peer");
    requireOpenSsl(EVP_PKEY_derive(ctx.get(), shared.data(), &sharedLen), "derive shared secret");
    if (sharedLen != shared.size()) {
        throw std::runtime_error("OpenSSL X25519 returned an unexpected shared-secret length");
    }
    return shared;
}

FieldElement pairMaskSeedFromSharedSecret(const X25519Key &sharedSecret, std::size_t lhs,
                                          std::size_t rhs, std::uint64_t seed) {
    const auto derivedSeed =
        blake3PrfU64s(seed, 0x7832353531392d73ULL, static_cast<FieldElement>(lhs),
                      static_cast<FieldElement>(rhs));
    const std::string_view secretView(reinterpret_cast<const char *>(sharedSecret.data()),
                                      sharedSecret.size());
    const auto value = hashToField(derivedSeed, secretView, seed);
    return value == 0 ? 1 : value;
}

std::vector<FieldElement> derivePairMaskSeeds(std::size_t providerIdx, const X25519Key &privateKey,
                                              const std::vector<X25519Key> &publicKeys,
                                              std::uint64_t seed) {
    if (providerIdx >= publicKeys.size()) {
        throw std::runtime_error("provider index out of range for X25519 public keys");
    }

    std::vector<FieldElement> pairSeeds(publicKeys.size(), 0);
    for (std::size_t other = 0; other < publicKeys.size(); ++other) {
        if (other == providerIdx) {
            continue;
        }
        const auto lhs = std::min(providerIdx, other);
        const auto rhs = std::max(providerIdx, other);
        const auto shared = deriveX25519SharedSecret(privateKey, publicKeys[other]);
        pairSeeds[other] = pairMaskSeedFromSharedSecret(shared, lhs, rhs, seed);
    }
    return pairSeeds;
}

std::uint16_t pairwiseSetupPort(std::uint16_t basePort, std::size_t providerCount, std::size_t lhs,
                                std::size_t rhs) {
    const auto value = static_cast<std::size_t>(basePort) + 1000 + lhs * providerCount + rhs;
    if (value > std::numeric_limits<std::uint16_t>::max()) {
        throw std::runtime_error("base port is too high for pairwise X25519 setup provider ports");
    }
    return static_cast<std::uint16_t>(value);
}

} // namespace

PairwiseMaskSetup establishDirectPairMaskSeeds(std::size_t providerIdx, std::size_t providerCount,
                                               const std::string &host, std::uint16_t basePort,
                                               std::uint64_t seed) {
    if (providerIdx >= providerCount) {
        throw std::runtime_error("provider index must be in [0, providerCount) for pairwise DH");
    }

    const auto keyPair = makeX25519KeyPair();
    std::vector<X25519Key> publicKeys(providerCount);
    publicKeys[providerIdx] = keyPair.publicKey;

    PairwiseMaskSetup setup;
    std::vector<std::size_t> listeningPeers;
    std::vector<TcpListener> listeners;
    for (std::size_t other = providerIdx + 1; other < providerCount; ++other) {
        listeners.emplace_back(
            TcpListener::bind(pairwiseSetupPort(basePort, providerCount, providerIdx, other), 1));
        listeningPeers.push_back(other);
    }

    for (std::size_t other = 0; other < providerIdx; ++other) {
        auto peer = TcpSocket::connectTo(
            host, pairwiseSetupPort(basePort, providerCount, other, providerIdx));
        sendBytes(peer, keyToBytes(keyPair.publicKey));
        publicKeys[other] = parseX25519PublicKey(recvBytes(peer));
    }

    for (std::size_t i = 0; i < listeners.size(); ++i) {
        auto peer = listeners[i].accept();
        const auto other = listeningPeers[i];
        publicKeys[other] = parseX25519PublicKey(recvBytes(peer));
        sendBytes(peer, keyToBytes(keyPair.publicKey));
    }

    setup.pairMaskSeeds = derivePairMaskSeeds(providerIdx, keyPair.privateKey, publicKeys, seed);
    return setup;
}

} // namespace memdedup
