#pragma once
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <array>
#include <algorithm>
#include <vector>
#include <stdexcept>
#include <memory>
#include <limits>
#include <cstdint>
namespace memdedup::wire {
using Bytes = std::vector<unsigned char>;
inline void check(int v) {
    if (v != 1)
        throw std::runtime_error("OpenSSL operation failed");
}
// Fisher-Yates permutation with unbiased OpenSSL random index selection.
// This protects permutation randomness; it does not provide network anonymity.
template <typename T> inline void shuffle(std::vector<T> &values) {
    for (std::size_t size = values.size(); size > 1; --size) {
        const auto bound = static_cast<std::uint64_t>(size);
        const auto maximum = std::numeric_limits<std::uint64_t>::max();
        const auto cutoff = maximum - maximum % bound;
        std::uint64_t draw = 0;
        do {
            check(RAND_bytes(reinterpret_cast<unsigned char *>(&draw), sizeof(draw)));
        } while (draw >= cutoff);
        std::swap(values[size - 1], values[draw % bound]);
    }
}
struct Key {
    std::array<unsigned char, 32> secret{}, pub{};
};
inline Key keygen() {
    Key k;
    auto ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
    EVP_PKEY *p = nullptr;
    check(EVP_PKEY_keygen_init(ctx));
    check(EVP_PKEY_keygen(ctx, &p));
    size_t n = 32;
    check(EVP_PKEY_get_raw_private_key(p, k.secret.data(), &n));
    n = 32;
    check(EVP_PKEY_get_raw_public_key(p, k.pub.data(), &n));
    EVP_PKEY_free(p);
    EVP_PKEY_CTX_free(ctx);
    return k;
}
inline std::array<unsigned char, 32> dh(const Key &k, const unsigned char *pub) {
    auto a = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, k.secret.data(), 32);
    auto b = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, pub, 32);
    auto c = EVP_PKEY_CTX_new(a, nullptr);
    check(EVP_PKEY_derive_init(c));
    check(EVP_PKEY_derive_set_peer(c, b));
    std::array<unsigned char, 32> shared{}, out{};
    size_t n = 32;
    check(EVP_PKEY_derive(c, shared.data(), &n));
    unsigned int m;
    check(EVP_Digest(shared.data(), 32, out.data(), &m, EVP_sha256(), nullptr));
    EVP_PKEY_CTX_free(c);
    EVP_PKEY_free(a);
    EVP_PKEY_free(b);
    return out;
}
inline Bytes seal(const Bytes &plain, const Key &server, uint64_t batch, int round) {
    auto eph = keygen();
    auto key = dh(eph, server.pub.data());
    Bytes out(44 + plain.size() + 16);
    std::copy(eph.pub.begin(), eph.pub.end(), out.begin());
    check(RAND_bytes(out.data() + 32, 12));
    auto c = EVP_CIPHER_CTX_new();
    check(EVP_EncryptInit_ex(c, EVP_aes_256_gcm(), nullptr, key.data(), out.data() + 32));
    int n = 0, m = 0;
    std::array<unsigned char, 16> aad{};
    for (int i = 0; i < 8; ++i)
        aad[i] = (batch >> (i * 8)) & 255;
    aad[8] = round;
    check(EVP_EncryptUpdate(c, nullptr, &n, aad.data(), 16));
    check(EVP_EncryptUpdate(c, out.data() + 44, &n, plain.data(), plain.size()));
    check(EVP_EncryptFinal_ex(c, out.data() + 44 + n, &m));
    check(EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_GET_TAG, 16, out.data() + 44 + plain.size()));
    EVP_CIPHER_CTX_free(c);
    return out;
}
inline Bytes open(const Bytes &in, const Key &server, uint64_t batch, int round) {
    if (in.size() < 60)
        throw std::runtime_error("short envelope");
    auto key = dh(server, in.data());
    Bytes out(in.size() - 60);
    auto c = EVP_CIPHER_CTX_new();
    check(EVP_DecryptInit_ex(c, EVP_aes_256_gcm(), nullptr, key.data(), in.data() + 32));
    int n, m;
    std::array<unsigned char, 16> aad{};
    for (int i = 0; i < 8; ++i)
        aad[i] = (batch >> (i * 8)) & 255;
    aad[8] = round;
    check(EVP_DecryptUpdate(c, nullptr, &n, aad.data(), 16));
    check(EVP_DecryptUpdate(c, out.data(), &n, in.data() + 44, out.size()));
    check(EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_TAG, 16, (void *)(in.data() + in.size() - 16)));
    int ok = EVP_DecryptFinal_ex(c, out.data() + n, &m);
    EVP_CIPHER_CTX_free(c);
    check(ok);
    return out;
}
} // namespace memdedup::wire
