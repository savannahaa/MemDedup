#pragma once
#include <boost/multiprecision/cpp_int.hpp>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <functional>
#include <limits>
namespace memdedup {
using FieldElement = boost::multiprecision::uint512_t;
class Field {
  public:
    using u128 = boost::multiprecision::uint1024_t;
    static void configureElementBits(std::size_t bits) {
        if (bits != 512)
            throw std::invalid_argument("the protocol requires 512-bit records");
    }
    static FieldElement modulus() { return std::numeric_limits<FieldElement>::max() - 568; }
    // Complete compact JSON arrays start with '[' (0x5b), so their 64-byte
    // big-endian encodings lie below this bound. Cycle walking preserves this
    // domain and reserves one bit for an injective insertion/deletion encoding.
    static FieldElement recordDomainLimit() { return (modulus() - 1) / 2; }
    static constexpr std::size_t wireBytes = 64;
    static FieldElement add(FieldElement a, FieldElement b) {
        return FieldElement((u128(a) + b) % modulus());
    }
    static FieldElement sub(FieldElement a, FieldElement b) {
        return a >= b ? a - b : modulus() - (b - a);
    }
    static FieldElement mul(FieldElement a, FieldElement b) {
        return FieldElement((u128(a) * b) % modulus());
    }
    static FieldElement inv(FieldElement a) {
        using boost::multiprecision::cpp_int;
        if (a == 0)
            throw std::runtime_error("division by zero");
        cpp_int t = 0, nt = 1, r = modulus(), nr = a;
        while (nr != 0) {
            cpp_int q = r / nr;
            cpp_int z = t - q * nt;
            t = nt;
            nt = z;
            z = r - q * nr;
            r = nr;
            nr = z;
        }
        if (r != 1)
            throw std::runtime_error("noninvertible");
        if (t < 0)
            t += cpp_int(modulus());
        return FieldElement(t);
    }
    static FieldElement div(FieldElement a, FieldElement b) { return mul(a, inv(b)); }
};
} // namespace memdedup
namespace std {
template <> struct hash<memdedup::FieldElement> {
    size_t operator()(const memdedup::FieldElement &a) const {
        return boost::multiprecision::hash_value(a);
    }
};
} // namespace std
