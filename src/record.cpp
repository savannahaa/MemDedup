#include "record.h"
#include <stdexcept>

namespace memdedup {
namespace {
std::string quote(const std::string &text) {
    const char *hex = "0123456789abcdef";
    std::string result = "\"";
    for (unsigned char c : text) {
        switch (c) {
        case '"':
            result += "\\\"";
            break;
        case '\\':
            result += "\\\\";
            break;
        case '\b':
            result += "\\b";
            break;
        case '\f':
            result += "\\f";
            break;
        case '\n':
            result += "\\n";
            break;
        case '\r':
            result += "\\r";
            break;
        case '\t':
            result += "\\t";
            break;
        default:
            if (c < 0x20) {
                result += "\\u00";
                result += hex[c >> 4];
                result += hex[c & 15];
            } else {
                result += static_cast<char>(c);
            }
        }
    }
    return result + '"';
}
} // namespace

Item encodeTriple(const std::array<std::string, 3> &triple) {
    const auto json =
        '[' + quote(triple[0]) + ',' + quote(triple[1]) + ',' + quote(triple[2]) + ']';
    if (json.size() > 64)
        throw std::invalid_argument("complete JSON triple exceeds 64 bytes");
    Item result = 0;
    for (std::size_t i = 0; i < 64; ++i)
        result = (result << 8) | (i < json.size() ? static_cast<unsigned char>(json[i]) : 0);
    return result;
}

std::string decodeTripleRecord(const Item &record) {
    std::string result;
    bool padded = false;
    for (int i = 63; i >= 0; --i) {
        const auto byte = static_cast<unsigned char>((record >> (8 * i)) & 255);
        if (byte == 0) {
            padded = true;
        } else {
            if (padded)
                throw std::invalid_argument("nonzero byte after record padding");
            result += static_cast<char>(byte);
        }
    }
    if (result.empty() || result.front() != '[' || result.back() != ']')
        throw std::invalid_argument("record is not an encoded JSON array");
    return result;
}
} // namespace memdedup
