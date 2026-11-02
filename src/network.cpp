#include "network.h"

#include <arpa/inet.h>
#include <cerrno>
#include <chrono>
#include <cmath>
#include <cstring>
#include <netinet/in.h>
#include <stdexcept>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <utility>

namespace memdedup {

namespace {

[[noreturn]] void throwErrno(const std::string &action) {
    throw std::runtime_error(action + ": " + std::strerror(errno));
}

void setReuseAddr(int fd) {
    int opt = 1;
    if (::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) != 0) {
        throwErrno("setsockopt(SO_REUSEADDR)");
    }
#ifdef SO_REUSEPORT
    ::setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
#endif
}

std::uint64_t loadU64LE(const unsigned char *data) {
    std::uint64_t value = 0;
    for (std::size_t i = 0; i < 8; ++i) {
        value |= static_cast<std::uint64_t>(data[i]) << (8 * i);
    }
    return value;
}

void storeU64LE(std::uint64_t value, unsigned char *data) {
    for (std::size_t i = 0; i < 8; ++i) {
        data[i] = static_cast<unsigned char>((value >> (8 * i)) & 0xffU);
    }
}

int sendFlags() {
#ifdef MSG_NOSIGNAL
    return MSG_NOSIGNAL;
#else
    return 0;
#endif
}

std::size_t fieldElementPayloadBytes(std::size_t elementCount, std::size_t elementBits) {
    if (elementBits != 512) {
        throw std::invalid_argument("element bit length must be 512");
    }
    return (elementCount * elementBits + 7) / 8;
}

void storeFieldElementBits(std::vector<unsigned char> &payload, std::size_t &bitOffset,
                           FieldElement value, std::size_t elementBits) {
    for (std::size_t bit = 0; bit < elementBits; ++bit) {
        if (((value >> bit) & 1U) != 0) {
            payload[(bitOffset + bit) / 8] |=
                static_cast<unsigned char>(1U << ((bitOffset + bit) % 8));
        }
    }
    bitOffset += elementBits;
}

FieldElement loadFieldElementBits(const std::vector<unsigned char> &payload, std::size_t &bitOffset,
                                  std::size_t elementBits) {
    FieldElement value = 0;
    for (std::size_t bit = 0; bit < elementBits; ++bit) {
        const auto set = (payload[(bitOffset + bit) / 8] >> ((bitOffset + bit) % 8)) & 1U;
        if (set != 0) {
            value |= (FieldElement(1) << bit);
        }
    }
    bitOffset += elementBits;
    return value;
}

} // namespace

TcpSocket::TcpSocket(int fd) : mFd(fd) {}

TcpSocket::~TcpSocket() { close(); }

TcpSocket::TcpSocket(TcpSocket &&other) noexcept { *this = std::move(other); }

TcpSocket &TcpSocket::operator=(TcpSocket &&other) noexcept {
    if (this != &other) {
        close();
        mFd = other.mFd;
        other.mFd = -1;
    }
    return *this;
}

TcpSocket TcpSocket::connectTo(const std::string &host, std::uint16_t port, std::size_t maxAttempts,
                               std::size_t retryDelayMs) {
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (::inet_pton(AF_INET, host.c_str(), &addr.sin_addr) != 1) {
        throw std::invalid_argument("host must be an IPv4 address, e.g. 127.0.0.1");
    }

    int lastErrno = 0;
    for (std::size_t attempt = 0; attempt < maxAttempts; ++attempt) {
        int fd = ::socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) {
            throwErrno("socket");
        }
        if (::connect(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) == 0) {
            return TcpSocket(fd);
        }
        lastErrno = errno;
        ::close(fd);
        std::this_thread::sleep_for(std::chrono::milliseconds(retryDelayMs));
    }

    errno = lastErrno;
    throwErrno("connect");
}

void TcpSocket::sendAll(const void *data, std::size_t size) {
    const auto *cursor = static_cast<const unsigned char *>(data);
    while (size > 0) {
        const auto sent = ::send(mFd, cursor, size, sendFlags());
        if (sent < 0) {
            if (errno == EINTR) {
                continue;
            }
            throwErrno("send");
        }
        if (sent == 0) {
            throw std::runtime_error("send returned zero bytes");
        }
        cursor += sent;
        size -= static_cast<std::size_t>(sent);
    }
}

void TcpSocket::recvAll(void *data, std::size_t size) {
    auto *cursor = static_cast<unsigned char *>(data);
    while (size > 0) {
        const auto received = ::recv(mFd, cursor, size, 0);
        if (received < 0) {
            if (errno == EINTR) {
                continue;
            }
            throwErrno("recv");
        }
        if (received == 0) {
            throw std::runtime_error("peer closed socket while receiving");
        }
        cursor += received;
        size -= static_cast<std::size_t>(received);
    }
}

void TcpSocket::close() {
    if (mFd >= 0) {
        ::close(mFd);
        mFd = -1;
    }
}

TcpListener::TcpListener(int fd) : mFd(fd) {}

TcpListener::~TcpListener() { close(); }

TcpListener::TcpListener(TcpListener &&other) noexcept { *this = std::move(other); }

TcpListener &TcpListener::operator=(TcpListener &&other) noexcept {
    if (this != &other) {
        close();
        mFd = other.mFd;
        other.mFd = -1;
    }
    return *this;
}

TcpListener TcpListener::bind(std::uint16_t port, int backlog) {
    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        throwErrno("socket");
    }

    try {
        setReuseAddr(fd);

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
        addr.sin_port = htons(port);
        if (::bind(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) != 0) {
            throwErrno("bind");
        }
        if (::listen(fd, backlog) != 0) {
            throwErrno("listen");
        }
        return TcpListener(fd);
    } catch (...) {
        ::close(fd);
        throw;
    }
}

TcpSocket TcpListener::accept() {
    while (true) {
        const int fd = ::accept(mFd, nullptr, nullptr);
        if (fd >= 0) {
            return TcpSocket(fd);
        }
        if (errno == EINTR) {
            continue;
        }
        throwErrno("accept");
    }
}

void TcpListener::close() {
    if (mFd >= 0) {
        ::close(mFd);
        mFd = -1;
    }
}

void sendU64(TcpSocket &socket, std::uint64_t value) {
    unsigned char data[8];
    storeU64LE(value, data);
    socket.sendAll(data, sizeof(data));
}

std::uint64_t recvU64(TcpSocket &socket) {
    unsigned char data[8];
    socket.recvAll(data, sizeof(data));
    return loadU64LE(data);
}

void sendBytes(TcpSocket &socket, const std::vector<unsigned char> &bytes) {
    sendU64(socket, bytes.size());
    if (!bytes.empty()) {
        socket.sendAll(bytes.data(), bytes.size());
    }
}

std::vector<unsigned char> recvBytes(TcpSocket &socket) {
    const auto size = static_cast<std::size_t>(recvU64(socket));
    std::vector<unsigned char> bytes(size);
    if (!bytes.empty()) {
        socket.recvAll(bytes.data(), bytes.size());
    }
    return bytes;
}

void sendBucketTable(TcpSocket &socket, const std::vector<Bucket> &table, std::size_t elementBits) {
    sendU64(socket, table.size());
    std::vector<unsigned char> payload(fieldElementPayloadBytes(table.size() * 3, elementBits));
    std::size_t bitOffset = 0;
    for (const auto &bucket : table) {
        storeFieldElementBits(payload, bitOffset, bucket.cnt, elementBits);
        storeFieldElementBits(payload, bitOffset, bucket.sumCipher, elementBits);
        storeFieldElementBits(payload, bitOffset, bucket.sumTag, elementBits);
    }
    if (!payload.empty()) {
        socket.sendAll(payload.data(), payload.size());
    }
}

std::vector<Bucket> recvBucketTable(TcpSocket &socket, std::size_t expectedBuckets,
                                    std::size_t elementBits) {
    const auto count = static_cast<std::size_t>(recvU64(socket));
    if (count != expectedBuckets) {
        throw std::runtime_error("received bucket table with unexpected size");
    }

    std::vector<unsigned char> payload(fieldElementPayloadBytes(count * 3, elementBits));
    if (!payload.empty()) {
        socket.recvAll(payload.data(), payload.size());
    }

    std::vector<Bucket> table(count);
    std::size_t bitOffset = 0;
    for (auto &bucket : table) {
        bucket.cnt = loadFieldElementBits(payload, bitOffset, elementBits);
        bucket.sumCipher = loadFieldElementBits(payload, bitOffset, elementBits);
        bucket.sumTag = loadFieldElementBits(payload, bitOffset, elementBits);
    }
    return table;
}

std::vector<unsigned char> encodeBitmap(const std::vector<std::size_t> &indices,
                                        std::size_t bitCount) {
    std::vector<unsigned char> bitmap((bitCount + 7) / 8, 0);
    for (auto index : indices) {
        if (index >= bitCount) {
            throw std::runtime_error("bitmap index exceeds bit count");
        }
        bitmap[index / 8] |= static_cast<unsigned char>(1U << (index % 8));
    }
    return bitmap;
}

std::vector<unsigned char> bitmapToMap(const std::vector<unsigned char> &bitmap,
                                       std::size_t bitCount) {
    if (bitmap.size() != (bitCount + 7) / 8) {
        throw std::runtime_error("bitmap payload has unexpected size");
    }

    std::vector<unsigned char> map(bitCount, 0);
    for (std::size_t index = 0; index < bitCount; ++index) {
        map[index] = static_cast<unsigned char>((bitmap[index / 8] >> (index % 8)) & 1U);
    }
    return map;
}

} // namespace memdedup
