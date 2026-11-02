#pragma once

#include "bucket.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace memdedup {

class TcpSocket {
  public:
    TcpSocket() = default;
    explicit TcpSocket(int fd);
    ~TcpSocket();

    TcpSocket(const TcpSocket &) = delete;
    TcpSocket &operator=(const TcpSocket &) = delete;

    TcpSocket(TcpSocket &&other) noexcept;
    TcpSocket &operator=(TcpSocket &&other) noexcept;

    static TcpSocket connectTo(const std::string &host, std::uint16_t port,
                               std::size_t maxAttempts = 200, std::size_t retryDelayMs = 25);

    void sendAll(const void *data, std::size_t size);
    void recvAll(void *data, std::size_t size);
    void close();

    bool valid() const { return mFd >= 0; }

  private:
    int mFd = -1;
};

class TcpListener {
  public:
    TcpListener() = default;
    explicit TcpListener(int fd);
    ~TcpListener();

    TcpListener(const TcpListener &) = delete;
    TcpListener &operator=(const TcpListener &) = delete;

    TcpListener(TcpListener &&other) noexcept;
    TcpListener &operator=(TcpListener &&other) noexcept;

    static TcpListener bind(std::uint16_t port, int backlog);
    TcpSocket accept();
    void close();

  private:
    int mFd = -1;
};

void sendU64(TcpSocket &socket, std::uint64_t value);
std::uint64_t recvU64(TcpSocket &socket);

void sendBytes(TcpSocket &socket, const std::vector<unsigned char> &bytes);
std::vector<unsigned char> recvBytes(TcpSocket &socket);

void sendBucketTable(TcpSocket &socket, const std::vector<Bucket> &table, std::size_t elementBits);
std::vector<Bucket> recvBucketTable(TcpSocket &socket, std::size_t expectedBuckets,
                                    std::size_t elementBits);

std::vector<unsigned char> encodeBitmap(const std::vector<std::size_t> &indices,
                                        std::size_t bitCount);
std::vector<unsigned char> bitmapToMap(const std::vector<unsigned char> &bitmap,
                                       std::size_t bitCount);

} // namespace memdedup
