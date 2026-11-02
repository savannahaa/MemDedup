#include "update_protocol.h"
#include <algorithm>
#include <limits>
#include <stdexcept>
#include <set>

namespace memdedup {
namespace {
ProtocolParams operationParams(ProtocolParams params) {
    if (params.providerCount == 0 || params.hashCount == 0 ||
        params.primaryBuckets < params.hashCount)
        throw std::invalid_argument("invalid batch dimensions");
    params.packedOperations = true;
    return params;
}
std::size_t tableBytes(std::size_t buckets) {
    constexpr std::size_t width = 3 * Field::wireBytes;
    if (buckets > std::numeric_limits<std::size_t>::max() / width)
        throw std::invalid_argument("table size overflow");
    return buckets * width;
}
void append64(wire::Bytes &bytes, std::uint64_t value) {
    for (int i = 0; i < 8; ++i)
        bytes.push_back(static_cast<unsigned char>((value >> (8 * i)) & 255));
}
std::uint64_t read64(const wire::Bytes &bytes, std::size_t offset) {
    if (offset > bytes.size() || bytes.size() - offset < 8)
        throw std::invalid_argument("short batch descriptor");
    std::uint64_t value = 0;
    for (int i = 0; i < 8; ++i)
        value |= std::uint64_t(bytes[offset + i]) << (8 * i);
    return value;
}
} // namespace

wire::Bytes encodeBatchDescriptor(const BatchDescriptor &descriptor) {
    if (descriptor.participants.empty() || descriptor.hashCount == 0 ||
        descriptor.primaryBuckets < descriptor.hashCount ||
        std::set<std::uint64_t>(descriptor.participants.begin(), descriptor.participants.end())
                .size() != descriptor.participants.size())
        throw std::invalid_argument("invalid descriptor dimensions or duplicate participant");
    wire::Bytes result;
    for (auto value :
         {std::uint64_t(1), descriptor.batch, std::uint64_t(descriptor.participants.size()),
          std::uint64_t(descriptor.primaryBuckets), std::uint64_t(descriptor.hashCount),
          std::uint64_t(512), std::uint64_t(512)})
        append64(result, value);
    for (auto participant : descriptor.participants)
        append64(result, participant);
    std::array<unsigned char, 32> digest{};
    unsigned int length = 0;
    wire::check(
        EVP_Digest(result.data(), result.size(), digest.data(), &length, EVP_sha256(), nullptr));
    result.insert(result.end(), digest.begin(), digest.end());
    return result;
}

BatchDescriptor decodeBatchDescriptor(const wire::Bytes &message) {
    if (message.size() < 96 || read64(message, 0) != 1 || read64(message, 40) != 512 ||
        read64(message, 48) != 512)
        throw std::invalid_argument("unsupported or short batch descriptor");
    const auto participants = read64(message, 16);
    if (participants != (message.size() - 88) / 8 || (message.size() - 88) % 8)
        throw std::invalid_argument("batch descriptor roster length mismatch");
    BatchDescriptor result{read64(message, 8),
                           {},
                           static_cast<std::size_t>(read64(message, 24)),
                           static_cast<std::size_t>(read64(message, 32))};
    for (std::size_t i = 0; i < participants; ++i)
        result.participants.push_back(read64(message, 56 + i * 8));
    if (encodeBatchDescriptor(result) != message)
        throw std::invalid_argument("batch parameter digest mismatch");
    return result;
}

void validateBatchDescriptor(const BatchDescriptor &descriptor, const ProtocolParams &params) {
    if (descriptor.batch != params.seed || descriptor.participants.size() != params.providerCount ||
        descriptor.primaryBuckets != params.primaryBuckets ||
        descriptor.hashCount != params.hashCount)
        throw std::invalid_argument("batch descriptor differs from local protocol parameters");
    (void)encodeBatchDescriptor(descriptor);
}

std::vector<Bucket> aggregateTables(const std::vector<std::vector<Bucket>> &tables,
                                    std::size_t buckets, std::size_t participants) {
    if (!participants || tables.size() != participants || !buckets)
        throw std::invalid_argument("missing participant table or invalid dimensions");
    std::vector<Bucket> result(buckets);
    for (const auto &table : tables) {
        if (table.size() != buckets)
            throw std::invalid_argument("inconsistent table dimensions");
        for (std::size_t i = 0; i < buckets; ++i)
            result[i].add(table[i]);
    }
    return result;
}

wire::Bytes serializeTable(const std::vector<Bucket> &table) {
    wire::Bytes result(tableBytes(table.size()));
    std::size_t position = 0;
    for (const auto &bucket : table)
        for (const auto &value : {bucket.cnt, bucket.sumCipher, bucket.sumTag}) {
            if (value >= Field::modulus())
                throw std::invalid_argument("noncanonical field element");
            for (std::size_t i = 0; i < Field::wireBytes; ++i)
                result[position++] = static_cast<unsigned char>((value >> (8 * i)) & 255);
        }
    return result;
}

std::vector<Bucket> deserializeTable(const wire::Bytes &bytes, std::size_t buckets) {
    if (bytes.size() != tableBytes(buckets))
        throw std::invalid_argument("invalid table wire length");
    std::vector<Bucket> result(buckets);
    std::size_t position = 0;
    for (auto &bucket : result)
        for (auto *value : {&bucket.cnt, &bucket.sumCipher, &bucket.sumTag}) {
            for (std::size_t i = 0; i < Field::wireBytes; ++i)
                *value |= Item(bytes[position++]) << (8 * i);
            if (*value >= Field::modulus())
                throw std::invalid_argument("noncanonical field element");
        }
    return result;
}

UpdateProvider::UpdateProvider(ProtocolParams params, std::size_t rank,
                               const std::vector<UpdateOperation> &operations)
    : m_rank(rank), m_params(operationParams(std::move(params))), m_protocol(m_params) {
    if (rank >= m_params.providerCount || !m_params.providerHasSecretSeed ||
        m_params.pairMaskSeeds.size() != m_params.providerCount)
        throw std::invalid_argument("provider secrets or roster are incomplete");
    auto recordParams = m_params;
    recordParams.packedOperations = false;
    DedupProtocol cipher(recordParams);
    RecordSet unique;
    for (const auto &operation : operations)
        unique.insert(packOperation(cipher.encrypt(operation.record), operation.deletion));
    m_operations.assign(unique.begin(), unique.end());
    std::sort(m_operations.begin(), m_operations.end());
}

std::vector<Bucket> UpdateProvider::primary() const {
    return m_protocol.encodePrimary(m_rank, m_operations);
}

std::vector<Bucket> UpdateProvider::auxiliary(const std::vector<unsigned char> &unresolved,
                                              std::size_t buckets) const {
    if (unresolved.size() != m_params.primaryBuckets || buckets < m_params.hashCount)
        throw std::invalid_argument("invalid auxiliary dimensions or primary residual map");
    return m_protocol.encodeAuxiliary(m_rank, m_operations, unresolved, buckets);
}

UpdateAggregator::UpdateAggregator(ProtocolParams params)
    : m_params(operationParams(std::move(params))), m_protocol(m_params) {}

void UpdateAggregator::primary(const std::vector<std::vector<Bucket>> &tables) {
    if (m_started)
        throw std::logic_error("use a fresh aggregator object for a new batch");
    auto decoded =
        m_protocol.decode(aggregateTables(tables, m_params.primaryBuckets, m_params.providerCount),
                          m_params.primaryBuckets, m_protocol.primaryHashSeed());
    m_operations = std::move(decoded.items);
    m_unresolvedPrimary = std::move(decoded.unresolvedBuckets);
    m_complete = m_unresolvedPrimary.empty();
    m_started = true;
}

void UpdateAggregator::auxiliary(const std::vector<std::vector<Bucket>> &tables,
                                 std::size_t buckets) {
    if (!m_started || m_complete || buckets < m_params.hashCount)
        throw std::logic_error("auxiliary round requires a primary residual core");
    auto decoded = m_protocol.decode(aggregateTables(tables, buckets, m_params.providerCount),
                                     buckets, m_protocol.auxiliaryHashSeed());
    m_operations.insert(decoded.items.begin(), decoded.items.end());
    m_complete = decoded.unresolvedBuckets.empty();
}

std::vector<unsigned char> UpdateAggregator::unresolvedPrimaryMap() const {
    if (!m_started)
        throw std::logic_error("primary round has not run");
    std::vector<unsigned char> map(m_params.primaryBuckets);
    for (auto bucket : m_unresolvedPrimary)
        map[bucket] = 1;
    return map;
}

bool UpdateAggregator::commit(State &state, std::uint64_t batch,
                              const std::vector<std::string> &requestIds) {
    if (batch != m_params.seed)
        throw std::invalid_argument("batch identifier differs from the session seed");
    if (!complete() || m_committed)
        return false;
    auto recordParams = m_params;
    recordParams.packedOperations = false;
    DedupProtocol cipher(recordParams);
    RecordSet inserts, deletes;
    for (auto packed : m_operations) {
        auto [ciphertext, deletion] = unpackOperation(packed);
        (deletion ? deletes : inserts).insert(cipher.decrypt(ciphertext));
    }
    m_committed = state.commit(batch, requestIds, inserts, deletes, true);
    return m_committed;
}

void sendProtectedControl(TcpSocket &socket, const wire::Bytes &message, const wire::Key &recipient,
                          std::uint64_t batch, int phase) {
    sendBytes(socket, wire::seal(message, recipient, batch, phase));
}
wire::Bytes receiveProtectedControl(TcpSocket &socket, const wire::Key &recipient,
                                    std::uint64_t batch, int phase) {
    return wire::open(recvBytes(socket), recipient, batch, phase);
}
void sendProtectedTable(TcpSocket &socket, const std::vector<Bucket> &table,
                        const wire::Key &recipient, std::uint64_t batch, int phase) {
    sendProtectedControl(socket, serializeTable(table), recipient, batch, phase);
}
std::vector<Bucket> receiveProtectedTable(TcpSocket &socket, std::size_t buckets,
                                          const wire::Key &recipient, std::uint64_t batch,
                                          int phase) {
    return deserializeTable(receiveProtectedControl(socket, recipient, batch, phase), buckets);
}
void forwardShuffledTables(const std::vector<TcpSocket *> &providers, TcpSocket &aggregator) {
    if (providers.empty())
        throw std::invalid_argument("empty shuffle participant roster");
    for (auto *socket : providers)
        if (!socket || !socket->valid())
            throw std::invalid_argument("missing shuffle provider connection");
    std::vector<wire::Bytes> messages;
    for (auto *socket : providers)
        messages.push_back(recvBytes(*socket));
    wire::shuffle(messages);
    sendU64(aggregator, messages.size());
    for (const auto &message : messages)
        sendBytes(aggregator, message);
}
std::vector<std::vector<Bucket>> receiveShuffledTables(TcpSocket &shuffle, std::size_t participants,
                                                       std::size_t buckets,
                                                       const wire::Key &recipient,
                                                       std::uint64_t batch, int phase) {
    if (!participants || recvU64(shuffle) != participants)
        throw std::runtime_error("shuffle participant count mismatch");
    std::vector<std::vector<Bucket>> result;
    for (std::size_t i = 0; i < participants; ++i)
        result.push_back(receiveProtectedTable(shuffle, buckets, recipient, batch, phase));
    return result;
}
} // namespace memdedup
