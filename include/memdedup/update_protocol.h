#pragma once
#include "dedup_protocol.h"
#include "envelope.h"
#include "network.h"
#include "update_state.h"

namespace memdedup {
struct UpdateOperation {
    Item record;
    bool deletion = false;
};
// Send this descriptor only through protected controls to the agreed providers.
// Roster order defines dense local indices for pairwise masks and provider rank.
struct BatchDescriptor {
    std::uint64_t batch;
    std::vector<std::uint64_t> participants;
    std::size_t primaryBuckets;
    std::size_t hashCount;
};
wire::Bytes encodeBatchDescriptor(const BatchDescriptor &descriptor);
BatchDescriptor decodeBatchDescriptor(const wire::Bytes &message);
void validateBatchDescriptor(const BatchDescriptor &descriptor, const ProtocolParams &params);

// Every agreed participant must supply one table of the agreed dimensions.
std::vector<Bucket> aggregateTables(const std::vector<std::vector<Bucket>> &tables,
                                    std::size_t buckets, std::size_t participants);
wire::Bytes serializeTable(const std::vector<Bucket> &table);
std::vector<Bucket> deserializeTable(const wire::Bytes &bytes, std::size_t buckets);

// One immutable operation set, participant roster and parameter set per batch.
// An empty input still produces the pairwise masks required of a cover provider.
class UpdateProvider {
  public:
    UpdateProvider(ProtocolParams params, std::size_t rank,
                   const std::vector<UpdateOperation> &operations);
    std::vector<Bucket> primary() const;
    std::vector<Bucket> auxiliary(const std::vector<unsigned char> &unresolvedPrimary,
                                  std::size_t buckets) const;

  private:
    std::size_t m_rank;
    ProtocolParams m_params;
    DedupProtocol m_protocol;
    std::vector<Item> m_operations;
};

// Holds decoded operations until complete recovery; it never commits a partial batch.
class UpdateAggregator {
  public:
    explicit UpdateAggregator(ProtocolParams params);
    void primary(const std::vector<std::vector<Bucket>> &tables);
    void auxiliary(const std::vector<std::vector<Bucket>> &tables, std::size_t buckets);
    std::vector<unsigned char> unresolvedPrimaryMap() const;
    bool complete() const { return m_started && m_complete; }
    bool commit(State &state, std::uint64_t batch, const std::vector<std::string> &requestIds);

  private:
    ProtocolParams m_params;
    DedupProtocol m_protocol;
    RecordSet m_operations;
    std::vector<std::size_t> m_unresolvedPrimary;
    bool m_started = false;
    bool m_complete = false;
    bool m_committed = false;
};

// Protected transport helpers: phase and batch are authenticated as envelope AAD.
void sendProtectedControl(TcpSocket &socket, const wire::Bytes &message, const wire::Key &recipient,
                          std::uint64_t batch, int phase);
wire::Bytes receiveProtectedControl(TcpSocket &socket, const wire::Key &recipient,
                                    std::uint64_t batch, int phase);
void sendProtectedTable(TcpSocket &socket, const std::vector<Bucket> &table,
                        const wire::Key &recipient, std::uint64_t batch, int phase);
std::vector<Bucket> receiveProtectedTable(TcpSocket &socket, std::size_t buckets,
                                          const wire::Key &recipient, std::uint64_t batch,
                                          int phase);

// Shuffle forwards opaque provider envelopes, never decrypting their tables.
void forwardShuffledTables(const std::vector<TcpSocket *> &providers, TcpSocket &aggregator);
std::vector<std::vector<Bucket>> receiveShuffledTables(TcpSocket &shuffle, std::size_t participants,
                                                       std::size_t buckets,
                                                       const wire::Key &recipient,
                                                       std::uint64_t batch, int phase);
} // namespace memdedup
